package client

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	logger "github.com/komari-monitor/komari/utils/log"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/database/clients"
	"github.com/komari-monitor/komari/database/tasks"
	v2 "github.com/komari-monitor/komari/protocol/v2"
	"github.com/komari-monitor/komari/utils/notifier"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
	"github.com/komari-monitor/komari/web/api"
	"github.com/komari-monitor/komari/web/connection"
	"github.com/komari-monitor/komari/web/filemanager"
)

// Agent v2 HTTP 上报的体积上限。
//
// 该通道承载 report / basic info / ping result / task result / file result /
// event pull 等 JSON-RPC 消息；正常负载在几十 KB 量级，1 MiB 对含大量 GPU
// 或进程条目的上报仍留有一个数量级的余量，并与 WebSocket Agent 通道的
// MaxAgentMessageBytes 保持一致。
const (
	// MaxAgentRequestBodyBytes 限制网络传输（压缩后）的请求体字节数。
	MaxAgentRequestBodyBytes int64 = 1 << 20
	// MaxAgentDecompressedBodyBytes 限制 gzip 解压后的字节数，防止压缩炸弹。
	MaxAgentDecompressedBodyBytes int64 = 1 << 20
)

// errAgentBodyTooLarge 表示上报体超过上限，调用方应返回 413。
var errAgentBodyTooLarge = errors.New("agent request body exceeds limit")

// countingReader 记录底层已读取的字节数，用于区分“压缩体本身超限”与
// “压缩体损坏”。
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func readMaybeCompressedBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()

	// 先限制网络字节数：LimitReader 在读取过程中截断，因此分块传输或没有
	// 可信 Content-Length 的请求同样受约束，不会先完整缓冲再检查。
	wire := &countingReader{r: io.LimitReader(r.Body, MaxAgentRequestBodyBytes+1)}

	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(wire)
		if err != nil {
			if wire.n > MaxAgentRequestBodyBytes {
				return nil, errAgentBodyTooLarge
			}
			return nil, err
		}
		defer zr.Close()

		// 再限制解压后的体积：压缩后很小、解压后超限时在读取到上限+1 时
		// 立即停止，不会缓冲完整解压结果。
		data, err := io.ReadAll(io.LimitReader(zr, MaxAgentDecompressedBodyBytes+1))
		if err != nil {
			if wire.n > MaxAgentRequestBodyBytes {
				return nil, errAgentBodyTooLarge
			}
			return nil, err
		}
		if int64(len(data)) > MaxAgentDecompressedBodyBytes {
			return nil, errAgentBodyTooLarge
		}
		return data, nil
	}

	data, err := io.ReadAll(wire)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxAgentRequestBodyBytes || wire.n > MaxAgentRequestBodyBytes {
		return nil, errAgentBodyTooLarge
	}
	return data, nil
}

func bindV2Params[T any](raw any, target *T) error {
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, target)
}

func handleV2RPC(uuid string, req v2.Request, allowWait bool) v2.Response {
	if req.JSONRPC != v2.Version {
		return v2.Error(req.ID, -32600, "invalid jsonrpc version", nil)
	}
	switch req.Method {
	case v2.MethodAgentReport:
		var params v2.ReportParams
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid report params", err.Error())
		}
		if err := ingestReport(uuid, params.Report, true); err != nil {
			return v2.Error(req.ID, -32000, "failed to save report", err.Error())
		}
		return v2.Success(req.ID, gin.H{
			"status": "success",
			"events": agent_runtime.TakeV2Events(uuid, params.AckEventIDs, 8),
		})
	case v2.MethodAgentBasicInfo:
		var params v2.BasicInfoParams
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid basic info params", err.Error())
		}
		if err := ingestBasicInfo(uuid, params.Info, ""); err != nil {
			return v2.Error(req.ID, -32000, "failed to save basic info", err.Error())
		}
		return v2.Success(req.ID, gin.H{"status": "success"})
	case v2.MethodAgentPingResult:
		var params v2.PingResultParams
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid ping result params", err.Error())
		}
		if err := ingestPingResult(uuid, params.TaskID, params.Value); err != nil {
			return v2.Error(req.ID, -32000, "failed to save ping result", err.Error())
		}
		return v2.Success(req.ID, gin.H{"status": "success"})
	case v2.MethodAgentTaskResult:
		var params v2.TaskResultParams
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid task result params", err.Error())
		}
		finishedAt := params.FinishedAt
		if finishedAt.IsZero() {
			finishedAt = time.Now().UTC()
		}
		if err := tasks.SaveTaskResult(params.TaskID, uuid, params.Result, params.ExitCode, finishedAt); err != nil {
			return v2.Error(req.ID, -32000, "failed to save task result", err.Error())
		}
		return v2.Success(req.ID, gin.H{"status": "success"})
	case v2.MethodAgentPull:
		var params v2.PullParams
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid pull params", err.Error())
		}
		refreshPostPresence(uuid)
		agent_runtime.MarkV2Client(uuid)
		timeout := 0 * time.Second
		if allowWait {
			timeout = 25 * time.Second
		}
		return v2.Success(req.ID, gin.H{
			"events": agent_runtime.WaitV2Events(uuid, params.AckEventIDs, timeout),
		})
	case v2.MethodAgentFileResult:
		var params v2.FileResult
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid file result params", err.Error())
		}
		params.UUID = uuid
		if !filemanager.Resolve(params) {
			return v2.Error(req.ID, -32004, "unknown or expired file operation", nil)
		}
		return v2.Success(req.ID, gin.H{"status": "success"})
	case v2.MethodAgentStartupConfigResult:
		var params v2.StartupConfigResult
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid startup configuration result", nil)
		}
		if !agent_runtime.ResolveStartupConfig(uuid, params) {
			return v2.Error(req.ID, -32004, "unknown or expired startup configuration request", nil)
		}
		return v2.Success(req.ID, gin.H{"status": "success"})
	default:
		return v2.Error(req.ID, -32601, "method not found", req.Method)
	}
}

func UploadV2RPC(c *gin.Context) {
	bytesBody, err := readMaybeCompressedBody(c.Request)
	if err != nil {
		if errors.Is(err, errAgentBodyTooLarge) {
			c.JSON(http.StatusRequestEntityTooLarge, v2.Error(nil, -32000, "request body too large", nil))
			return
		}
		c.JSON(http.StatusBadRequest, v2.Error(nil, -32700, "invalid compressed body", err.Error()))
		return
	}
	var req v2.Request
	if err := json.Unmarshal(bytesBody, &req); err != nil {
		c.JSON(http.StatusBadRequest, v2.Error(nil, -32700, "parse error", err.Error()))
		return
	}
	uuid, ok := clientUUIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, v2.Error(req.ID, -32001, "invalid token", nil))
		return
	}
	resp := handleV2RPC(uuid, req, true)
	status := http.StatusOK
	if resp.Error != nil {
		status = http.StatusBadRequest
	}
	c.JSON(status, resp)
}

func WebSocketV2RPC(c *gin.Context) {
	if !api.IsWebSocketUpgrade(c) {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "Require WebSocket upgrade"})
		return
	}
	conn, err := api.UpgradeSafeConnWithLimit(c, api.MaxAgentMessageBytes, api.EnableWebSocketCompression)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "Failed to upgrade to WebSocket." + err.Error()})
		return
	}
	defer conn.Close()

	uuid, ok := clientUUIDFromContext(c)
	if !ok {
		conn.WriteJSON(v2.Error(nil, -32001, "invalid token", nil))
		return
	}
	if oldConn, exists := agent_runtime.GetConnectedClients()[uuid]; exists {
		go oldConn.Close()
	}
	agent_runtime.SetConnectedClients(uuid, conn)
	agent_runtime.MarkV2Client(uuid)
	go notifierOnline(uuid, conn.ID)
	defer func() {
		agent_runtime.DeleteClientConditionally(uuid, conn)
		notifierOffline(uuid, conn.ID)
	}()
	if !pushQueuedV2Events(conn, uuid) {
		return
	}
	setWebSocketPingHandler(conn, v2WebSocketReadWait, v2WebSocketWriteWait)

	for {
		conn.SetReadDeadline(time.Now().Add(v2WebSocketReadWait))
		_, message, err := conn.ReadMessage()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logger.Errorf("client-api", "Client %s v2 heartbeat timed out after %s", uuid, v2WebSocketReadWait)
			} else if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.Errorf("client-api", "Client %s v2 connection error: %v", uuid, err)
			}
			return
		}
		message = bytes.TrimSpace(message)
		var req v2.Request
		if err := json.Unmarshal(message, &req); err != nil {
			conn.WriteJSON(v2.Error(nil, -32700, "parse error", err.Error()))
			continue
		}
		resp := handleV2RPC(uuid, req, false)
		if req.ID != nil {
			if err := conn.WriteJSON(resp); err != nil {
				logger.Errorf("client-api", "failed to write v2 rpc response: %v", err)
				return
			}
		}
	}
}

func pushQueuedV2Events(conn *connection.SafeConn, uuid string) bool {
	events := agent_runtime.TakeV2Events(uuid, nil, 0)
	if len(events) == 0 {
		return true
	}
	ackIDs := make([]string, 0, len(events))
	for _, event := range events {
		payload := v2.Request{JSONRPC: v2.Version, Method: event.Method, Params: event.Params}
		if err := conn.WriteJSON(payload); err != nil {
			agent_runtime.AckV2Events(uuid, ackIDs)
			logger.Errorf("client-api", "failed to push queued v2 event %s to client %s: %v", event.ID, uuid, err)
			return false
		}
		ackIDs = append(ackIDs, event.ID)
	}
	agent_runtime.AckV2Events(uuid, ackIDs)
	return true
}

func clientUUIDFromContext(c *gin.Context) (string, bool) {
	if v, ok := c.Get("client_uuid"); ok {
		if uuid, ok := v.(string); ok && uuid != "" {
			return uuid, true
		}
	}
	token := c.Query("token")
	if token == "" {
		return "", false
	}
	uuid, err := clients.GetClientUUIDByToken(token)
	return uuid, err == nil && uuid != ""
}

func notifierOnline(uuid string, connID int64) {
	go notifier.OnlineNotification(uuid, connID)
}

func notifierOffline(uuid string, connID int64) {
	notifier.OfflineNotification(uuid, connID)
}
