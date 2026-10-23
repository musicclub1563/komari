package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/web/connection"
	"github.com/komari-monitor/komari/web/security"
)

type WebSocketUpgradeOption func(*websocket.Upgrader)

// Per-endpoint inbound message limits. They are applied while reading, before
// the payload is buffered (see connection.SafeConn.SetReadLimit), and are
// deliberately much smaller than the 8 MiB that was previously accepted
// everywhere. File transfers and other bulk payloads use dedicated REST
// endpoints instead of the WebSocket control channels.
const (
	// DefaultMaxWebSocketMessageBytes bounds any connection that does not pick
	// an explicit limit. Keeping a fallback means a new endpoint cannot silently
	// inherit an unbounded read.
	DefaultMaxWebSocketMessageBytes int64 = 1 << 20
	// MaxRPCMessageBytes bounds JSON-RPC frames on /api/rpc2. Requests are
	// control messages; bulk data does not travel over this channel.
	MaxRPCMessageBytes int64 = 1 << 20
	// MaxAgentMessageBytes bounds agent v2 report/heartbeat frames.
	MaxAgentMessageBytes int64 = 1 << 20
	// MaxTerminalMessageBytes bounds terminal keystrokes and output chunks.
	MaxTerminalMessageBytes int64 = 1 << 20
	// MaxPublicStreamMessageBytes bounds the public client-status stream, whose
	// protocol is limited to "get" and "get <uuid>".
	MaxPublicStreamMessageBytes int64 = 4 << 10
)

func IsWebSocketUpgrade(c *gin.Context) bool {
	return websocket.IsWebSocketUpgrade(c.Request)
}

func EnableWebSocketCompression(upgrader *websocket.Upgrader) {
	upgrader.EnableCompression = true
}

func UpgradeWebSocket(c *gin.Context, options ...WebSocketUpgradeOption) (*websocket.Conn, error) {
	if !IsWebSocketUpgrade(c) {
		return nil, fmt.Errorf("require websocket upgrade")
	}
	upgrader := websocket.Upgrader{
		CheckOrigin: CheckWebSocketOrigin,
	}
	for _, option := range options {
		option(&upgrader)
	}
	return upgrader.Upgrade(c.Writer, c.Request, nil)
}

// UpgradeSafeConn upgrades the request to a WebSocket and attaches the
// process-wide plugin frame interceptor (when one is wired). A plugin
// wsConnect hook may deny the connection: the peer receives a
// policy-violation close frame and the caller gets an error.
func UpgradeSafeConn(c *gin.Context, options ...WebSocketUpgradeOption) (*connection.SafeConn, error) {
	return UpgradeSafeConnWithLimit(c, DefaultMaxWebSocketMessageBytes, options...)
}

// UpgradeSafeConnWithLimit is UpgradeSafeConn with an explicit inbound message
// limit. The limit is installed before the plugin hook runs and before any read,
// so oversized frames are rejected without being buffered by the server or by
// plugin frame hooks.
func UpgradeSafeConnWithLimit(c *gin.Context, limit int64, options ...WebSocketUpgradeOption) (*connection.SafeConn, error) {
	unsafeConn, err := UpgradeWebSocket(c, options...)
	if err != nil {
		return nil, err
	}
	sc := connection.NewSafeConn(unsafeConn)
	if limit > 0 {
		sc.SetReadLimit(limit)
	}
	interceptor := connection.Interceptor()
	if interceptor == nil {
		return sc, nil
	}
	info := &connection.ConnInfo{
		ID:        sc.ID,
		Path:      c.Request.URL.Path,
		RemoteIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	}
	if clientUUID, ok := c.Get("client_uuid"); ok {
		if s, ok := clientUUID.(string); ok {
			info.ClientUUID = s
		}
	}
	if deny, reason := interceptor.OnConnect(info); deny {
		_ = unsafeConn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, reason),
			time.Now().Add(time.Second))
		_ = unsafeConn.Close()
		return nil, errors.New("websocket connection denied by plugin")
	}
	sc.SetInterceptor(info, interceptor)
	return sc, nil
}

func CheckWebSocketOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if strings.EqualFold(os.Getenv("KOMARI_WS_DISABLE_ORIGIN"), "true") {
		return true
	}
	if security.IsAPIKeyRequest(r) {
		return true
	}
	if origin == "" && r.URL.Query().Get("token") != "" {
		return true
	}
	enabled, _ := config.GetAs[bool](config.WsOriginCheckEnabledKey, true)
	if !enabled {
		return true
	}
	if origin == "" {
		return false
	}
	if security.OriginMatchesHost(origin, r.Host) {
		return true
	}
	allowlist, _ := config.GetAs[string](config.WsAllowedOriginsKey, "")
	return security.OriginInAllowlist(origin, allowlist)
}
