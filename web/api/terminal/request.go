package terminal

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/clients"
	v2 "github.com/komari-monitor/komari/protocol/v2"
	"github.com/komari-monitor/komari/pkg/rpc"
	"github.com/komari-monitor/komari/utils"
	logger "github.com/komari-monitor/komari/utils/log"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
	"github.com/komari-monitor/komari/web/api"
)

func dispatchTerminalRequest(uuid, id string) bool {
	return agent_runtime.DispatchV2Event(uuid, v2.MethodAgentTerminal, v2.TerminalRequestParams{RequestID: id})
}

// captureTerminalCredential 把当前请求的凭据固化成独立快照。
//
// 终端 handler 返回后 gin.Context 会被复用，后台转发 goroutine 不能持有它；
// 同时授权必须能追溯到建立连接时实际使用的凭据，而不是 UserUUID（API Key
// 共用占位 UUID，无法据此判断密钥是否已轮换）。
func captureTerminalCredential(c *gin.Context) *terminalCredential {
	p := api.IdentifyPrincipal(c)
	switch p.Type {
	case rpc.PrincipalAPIKey:
		const bearerPrefix = "Bearer "
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, bearerPrefix) {
			return nil
		}
		key := strings.TrimSpace(strings.TrimPrefix(auth, bearerPrefix))
		if key == "" {
			return nil
		}
		return &terminalCredential{apiKey: key}
	case rpc.PrincipalUser:
		token, err := c.Cookie("session_token")
		if err != nil || token == "" {
			return nil
		}
		return &terminalCredential{sessionToken: token, userUUID: p.UserUUID}
	default:
		return nil
	}
}

func RequestTerminal(c *gin.Context) {
	uuid := c.Param("uuid")
	userUUID, _ := c.Get("uuid")
	userID, _ := userUUID.(string)
	_, err := clients.GetClientByUUID(uuid)
	if err != nil {
		c.JSON(400, gin.H{
			"status":  "error",
			"message": "Client not found",
		})
		return
	}

	// 在 handler 内固化凭据并立即校验一次；handler 返回后 gin.Context 会被
	// 复用，后台转发 goroutine 只使用这个独立快照。
	credential := captureTerminalCredential(c)
	if credential == nil || !credential.valid() {
		api.RespondError(c, http.StatusUnauthorized, "Credential is no longer valid")
		return
	}

	id := strings.TrimSpace(c.Query("request_id"))
	if id == "" {
		// Only a new terminal request is a sensitive operation. Reattaching an
		// existing session is authorized by its owner below and must not require
		// a fresh (and potentially expired) TOTP code.
		if err := api.VerifySensitive2FA(c); err != nil {
			api.RespondError(c, http.StatusUnauthorized, err.Error())
			return
		}
	} else {
		TerminalSessionsMutex.Lock()
		session := TerminalSessions[id]
		allowed := session != nil && session.UUID == uuid &&
			(credential.apiKey != "" || session.UserUUID == userID)
		TerminalSessionsMutex.Unlock()
		if !allowed {
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Terminal session not found"})
			return
		}
	}

	// 建立ws
	if !api.IsWebSocketUpgrade(c) {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Require WebSocket upgrade"})
		return
	}
	conn, err := api.UpgradeSafeConnWithLimit(c, api.MaxTerminalMessageBytes, api.EnableWebSocketCompression)
	if err != nil {
		return
	}

	if id != "" {
		session, ok := attachBrowser(id, userID, credential, conn)
		if !ok || session.UUID != uuid {
			conn.WriteMessage(1, []byte("Terminal session expired\n终端会话已过期\n"))
			conn.Close()
			return
		}
		conn.SetCloseHandler(func(code int, text string) error {
			logger.InfoArgs("terminal", "Terminal browser connection closed:", code, text)
			suspendSession(id, conn, nil)
			return nil
		})
		conn.WriteJSON(gin.H{"request_id": id})
		if !dispatchTerminalRequest(uuid, id) {
			conn.WriteMessage(1, []byte("Client offline!\n被控端离线!\n"))
			closeSession(id)
			return
		}
		if session.Agent == nil {
			conn.WriteMessage(1, []byte("等待被控端连接 waiting for agent...\n"))
		}
		maybeStartForwarding(id)
		return
	}

	// 新建一个终端连接
	id = utils.GenerateRandomString(32)
	session := &TerminalSession{
		UserUUID:    userID,
		UUID:        uuid,
		Browser:     conn,
		Agent:       nil,
		RequesterIp: c.ClientIP(),
		Credential:  credential,
	}

	TerminalSessionsMutex.Lock()
	TerminalSessions[id] = session
	scheduleCleanup(id, session)
	TerminalSessionsMutex.Unlock()
	conn.SetCloseHandler(func(code int, text string) error {
		logger.InfoArgs("terminal", "Terminal browser connection closed:", code, text)
		suspendSession(id, conn, nil)
		return nil
	})
	conn.WriteJSON(gin.H{"request_id": id})
	if !dispatchTerminalRequest(uuid, id) {
		conn.Close()
		closeSession(id)
		return
	}
	conn.WriteMessage(1, []byte("等待被控端连接 waiting for agent...\n"))
}
