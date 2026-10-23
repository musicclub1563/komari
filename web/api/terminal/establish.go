package terminal

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/web/api"
)

func EstablishConnection(c *gin.Context) {
	session_id := c.Query("id")
	// Browser 会在重连/挂起路径上被并发替换，必须在锁内读取快照。
	TerminalSessionsMutex.Lock()
	session, exists := TerminalSessions[session_id]
	active := exists && session != nil && session.Browser != nil
	sessionUUID := ""
	if active {
		sessionUUID = session.UUID
	}
	TerminalSessionsMutex.Unlock()
	authenticatedUUID, _ := c.Get("client_uuid")
	authenticatedString, hasAuthenticatedUUID := authenticatedUUID.(string)
	if !active ||
		(hasAuthenticatedUUID && authenticatedString != "" && authenticatedString != sessionUUID) {
		c.JSON(404, gin.H{"status": "error", "error": "Session not found"})
		return
	}
	// Upgrade the connection to WebSocket
	if !api.IsWebSocketUpgrade(c) {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "Require WebSocket upgrade"})
		return
	}
	conn, err := api.UpgradeSafeConnWithLimit(c, api.MaxTerminalMessageBytes, api.EnableWebSocketCompression)
	if err != nil {
		closeSession(session_id)
		return
	}
	_, ok := attachAgent(session_id, conn)
	if !ok {
		conn.Close()
		return
	}
	conn.SetCloseHandler(func(code int, text string) error {
		suspendSession(session_id, nil, conn)
		return nil
	})
	maybeStartForwarding(session_id)
}
