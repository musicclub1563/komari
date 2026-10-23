package client

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/clients"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	v2 "github.com/komari-monitor/komari/protocol/v2"
	"github.com/komari-monitor/komari/web/api"
)

func ensureClientTestDB() {
	flags.DatabaseType = "sqlite"
	flags.DatabaseFile = "file:komari_client_ws_credential_test?mode=memory&cache=shared"
	_ = dbcore.GetDBInstance()
}

func newAgentWSTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	engine := gin.New()
	engine.Use(api.IdentityMiddleware())
	group := engine.Group("/api/clients", api.RequireRole(api.RoleAdmin, api.RoleClient))
	group.GET("/v2/rpc", WebSocketV2RPC)
	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)
	return server
}

func dialAgentWS(t *testing.T, server *httptest.Server, token string) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/clients/v2/rpc?token=" + token
	conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial agent ws: %v (status %d)", err, status)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func sendBasicInfo(t *testing.T, conn *websocket.Conn, osName string) v2.Response {
	t.Helper()
	req := v2.Request{
		JSONRPC: v2.Version,
		Method:  v2.MethodAgentBasicInfo,
		Params:  v2.BasicInfoParams{Info: map[string]interface{}{"os": osName}},
		ID:      1,
	}
	if err := conn.WriteJSON(req); err != nil {
		t.Fatalf("write basic info: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp v2.Response
	if err := conn.ReadJSON(&resp); err != nil {
		t.Fatalf("read basic info response: %v", err)
	}
	return resp
}

// expectReportRejected sends a report on a connection that should no longer be
// authorized and waits until the server either answers with an error or closes
// the connection. The error response can race with the close frame, so both
// outcomes count; callers assert the database stayed unchanged.
func expectReportRejected(t *testing.T, conn *websocket.Conn, osName string) {
	t.Helper()
	req := v2.Request{
		JSONRPC: v2.Version,
		Method:  v2.MethodAgentBasicInfo,
		Params:  v2.BasicInfoParams{Info: map[string]interface{}{"os": osName}},
		ID:      2,
	}
	_ = conn.WriteJSON(req)
	deadline := time.Now().Add(3 * time.Second)
	for {
		_ = conn.SetReadDeadline(deadline)
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var resp v2.Response
		if json.Unmarshal(data, &resp) == nil && resp.Error != nil {
			return
		}
	}
}

func storedClientOS(t *testing.T, clientUUID string) string {
	t.Helper()
	var client models.Client
	if err := dbcore.GetDBInstance().Where("uuid = ?", clientUUID).First(&client).Error; err != nil {
		t.Fatalf("read client: %v", err)
	}
	return client.OS
}

// TestAgentWebSocketRevalidatesTokenPerMessage covers the reported bug: after
// the agent token is rotated, HTTP requests were rejected but the existing
// WebSocket kept writing basic info. Every message must be checked against the
// current token, and a new connection with the new token must keep working.
func TestAgentWebSocketRevalidatesTokenPerMessage(t *testing.T) {
	ensureClientTestDB()
	server := newAgentWSTestServer(t)

	clientUUID := uuid.NewString()
	token1 := "agent-token-one-" + clientUUID
	token2 := "agent-token-two-" + clientUUID
	if err := dbcore.GetDBInstance().Create(&models.Client{
		UUID:  clientUUID,
		Token: token1,
		Name:  "ws-credential-test",
	}).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(func() {
		_ = dbcore.GetDBInstance().Where("uuid = ?", clientUUID).Delete(&models.Client{}).Error
	})

	oldConn := dialAgentWS(t, server, token1)
	if resp := sendBasicInfo(t, oldConn, "linux-before"); resp.Error != nil {
		t.Fatalf("initial basic info failed: %+v", resp.Error)
	}
	if got := storedClientOS(t, clientUUID); got != "linux-before" {
		t.Fatalf("stored OS = %q after first report", got)
	}

	// Rotate the token while the old connection stays open.
	if err := dbcore.GetDBInstance().Model(&models.Client{}).
		Where("uuid = ?", clientUUID).Update("token", token2).Error; err != nil {
		t.Fatalf("rotate token: %v", err)
	}
	if _, err := clients.GetClientUUIDByToken(token1); err == nil {
		t.Fatal("old token still resolves after rotation")
	}

	expectReportRejected(t, oldConn, "linux-after")
	if got := storedClientOS(t, clientUUID); got != "linux-before" {
		t.Fatalf("stored OS = %q after rejected report, want linux-before", got)
	}
	// The server must close the revoked connection instead of keeping it alive.
	_ = oldConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := oldConn.ReadMessage(); err == nil {
		t.Fatal("revoked connection stayed open")
	}

	// The new token can connect and report normally.
	newConn := dialAgentWS(t, server, token2)
	if resp := sendBasicInfo(t, newConn, "linux-new"); resp.Error != nil {
		t.Fatalf("new connection basic info failed: %+v", resp.Error)
	}
	if got := storedClientOS(t, clientUUID); got != "linux-new" {
		t.Fatalf("stored OS = %q after new-token report", got)
	}
}

// TestAgentWebSocketOtherConnectionUnaffected keeps the conditional cleanup
// guarantee: closing a revoked connection must not remove the new connection
// or its online state.
func TestAgentWebSocketOtherConnectionUnaffected(t *testing.T) {
	ensureClientTestDB()
	server := newAgentWSTestServer(t)

	clientUUID := uuid.NewString()
	token1 := "agent-token-a-" + clientUUID
	token2 := "agent-token-b-" + clientUUID
	if err := dbcore.GetDBInstance().Create(&models.Client{
		UUID:  clientUUID,
		Token: token1,
		Name:  "ws-credential-conditional",
	}).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(func() {
		_ = dbcore.GetDBInstance().Where("uuid = ?", clientUUID).Delete(&models.Client{}).Error
	})

	oldConn := dialAgentWS(t, server, token1)
	if resp := sendBasicInfo(t, oldConn, "old"); resp.Error != nil {
		t.Fatalf("old connection report failed: %+v", resp.Error)
	}

	if err := dbcore.GetDBInstance().Model(&models.Client{}).
		Where("uuid = ?", clientUUID).Update("token", token2).Error; err != nil {
		t.Fatalf("rotate token: %v", err)
	}
	newConn := dialAgentWS(t, server, token2)
	if resp := sendBasicInfo(t, newConn, "new"); resp.Error != nil {
		t.Fatalf("new connection report failed: %+v", resp.Error)
	}
	// Revoke the old connection only after the new one is registered.
	expectReportRejected(t, oldConn, "revoked")
	if got := storedClientOS(t, clientUUID); got != "new" {
		t.Fatalf("stored OS = %q after rejected old report, want new", got)
	}

	time.Sleep(100 * time.Millisecond)
	if resp := sendBasicInfo(t, newConn, "newer"); resp.Error != nil {
		t.Fatalf("new connection was affected by old connection cleanup: %+v", resp.Error)
	}
	if got := storedClientOS(t, clientUUID); got != "newer" {
		t.Fatalf("stored OS = %q, want newer", got)
	}
}
