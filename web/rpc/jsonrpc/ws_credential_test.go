package jsonrpc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/pkg/rpc"
)

// wsCredentialProbeMethod is an admin-only method used to observe whether a
// long-lived WebSocket connection still carries admin authority after its
// credential was revoked. It needs no database state of its own.
const wsCredentialProbeMethod = "admin:ws_credential_probe"

var (
	probeOnce     sync.Once
	probeRegister error
)

func registerCredentialProbe(t *testing.T) {
	t.Helper()
	probeOnce.Do(func() {
		probeRegister = rpc.Register(wsCredentialProbeMethod,
			func(context.Context, *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
				return "ok", nil
			})
	})
	if probeRegister != nil && !strings.Contains(probeRegister.Error(), "already registered") {
		t.Fatalf("register probe method: %v", probeRegister)
	}
}

func newRPCWebSocketServer(t *testing.T) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/api/rpc2", OnRpcRequest)
	return httptest.NewServer(engine)
}

func dialRPCWebSocket(t *testing.T, serverURL string, header http.Header) *websocket.Conn {
	t.Helper()
	if header == nil {
		header = http.Header{}
	}
	// Same-origin handshake: the identity under test is the credential, not the
	// origin policy.
	header.Set("Origin", serverURL)
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	conn, resp, err := dialer.Dial("ws"+strings.TrimPrefix(serverURL, "http")+"/api/rpc2", header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial rpc websocket: %v (status %d)", err, status)
	}
	return conn
}

func callCredentialProbe(t *testing.T, conn *websocket.Conn, id int) *rpc.JsonRpcResponse {
	t.Helper()
	req := rpc.NewRequest(id, wsCredentialProbeMethod, map[string]any{})
	if err := conn.WriteJSON(req); err != nil {
		t.Fatalf("write probe request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp rpc.JsonRpcResponse
	if err := conn.ReadJSON(&resp); err != nil {
		t.Fatalf("read probe response: %v", err)
	}
	return &resp
}

func expectConnectionClosed(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("connection stayed open after its credential was revoked")
	}
}

// TestWebSocketRevokedAPIKeyLosesAdminAccess reproduces the reported bug: a
// connection established with an admin API key kept calling admin RPCs after
// the server rotated the key.
func TestWebSocketRevokedAPIKeyLosesAdminAccess(t *testing.T) {
	registerCredentialProbe(t)

	validKey := "ws-credential-test-key-0123456789"
	if err := config.Set(config.ApiKeyKey, validKey); err != nil {
		t.Fatalf("set api key: %v", err)
	}

	server := newRPCWebSocketServer(t)
	defer server.Close()

	conn := dialRPCWebSocket(t, server.URL, http.Header{
		"Authorization": []string{"Bearer " + validKey},
	})
	defer conn.Close()

	if resp := callCredentialProbe(t, conn, 1); resp.Error != nil {
		t.Fatalf("admin RPC with a valid API key failed: %+v", resp.Error)
	}

	// Rotate (revoke) the key. The connection's handshake credential is now
	// invalid even though the gin.Context still holds the old principal.
	if err := config.Set(config.ApiKeyKey, "ws-credential-rotated-key-9876543210"); err != nil {
		t.Fatalf("rotate api key: %v", err)
	}

	resp := callCredentialProbe(t, conn, 2)
	if resp.Error == nil {
		t.Fatal("revoked API key still authorized an admin RPC")
	}
	if resp.Error.Code != rpc.Unauthenticated {
		t.Fatalf("error code = %d, want %d (%s)", resp.Error.Code, rpc.Unauthenticated, resp.Error.Message)
	}
	expectConnectionClosed(t, conn)
}

// TestWebSocketDeletedSessionLosesAdminAccess covers logout: deleting the
// session row must invalidate connections that were opened with it.
func TestWebSocketDeletedSessionLosesAdminAccess(t *testing.T) {
	registerCredentialProbe(t)

	session, cleanup := newTestSession(t)
	defer cleanup()

	server := newRPCWebSocketServer(t)
	defer server.Close()

	conn := dialRPCWebSocket(t, server.URL, http.Header{
		"Cookie": []string{"session_token=" + session},
	})
	defer conn.Close()

	if resp := callCredentialProbe(t, conn, 1); resp.Error != nil {
		t.Fatalf("admin RPC with a valid session failed: %+v", resp.Error)
	}

	if err := accounts.DeleteSession(session); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	resp := callCredentialProbe(t, conn, 2)
	if resp.Error == nil {
		t.Fatal("deleted session still authorized an admin RPC")
	}
	if resp.Error.Code != rpc.Unauthenticated {
		t.Fatalf("error code = %d, want %d (%s)", resp.Error.Code, rpc.Unauthenticated, resp.Error.Message)
	}
	expectConnectionClosed(t, conn)
}

// TestWebSocketExpiredSessionLosesAdminAccess covers expiry without sleeping:
// the session row is moved into the past while the connection stays open.
func TestWebSocketExpiredSessionLosesAdminAccess(t *testing.T) {
	registerCredentialProbe(t)

	session, cleanup := newTestSession(t)
	defer cleanup()

	server := newRPCWebSocketServer(t)
	defer server.Close()

	conn := dialRPCWebSocket(t, server.URL, http.Header{
		"Cookie": []string{"session_token=" + session},
	})
	defer conn.Close()

	if resp := callCredentialProbe(t, conn, 1); resp.Error != nil {
		t.Fatalf("admin RPC with a valid session failed: %+v", resp.Error)
	}

	past := time.Now().UTC().Add(-time.Minute)
	if err := dbcore.GetDBInstance().Model(&models.Session{}).
		Where("session = ?", session).
		Update("expires", past).Error; err != nil {
		t.Fatalf("expire session: %v", err)
	}

	resp := callCredentialProbe(t, conn, 2)
	if resp.Error == nil {
		t.Fatal("expired session still authorized an admin RPC")
	}
	if resp.Error.Code != rpc.Unauthenticated {
		t.Fatalf("error code = %d, want %d (%s)", resp.Error.Code, rpc.Unauthenticated, resp.Error.Message)
	}
	expectConnectionClosed(t, conn)
}

// TestWebSocketValidSessionKeepsAccess keeps the normal admin connection path
// working across multiple messages.
func TestWebSocketValidSessionKeepsAccess(t *testing.T) {
	registerCredentialProbe(t)

	session, cleanup := newTestSession(t)
	defer cleanup()

	server := newRPCWebSocketServer(t)
	defer server.Close()

	conn := dialRPCWebSocket(t, server.URL, http.Header{
		"Cookie": []string{"session_token=" + session},
	})
	defer conn.Close()

	for id := 1; id <= 3; id++ {
		if resp := callCredentialProbe(t, conn, id); resp.Error != nil {
			t.Fatalf("probe %d failed on a valid session: %+v", id, resp.Error)
		}
	}
}

func newTestSession(t *testing.T) (string, func()) {
	t.Helper()
	username := fmt.Sprintf("ws-credential-%d", time.Now().UnixNano())
	user, err := accounts.CreateAccount(username, "test-password")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	session, err := accounts.CreateSession(user.UUID, 3600, "ws-credential-test", "127.0.0.1", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	cleanup := func() {
		_ = accounts.DeleteSession(session)
		_ = accounts.DeleteAccountByUsername(username)
	}
	return session, cleanup
}
