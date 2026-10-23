package terminal

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/web/api"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	flags.DatabaseType = "sqlite"
	flags.DatabaseFile = "file:komari_terminal_revocation_test?mode=memory&cache=shared"
	_ = dbcore.GetDBInstance()
	// Shorten the idle re-check so revocation without user input is testable.
	terminalCredentialRecheckNanos.Store(int64(50 * time.Millisecond))
	os.Exit(m.Run())
}

// newTerminalTestServer mounts the real handlers with the production
// middleware chain.
func newTerminalTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	engine := gin.New()
	engine.Use(api.IdentityMiddleware(), api.PrivateSiteMiddleware())

	admin := engine.Group("/api/admin", api.RequireRole(api.RoleAdmin))
	admin.GET("/client/:uuid/terminal", RequestTerminal)

	agentGroup := engine.Group("/api/clients", api.RequireRole(api.RoleAdmin, api.RoleClient))
	agentGroup.GET("/terminal", EstablishConnection)

	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)
	return server
}

func wsURL(server *httptest.Server, path string) string {
	return "ws" + strings.TrimPrefix(server.URL, "http") + path
}

func createTerminalTestClient(t *testing.T) (clientUUID, token string) {
	t.Helper()
	clientUUID = uuid.NewString()
	token = "agent-token-" + clientUUID
	db := dbcore.GetDBInstance()
	if err := db.Create(&models.Client{
		UUID:  clientUUID,
		Token: token,
		Name:  "terminal-" + clientUUID[:8],
	}).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}
	// Pretend a v2 agent is reachable so RequestTerminal can dispatch.
	agent_runtime.MarkV2Client(clientUUID)
	t.Cleanup(func() {
		agent_runtime.DeleteConnectedClients(clientUUID)
		_ = db.Where("uuid = ?", clientUUID).Delete(&models.Client{}).Error
	})
	return clientUUID, token
}

func createTerminalTestSession(t *testing.T) (session string) {
	t.Helper()
	username := "terminal-user-" + uuid.NewString()
	user, err := accounts.CreateAccount(username, "test-password")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	session, err = accounts.CreateSession(user.UUID, 3600, "terminal-test", "127.0.0.1", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	t.Cleanup(func() {
		_ = accounts.DeleteSession(session)
		_ = accounts.DeleteAccountByUsername(username)
	})
	return session
}

func sessionHeaders(session string) http.Header {
	return http.Header{"Cookie": []string{"session_token=" + session}}
}

// dialBrowser opens a terminal as the browser side and returns the request id.
func dialBrowser(t *testing.T, server *httptest.Server, clientUUID string, header http.Header) (*websocket.Conn, string) {
	t.Helper()
	if header == nil {
		header = http.Header{}
	}
	header.Set("Origin", server.URL)
	conn, resp, err := websocket.DefaultDialer.Dial(
		wsURL(server, "/api/admin/client/"+clientUUID+"/terminal"), header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial browser terminal: %v (status %d)", err, status)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var init struct {
		RequestID string `json:"request_id"`
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := conn.ReadJSON(&init); err != nil {
		t.Fatalf("read request_id: %v", err)
	}
	if init.RequestID == "" {
		t.Fatal("empty request_id")
	}
	return conn, init.RequestID
}

func reattachBrowser(t *testing.T, server *httptest.Server, clientUUID, id string, header http.Header) (*websocket.Conn, bool) {
	t.Helper()
	if header == nil {
		header = http.Header{}
	}
	header.Set("Origin", server.URL)
	conn, _, err := websocket.DefaultDialer.Dial(
		wsURL(server, "/api/admin/client/"+clientUUID+"/terminal?request_id="+id), header)
	if err != nil {
		return nil, false
	}
	t.Cleanup(func() { _ = conn.Close() })
	var init struct {
		RequestID string `json:"request_id"`
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := conn.ReadJSON(&init); err != nil {
		return conn, false
	}
	return conn, init.RequestID == id
}

func dialAgent(t *testing.T, server *httptest.Server, token, id string) (*websocket.Conn, bool) {
	t.Helper()
	header := http.Header{"Origin": []string{server.URL}}
	conn, resp, err := websocket.DefaultDialer.Dial(
		wsURL(server, "/api/clients/terminal?id="+id+"&token="+token), header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Logf("agent dial failed: %v (status %d)", err, status)
		return nil, false
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, true
}

func writeMarker(t *testing.T, conn *websocket.Conn, marker string) {
	t.Helper()
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte(marker)); err != nil {
		t.Fatalf("write marker %q: %v", marker, err)
	}
}

func expectAgentMarker(t *testing.T, conn *websocket.Conn, want string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("agent did not receive %q: %v", want, err)
	}
	if !bytes.Equal(data, []byte(want)) {
		t.Fatalf("agent received %q, want %q", data, want)
	}
}

// expectBrowserMarker reads until the expected binary marker arrives, skipping
// the informational text frames the handler sends while waiting for an agent.
func expectBrowserMarker(t *testing.T, conn *websocket.Conn, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_ = conn.SetReadDeadline(deadline)
		messageType, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("browser did not receive %q: %v", want, err)
		}
		if messageType == websocket.BinaryMessage && string(data) == want {
			return
		}
	}
}

// expectBrowserClosed waits for the browser side to be closed by the server.
func expectBrowserClosed(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				t.Fatal("browser connection stayed open")
			}
			return
		}
	}
}

// expectNoForwarding asserts the agent neither receives the marker nor keeps a
// usable connection after revocation.
func expectNoForwarding(t *testing.T, conn *websocket.Conn, marker string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, data, err := conn.ReadMessage()
	if err == nil {
		t.Fatalf("agent received %q after revocation, want no forwarding", data)
	}
	// Either the read timed out (nothing was forwarded) or the connection was
	// closed by the revocation path; both are correct.
	if netErr, ok := err.(net.Error); ok && !netErr.Timeout() {
		return
	}
}

func setupTerminal(t *testing.T, server *httptest.Server, clientUUID, token string, header http.Header) (browser, agent *websocket.Conn, id string) {
	t.Helper()
	browser, id = dialBrowser(t, server, clientUUID, header)
	agent, ok := dialAgent(t, server, token, id)
	if !ok {
		t.Fatal("agent could not attach")
	}
	return browser, agent, id
}

func TestTerminalSessionForwardsWithValidCredential(t *testing.T) {
	clientUUID, token := createTerminalTestClient(t)
	session := createTerminalTestSession(t)
	server := newTerminalTestServer(t)
	browser, agent, _ := setupTerminal(t, server, clientUUID, token, sessionHeaders(session))

	writeMarker(t, browser, "MARK-INPUT")
	expectAgentMarker(t, agent, "MARK-INPUT")

	if err := agent.WriteMessage(websocket.BinaryMessage, []byte("MARK-OUTPUT")); err != nil {
		t.Fatalf("write output marker: %v", err)
	}
	expectBrowserMarker(t, browser, "MARK-OUTPUT")
}

func TestTerminalAPIKeyForwardsWithValidCredential(t *testing.T) {
	if err := config.Set(config.PrivateSiteKey, false); err != nil {
		t.Fatalf("reset private site: %v", err)
	}
	const key = "terminal-api-key-0123456789"
	if err := config.Set(config.ApiKeyKey, key); err != nil {
		t.Fatalf("set api key: %v", err)
	}
	t.Cleanup(func() { _ = config.Set(config.ApiKeyKey, "") })

	clientUUID, token := createTerminalTestClient(t)
	server := newTerminalTestServer(t)
	browser, agent, _ := setupTerminal(t, server, clientUUID, token,
		http.Header{"Authorization": []string{"Bearer " + key}})

	writeMarker(t, browser, "APIKEY-INPUT")
	expectAgentMarker(t, agent, "APIKEY-INPUT")
}

func TestTerminalStopsForwardingAfterSessionDeleted(t *testing.T) {
	clientUUID, token := createTerminalTestClient(t)
	session := createTerminalTestSession(t)
	server := newTerminalTestServer(t)
	browser, agent, id := setupTerminal(t, server, clientUUID, token, sessionHeaders(session))

	writeMarker(t, browser, "BEFORE-DELETE")
	expectAgentMarker(t, agent, "BEFORE-DELETE")

	if err := accounts.DeleteSession(session); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	writeMarker(t, browser, "AFTER-DELETE")
	expectNoForwarding(t, agent, "AFTER-DELETE")

	// Control: the revoked credential cannot open a new terminal.
	if _, ok := dialBrowserRaw(server, clientUUID, sessionHeaders(session)); ok {
		t.Fatal("deleted session still established a new terminal")
	}

	// The stale request_id cannot be reused with the revoked credential either.
	if _, ok := reattachBrowser(t, server, clientUUID, id, sessionHeaders(session)); ok {
		t.Fatal("deleted session reattached to the old request_id")
	}
}

func TestTerminalStopsForwardingAfterSessionExpired(t *testing.T) {
	clientUUID, token := createTerminalTestClient(t)
	session := createTerminalTestSession(t)
	server := newTerminalTestServer(t)
	browser, agent, _ := setupTerminal(t, server, clientUUID, token, sessionHeaders(session))

	writeMarker(t, browser, "BEFORE-EXPIRY")
	expectAgentMarker(t, agent, "BEFORE-EXPIRY")

	past := time.Now().UTC().Add(-time.Minute)
	if err := dbcore.GetDBInstance().Model(&models.Session{}).
		Where("session = ?", session).
		Update("expires", past).Error; err != nil {
		t.Fatalf("expire session: %v", err)
	}

	writeMarker(t, browser, "AFTER-EXPIRY")
	expectNoForwarding(t, agent, "AFTER-EXPIRY")

	if _, ok := dialBrowserRaw(server, clientUUID, sessionHeaders(session)); ok {
		t.Fatal("expired session still established a new terminal")
	}
}

func TestTerminalStopsForwardingAfterAPIKeyRotation(t *testing.T) {
	if err := config.Set(config.PrivateSiteKey, false); err != nil {
		t.Fatalf("reset private site: %v", err)
	}
	const originalKey = "terminal-api-key-original-0001"
	if err := config.Set(config.ApiKeyKey, originalKey); err != nil {
		t.Fatalf("set api key: %v", err)
	}
	t.Cleanup(func() { _ = config.Set(config.ApiKeyKey, "") })

	clientUUID, token := createTerminalTestClient(t)
	server := newTerminalTestServer(t)
	header := http.Header{"Authorization": []string{"Bearer " + originalKey}}
	browser, agent, id := setupTerminal(t, server, clientUUID, token, header)

	writeMarker(t, browser, "BEFORE-ROTATE")
	expectAgentMarker(t, agent, "BEFORE-ROTATE")

	if err := config.Set(config.ApiKeyKey, "terminal-api-key-rotated-0002"); err != nil {
		t.Fatalf("rotate api key: %v", err)
	}

	writeMarker(t, browser, "AFTER-ROTATE")
	expectNoForwarding(t, agent, "AFTER-ROTATE")

	if _, ok := dialBrowserRaw(server, clientUUID, http.Header{
		"Authorization": []string{"Bearer " + originalKey}}); ok {
		t.Fatal("rotated api key still established a new terminal")
	}
	if _, ok := reattachBrowser(t, server, clientUUID, id, http.Header{
		"Authorization": []string{"Bearer " + originalKey}}); ok {
		t.Fatal("rotated api key reattached to the old request_id")
	}
}

// TestTerminalIdleConnectionRevokedWithoutInput covers the output direction:
// the stream must be closed even when the user never sends another keystroke.
func TestTerminalIdleConnectionRevokedWithoutInput(t *testing.T) {
	clientUUID, token := createTerminalTestClient(t)
	session := createTerminalTestSession(t)
	server := newTerminalTestServer(t)
	_, agent, _ := setupTerminal(t, server, clientUUID, token, sessionHeaders(session))

	if err := accounts.DeleteSession(session); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	// The agent connection must be closed by the credential watcher; a mere
	// read timeout means the idle connection was kept alive.
	deadline := time.Now().Add(2 * time.Second)
	for {
		_ = agent.SetReadDeadline(deadline)
		if _, _, err := agent.ReadMessage(); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				t.Fatal("idle terminal stayed open after its session was deleted")
			}
			return
		}
	}
}

func TestTerminalReattachUsesCurrentCredential(t *testing.T) {
	clientUUID, token := createTerminalTestClient(t)
	session := createTerminalTestSession(t)
	server := newTerminalTestServer(t)
	browser, agent, id := setupTerminal(t, server, clientUUID, token, sessionHeaders(session))

	writeMarker(t, browser, "FIRST")
	expectAgentMarker(t, agent, "FIRST")

	// Browser goes away; the session is retained for reattachment.
	_ = browser.Close()
	time.Sleep(100 * time.Millisecond)

	newBrowser, ok := reattachBrowser(t, server, clientUUID, id, sessionHeaders(session))
	if !ok {
		t.Fatal("valid session could not reattach")
	}
	newAgent, ok := dialAgent(t, server, token, id)
	if !ok {
		t.Fatal("agent could not reattach")
	}

	writeMarker(t, newBrowser, "SECOND")
	expectAgentMarker(t, newAgent, "SECOND")
}

func TestTerminalBrowserReplacementKeepsAgent(t *testing.T) {
	clientUUID, token := createTerminalTestClient(t)
	session := createTerminalTestSession(t)
	server := newTerminalTestServer(t)
	browser, agent, id := setupTerminal(t, server, clientUUID, token, sessionHeaders(session))

	writeMarker(t, browser, "OLD")
	expectAgentMarker(t, agent, "OLD")

	replacement, ok := reattachBrowser(t, server, clientUUID, id, sessionHeaders(session))
	if !ok {
		t.Fatal("replacement browser could not attach")
	}
	// The replaced browser and the old agent connection must be closed; the
	// agent reconnects after the fresh terminal request event.
	expectBrowserClosed(t, browser)
	_ = agent.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := agent.ReadMessage(); err == nil {
		t.Fatal("old agent connection stayed open after browser replacement")
	}

	newAgent, ok := dialAgent(t, server, token, id)
	if !ok {
		t.Fatal("agent could not reattach")
	}

	writeMarker(t, replacement, "NEW")
	expectAgentMarker(t, newAgent, "NEW")
}

func TestTerminalRevocationDoesNotAffectOtherSessions(t *testing.T) {
	clientA, tokenA := createTerminalTestClient(t)
	clientB, tokenB := createTerminalTestClient(t)
	sessionA := createTerminalTestSession(t)
	sessionB := createTerminalTestSession(t)
	server := newTerminalTestServer(t)

	browserA, agentA, _ := setupTerminal(t, server, clientA, tokenA, sessionHeaders(sessionA))
	browserB, agentB, _ := setupTerminal(t, server, clientB, tokenB, sessionHeaders(sessionB))

	writeMarker(t, browserA, "A-BEFORE")
	expectAgentMarker(t, agentA, "A-BEFORE")

	if err := accounts.DeleteSession(sessionA); err != nil {
		t.Fatalf("delete session A: %v", err)
	}
	writeMarker(t, browserA, "A-AFTER")
	expectNoForwarding(t, agentA, "A-AFTER")

	// Session B is untouched by A's revocation.
	writeMarker(t, browserB, "B-AFTER")
	expectAgentMarker(t, agentB, "B-AFTER")
}

func TestTerminalConcurrentCloseCleansUp(t *testing.T) {
	clientUUID, token := createTerminalTestClient(t)
	session := createTerminalTestSession(t)
	server := newTerminalTestServer(t)
	browser, agent, id := setupTerminal(t, server, clientUUID, token, sessionHeaders(session))

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = browser.Close()
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = agent.Close()
		}()
	}
	wg.Wait()

	deadline := time.Now().Add(3 * time.Second)
	for {
		TerminalSessionsMutex.Lock()
		session, ok := TerminalSessions[id]
		suspended := !ok || session == nil || (session.Browser == nil && session.Agent == nil)
		TerminalSessionsMutex.Unlock()
		if suspended {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("terminal session was not suspended after concurrent close")
		}
		time.Sleep(20 * time.Millisecond)
	}

	closeSession(id)
	TerminalSessionsMutex.Lock()
	_, exists := TerminalSessions[id]
	TerminalSessionsMutex.Unlock()
	if exists {
		t.Fatal("closeSession did not remove the terminal session")
	}
}

// dialBrowserRaw probes the handshake without expecting success.
func dialBrowserRaw(server *httptest.Server, clientUUID string, header http.Header) (*websocket.Conn, bool) {
	if header == nil {
		header = http.Header{}
	}
	header.Set("Origin", server.URL)
	dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	conn, _, err := dialer.Dial(wsURL(server, "/api/admin/client/"+clientUUID+"/terminal"), header)
	if err != nil {
		return nil, false
	}
	_ = conn.Close()
	return conn, true
}
