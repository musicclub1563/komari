package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
	v2 "github.com/komari-monitor/komari/protocol/v2"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	flags.DatabaseType = flags.DatabaseTypeSQLite
	flags.DatabaseFile = "file:komari_web_api_ws_test?mode=memory&cache=shared"
	// Initialise the shared test database (also wires config.SetDb).
	_ = dbcore.GetDBInstance()
	os.Exit(m.Run())
}

type clientsStreamResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		Online []string             `json:"online"`
		Data   map[string]v2.Report `json:"data"`
	} `json:"data"`
}

// newClientsTestServer mounts the real handler with the production middleware
// chain so the test exercises the same identity and private-site semantics.
func newClientsTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	engine := gin.New()
	engine.Use(IdentityMiddleware(), PrivateSiteMiddleware())
	engine.GET("/api/clients", GetClients)
	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)
	return server
}

func dialClients(t *testing.T, server *httptest.Server, header http.Header) *websocket.Conn {
	t.Helper()
	if header == nil {
		header = http.Header{}
	}
	header.Set("Origin", server.URL)
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	conn, resp, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/api/clients", header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial clients websocket: %v (status %d)", err, status)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func requestClients(t *testing.T, conn *websocket.Conn, message string) clientsStreamResponse {
	t.Helper()
	if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
		t.Fatalf("write %q: %v", message, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp clientsStreamResponse
	if err := conn.ReadJSON(&resp); err != nil {
		t.Fatalf("read response for %q: %v", message, err)
	}
	return resp
}

func expectClientsStreamClosed(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("connection stayed open after access was revoked")
	}
}

func hasUUID(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// assertVisibility checks both result fields, since the stream must filter
// "online" and "data" consistently.
func assertVisibility(t *testing.T, resp clientsStreamResponse, uuid string, visible bool) {
	t.Helper()
	if resp.Status != "success" {
		t.Fatalf("status = %q, error = %q", resp.Status, resp.Error)
	}
	if got := hasUUID(resp.Data.Online, uuid); got != visible {
		t.Fatalf("online contains %s = %v, want %v", uuid, got, visible)
	}
	if _, got := resp.Data.Data[uuid]; got != visible {
		t.Fatalf("data contains %s = %v, want %v", uuid, got, visible)
	}
}

// createTestClient registers a node in the database and marks it online with a
// report so both result fields can be asserted.
func createTestClient(t *testing.T, hidden bool) string {
	t.Helper()
	clientUUID := uuid.NewString()
	client := models.Client{
		UUID:   clientUUID,
		Token:  "token-" + clientUUID,
		Name:   "test-" + clientUUID[:8],
		Hidden: hidden,
	}
	db := dbcore.GetDBInstance()
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}
	presenceID := time.Now().UnixNano()
	agent_runtime.SetPresence(clientUUID, presenceID, true)
	agent_runtime.RecordReport(v2.Report{UUID: clientUUID, UpdatedAt: time.Now()})
	t.Cleanup(func() {
		_ = db.Where("uuid = ?", clientUUID).Delete(&models.Client{}).Error
	})
	return clientUUID
}

func setClientHidden(t *testing.T, clientUUID string, hidden bool) {
	t.Helper()
	if err := dbcore.GetDBInstance().Model(&models.Client{}).
		Where("uuid = ?", clientUUID).
		Update("hidden", hidden).Error; err != nil {
		t.Fatalf("set client hidden=%v: %v", hidden, err)
	}
}

func createAdminSession(t *testing.T) string {
	t.Helper()
	username := "ws-clients-" + uuid.NewString()
	user, err := accounts.CreateAccount(username, "test-password")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	session, err := accounts.CreateSession(user.UUID, 3600, "ws-clients-test", "127.0.0.1", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	t.Cleanup(func() {
		_ = accounts.DeleteSession(session)
		_ = accounts.DeleteAccountByUsername(username)
	})
	return session
}

func sessionHeader(session string) http.Header {
	return http.Header{"Cookie": []string{"session_token=" + session}}
}

// TestClientsAdminSeesHiddenNodes is the positive baseline: an authenticated
// admin can read hidden nodes for both request forms.
func TestClientsAdminSeesHiddenNodes(t *testing.T) {
	hiddenUUID := createTestClient(t, true)
	session := createAdminSession(t)
	server := newClientsTestServer(t)
	conn := dialClients(t, server, sessionHeader(session))

	resp := requestClients(t, conn, "get")
	assertVisibility(t, resp, hiddenUUID, true)

	resp = requestClients(t, conn, "get "+hiddenUUID)
	assertVisibility(t, resp, hiddenUUID, true)
	if len(resp.Data.Online) != 1 || resp.Data.Online[0] != hiddenUUID {
		t.Fatalf("online = %v, want only %s", resp.Data.Online, hiddenUUID)
	}
}

// TestClientsDeletedSessionLosesHiddenAccess reproduces the leaked-state bug:
// the connection was opened as admin and keeps serving hidden nodes after the
// session row is deleted.
func TestClientsDeletedSessionLosesHiddenAccess(t *testing.T) {
	hiddenUUID := createTestClient(t, true)
	session := createAdminSession(t)
	server := newClientsTestServer(t)
	conn := dialClients(t, server, sessionHeader(session))

	assertVisibility(t, requestClients(t, conn, "get"), hiddenUUID, true)

	if err := accounts.DeleteSession(session); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	resp := requestClients(t, conn, "get")
	assertVisibility(t, resp, hiddenUUID, false)
	resp = requestClients(t, conn, "get "+hiddenUUID)
	assertVisibility(t, resp, hiddenUUID, false)

	// Control: a fresh guest connection sees the same filtered view.
	guest := dialClients(t, server, nil)
	assertVisibility(t, requestClients(t, guest, "get"), hiddenUUID, false)
}

// TestClientsExpiredSessionLosesHiddenAccess covers expiry without sleeping.
func TestClientsExpiredSessionLosesHiddenAccess(t *testing.T) {
	hiddenUUID := createTestClient(t, true)
	session := createAdminSession(t)
	server := newClientsTestServer(t)
	conn := dialClients(t, server, sessionHeader(session))

	assertVisibility(t, requestClients(t, conn, "get"), hiddenUUID, true)

	past := time.Now().UTC().Add(-time.Minute)
	if err := dbcore.GetDBInstance().Model(&models.Session{}).
		Where("session = ?", session).
		Update("expires", past).Error; err != nil {
		t.Fatalf("expire session: %v", err)
	}

	resp := requestClients(t, conn, "get")
	assertVisibility(t, resp, hiddenUUID, false)
	resp = requestClients(t, conn, "get "+hiddenUUID)
	assertVisibility(t, resp, hiddenUUID, false)

	guest := dialClients(t, server, nil)
	assertVisibility(t, requestClients(t, guest, "get"), hiddenUUID, false)
}

// TestClientsGuestSeesNewlyHiddenNode reproduces the second leak: a guest
// stream built its hidden map at handshake and never refreshed it.
func TestClientsGuestSeesNewlyHiddenNode(t *testing.T) {
	publicUUID := createTestClient(t, false)
	server := newClientsTestServer(t)
	conn := dialClients(t, server, nil)

	assertVisibility(t, requestClients(t, conn, "get"), publicUUID, true)

	setClientHidden(t, publicUUID, true)

	assertVisibility(t, requestClients(t, conn, "get"), publicUUID, false)
	assertVisibility(t, requestClients(t, conn, "get "+publicUUID), publicUUID, false)

	// Control: a node that is still public remains visible to the same guest.
	otherUUID := createTestClient(t, false)
	assertVisibility(t, requestClients(t, conn, "get"), otherUUID, true)
}

// TestClientsPrivateSiteChangeRevokesGuestStream covers enabling private site
// after the stream was established.
func TestClientsPrivateSiteChangeRevokesGuestStream(t *testing.T) {
	if err := config.Set(config.PrivateSiteKey, false); err != nil {
		t.Fatalf("reset private site: %v", err)
	}
	t.Cleanup(func() { _ = config.Set(config.PrivateSiteKey, false) })

	publicUUID := createTestClient(t, false)
	hiddenUUID := createTestClient(t, true)
	server := newClientsTestServer(t)
	conn := dialClients(t, server, nil)

	assertVisibility(t, requestClients(t, conn, "get"), publicUUID, true)

	if err := config.Set(config.PrivateSiteKey, true); err != nil {
		t.Fatalf("enable private site: %v", err)
	}

	// The established guest connection must not serve data any more.
	resp := requestClients(t, conn, "get")
	if resp.Status != "error" {
		t.Fatalf("guest stream returned %q while the private site is enabled", resp.Status)
	}
	if len(resp.Data.Online) != 0 || len(resp.Data.Data) != 0 {
		t.Fatal("guest stream returned node data while the private site is enabled")
	}
	expectClientsStreamClosed(t, conn)

	// A fresh guest cannot even complete the handshake.
	if _, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(server.URL, "http")+"/api/clients", nil); err == nil {
		t.Fatal("guest handshake succeeded while the private site is enabled")
	}

	// Admins keep working, including hidden nodes.
	session := createAdminSession(t)
	adminConn := dialClients(t, server, sessionHeader(session))
	assertVisibility(t, requestClients(t, adminConn, "get"), hiddenUUID, true)
}

// TestClientsTemporaryAccessExpiry covers revoking/expiring the temporary
// share token while a stream is open.
func TestClientsTemporaryAccessExpiry(t *testing.T) {
	const tempToken = "temp-access-token-for-ws-test"
	t.Cleanup(func() {
		_ = config.Set(config.PrivateSiteKey, false)
		_ = config.Set("tempory_share_token", "")
		_ = config.Set("tempory_share_token_expire_at", int64(0))
	})
	if err := config.Set(config.PrivateSiteKey, true); err != nil {
		t.Fatalf("enable private site: %v", err)
	}
	if err := config.Set("tempory_share_token", tempToken); err != nil {
		t.Fatalf("set temp token: %v", err)
	}
	if err := config.Set("tempory_share_token_expire_at", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatalf("set temp token expiry: %v", err)
	}

	publicUUID := createTestClient(t, false)
	server := newClientsTestServer(t)
	conn := dialClients(t, server, http.Header{
		"Cookie": []string{"temp_key=" + tempToken},
	})

	assertVisibility(t, requestClients(t, conn, "get"), publicUUID, true)

	if err := config.Set("tempory_share_token_expire_at", time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatalf("expire temp token: %v", err)
	}

	resp := requestClients(t, conn, "get")
	if resp.Status != "error" {
		t.Fatalf("temporarily authorised stream kept serving data after expiry (status %q)", resp.Status)
	}
	if len(resp.Data.Online) != 0 || len(resp.Data.Data) != 0 {
		t.Fatal("temporarily authorised stream returned data after expiry")
	}
	expectClientsStreamClosed(t, conn)
}

// TestClientsAPIKeyRotation covers the API key credential on this endpoint.
func TestClientsAPIKeyRotation(t *testing.T) {
	if err := config.Set(config.PrivateSiteKey, false); err != nil {
		t.Fatalf("reset private site: %v", err)
	}
	t.Cleanup(func() { _ = config.Set(config.ApiKeyKey, "") })

	const originalKey = "ws-clients-api-key-0123456789"
	if err := config.Set(config.ApiKeyKey, originalKey); err != nil {
		t.Fatalf("set api key: %v", err)
	}

	hiddenUUID := createTestClient(t, true)
	server := newClientsTestServer(t)
	conn := dialClients(t, server, http.Header{
		"Authorization": []string{"Bearer " + originalKey},
	})

	assertVisibility(t, requestClients(t, conn, "get"), hiddenUUID, true)

	// Rotating the key must invalidate the existing stream; it degrades to the
	// public view instead of keeping admin visibility.
	if err := config.Set(config.ApiKeyKey, "ws-clients-rotated-key-9876543210"); err != nil {
		t.Fatalf("rotate api key: %v", err)
	}
	assertVisibility(t, requestClients(t, conn, "get"), hiddenUUID, false)

	// Control: a fresh connection using the old key is anonymous too.
	stale := dialClients(t, server, http.Header{
		"Authorization": []string{"Bearer " + originalKey},
	})
	assertVisibility(t, requestClients(t, stale, "get"), hiddenUUID, false)
}

// TestClientsHiddenQueryFailureDoesNotLeak guards the visibility query error
// path: a failed lookup must not be treated as "there are no hidden nodes".
func TestClientsHiddenQueryFailureDoesNotLeak(t *testing.T) {
	createTestClient(t, true)
	server := newClientsTestServer(t)
	conn := dialClients(t, server, nil)

	db := dbcore.GetDBInstance()
	if err := db.Migrator().DropTable(&models.Client{}); err != nil {
		t.Fatalf("drop clients table: %v", err)
	}
	t.Cleanup(func() { _ = db.AutoMigrate(&models.Client{}) })

	resp := requestClients(t, conn, "get")
	if resp.Status != "error" {
		t.Fatalf("status = %q while the visibility query was failing", resp.Status)
	}
	if len(resp.Data.Online) != 0 || len(resp.Data.Data) != 0 {
		t.Fatal("returned node data even though visibility could not be determined")
	}

	// Once the table is back the same connection recovers and filters again.
	if err := db.AutoMigrate(&models.Client{}); err != nil {
		t.Fatalf("recreate clients table: %v", err)
	}
	resp = requestClients(t, conn, "get")
	if resp.Status != "success" {
		t.Fatalf("status after recovery = %q, want success", resp.Status)
	}
}

// TestClientsOversizedMessageStillRejected keeps the 4 KiB public-stream limit
// intact and verifies the handler exits cleanly afterwards.
func TestClientsOversizedMessageStillRejected(t *testing.T) {
	createTestClient(t, false)
	server := newClientsTestServer(t)
	conn := dialClients(t, server, nil)

	if err := conn.WriteMessage(websocket.TextMessage, []byte(strings.Repeat("a", 8<<10))); err != nil {
		t.Fatalf("write oversized message: %v", err)
	}
	expectClientsStreamClosed(t, conn)

	// The server must stay usable for new connections after cleaning up the
	// oversized one.
	next := dialClients(t, server, nil)
	if resp := requestClients(t, next, "get"); resp.Status != "success" {
		t.Fatalf("server unusable after oversized message: status %q", resp.Status)
	}
}
