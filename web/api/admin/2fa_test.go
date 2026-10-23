package admin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/web/api"
	"github.com/pquerna/otp/totp"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	flags.DatabaseType = "sqlite"
	flags.DatabaseFile = "file:komari_admin_2fa_test?mode=memory&cache=shared"
	_ = dbcore.GetDBInstance()
	os.Exit(m.Run())
}

func new2FATestServer(t *testing.T) *httptest.Server {
	t.Helper()
	engine := gin.New()
	engine.Use(api.IdentityMiddleware())
	admin := engine.Group("/api/admin", api.RequireRole(api.RoleAdmin))
	admin.GET("/2fa/generate", Generate2FA)
	admin.POST("/2fa/enable", Enable2FA)
	admin.POST("/2fa/disable", api.RequireSensitive2FA(), Disable2FA)
	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)
	return server
}

func new2FATestSession(t *testing.T) (userUUID, session string) {
	t.Helper()
	user, err := accounts.CreateAccount("2fa-admin-"+uuid.NewString(), "test-password")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	session, err = accounts.CreateSession(user.UUID, 3600, "2fa-test", "127.0.0.1", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	t.Cleanup(func() {
		_ = accounts.DeleteSession(session)
		_ = accounts.DeleteAccountByUsername(user.Username)
	})
	return user.UUID, session
}

func request2FA(t *testing.T, method, url, session string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "session_token", Value: session})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func generatePending(t *testing.T, server *httptest.Server, session, userUUID string) string {
	t.Helper()
	secret, _ := generatePendingWithCookie(t, server, session, userUUID)
	return secret
}

// generatePendingWithCookie also returns the 2fa_secret cookie the handler set,
// so regression tests can replay the old client-supplied secret flow.
func generatePendingWithCookie(t *testing.T, server *httptest.Server, session, userUUID string) (string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/admin/2fa/generate", nil)
	if err != nil {
		t.Fatalf("build generate request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "session_token", Value: session})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("generate request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("generate status = %d", resp.StatusCode)
	}
	cookieValue := ""
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "2fa_secret" {
			cookieValue = cookie.Value
		}
	}
	secret, ok := accounts.Pending2FASecret(userUUID)
	if !ok {
		t.Fatal("server did not keep a pending 2FA secret for the user")
	}
	return secret, cookieValue
}

func totpCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}
	return code
}

func storedSecret(t *testing.T, userUUID string) string {
	t.Helper()
	secret, err := accounts.Get2FaSecret(userUUID)
	if err != nil {
		t.Fatalf("read stored secret: %v", err)
	}
	return secret
}

func TestEnable2FAFirstEnrollment(t *testing.T) {
	userUUID, session := new2FATestSession(t)
	server := new2FATestServer(t)

	pending := generatePending(t, server, session, userUUID)
	status := request2FA(t, http.MethodPost,
		server.URL+"/api/admin/2fa/enable?code="+totpCode(t, pending), session)
	if status != http.StatusOK {
		t.Fatalf("enable status = %d", status)
	}
	if got := storedSecret(t, userUUID); got != pending {
		t.Fatalf("stored secret = %q, want the generated pending secret", got)
	}
	if valid, err := accounts.Verify2Fa(userUUID, totpCode(t, pending)); err != nil || !valid {
		t.Fatalf("Verify2Fa after enable = %v, %v", valid, err)
	}
}

func TestEnable2FARejectsOverwriteWithoutCurrentCode(t *testing.T) {
	userUUID, session := new2FATestSession(t)
	server := new2FATestServer(t)

	first := generatePending(t, server, session, userUUID)
	if status := request2FA(t, http.MethodPost,
		server.URL+"/api/admin/2fa/enable?code="+totpCode(t, first), session); status != http.StatusOK {
		t.Fatalf("initial enable status = %d", status)
	}

	second := generatePending(t, server, session, userUUID)
	status := request2FA(t, http.MethodPost,
		server.URL+"/api/admin/2fa/enable?code="+totpCode(t, second), session)
	if status != http.StatusForbidden {
		t.Fatalf("overwrite status = %d, want %d", status, http.StatusForbidden)
	}
	if got := storedSecret(t, userUUID); got != first {
		t.Fatal("a request without the current 2FA code replaced the stored secret")
	}

	// A wrong current code must not be treated as proof either.
	status = request2FA(t, http.MethodPost,
		server.URL+"/api/admin/2fa/enable?code="+totpCode(t, second)+"&current_code=000000", session)
	if status != http.StatusForbidden {
		t.Fatalf("wrong current code status = %d, want %d", status, http.StatusForbidden)
	}
	if got := storedSecret(t, userUUID); got != first {
		t.Fatal("an invalid current 2FA code replaced the stored secret")
	}
}

// TestEnable2FADoesNotTrustClientSuppliedSecret replays the reported exploit:
// an administrator with 2FA enabled requests a new secret and submits the new
// code together with the secret cookie. The enable endpoint must not use that
// client-supplied value to replace the stored secret.
func TestEnable2FADoesNotTrustClientSuppliedSecret(t *testing.T) {
	userUUID, session := new2FATestSession(t)
	server := new2FATestServer(t)

	first := generatePending(t, server, session, userUUID)
	if status := request2FA(t, http.MethodPost,
		server.URL+"/api/admin/2fa/enable?code="+totpCode(t, first), session); status != http.StatusOK {
		t.Fatalf("initial enable status = %d", status)
	}

	second, cookieValue := generatePendingWithCookie(t, server, session, userUUID)
	if cookieValue == "" {
		t.Fatal("generate did not set the 2fa_secret cookie")
	}
	req, err := http.NewRequest(http.MethodPost,
		server.URL+"/api/admin/2fa/enable?code="+totpCode(t, second), nil)
	if err != nil {
		t.Fatalf("build enable request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "session_token", Value: session})
	req.AddCookie(&http.Cookie{Name: "2fa_secret", Value: cookieValue})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("enable request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("client-supplied secret enable status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if got := storedSecret(t, userUUID); got != first {
		t.Fatal("a client-supplied secret cookie replaced the stored secret")
	}
}

func TestEnable2FAReplacesWithCurrentCode(t *testing.T) {
	userUUID, session := new2FATestSession(t)
	server := new2FATestServer(t)

	first := generatePending(t, server, session, userUUID)
	if status := request2FA(t, http.MethodPost,
		server.URL+"/api/admin/2fa/enable?code="+totpCode(t, first), session); status != http.StatusOK {
		t.Fatalf("initial enable status = %d", status)
	}

	second := generatePending(t, server, session, userUUID)
	url := server.URL + "/api/admin/2fa/enable?code=" + totpCode(t, second) +
		"&current_code=" + totpCode(t, first)
	if status := request2FA(t, http.MethodPost, url, session); status != http.StatusOK {
		t.Fatalf("replacement status = %d", status)
	}
	if got := storedSecret(t, userUUID); got != second {
		t.Fatal("verified replacement did not store the new secret")
	}
}

func TestEnable2FAInvalidNewCodeKeepsExistingSecret(t *testing.T) {
	userUUID, session := new2FATestSession(t)
	server := new2FATestServer(t)

	first := generatePending(t, server, session, userUUID)
	if status := request2FA(t, http.MethodPost,
		server.URL+"/api/admin/2fa/enable?code="+totpCode(t, first), session); status != http.StatusOK {
		t.Fatalf("initial enable status = %d", status)
	}

	_ = generatePending(t, server, session, userUUID)
	url := server.URL + "/api/admin/2fa/enable?code=000000&current_code=" + totpCode(t, first)
	if status := request2FA(t, http.MethodPost, url, session); status != http.StatusBadRequest {
		t.Fatalf("invalid new code status = %d, want %d", status, http.StatusBadRequest)
	}
	if got := storedSecret(t, userUUID); got != first {
		t.Fatal("an invalid new 2FA code replaced the stored secret")
	}
}

func TestEnable2FARejectsAnotherUsersPendingEnrollment(t *testing.T) {
	ownerUUID, ownerSession := new2FATestSession(t)
	otherUUID, otherSession := new2FATestSession(t)
	server := new2FATestServer(t)

	ownerSecret := generatePending(t, server, ownerSession, ownerUUID)
	// The other user never requested an enrollment, so the owner's code has no
	// pending state to match against.
	status := request2FA(t, http.MethodPost,
		server.URL+"/api/admin/2fa/enable?code="+totpCode(t, ownerSecret), otherSession)
	if status != http.StatusBadRequest {
		t.Fatalf("cross-user enable status = %d, want %d", status, http.StatusBadRequest)
	}
	if got := storedSecret(t, otherUUID); got != "" {
		t.Fatal("another user's pending enrollment enabled 2FA")
	}
	if got := storedSecret(t, ownerUUID); got != "" {
		t.Fatal("another user's request completed the owner enrollment")
	}
}

func TestDisable2FARemainsAvailable(t *testing.T) {
	userUUID, session := new2FATestSession(t)
	server := new2FATestServer(t)

	first := generatePending(t, server, session, userUUID)
	if status := request2FA(t, http.MethodPost,
		server.URL+"/api/admin/2fa/enable?code="+totpCode(t, first), session); status != http.StatusOK {
		t.Fatalf("initial enable status = %d", status)
	}

	url := server.URL + "/api/admin/2fa/disable?2fa_code=" + totpCode(t, first)
	if status := request2FA(t, http.MethodPost, url, session); status != http.StatusOK {
		t.Fatalf("disable status = %d", status)
	}
	if got := storedSecret(t, userUUID); got != "" {
		t.Fatal("disable did not clear the stored secret")
	}
}
