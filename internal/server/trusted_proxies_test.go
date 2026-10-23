package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func clientIPWithHeaders(t *testing.T, configured, remoteAddr string, headers map[string]string) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	if err := applyTrustedProxies(engine, configured); err != nil {
		t.Fatalf("apply trusted proxies: %v", err)
	}
	engine.GET("/ip", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})

	request := httptest.NewRequest(http.MethodGet, "/ip", nil)
	request.RemoteAddr = remoteAddr
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	return recorder.Body.String()
}

// TestClientIPIgnoresForwardedHeadersByDefault covers the audit finding: gin
// trusts X-Forwarded-For from every peer unless trusted proxies are set, so any
// caller could pick the IP recorded in audit logs and sessions.
// TestGinDefaultTrustsForwardedHeader documents the behaviour this fix guards
// against: a gin engine without SetTrustedProxies accepts X-Forwarded-For from
// any peer, which is what callers recorded in audit logs and sessions before
// the trusted proxy configuration was applied. If this test starts failing,
// gin's default changed and the explicit configuration is still the safe
// baseline.
func TestGinDefaultTrustsForwardedHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/ip", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})
	request := httptest.NewRequest(http.MethodGet, "/ip", nil)
	request.RemoteAddr = "203.0.113.9:1234"
	request.Header.Set("X-Forwarded-For", "1.2.3.4")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	if got := recorder.Body.String(); got != "1.2.3.4" {
		t.Fatalf("gin default client IP = %q, expected the unverified forwarded address", got)
	}
}

func TestClientIPIgnoresForwardedHeadersByDefault(t *testing.T) {
	t.Setenv(envTrustedProxies, "")
	remote := "203.0.113.9:1234"
	headers := map[string]string{
		"X-Forwarded-For": "1.2.3.4, 5.6.7.8",
		"X-Real-IP":       "9.9.9.9",
	}
	if got := clientIPWithHeaders(t, "", remote, headers); got != "203.0.113.9" {
		t.Fatalf("client IP = %q, want the connection address with no trusted proxies", got)
	}
}

func TestClientIPUsesHeadersFromTrustedProxy(t *testing.T) {
	t.Setenv(envTrustedProxies, "")
	// gin walks X-Forwarded-For from the right and skips trusted proxies, so the
	// rightmost untrusted entry is the client. Left-hand entries are supplied by
	// the caller of the trusted proxy and cannot override it.
	headers := map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8"}
	if got := clientIPWithHeaders(t, "10.0.0.0/8", "10.1.2.3:1234", headers); got != "5.6.7.8" {
		t.Fatalf("client IP = %q, want the rightmost untrusted address", got)
	}
	headers = map[string]string{"X-Forwarded-For": "1.2.3.4, 10.2.2.2"}
	if got := clientIPWithHeaders(t, "10.0.0.0/8", "10.1.2.3:1234", headers); got != "1.2.3.4" {
		t.Fatalf("client IP = %q, want the address behind the trusted proxy chain", got)
	}
	// A peer outside the trusted range must not be able to forge the header.
	headers = map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8"}
	if got := clientIPWithHeaders(t, "10.0.0.0/8", "203.0.113.9:1234", headers); got != "203.0.113.9" {
		t.Fatalf("client IP = %q, want the connection address for an untrusted peer", got)
	}
}

// TestClientIPMalformedChainFallsBackToPeer documents the fallback for a chain
// that cannot be parsed: the header is discarded as a whole and the connection
// address is used. Skipping the malformed entry instead would let the caller
// supply the left-hand value it wants recorded.
func TestClientIPMalformedChainFallsBackToPeer(t *testing.T) {
	t.Setenv(envTrustedProxies, "")
	cases := map[string]map[string]string{
		"malformed rightmost":         {"X-Forwarded-For": "1.2.3.4, not-an-ip"},
		"malformed after trusted hop": {"X-Forwarded-For": "1.2.3.4, 10.2.2.2, junk"},
		"empty rightmost":             {"X-Forwarded-For": "1.2.3.4,"},
	}
	for name, headers := range cases {
		if got := clientIPWithHeaders(t, "10.0.0.0/8", "10.1.2.3:1234", headers); got != "10.1.2.3" {
			t.Fatalf("%s: client IP = %q, want the connection address", name, got)
		}
	}
	// A valid chain resolving to the proxy itself is still reported.
	headers := map[string]string{"X-Real-IP": "5.6.7.8"}
	if got := clientIPWithHeaders(t, "10.0.0.0/8", "10.1.2.3:1234", headers); got != "5.6.7.8" {
		t.Fatalf("client IP = %q, want the X-Real-IP address", got)
	}
}

func TestInvalidTrustedProxyConfigurationFailsSafe(t *testing.T) {
	t.Setenv(envTrustedProxies, "")
	headers := map[string]string{"X-Forwarded-For": "1.2.3.4"}
	if got := clientIPWithHeaders(t, "not-a-cidr", "203.0.113.9:1234", headers); got != "203.0.113.9" {
		t.Fatalf("client IP = %q, invalid configuration must not trust headers", got)
	}
	if _, err := parseTrustedProxies("10.0.0.0/8, nope"); err == nil {
		t.Fatal("invalid trusted proxy entry was accepted")
	}
	entries, err := parseTrustedProxies("10.0.0.1, 192.168.0.0/16")
	if err != nil {
		t.Fatalf("valid entries were rejected: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %#v, want 2", entries)
	}
}

func TestTrustedProxiesEnvironmentFallback(t *testing.T) {
	t.Setenv(envTrustedProxies, "10.0.0.0/8")
	headers := map[string]string{"X-Forwarded-For": "1.2.3.4"}
	if got := clientIPWithHeaders(t, "", "10.1.2.3:1234", headers); got != "1.2.3.4" {
		t.Fatalf("client IP = %q, environment proxy list was not applied", got)
	}
}
