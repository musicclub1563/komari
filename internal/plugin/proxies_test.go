package plugin

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func resetTrustedProxies(t *testing.T, entries []string) {
	t.Helper()
	if err := SetTrustedProxies(entries); err != nil {
		t.Fatalf("set trusted proxies %v: %v", entries, err)
	}
	t.Cleanup(func() { _ = SetTrustedProxies(nil) })
}

func newProxyTestRequest(remoteAddr string, headers map[string]string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = remoteAddr
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	return request
}

func TestRemoteIPIgnoresForwardedHeadersWithoutTrustedProxies(t *testing.T) {
	resetTrustedProxies(t, nil)

	request := newProxyTestRequest("203.0.113.9:1234", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
		"X-Real-IP":       "5.6.7.8",
	})
	if got := remoteIP(request); got != "203.0.113.9" {
		t.Fatalf("remote IP = %q, want the connection address", got)
	}
}

func TestRemoteIPUsesHeadersFromConfiguredProxyOnly(t *testing.T) {
	resetTrustedProxies(t, []string{"10.0.0.0/8"})

	request := newProxyTestRequest("10.1.2.3:1234", map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8"})
	if got := remoteIP(request); got != "5.6.7.8" {
		t.Fatalf("remote IP = %q, want the rightmost untrusted address", got)
	}
	// Entries that are themselves trusted proxies are skipped.
	request.Header.Set("X-Forwarded-For", "1.2.3.4, 10.2.2.2")
	if got := remoteIP(request); got != "1.2.3.4" {
		t.Fatalf("remote IP = %q, want the address behind the trusted chain", got)
	}

	// Malformed header values are ignored instead of being passed to plugins.
	request.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := remoteIP(request); got != "10.1.2.3" {
		t.Fatalf("remote IP = %q, malformed header must be ignored", got)
	}

	// An untrusted peer cannot forge the header even with a trust list set.
	request.RemoteAddr = "203.0.113.9:1234"
	request.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := remoteIP(request); got != "203.0.113.9" {
		t.Fatalf("remote IP = %q, untrusted peer must not supply the address", got)
	}
}

// TestRemoteIPRejectsMalformedChain pins the unsafe variant that skipped a
// malformed entry and kept walking left: the caller controls the left-hand
// entries, so only the right-hand end appended by the trusted proxy may be
// used. A malformed end invalidates the header and falls back to the peer.
func TestRemoteIPRejectsMalformedChain(t *testing.T) {
	resetTrustedProxies(t, []string{"10.0.0.0/8"})

	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"malformed rightmost", "1.2.3.4, not-an-ip", "10.1.2.3"},
		{"malformed after trusted hop", "1.2.3.4, 10.2.2.2, junk", "10.1.2.3"},
		{"empty rightmost", "1.2.3.4,", "10.1.2.3"},
		{"valid rightmost", "1.2.3.4, 5.6.7.8", "5.6.7.8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := newProxyTestRequest("10.1.2.3:1234", map[string]string{"X-Forwarded-For": tc.header})
			if got := remoteIP(request); got != tc.want {
				t.Fatalf("remote IP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRemoteIPMatchesGinClientIP is the consistency check between the plugin
// hook layer (raw *http.Request) and the gin middleware layer it runs before.
// Both are fed the same trust list and the same request; any divergence in the
// parsing rules shows up here.
func TestRemoteIPMatchesGinClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lists := [][]string{
		nil,
		{"10.0.0.0/8"},
		{"10.0.0.1", "192.168.0.0/16"},
		{"2001:db8::/32"},
	}
	cases := []struct {
		name    string
		remote  string
		headers map[string]string
	}{
		{"no headers", "203.0.113.9:1234", nil},
		{"spoofed from untrusted peer", "203.0.113.9:1234", map[string]string{"X-Forwarded-For": "1.2.3.4"}},
		{"single hop", "10.1.2.3:1234", map[string]string{"X-Forwarded-For": "1.2.3.4"}},
		{"chain with trusted hop", "10.1.2.3:1234", map[string]string{"X-Forwarded-For": "1.2.3.4, 10.2.2.2"}},
		{"malformed rightmost", "10.1.2.3:1234", map[string]string{"X-Forwarded-For": "1.2.3.4, junk"}},
		{"malformed leftmost", "10.1.2.3:1234", map[string]string{"X-Forwarded-For": "junk, 1.2.3.4"}},
		{"real ip fallback", "10.1.2.3:1234", map[string]string{"X-Forwarded-For": "junk", "X-Real-IP": "5.6.7.8"}},
		{"real ip only", "10.1.2.3:1234", map[string]string{"X-Real-IP": "10.9.9.9"}},
		{"exact proxy ip", "10.0.0.1:1234", map[string]string{"X-Forwarded-For": "1.2.3.4"}},
		{"ipv6 peer", "[2001:db8::1]:443", map[string]string{"X-Forwarded-For": "2001:db8:ffff::9, 2001:db8:2::2"}},
	}

	for _, entries := range lists {
		resetTrustedProxies(t, entries)
		engine := gin.New()
		if err := engine.SetTrustedProxies(entries); err != nil {
			t.Fatalf("gin trusted proxies %v: %v", entries, err)
		}
		engine.GET("/ip", func(c *gin.Context) {
			c.String(http.StatusOK, c.ClientIP())
		})
		for _, tc := range cases {
			request := newProxyTestRequest(tc.remote, tc.headers)
			request.URL.Path = "/ip"
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, request)

			ginIP := canonicalIP(recorder.Body.String())
			hookIP := canonicalIP(remoteIP(request))
			if ginIP != hookIP {
				t.Fatalf("trusted=%v %s: gin client IP %q != hook remote IP %q", entries, tc.name, ginIP, hookIP)
			}
		}
	}
}

// canonicalIP normalizes both sides of the comparison: gin returns the header
// text verbatim while the hook layer returns net.IP.String.
func canonicalIP(value string) string {
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}

func TestSetTrustedProxiesRejectsInvalidEntries(t *testing.T) {
	resetTrustedProxies(t, nil)
	if err := SetTrustedProxies([]string{"10.0.0.0/8", "bogus"}); err == nil {
		t.Fatal("invalid trusted proxy entry was accepted")
	}
	// A rejected update must not clear the previously applied list.
	if err := SetTrustedProxies([]string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("set trusted proxies: %v", err)
	}
	if err := SetTrustedProxies([]string{"bogus"}); err == nil {
		t.Fatal("invalid trusted proxy entry was accepted")
	}
	request := newProxyTestRequest("10.1.2.3:1234", map[string]string{"X-Forwarded-For": "1.2.3.4"})
	if got := remoteIP(request); got != "1.2.3.4" {
		t.Fatalf("remote IP = %q, a rejected update must keep the previous list", got)
	}
}
