package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func requestWith(remoteAddr string, headers map[string]string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = remoteAddr
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	return request
}

func TestResolveWithoutTrustedProxiesIgnoresHeaders(t *testing.T) {
	var nilResolver *Resolver
	request := requestWith("203.0.113.9:1234", map[string]string{
		"X-Forwarded-For": "1.2.3.4, 5.6.7.8",
		"X-Real-IP":       "9.9.9.9",
	})
	if got := nilResolver.Resolve(request.RemoteAddr, request.Header); got != "203.0.113.9" {
		t.Fatalf("client IP = %q, want the connection address", got)
	}
	resolver, err := New(nil)
	if err != nil {
		t.Fatalf("empty resolver: %v", err)
	}
	if got := resolver.Resolve(request.RemoteAddr, request.Header); got != "203.0.113.9" {
		t.Fatalf("client IP = %q, want the connection address", got)
	}
}

func TestResolveFromTrustedProxyChain(t *testing.T) {
	resolver, err := New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	cases := []struct {
		name      string
		remote    string
		headers   map[string]string
		want      string
		wantEmpty bool
	}{
		{
			name:    "single hop",
			remote:  "10.1.2.3:1234",
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4"},
			want:    "1.2.3.4",
		},
		{
			name:    "rightmost untrusted wins",
			remote:  "10.1.2.3:1234",
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8"},
			want:    "5.6.7.8",
		},
		{
			name:    "trusted entries are skipped right to left",
			remote:  "10.1.2.3:1234",
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4, 10.2.2.2"},
			want:    "1.2.3.4",
		},
		{
			name:    "untrusted peer cannot supply a header",
			remote:  "203.0.113.9:1234",
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4"},
			want:    "203.0.113.9",
		},
		{
			// The rightmost entry is appended by the trusted proxy. If it does
			// not parse, the whole header is untrustworthy: falling back to the
			// peer is required, while skipping the entry would hand the
			// left-hand, caller-chosen value to the caller.
			name:    "malformed rightmost entry falls back to peer",
			remote:  "10.1.2.3:1234",
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4, not-an-ip"},
			want:    "10.1.2.3",
		},
		{
			name:    "malformed entry after a trusted hop falls back to peer",
			remote:  "10.1.2.3:1234",
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4, 10.2.2.2, junk"},
			want:    "10.1.2.3",
		},
		{
			name:    "empty entry falls back to peer",
			remote:  "10.1.2.3:1234",
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4,"},
			want:    "10.1.2.3",
		},
		{
			// Entries left of the first valid untrusted address never matter.
			name:    "malformed leftmost entry is irrelevant",
			remote:  "10.1.2.3:1234",
			headers: map[string]string{"X-Forwarded-For": "junk, 1.2.3.4"},
			want:    "1.2.3.4",
		},
		{
			name:   "invalid forwarded header falls through to X-Real-IP",
			remote: "10.1.2.3:1234",
			headers: map[string]string{
				"X-Forwarded-For": "junk",
				"X-Real-IP":       "5.6.7.8",
			},
			want: "5.6.7.8",
		},
		{
			name:    "X-Real-IP is returned as the far end of the chain",
			remote:  "10.1.2.3:1234",
			headers: map[string]string{"X-Real-IP": "10.9.9.9"},
			want:    "10.9.9.9",
		},
		{
			name:    "no forwarded headers",
			remote:  "10.1.2.3:1234",
			headers: nil,
			want:    "10.1.2.3",
		},
		{
			name:      "unparsable connection address",
			remote:    "not-a-host",
			headers:   map[string]string{"X-Forwarded-For": "1.2.3.4"},
			wantEmpty: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolver.Resolve(tc.remote, requestWith(tc.remote, tc.headers).Header)
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("client IP = %q, want empty", got)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("client IP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveIPv6(t *testing.T) {
	resolver, err := New([]string{"2001:db8::/32"})
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	got := resolver.Resolve("[2001:db8::1]:443", http.Header{"X-Forwarded-For": []string{"2001:db8:ffff::9, 2001:db8:2::2"}})
	if got != "2001:db8:ffff::9" {
		t.Fatalf("client IP = %q", got)
	}
}

func TestNewValidatesEveryEntry(t *testing.T) {
	if _, err := New([]string{"10.0.0.0/8", "not-a-cidr"}); err == nil {
		t.Fatal("invalid entry was accepted")
	}
	resolver, err := New([]string{"10.0.0.1", " 192.168.0.0/16 ", ""})
	if err != nil {
		t.Fatalf("valid entries were rejected: %v", err)
	}
	entries := resolver.Entries()
	if len(entries) != 2 || entries[0] != "10.0.0.1/32" || entries[1] != "192.168.0.0/16" {
		t.Fatalf("entries = %#v", entries)
	}
	if resolver.Trusted(nil) {
		t.Fatal("nil address must not be trusted")
	}
}
