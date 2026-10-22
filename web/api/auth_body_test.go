package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// countingReadCloser records how many bytes a component consumed from a body.
type countingReadCloser struct {
	reader io.Reader
	read   int
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	c.read += n
	return n, err
}

func (c *countingReadCloser) Close() error { return nil }

// TestExtractClientTokenDoesNotReadBody guards the identity stage: an anonymous
// 16 MiB POST used to be fully buffered before any handler or limit applied.
func TestExtractClientTokenDoesNotReadBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	body := &countingReadCloser{reader: bytes.NewReader(bytes.Repeat([]byte("a"), 16<<20))}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/api/clients/v2/rpc", nil)
	c.Request.Body = body

	if token := extractClientToken(c); token != "" {
		t.Fatalf("expected no token from body, got %q", token)
	}
	if body.read != 0 {
		t.Fatalf("identity stage read %d body bytes, want 0", body.read)
	}
}

// TestExtractClientTokenQueryCompatibility keeps the agent protocol working:
// the client token is carried in the query string.
func TestExtractClientTokenQueryCompatibility(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name  string
		query string
		want  string
	}{
		{name: "token", query: "?token=agent-token", want: "agent-token"},
		{name: "authorization query", query: "?Authorization=agent-token-2", want: "agent-token-2"},
		{name: "token wins over authorization", query: "?token=first&Authorization=second", want: "first"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/api/clients/v2/rpc"+tc.query, nil)
			if got := extractClientToken(c); got != tc.want {
				t.Fatalf("extractClientToken() = %q, want %q", got, tc.want)
			}
		})
	}
}
