package jsonrpc

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/pkg/rpc"
)

func newJSONRPCContext(t *testing.T, method, target string, body io.Reader, contentLength int64) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(method, target, nil)
	req.Body = io.NopCloser(body)
	req.ContentLength = contentLength
	c.Request = req
	return c
}

// TestReadLimitedJSONBodyRejectsChunkedOversize covers requests whose length is
// unknown: the limit must be enforced while reading, not from Content-Length.
func TestReadLimitedJSONBodyRejectsChunkedOversize(t *testing.T) {
	body := bytes.Repeat([]byte("a"), maxJSONBodyBytes+1)
	c := newJSONRPCContext(t, http.MethodPost, "/api/rpc2", bytes.NewReader(body), -1)

	_, err := readLimitedJSONBody(c)
	if !isBodyTooLarge(err) {
		t.Fatalf("expected body-too-large error, got %v", err)
	}
}

// TestReadLimitedJSONBodyPropagatesReadError distinguishes a real read failure
// from the size limit.
func TestReadLimitedJSONBodyPropagatesReadError(t *testing.T) {
	c := newJSONRPCContext(t, http.MethodPost, "/api/rpc2", errReader{}, -1)

	_, err := readLimitedJSONBody(c)
	if err == nil {
		t.Fatal("expected a read error")
	}
	if isBodyTooLarge(err) {
		t.Fatalf("read error must not be reported as size limit: %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// TestServePostRejectsOversizedBody checks the HTTP status an anonymous caller
// receives instead of having the whole body buffered.
func TestServePostRejectsOversizedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/rpc2", servePost)

	body := bytes.Repeat([]byte("a"), maxJSONBodyBytes+1024)
	req := httptest.NewRequest(http.MethodPost, "/api/rpc2", bytes.NewReader(body))
	req.ContentLength = -1 // simulate chunked transfer encoding
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

// TestServePostAcceptsNormalRequest keeps normal JSON-RPC bodies readable.
func TestServePostAcceptsNormalRequest(t *testing.T) {
	c := newJSONRPCContext(t, http.MethodPost, "/api/rpc2",
		bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"rpc.help","id":1}`)), 40)

	body, err := readLimitedJSONBody(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("body was not readable")
	}
}

// TestParseRequestsBatchLimit bounds fan-out independently of the body size.
func TestParseRequestsBatchLimit(t *testing.T) {
	requests := make([]map[string]any, 0, rpc.MaxBatchRequests+1)
	for i := 0; i <= rpc.MaxBatchRequests; i++ {
		requests = append(requests, map[string]any{
			"jsonrpc": "2.0",
			"method":  "rpc.help",
			"id":      i,
		})
	}
	payload, err := json.Marshal(requests)
	if err != nil {
		t.Fatal(err)
	}

	if _, jerr := rpc.ParseRequests(payload); jerr == nil {
		t.Fatal("expected batch-too-large error")
	} else if jerr.Code != rpc.InvalidRequest {
		t.Fatalf("error code = %d, want %d", jerr.Code, rpc.InvalidRequest)
	}

	// A batch at the limit still parses.
	withinLimit, err := json.Marshal(requests[:rpc.MaxBatchRequests])
	if err != nil {
		t.Fatal(err)
	}
	if _, jerr := rpc.ParseRequests(withinLimit); jerr != nil {
		t.Fatalf("batch at the limit was rejected: %v", jerr)
	}
}

// TestBindRejectsOversizedBody covers the declarative bridge, which buffers
// bodies too.
func TestBindRejectsOversizedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/bound", Bind("public:getMe"))

	body := bytes.Repeat([]byte("a"), maxJSONBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/api/bound", bytes.NewReader(body))
	req.ContentLength = -1
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}
