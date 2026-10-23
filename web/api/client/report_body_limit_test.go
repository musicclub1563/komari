package client

import (
	"bytes"
	"compress/gzip"
	crand "crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/web/api"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	flags.DatabaseType = "sqlite"
	flags.DatabaseFile = "file:komari_client_body_limit_test?mode=memory&cache=shared"
	_ = dbcore.GetDBInstance()
	os.Exit(m.Run())
}

type v2UploadFixture struct {
	server *httptest.Server
	token  string
	uuid   string
}

func newV2UploadFixture(t *testing.T) *v2UploadFixture {
	t.Helper()
	clientUUID := uuid.NewString()
	token := "body-limit-token-" + clientUUID
	db := dbcore.GetDBInstance()
	if err := db.Create(&models.Client{
		UUID:  clientUUID,
		Token: token,
		Name:  "initial-name",
	}).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(func() { _ = db.Where("uuid = ?", clientUUID).Delete(&models.Client{}).Error })

	engine := gin.New()
	engine.Use(api.IdentityMiddleware())
	engine.POST("/api/clients/v2/rpc", api.RequireRole(api.RoleAdmin, api.RoleClient), UploadV2RPC)
	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)

	return &v2UploadFixture{server: server, token: token, uuid: clientUUID}
}

func (f *v2UploadFixture) post(t *testing.T, body []byte, contentEncoding string, chunked bool) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader = bytes.NewReader(body)
	if chunked {
		// Wrapping in NopCloser hides the concrete reader type so net/http does
		// not infer a Content-Length and uses chunked transfer instead.
		reader = io.NopCloser(bytes.NewReader(body))
	}
	req, err := http.NewRequest(http.MethodPost, f.server.URL+"/api/clients/v2/rpc?token="+f.token, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, data
}

// paddedBasicInfo builds a valid agent.basic_info JSON-RPC body of exactly
// total bytes by padding an ignored field.
func paddedBasicInfo(name string, total int) []byte {
	prefix := `{"jsonrpc":"2.0","id":"body-limit","method":"agent.basicInfo","params":{"info":{"name":"` + name + `"}},"pad":"`
	suffix := `"}`
	pad := total - len(prefix) - len(suffix)
	if pad < 0 {
		panic("total is smaller than the JSON skeleton")
	}
	return []byte(prefix + strings.Repeat("a", pad) + suffix)
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestUploadV2RPCAcceptsNormalJSONAndGzip(t *testing.T) {
	f := newV2UploadFixture(t)
	body := paddedBasicInfo("json-ok", 1024)

	resp, data := f.post(t, body, "", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("plain JSON status = %d, body = %s", resp.StatusCode, data)
	}

	resp, data = f.post(t, gzipBytes(t, body), "gzip", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gzip status = %d, body = %s", resp.StatusCode, data)
	}
}

func TestUploadV2RPCRejectsPlainBodyOverLimit(t *testing.T) {
	f := newV2UploadFixture(t)
	body := bytes.Repeat([]byte("a"), int(MaxAgentRequestBodyBytes)+1)

	resp, data := f.post(t, body, "", false)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body = %s", resp.StatusCode, data)
	}
	if !bytes.Contains(data, []byte("request body too large")) {
		t.Fatalf("response does not report the size error: %s", data)
	}
}

func TestUploadV2RPCRejectsCompressedBodyOverLimit(t *testing.T) {
	f := newV2UploadFixture(t)
	// Incompressible data so the gzip stream itself exceeds the wire limit.
	raw := make([]byte, int(MaxAgentRequestBodyBytes)*2)
	if _, err := crand.Read(raw); err != nil {
		t.Fatalf("random data: %v", err)
	}
	compressed := gzipBytes(t, raw)
	if int64(len(compressed)) <= MaxAgentRequestBodyBytes {
		t.Fatalf("test precondition failed: compressed size %d", len(compressed))
	}

	resp, data := f.post(t, compressed, "gzip", false)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body = %s", resp.StatusCode, data)
	}
}

func TestUploadV2RPCRejectsDecompressionBomb(t *testing.T) {
	f := newV2UploadFixture(t)
	raw := bytes.Repeat([]byte("a"), int(MaxAgentDecompressedBodyBytes)+1)
	compressed := gzipBytes(t, raw)
	if int64(len(compressed)) >= MaxAgentDecompressedBodyBytes {
		t.Fatalf("test precondition failed: compressed size %d", len(compressed))
	}

	resp, data := f.post(t, compressed, "gzip", false)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body = %s", resp.StatusCode, data)
	}
}

func TestUploadV2RPCRejectsChunkedBodyOverLimit(t *testing.T) {
	f := newV2UploadFixture(t)
	body := bytes.Repeat([]byte("a"), int(MaxAgentRequestBodyBytes)+1)

	resp, data := f.post(t, body, "", true)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked status = %d, want 413; body = %s", resp.StatusCode, data)
	}
}

func TestUploadV2RPCBodyLimitBoundary(t *testing.T) {
	f := newV2UploadFixture(t)

	atLimit := paddedBasicInfo("at-limit", int(MaxAgentRequestBodyBytes))
	if len(atLimit) != int(MaxAgentRequestBodyBytes) {
		t.Fatalf("boundary body size = %d", len(atLimit))
	}
	if resp, data := f.post(t, atLimit, "", false); resp.StatusCode != http.StatusOK {
		t.Fatalf("at-limit status = %d, body = %s", resp.StatusCode, data)
	}
	if resp, _ := f.post(t, gzipBytes(t, atLimit), "gzip", false); resp.StatusCode != http.StatusOK {
		t.Fatalf("at-limit gzip status = %d", resp.StatusCode)
	}

	overLimit := paddedBasicInfo("over-limit", int(MaxAgentRequestBodyBytes)+1)
	if resp, data := f.post(t, overLimit, "", false); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit status = %d, want 413; body = %s", resp.StatusCode, data)
	}
	if resp, data := f.post(t, gzipBytes(t, overLimit), "gzip", false); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit gzip status = %d, want 413; body = %s", resp.StatusCode, data)
	}
}

func TestUploadV2RPCMalformedAndTruncatedGzip(t *testing.T) {
	f := newV2UploadFixture(t)

	resp, _ := f.post(t, []byte("this is not gzip"), "gzip", false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed gzip status = %d, want 400", resp.StatusCode)
	}

	valid := gzipBytes(t, paddedBasicInfo("truncated", 2048))
	truncated := valid[:len(valid)/2]
	resp, _ = f.post(t, truncated, "gzip", false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("truncated gzip status = %d, want 400", resp.StatusCode)
	}
}

// TestUploadV2RPCOversizedBodySkipsBusinessLogic proves the request is rejected
// before the JSON-RPC handler runs: the body is valid JSON that would rename the
// client if it were processed.
func TestUploadV2RPCOversizedBodySkipsBusinessLogic(t *testing.T) {
	f := newV2UploadFixture(t)
	body := paddedBasicInfo("should-not-apply", int(MaxAgentRequestBodyBytes)+1)

	resp, _ := f.post(t, body, "", false)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}

	var stored models.Client
	if err := dbcore.GetDBInstance().First(&stored, "uuid = ?", f.uuid).Error; err != nil {
		t.Fatalf("load client: %v", err)
	}
	if stored.Name != "initial-name" {
		t.Fatalf("client name = %q, oversized request reached business logic", stored.Name)
	}
}
