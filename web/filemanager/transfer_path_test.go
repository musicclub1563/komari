package filemanager

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/dbcore"
	v2 "github.com/komari-monitor/komari/protocol/v2"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
)

// exactPaths 覆盖首尾空白、中文与平台支持的合法特殊字符。这些名字在服务端
// 必须原样传递："/tmp/report " 与 "/tmp/report" 是两个不同的文件。
func exactPaths() []string {
	return []string{
		"/tmp/report ",
		"/tmp/ report",
		"/tmp/中文 文档.txt",
		"/tmp/报告.txt",
		"/tmp/file (1).txt",
		"/tmp/tab\tfile.txt",
	}
}

func ensureFileTransferTestDB() {
	flags.DatabaseType = "sqlite"
	flags.DatabaseFile = "file:komari_filemanager_test?mode=memory&cache=shared"
	_ = dbcore.GetDBInstance()
}

func newFileTransferEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/:uuid/file/upload", Upload)
	engine.GET("/:uuid/file/download", Download)
	engine.GET("/:uuid/file/preview-token", CreatePreviewToken)
	engine.GET("/preview/client/:uuid/file/download", PreviewDownload)
	return engine
}

// markAgent registers a v2 client without a WebSocket connection, so file
// operations are queued for the agent and the test can answer them.
func markAgent(t *testing.T, clientUUID string) {
	t.Helper()
	agent_runtime.MarkV2Client(clientUUID)
	t.Cleanup(func() {
		agent_runtime.DeleteConnectedClients(clientUUID)
	})
}

// expectAgentCall runs handler and answers the file operation it dispatches,
// returning the arguments the server actually sent to the agent.
func expectAgentCall(t *testing.T, clientUUID, op string, handler func(), respond func(args map[string]any) json.RawMessage) map[string]any {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler()
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, event := range agent_runtime.WaitV2Events(clientUUID, nil, 0) {
			if event.Method != v2.MethodAgentFile {
				continue
			}
			operation, ok := event.Params.(v2.FileOperation)
			if !ok || operation.Op != op {
				continue
			}
			// Consume the event so later assertions cannot see it again.
			agent_runtime.WaitV2Events(clientUUID, []string{event.ID}, 0)
			var result json.RawMessage
			if respond != nil {
				result = respond(operation.Args)
			}
			if !Resolve(v2.FileResult{UUID: operation.UUID, RequestID: operation.RequestID, OK: true, Result: result}) {
				t.Fatalf("could not answer agent call %q", op)
			}
			<-done
			return operation.Args
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent operation %q was never dispatched", op)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func successData(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Status string         `json:"status"`
		Data   map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v (%s)", err, recorder.Body.String())
	}
	if response.Status != "success" {
		t.Fatalf("response = %s", recorder.Body.String())
	}
	return response.Data
}

func sessionPath(id string) (string, bool) {
	uploadMu.Lock()
	defer uploadMu.Unlock()
	session := uploadSessions[id]
	if session == nil {
		return "", false
	}
	return session.Path, true
}

func persistedSessionPath(t *testing.T, id string) string {
	t.Helper()
	data, err := os.ReadFile(uploadSessionPath(id))
	if err != nil {
		t.Fatalf("persisted session missing: %v", err)
	}
	var persisted persistedUploadSession
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("decode persisted session: %v", err)
	}
	return persisted.Path
}

func doUploadInit(t *testing.T, clientUUID, path string, size int64) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"path": path, "size": size})
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/"+clientUUID+"/file/upload?operation=init", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	newFileTransferEngine().ServeHTTP(recorder, request)
	return recorder
}

func TestUploadInitKeepsExactPath(t *testing.T) {
	ensureFileTransferTestDB()
	clientUUID := "client-init-path"
	markAgent(t, clientUUID)

	for _, path := range exactPaths() {
		t.Run(path, func(t *testing.T) {
			resetUploadSessionsForTest()
			t.Cleanup(resetUploadSessionsForTest)

			recorder := doUploadInit(t, clientUUID, path, 4096)
			data := successData(t, recorder)
			uploadID, _ := data["upload_id"].(string)
			if uploadID == "" {
				t.Fatalf("response has no upload_id: %s", recorder.Body.String())
			}
			stored, ok := sessionPath(uploadID)
			if !ok {
				t.Fatal("upload session was not kept in memory")
			}
			if stored != path {
				t.Fatalf("session path = %q, want %q", stored, path)
			}
			if persisted := persistedSessionPath(t, uploadID); persisted != path {
				t.Fatalf("persisted session path = %q, want %q", persisted, path)
			}
		})
	}
}

func TestZeroByteUploadDispatchesExactPath(t *testing.T) {
	ensureFileTransferTestDB()
	clientUUID := "client-zero-byte"
	markAgent(t, clientUUID)

	for _, path := range exactPaths() {
		t.Run(path, func(t *testing.T) {
			var recorder *httptest.ResponseRecorder
			args := expectAgentCall(t, clientUUID, "create", func() {
				recorder = doUploadInit(t, clientUUID, path, 0)
			}, nil)
			if got := args["path"]; got != path {
				t.Fatalf("dispatched create path = %q, want %q", got, path)
			}
			if data := successData(t, recorder); data["complete"] != true {
				t.Fatalf("zero byte upload was not completed: %s", recorder.Body.String())
			}
		})
	}
}

func TestUploadCommitDispatchesExactPath(t *testing.T) {
	ensureFileTransferTestDB()
	clientUUID := "client-commit"
	markAgent(t, clientUUID)

	for _, path := range exactPaths() {
		t.Run(path, func(t *testing.T) {
			resetUploadSessionsForTest()
			t.Cleanup(resetUploadSessionsForTest)

			init := doUploadInit(t, clientUUID, path, 4096)
			uploadID, _ := successData(t, init)["upload_id"].(string)
			if uploadID == "" {
				t.Fatal("upload init returned no upload_id")
			}

			body, err := json.Marshal(map[string]any{"upload_id": uploadID})
			if err != nil {
				t.Fatalf("encode request: %v", err)
			}
			request := httptest.NewRequest(http.MethodPost, "/"+clientUUID+"/file/upload?operation=merge", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			args := expectAgentCall(t, clientUUID, "upload_commit", func() {
				newFileTransferEngine().ServeHTTP(recorder, request)
			}, nil)
			if got := args["path"]; got != path {
				t.Fatalf("dispatched upload_commit path = %q, want %q", got, path)
			}
			if data := successData(t, recorder); data["complete"] != true {
				t.Fatalf("merge was not completed: %s", recorder.Body.String())
			}
		})
	}
}

func TestDownloadDispatchesExactPath(t *testing.T) {
	ensureFileTransferTestDB()
	clientUUID := "client-download"
	markAgent(t, clientUUID)

	for _, path := range exactPaths() {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/"+clientUUID+"/file/download?path="+url.QueryEscape(path), nil)
			recorder := httptest.NewRecorder()
			statResponse := []byte(`{"name":"report","size":0,"is_dir":false,"modified_at":"2026-10-23T00:00:00Z"}`)
			args := expectAgentCall(t, clientUUID, "stat", func() {
				newFileTransferEngine().ServeHTTP(recorder, request)
			}, func(map[string]any) json.RawMessage { return statResponse })
			if got := args["path"]; got != path {
				t.Fatalf("dispatched stat path = %q, want %q", got, path)
			}
			if recorder.Code != http.StatusOK {
				t.Fatalf("download status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestPreviewTokenKeepsExactPath(t *testing.T) {
	ensureFileTransferTestDB()
	clientUUID := "client-preview"
	markAgent(t, clientUUID)

	for _, path := range exactPaths() {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/"+clientUUID+"/file/preview-token?path="+url.QueryEscape(path), nil)
			recorder := httptest.NewRecorder()
			newFileTransferEngine().ServeHTTP(recorder, request)
			token, _ := successData(t, recorder)["token"].(string)
			if token == "" {
				t.Fatalf("preview token missing: %s", recorder.Body.String())
			}

			previewTokenMu.Lock()
			item := previewTokens[token]
			previewTokenMu.Unlock()
			if item.Path != path {
				t.Fatalf("preview token path = %q, want %q", item.Path, path)
			}

			previewRequest := httptest.NewRequest(http.MethodGet,
				"/preview/client/"+clientUUID+"/file/download?preview_token="+url.QueryEscape(token)+"&filename=preview.txt", nil)
			previewRecorder := httptest.NewRecorder()
			statResponse := []byte(`{"name":"report","size":0,"is_dir":false,"modified_at":"2026-10-23T00:00:00Z"}`)
			args := expectAgentCall(t, clientUUID, "stat", func() {
				newFileTransferEngine().ServeHTTP(previewRecorder, previewRequest)
			}, func(map[string]any) json.RawMessage { return statResponse })
			if got := args["path"]; got != path {
				t.Fatalf("preview download stat path = %q, want %q", got, path)
			}
			if previewRecorder.Code != http.StatusOK {
				t.Fatalf("preview download status = %d, body = %s", previewRecorder.Code, previewRecorder.Body.String())
			}
		})
	}
}

// TestSiblingPathsWithTrailingSpaceStayDistinct reproduces the reported case:
// both "/tmp/report" and "/tmp/report " exist, and operating on the second one
// must never resolve to the first one.
func TestSiblingPathsWithTrailingSpaceStayDistinct(t *testing.T) {
	ensureFileTransferTestDB()
	clientUUID := "client-siblings"
	markAgent(t, clientUUID)
	resetUploadSessionsForTest()
	t.Cleanup(resetUploadSessionsForTest)

	plain := doUploadInit(t, clientUUID, "/tmp/report", 4096)
	plainID, _ := successData(t, plain)["upload_id"].(string)
	spaced := doUploadInit(t, clientUUID, "/tmp/report ", 4096)
	spacedID, _ := successData(t, spaced)["upload_id"].(string)
	if plainID == "" || spacedID == "" {
		t.Fatal("upload init did not return upload ids")
	}
	if plainID == spacedID {
		t.Fatal("both paths resolved to the same upload session")
	}

	spacedPath, _ := sessionPath(spacedID)
	plainPath, _ := sessionPath(plainID)
	if spacedPath != "/tmp/report " {
		t.Fatalf("session path = %q, want %q", spacedPath, "/tmp/report ")
	}
	if plainPath != "/tmp/report" {
		t.Fatalf("sibling session path = %q, want %q", plainPath, "/tmp/report")
	}

	body, err := json.Marshal(map[string]any{"upload_id": spacedID})
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/"+clientUUID+"/file/upload?operation=merge", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	args := expectAgentCall(t, clientUUID, "upload_commit", func() {
		newFileTransferEngine().ServeHTTP(recorder, request)
	}, nil)
	if got := args["path"]; got != "/tmp/report " {
		t.Fatalf("dispatched merge path = %q, want %q", got, "/tmp/report ")
	}
	if _, ok := sessionPath(plainID); !ok {
		t.Fatal("operating on the spaced path disturbed the sibling session")
	}
}

// TestBlankPathStillRejected keeps the empty-path check: a blank value is not a
// usable path, but a real path must never be rewritten.
func TestBlankPathStillRejected(t *testing.T) {
	ensureFileTransferTestDB()
	clientUUID := "client-blank"
	markAgent(t, clientUUID)
	resetUploadSessionsForTest()
	t.Cleanup(resetUploadSessionsForTest)

	for _, path := range []string{"", "   ", "\t\n"} {
		body, err := json.Marshal(map[string]any{"path": path, "size": 4096})
		if err != nil {
			t.Fatalf("encode request: %v", err)
		}
		request := httptest.NewRequest(http.MethodPost, "/"+clientUUID+"/file/upload?operation=init", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		newFileTransferEngine().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("init status for %q = %d, want %d", path, recorder.Code, http.StatusBadRequest)
		}

		download := httptest.NewRequest(http.MethodGet, "/"+clientUUID+"/file/download?path="+url.QueryEscape(path), nil)
		downloadRecorder := httptest.NewRecorder()
		newFileTransferEngine().ServeHTTP(downloadRecorder, download)
		if downloadRecorder.Code != http.StatusBadRequest {
			t.Fatalf("download status for %q = %d, want %d", path, downloadRecorder.Code, http.StatusBadRequest)
		}

		token := httptest.NewRequest(http.MethodGet, "/"+clientUUID+"/file/preview-token?path="+url.QueryEscape(path), nil)
		tokenRecorder := httptest.NewRecorder()
		newFileTransferEngine().ServeHTTP(tokenRecorder, token)
		if tokenRecorder.Code != http.StatusBadRequest {
			t.Fatalf("preview token status for %q = %d, want %d", path, tokenRecorder.Code, http.StatusBadRequest)
		}
	}

	// A path that starts with a space is a real name and must be accepted.
	recorder := doUploadInit(t, clientUUID, " /tmp/leading-space.txt", 4096)
	uploadID, _ := successData(t, recorder)["upload_id"].(string)
	if stored, _ := sessionPath(uploadID); stored != " /tmp/leading-space.txt" {
		t.Fatalf("session path = %q, want the leading space preserved", stored)
	}
}
