package connection

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// recordingInterceptor captures calls and applies simple rewrites.
type recordingInterceptor struct {
	mu             sync.Mutex
	connects       []*ConnInfo
	lastInfo       *ConnInfo
	messages       []string
	sends          []string
	closes         int
	dropMessage    bool
	dropSend       bool
	rewriteMessage bool
}

func (r *recordingInterceptor) OnConnect(info *ConnInfo) (bool, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connects = append(r.connects, info)
	return false, ""
}

func (r *recordingInterceptor) OnMessage(info *ConnInfo, frameType int, data []byte) (int, []byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastInfo = info
	r.messages = append(r.messages, string(data))
	if r.dropMessage {
		return frameType, nil, true
	}
	if r.rewriteMessage {
		return frameType, []byte("rewritten:" + string(data)), false
	}
	return frameType, data, false
}

func (r *recordingInterceptor) OnSend(info *ConnInfo, frameType int, data []byte) (int, []byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastInfo = info
	r.sends = append(r.sends, string(data))
	if r.dropSend {
		return frameType, nil, true
	}
	return frameType, data, false
}

func (r *recordingInterceptor) OnClose(info *ConnInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closes++
}

func (r *recordingInterceptor) calls() (info *ConnInfo, messages []string, sends []string, closes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastInfo, append([]string(nil), r.messages...), append([]string(nil), r.sends...), r.closes
}

// wsEchoServer upgrades every request and echoes each frame back.
func wsEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	var upgrader websocket.Upgrader
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(mt, data); err != nil {
				return
			}
		}
	}))
}

func dialEcho(t *testing.T, server *httptest.Server) *SafeConn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewSafeConn(conn)
}

// TestSafeConnInterceptorWired 验证读写帧都经过拦截器，且连接信息与 ID 一致。
func TestSafeConnInterceptorWired(t *testing.T) {
	server := wsEchoServer(t)
	defer server.Close()
	sc := dialEcho(t, server)
	defer sc.Close()

	rec := &recordingInterceptor{}
	info := &ConnInfo{ID: sc.ID, Path: "/api/clients/v2/rpc", RemoteIP: "203.0.113.9"}
	sc.SetInterceptor(info, rec)

	if err := sc.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	mt, data, err := sc.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if mt != websocket.TextMessage || string(data) != "ping" {
		t.Fatalf("echo = type %d data %q", mt, data)
	}
	info, messages, sends, _ := rec.calls()
	if len(messages) != 1 || len(sends) != 1 || messages[0] != "ping" || sends[0] != "ping" {
		t.Fatalf("interceptor calls = messages %v sends %v", messages, sends)
	}
	// 帧回调收到的连接信息与附加时一致（OnConnect 由升级层调用，这里不做断言）。
	if info == nil || info.ID != sc.ID || info.Path != "/api/clients/v2/rpc" {
		t.Fatalf("frame info = %+v", info)
	}
}

func TestSafeConnPingHandlerWritesPongThroughInterceptor(t *testing.T) {
	pong := make(chan string, 1)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetPongHandler(func(data string) error {
			pong <- data
			return nil
		})
		if err := conn.WriteControl(websocket.PingMessage, []byte("heartbeat"), time.Now().Add(time.Second)); err != nil {
			return
		}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	sc := dialEcho(t, server)
	defer sc.Close()
	rec := &recordingInterceptor{}
	sc.SetInterceptor(&ConnInfo{ID: sc.ID, Path: "/x"}, rec)
	sc.SetPingHandler(func(data string) error {
		return sc.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
	})
	if err := sc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, _, err := sc.ReadMessage()
		readDone <- err
	}()

	select {
	case data := <-pong:
		if data != "heartbeat" {
			t.Fatalf("pong data = %q, want heartbeat", data)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive pong")
	}
	_, _, sends, _ := rec.calls()
	if len(sends) != 1 || sends[0] != "heartbeat" {
		t.Fatalf("interceptor sends = %v, want heartbeat pong", sends)
	}

	_ = sc.Close()
	<-readDone
}

// TestSafeConnRewriteAndWriteJSON 验证帧改写（读侧）与 WriteJSON 走同一拦截通道。
func TestSafeConnRewriteAndWriteJSON(t *testing.T) {
	server := wsEchoServer(t)
	defer server.Close()
	sc := dialEcho(t, server)
	defer sc.Close()

	rec := &recordingInterceptor{rewriteMessage: true}
	sc.SetInterceptor(&ConnInfo{ID: sc.ID, Path: "/x"}, rec)

	if err := sc.WriteJSON(map[string]any{"a": 1}); err != nil {
		t.Fatal(err)
	}
	mt, data, err := sc.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if mt != websocket.TextMessage || !strings.HasPrefix(string(data), "rewritten:") {
		t.Fatalf("read = type %d data %q", mt, data)
	}
	// WriteJSON 编码后的 JSON 文本也经过 wsSend 钩子。
	_, sends, _, _ := rec.calls()
	if len(sends) != 1 || !strings.Contains(sends[0], "\"a\"") {
		t.Fatalf("sends = %v", sends)
	}
}

// TestSafeConnDropSkipsFrame 验证被丢弃的帧被透明跳过，读侧只看到后续帧。
func TestSafeConnDropSkipsFrame(t *testing.T) {
	server := wsEchoServer(t)
	defer server.Close()
	sc := dialEcho(t, server)
	defer sc.Close()

	rec := &recordingInterceptor{dropMessage: true}
	sc.SetInterceptor(&ConnInfo{ID: sc.ID, Path: "/x"}, rec)

	// 发三帧：全部被丢弃；读侧应在连续丢弃达到上限后收到错误，而不是空数据。
	if err := sc.WriteMessage(websocket.TextMessage, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := sc.WriteMessage(websocket.TextMessage, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if err := sc.WriteMessage(websocket.TextMessage, []byte("c")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxConsecutiveDroppedFrames-3; i++ {
		if err := sc.WriteMessage(websocket.TextMessage, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := sc.ReadMessage(); !errors.Is(err, errTooManyDroppedFrames) {
		t.Fatalf("expected errTooManyDroppedFrames, got %v", err)
	}
}

// TestSafeConnDropSend 验证写侧丢弃：被丢弃的帧不会发到对端，后续帧不受影响。
func TestSafeConnDropSend(t *testing.T) {
	server := wsEchoServer(t)
	defer server.Close()
	sc := dialEcho(t, server)
	defer sc.Close()

	rec := &recordingInterceptor{dropSend: true}
	sc.SetInterceptor(&ConnInfo{ID: sc.ID, Path: "/x"}, rec)

	if err := sc.WriteMessage(websocket.TextMessage, []byte("hidden")); err != nil {
		t.Fatal(err)
	}
	// 关闭丢弃后发送的帧应该正常到达服务端并回显。
	rec.mu.Lock()
	rec.dropSend = false
	rec.mu.Unlock()
	if err := sc.WriteMessage(websocket.TextMessage, []byte("visible")); err != nil {
		t.Fatal(err)
	}
	mt, data, err := sc.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "visible" || mt != websocket.TextMessage {
		t.Fatalf("echo = %q (dropped frame must not reach the peer)", data)
	}
}

// TestSafeConnNoInterceptorZeroCost 验证未挂拦截器时读写路径原样工作。
func TestSafeConnNoInterceptorZeroCost(t *testing.T) {
	server := wsEchoServer(t)
	defer server.Close()
	sc := dialEcho(t, server)
	defer sc.Close()

	if err := sc.WriteMessage(websocket.TextMessage, []byte("plain")); err != nil {
		t.Fatal(err)
	}
	_, data, err := sc.ReadMessage()
	if err != nil || string(data) != "plain" {
		t.Fatalf("read = %q err %v", data, err)
	}
}

// readLimitOutcome 是限量读取服务端观测到的结果。
type readLimitOutcome struct {
	messageType int
	data        []byte
	err         error
}

// newReadLimitServer upgrades one connection, installs limit on a SafeConn and
// reports the first read. compress enables permessage-deflate negotiation.
func newReadLimitServer(t *testing.T, limit int64, compress bool) (*httptest.Server, <-chan readLimitOutcome) {
	t.Helper()
	outcome := make(chan readLimitOutcome, 1)
	upgrader := websocket.Upgrader{EnableCompression: compress, CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			outcome <- readLimitOutcome{err: err}
			return
		}
		sc := NewSafeConn(raw)
		defer sc.Close()
		sc.SetReadLimit(limit)
		mt, data, err := sc.ReadMessage()
		outcome <- readLimitOutcome{messageType: mt, data: data, err: err}
	}))
	return server, outcome
}

func dialWithCompression(t *testing.T, server *httptest.Server, compress bool) *websocket.Conn {
	t.Helper()
	dialer := websocket.Dialer{EnableCompression: compress}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// TestSafeConnReadLimitRejectsOversizedMessage guards the reproduced bug where
// an 8 MiB frame was fully buffered before any size check ran. The message is
// fragmented by the client's 4 KiB write buffer, so this also covers
// reassembly.
func TestSafeConnReadLimitRejectsOversizedMessage(t *testing.T) {
	const limit = 4096
	server, outcome := newReadLimitServer(t, limit, false)
	defer server.Close()
	client := dialWithCompression(t, server, false)
	defer client.Close()

	payload := bytes.Repeat([]byte("A"), 8<<20)
	go func() {
		_ = client.WriteMessage(websocket.TextMessage, payload)
	}()

	select {
	case got := <-outcome:
		if got.err == nil {
			t.Fatalf("server accepted an %d byte message with limit %d", len(got.data), limit)
		}
		if got.data != nil {
			t.Fatalf("server buffered %d bytes before rejecting the message", len(got.data))
		}
		if !errors.Is(got.err, websocket.ErrReadLimit) && !errors.Is(got.err, ErrMessageTooLarge) {
			t.Fatalf("server read error = %v, want a read limit error", got.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not reject the oversized message")
	}

	// The connection must be torn down without consuming the rest of the
	// message. While the client is still streaming 8 MiB a TCP reset can race
	// with the 1009 close frame, so only a close frame with a different code is
	// a failure.
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := client.ReadMessage()
	if err == nil {
		t.Fatal("connection stayed open after an oversized message")
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) && closeErr.Code != websocket.CloseMessageTooBig {
		t.Fatalf("client close code = %d, want %d", closeErr.Code, websocket.CloseMessageTooBig)
	}
}

// TestSafeConnReadLimitUsesDecompressedSize covers compressed amplification:
// the compressed payload is far below the limit while the decoded message is
// far above it. gorilla's SetReadLimit only sees wire bytes, so the bounded
// reader must count decompressed data.
func TestSafeConnReadLimitUsesDecompressedSize(t *testing.T) {
	const limit = 64 << 10
	server, outcome := newReadLimitServer(t, limit, true)
	defer server.Close()
	client := dialWithCompression(t, server, true)
	defer client.Close()

	payload := bytes.Repeat([]byte("a"), 1<<20)
	go func() {
		_ = client.WriteMessage(websocket.TextMessage, payload)
	}()

	select {
	case got := <-outcome:
		if !errors.Is(got.err, ErrMessageTooLarge) {
			t.Fatalf("server read error = %v, want ErrMessageTooLarge", got.err)
		}
		if len(got.data) != 0 {
			t.Fatalf("server buffered %d decoded bytes, want none", len(got.data))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not reject the decompressed oversized message")
	}

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := client.ReadMessage()
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) || closeErr.Code != websocket.CloseMessageTooBig {
		t.Fatalf("client close error = %v, want close code %d", err, websocket.CloseMessageTooBig)
	}
}

// TestSafeConnReadLimitAllowsMessagesAtTheLimit keeps normal traffic working,
// including compressed frames that stay within the limit.
func TestSafeConnReadLimitAllowsMessagesAtTheLimit(t *testing.T) {
	const limit = 64 << 10
	server, outcome := newReadLimitServer(t, limit, true)
	defer server.Close()
	client := dialWithCompression(t, server, true)
	defer client.Close()

	payload := bytes.Repeat([]byte("b"), 32<<10)
	if err := client.WriteMessage(websocket.TextMessage, payload); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-outcome:
		if got.err != nil {
			t.Fatalf("server rejected an in-limit message: %v", got.err)
		}
		if !bytes.Equal(got.data, payload) {
			t.Fatalf("server read %d bytes, want %d", len(got.data), len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not read the in-limit message")
	}
}

// TestSafeConnOnCloseOnce 验证 Close 只触发一次 OnClose。
func TestSafeConnOnCloseOnce(t *testing.T) {
	server := wsEchoServer(t)
	defer server.Close()
	sc := dialEcho(t, server)

	rec := &recordingInterceptor{}
	sc.SetInterceptor(&ConnInfo{ID: sc.ID, Path: "/x"}, rec)

	if err := sc.Close(); err != nil {
		t.Fatal(err)
	}
	// 第二次关闭连接已关闭：返回错误是预期行为，OnClose 只应触发一次。
	_ = sc.Close()
	_, _, _, closes := rec.calls()
	if closes != 1 {
		t.Fatalf("OnClose fired %d times", closes)
	}
}
