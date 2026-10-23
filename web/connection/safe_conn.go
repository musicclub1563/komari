package connection

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ConnInfo describes one WebSocket connection passed to interceptor
// callbacks. ID matches the owning SafeConn.
type ConnInfo struct {
	ID         int64
	Path       string
	RemoteIP   string
	UserAgent  string
	ClientUUID string
}

// FrameInterceptor is the optional hook chain around WebSocket connections
// and frames. The provider is wired once at startup by internal/server (the
// plugin manager); a nil interceptor leaves every connection untouched.
type FrameInterceptor interface {
	// OnConnect runs right after the upgrade. A denied connection is closed
	// by the caller; plugins bear the consequences of rejecting endpoints
	// such as /api/rpc2.
	OnConnect(info *ConnInfo) (deny bool, reason string)
	// OnMessage inspects one inbound frame; OnSend one outbound frame. They
	// return the possibly replaced payload and whether the frame is dropped.
	OnMessage(info *ConnInfo, frameType int, data []byte) (newType int, newData []byte, drop bool)
	OnSend(info *ConnInfo, frameType int, data []byte) (newType int, newData []byte, drop bool)
	// OnClose notifies that the connection ended.
	OnClose(info *ConnInfo)
}

// frameInterceptor is the process-wide WebSocket hook provider.
var frameInterceptor FrameInterceptor

// SetFrameInterceptor wires the plugin hook chain into every WebSocket
// connection. It must be called once at startup, before connections arrive.
func SetFrameInterceptor(i FrameInterceptor) { frameInterceptor = i }

// Interceptor returns the process-wide frame interceptor, or nil when no
// provider is wired.
func Interceptor() FrameInterceptor { return frameInterceptor }

// errTooManyDroppedFrames fails the read loop after a plugin dropped too many
// frames in a row, so a connection on a fully filtered endpoint cannot spin
// forever.
var errTooManyDroppedFrames = errors.New("too many frames dropped by plugin hooks")

// ErrMessageTooLarge is returned when an inbound message exceeds the limit set
// with SetReadLimit. The limit is enforced while reading, so an oversized
// payload is never fully buffered in memory.
var ErrMessageTooLarge = errors.New("websocket message exceeds read limit")

// maxConsecutiveDroppedFrames bounds the internal re-read loop.
const maxConsecutiveDroppedFrames = 16

// SafeConn wraps a websocket connection with a mutex so concurrent writes
// cannot interleave frames, and funnels every frame through the optional
// plugin interceptor when one is attached.
type SafeConn struct {
	conn *websocket.Conn
	// mu serializes writes only. It is held across the network write, so no
	// lifecycle operation (Close in particular) may wait for it.
	mu sync.Mutex

	// stateMu guards the fields below. It is only ever held for short,
	// non-blocking sections, which keeps reads and Close independent of a
	// blocked write.
	stateMu sync.Mutex

	ID int64

	readLimit   int64
	interceptor FrameInterceptor
	info        *ConnInfo
	closed      bool
}

func NewSafeConn(conn *websocket.Conn) *SafeConn {
	return &SafeConn{
		conn: conn,
		mu:   sync.Mutex{},
		ID:   time.Now().UnixNano(),
	}
}

// SetReadLimit bounds the size of inbound messages. The limit applies to the
// decoded payload: gorilla/websocket rejects oversized frames before
// reassembly, and the reader wrapper in readLimitedMessage additionally counts
// decompressed bytes. It must be called before the first read.
func (sc *SafeConn) SetReadLimit(limit int64) {
	sc.stateMu.Lock()
	defer sc.stateMu.Unlock()
	sc.readLimit = limit
	if limit > 0 {
		sc.conn.SetReadLimit(limit)
	}
}

// SetInterceptor attaches the hook provider and the connection identity. It
// must be called before any frame is read or written.
func (sc *SafeConn) SetInterceptor(info *ConnInfo, interceptor FrameInterceptor) {
	sc.stateMu.Lock()
	defer sc.stateMu.Unlock()
	sc.info = info
	sc.interceptor = interceptor
}

// readLimitedMessage reads one complete message through NextReader while
// enforcing the configured limit. Reading through a bounded reader (instead of
// ReadMessage followed by a length check) means an oversized message is
// rejected before the whole payload is buffered. LimitReader counts the bytes
// delivered after decompression, so compressed amplification is covered too.
func (sc *SafeConn) readLimitedMessage() (int, []byte, error) {
	messageType, reader, err := sc.conn.NextReader()
	if err != nil {
		return 0, nil, err
	}
	sc.stateMu.Lock()
	limit := sc.readLimit
	sc.stateMu.Unlock()
	if limit <= 0 {
		data, readErr := io.ReadAll(reader)
		return messageType, data, readErr
	}
	data, readErr := io.ReadAll(io.LimitReader(reader, limit+1))
	if readErr != nil {
		return 0, nil, readErr
	}
	if int64(len(data)) > limit {
		// Tell the peer why the connection is going away; gorilla only sends
		// this automatically for the pre-decompression limit.
		_ = sc.conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseMessageTooBig, "message too large"),
			time.Now().Add(time.Second))
		return 0, nil, ErrMessageTooLarge
	}
	return messageType, data, nil
}

// readFrame reads one frame and runs the wsMessage hook chain. Frames
// dropped by hooks are transparently skipped, so callers only ever see
// processed frames.
func (sc *SafeConn) readFrame() (int, []byte, error) {
	for dropped := 0; ; {
		messageType, data, err := sc.readLimitedMessage()
		if err != nil {
			return 0, nil, err
		}
		sc.stateMu.Lock()
		interceptor, info := sc.interceptor, sc.info
		sc.stateMu.Unlock()
		if interceptor == nil || info == nil {
			return messageType, data, nil
		}
		newType, newData, drop := interceptor.OnMessage(info, messageType, data)
		if !drop {
			return newType, newData, nil
		}
		if dropped++; dropped >= maxConsecutiveDroppedFrames {
			return 0, nil, errTooManyDroppedFrames
		}
	}
}

// writeFrame runs the wsSend hook chain then writes one frame. A dropped
// frame is silently skipped; a nil interceptor writes through immediately.
func (sc *SafeConn) writeFrame(messageType int, data []byte) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	interceptor, info, closed := sc.state()
	if closed {
		return net.ErrClosed
	}
	if interceptor == nil || info == nil {
		return sc.conn.WriteMessage(messageType, data)
	}
	newType, newData, drop := interceptor.OnSend(info, messageType, data)
	if drop {
		return nil
	}
	return sc.conn.WriteMessage(newType, newData)
}

// state returns a consistent snapshot of the hook state. stateMu is never
// held across I/O, so waiting for it while holding mu stays bounded.
func (sc *SafeConn) state() (FrameInterceptor, *ConnInfo, bool) {
	sc.stateMu.Lock()
	defer sc.stateMu.Unlock()
	return sc.interceptor, sc.info, sc.closed
}

func (sc *SafeConn) WriteMessage(messageType int, data []byte) error {
	return sc.writeFrame(messageType, data)
}

func (sc *SafeConn) WriteControl(messageType int, data []byte, deadline time.Time) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	interceptor, info, closed := sc.state()
	if closed {
		return net.ErrClosed
	}
	if interceptor == nil || info == nil {
		return sc.conn.WriteControl(messageType, data, deadline)
	}
	newType, newData, drop := interceptor.OnSend(info, messageType, data)
	if drop {
		return nil
	}
	return sc.conn.WriteControl(newType, newData, deadline)
}

// WriteJSON encodes v then sends it as one text frame through the wsSend
// hook chain.
func (sc *SafeConn) WriteJSON(v interface{}) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		return err
	}
	return sc.writeFrame(websocket.TextMessage, buf.Bytes())
}

// Close tears the connection down without waiting for in-flight writes. Writes
// hold mu while writing to the peer and have no deadline, so closing the socket
// under mu would let a peer that stops reading block the forced shutdown (and
// every lifecycle cleanup waiting on it) indefinitely. gorilla permits Close
// concurrently with reads and writes; closing the socket makes the blocked
// write return immediately.
func (sc *SafeConn) Close() error {
	sc.stateMu.Lock()
	interceptor, info := sc.interceptor, sc.info
	sc.interceptor, sc.info = nil, nil // run OnClose exactly once
	alreadyClosed := sc.closed
	sc.closed = true
	sc.stateMu.Unlock()
	if alreadyClosed {
		return nil
	}

	err := sc.conn.Close()
	if interceptor != nil && info != nil {
		interceptor.OnClose(info)
	}
	return err
}

func (sc *SafeConn) ReadMessage() (int, []byte, error) {
	return sc.readFrame()
}

func (sc *SafeConn) ReadJSON(v interface{}) error {
	_, data, err := sc.readFrame()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (sc *SafeConn) SetReadDeadline(t time.Time) error {
	return sc.conn.SetReadDeadline(t)
}

func (sc *SafeConn) SetPingHandler(h func(string) error) {
	sc.conn.SetPingHandler(h)
}

func (sc *SafeConn) GetConn() *websocket.Conn {
	return sc.conn
}

// SetCloseHandler forwards to the underlying connection (used by the
// terminal sessions to clean up on close).
func (sc *SafeConn) SetCloseHandler(h func(code int, text string) error) {
	sc.conn.SetCloseHandler(h)
}
