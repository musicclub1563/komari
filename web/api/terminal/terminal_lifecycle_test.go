package terminal

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/database/accounts"
)

// waitForTerminalSuspended waits until both sides of a terminal session are
// gone, i.e. the retention timer has been armed.
func waitForTerminalSuspended(t *testing.T, id string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		TerminalSessionsMutex.Lock()
		session, ok := TerminalSessions[id]
		suspended := ok && session != nil && session.Browser == nil && session.Agent == nil
		TerminalSessionsMutex.Unlock()
		if suspended {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("terminal session was not suspended after its browser disconnected")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTerminalReattachSurvivesRetentionTimer covers the replacement path: a
// browser reattaches to a suspended session while the agent is still offline.
// Reattachment must cancel the retention timer, otherwise it later deletes the
// live session and closes the fresh browser connection.
func TestTerminalReattachSurvivesRetentionTimer(t *testing.T) {
	const retention = time.Second
	terminalSessionRetentionNanos.Store(int64(retention))
	t.Cleanup(func() { terminalSessionRetentionNanos.Store(0) })

	clientUUID, token := createTerminalTestClient(t)
	session := createTerminalTestSession(t)
	server := newTerminalTestServer(t)
	browser, agent, id := setupTerminal(t, server, clientUUID, token, sessionHeaders(session))

	writeMarker(t, browser, "BEFORE-SUSPEND")
	expectAgentMarker(t, agent, "BEFORE-SUSPEND")

	// Abrupt browser disconnect: the session is retained for reattachment.
	_ = browser.Close()
	waitForTerminalSuspended(t, id)

	// Only the browser comes back; the agent is still offline, so nothing else
	// would cancel the timer armed by the suspension.
	replacement, ok := reattachBrowser(t, server, clientUUID, id, sessionHeaders(session))
	if !ok {
		t.Fatal("valid session could not reattach")
	}

	// Cross the retention deadline.
	time.Sleep(2 * retention)

	TerminalSessionsMutex.Lock()
	current, exists := TerminalSessions[id]
	reattached := exists && current != nil && current.Browser != nil
	TerminalSessionsMutex.Unlock()
	if !reattached {
		t.Fatal("retention timer removed the session after its browser reattached")
	}

	// The reattached browser must still be usable once the agent connects.
	newAgent, ok := dialAgent(t, server, token, id)
	if !ok {
		t.Fatal("agent could not attach to the reattached session")
	}
	writeMarker(t, replacement, "AFTER-RETENTION")
	expectAgentMarker(t, newAgent, "AFTER-RETENTION")
}

// waitForAgentClosed waits until the test-side agent connection is closed by
// the server, which means a replacement was installed.
func waitForAgentClosed(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				t.Fatal("old agent connection stayed open after replacement")
			}
			return
		}
	}
}

// expectNoMoreAgentData ensures no duplicate frame arrives after the expected
// marker: a short read deadline expiring is the success case.
func expectNoMoreAgentData(t *testing.T, conn *websocket.Conn, within time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(within))
	if _, data, err := conn.ReadMessage(); err == nil {
		t.Fatalf("agent received an unexpected extra frame %q", data)
	}
}

// TestTerminalAgentReplacementKeepsFirstInput covers the reported reconnect
// bug: the browser stays connected while the agent terminal connection is
// replaced. The first input after the handoff must reach the new agent exactly
// once instead of being consumed by the old forwarding path.
func TestTerminalAgentReplacementKeepsFirstInput(t *testing.T) {
	clientUUID, token := createTerminalTestClient(t)
	session := createTerminalTestSession(t)
	server := newTerminalTestServer(t)
	browser, firstAgent, id := setupTerminal(t, server, clientUUID, token, sessionHeaders(session))

	writeMarker(t, browser, "BEFORE")
	expectAgentMarker(t, firstAgent, "BEFORE")

	// Replace the agent twice while the browser never reconnects.
	secondAgent, ok := dialAgent(t, server, token, id)
	if !ok {
		t.Fatal("second agent could not attach")
	}
	waitForAgentClosed(t, firstAgent)

	thirdAgent, ok := dialAgent(t, server, token, id)
	if !ok {
		t.Fatal("third agent could not attach")
	}
	waitForAgentClosed(t, secondAgent)

	// The very first frame sent after the handoff must reach the current agent.
	writeMarker(t, browser, "FIRST-AFTER-HANDOFF")
	expectAgentMarker(t, thirdAgent, "FIRST-AFTER-HANDOFF")
	expectNoMoreAgentData(t, thirdAgent, 200*time.Millisecond)
}

// TestTerminalRevocationNotBlockedByAgentWrite reproduces the revocation bug:
// the agent stops reading, the server's write blocks, and the credential is
// revoked. The browser must close promptly, the session must not be
// reattachable, and the forwarding goroutines must exit.
func TestTerminalRevocationNotBlockedByAgentWrite(t *testing.T) {
	clientUUID, token := createTerminalTestClient(t)
	session := createTerminalTestSession(t)
	server := newTerminalTestServer(t)
	browser, agent, id := setupTerminal(t, server, clientUUID, token, sessionHeaders(session))

	writeMarker(t, browser, "WARMUP")
	expectAgentMarker(t, agent, "WARMUP")

	userUUID, err := accounts.GetSession(session)
	if err != nil {
		t.Fatalf("resolve session owner: %v", err)
	}

	TerminalSessionsMutex.Lock()
	sessionState := TerminalSessions[id]
	var done chan struct{}
	if sessionState != nil {
		done = sessionState.forwardDone
	}
	TerminalSessionsMutex.Unlock()
	if done == nil {
		t.Fatal("forwarding round was not running")
	}

	// The agent client never reads; keep pushing input until the server's
	// browser->agent write blocks on the full socket buffers.
	payload := bytes.Repeat([]byte("x"), 1<<20)
	go func() {
		for i := 0; i < 32; i++ {
			if err := browser.WriteMessage(websocket.BinaryMessage, payload); err != nil {
				return
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)

	if err := accounts.DeleteSession(session); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	// The browser must be closed without waiting for the agent to accept a
	// close notification (the notification write is stuck behind the blocked
	// data write).
	expectBrowserClosed(t, browser)

	// The session is invalidated permanently: even a fresh, valid credential
	// from the same user cannot reattach to the old request id.
	freshSession, err := accounts.CreateSession(userUUID, 3600, "terminal-test", "127.0.0.1", "password")
	if err != nil {
		t.Fatalf("create fresh session: %v", err)
	}
	t.Cleanup(func() { _ = accounts.DeleteSession(freshSession) })
	if _, ok := reattachBrowser(t, server, clientUUID, id, sessionHeaders(freshSession)); ok {
		t.Fatal("revoked terminal session allowed reattachment")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forwarding goroutines did not exit after revocation")
	}

	// The agent may still read the buffered close notification; the connection
	// must be closed once that frame has been drained.
	deadline := time.Now().Add(3 * time.Second)
	for {
		_ = agent.SetReadDeadline(deadline)
		if _, _, err := agent.ReadMessage(); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				t.Fatal("agent connection was not closed after revocation")
			}
			break
		}
	}
}
