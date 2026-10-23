package terminal

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/komari-monitor/komari/web/connection"
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

// TestForwardingRestartsAfterSlowPreviousRound covers the wait timeout in
// maybeStartForwarding. When the previous forwarding round outlives the wait,
// forwarding must be retried once that round exits: both sides are already
// attached, so no further attach event will arrive to restart it.
func TestForwardingRestartsAfterSlowPreviousRound(t *testing.T) {
	terminalForwardWaitNanos.Store(int64(20 * time.Millisecond))
	t.Cleanup(func() { terminalForwardWaitNanos.Store(0) })

	id := "slow-previous-" + uuid.NewString()
	previous := make(chan struct{})
	session := &TerminalSession{
		UUID:   uuid.NewString(),
		Browser: connection.NewSafeConn(nil),
		Agent:   connection.NewSafeConn(nil),
		// An empty requester makes forwardTerminal return right after its
		// session check, so this test exercises only the scheduling path and
		// never touches the placeholder connections.
		RequesterIp: "",
		forwardDone: previous,
	}
	TerminalSessionsMutex.Lock()
	TerminalSessions[id] = session
	TerminalSessionsMutex.Unlock()
	t.Cleanup(func() {
		TerminalSessionsMutex.Lock()
		delete(TerminalSessions, id)
		TerminalSessionsMutex.Unlock()
	})

	// The previous round misses the wait deadline.
	maybeStartForwarding(id)

	TerminalSessionsMutex.Lock()
	waiting := session.Forwarding == false && session.forwardDone == previous
	TerminalSessionsMutex.Unlock()
	if !waiting {
		t.Fatal("forwarding was not deferred while the previous round was running")
	}

	close(previous)

	deadline := time.Now().Add(2 * time.Second)
	for {
		TerminalSessionsMutex.Lock()
		restarted := session.forwardDone != previous
		TerminalSessionsMutex.Unlock()
		if restarted {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("forwarding was not restarted after the previous round exited")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
