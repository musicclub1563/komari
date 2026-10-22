package jsruntime

import (
	"bytes"
	"strings"
	"sync"
	"time"
)

// syncBuffer is a bytes.Buffer that is safe to write from the JS event loop
// while the test goroutine reads it. Tests that inspect console output must use
// it (and waitFor) instead of a bare bytes.Buffer plus time.Sleep, which is a
// data race under -race and flaky in general.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFor polls until the buffered output contains substr or timeout elapses.
// It returns true as soon as the expected output appears, so it does not slow
// down passing tests the way a fixed sleep does.
func (b *syncBuffer) waitFor(substr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if strings.Contains(b.String(), substr) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}
