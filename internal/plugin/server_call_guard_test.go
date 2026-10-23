package plugin

import (
	"strings"
	"testing"

	"github.com/komari-monitor/komari/pkg/rpc"
)

// TestPluginCallGuardRejectsForbiddenAndSensitiveMethods checks the admission
// rule itself. The real methods (raw SQL, admin:exec) are marked by their
// registration packages; that marking is covered by the jsonrpc tests.
func TestPluginCallGuardRejectsForbiddenAndSensitiveMethods(t *testing.T) {
	rpc.MarkPluginForbidden("test:forbidden")
	rpc.MarkSensitive("test:sensitive")

	for _, method := range []string{"test:forbidden", "test:sensitive"} {
		if err := pluginCallGuard(method); err == nil {
			t.Fatalf("plugin was allowed to call %s", method)
		}
	}
	if err := pluginCallGuard("admin:getSettings"); err != nil {
		t.Fatalf("ordinary method was rejected: %v", err)
	}

	err := pluginCallGuard("test:forbidden")
	if err == nil || !strings.Contains(err.Error(), "cannot invoke") {
		t.Fatalf("unexpected error: %v", err)
	}
}
