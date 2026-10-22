package jsruntime

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func helperEnvWithMarker(mode, marker string) map[string]string {
	environment := childHelperEnvironment(mode)
	if marker != "" {
		environment[childHelperMarkerEnvironment] = marker
	}
	return environment
}

// TestExecFileSyncMaxBufferTerminatesChild guards the reproduced bug where a
// child kept running after stdout exceeded maxBuffer and wrote a marker file
// ~300 ms later.
func TestExecFileSyncMaxBufferTerminatesChild(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker.txt")
	jsRuntime, err := New(`
		function verify(command, environment) {
			let code = "";
			try {
				require("child_process").execFileSync(
					command,
					["-test.run=^TestNodeChildProcessHelper$"],
					{ env: environment, maxBuffer: 64 }
				);
			} catch (error) {
				code = String(error.code);
			}
			return code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER";
		}
	`, Options{NodeJS: true, AllowExec: true, BaseDir: t.TempDir(), Console: io.Discard, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer jsRuntime.Close()

	if err := jsRuntime.Call("verify", os.Args[0], helperEnvWithMarker("output-marker", marker)); err != nil {
		t.Fatalf("maxBuffer overflow was not reported: %v", err)
	}

	// The helper writes the marker 300 ms after overflowing stdout. Wait past
	// that window; the file must not exist because the process was terminated.
	time.Sleep(700 * time.Millisecond)
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("child process survived maxBuffer overflow and wrote its marker")
	}
}

// TestRuntimeCloseTerminatesTimedOutSyncChild guards the reproduced 757 ms
// Close delay: a synchronous child was not registered with the runtime, so
// Close waited for the process to finish on its own.
func TestRuntimeCloseTerminatesTimedOutSyncChild(t *testing.T) {
	jsRuntime, err := New(`
		function run(command, environment) {
			require("child_process").execFileSync(
				command,
				["-test.run=^TestNodeChildProcessHelper$"],
				{ env: environment }
			);
			return true;
		}
	`, Options{NodeJS: true, AllowExec: true, BaseDir: t.TempDir(), Console: io.Discard, Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	if err := jsRuntime.Call("run", os.Args[0], childHelperEnvironment("sleep")); err == nil {
		t.Fatal("expected the call to time out")
	}

	closeStarted := time.Now()
	jsRuntime.Close()
	if elapsed := time.Since(closeStarted); elapsed > time.Second {
		t.Fatalf("Runtime.Close blocked for %s after a timed-out synchronous child", elapsed)
	}
}

// TestSpawnExitPrecedesCloseWhenBackgroundHoldsPipes covers the reported
// boundary: the direct child exits immediately while a background grandchild
// keeps stdout/stderr open, so exit must not wait for close.
func TestSpawnExitPrecedesCloseWhenBackgroundHoldsPipes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires /bin/sh")
	}
	var output syncBuffer
	jsRuntime, err := New(`
		function verify() {
			return new Promise((resolve) => {
				const child = require("child_process").spawn("/bin/sh", ["-c", "(sleep 0.8) & exit 0"]);
				const started = Date.now();
				let exitAt = -1;
				let closeAt = -1;
				let exitCount = 0;
				let closeCount = 0;
				child.on("exit", () => { exitAt = Date.now() - started; exitCount += 1; });
				child.on("close", () => {
					closeAt = Date.now() - started;
					closeCount += 1;
					console.log("exitAt=" + exitAt + " closeAt=" + closeAt + " exitCount=" + exitCount + " closeCount=" + closeCount);
					resolve(exitCount === 1 && closeCount === 1 && exitAt >= 0 && exitAt < 400 && closeAt > 600 && exitAt < closeAt);
				});
			});
		}
	`, Options{NodeJS: true, AllowExec: true, BaseDir: t.TempDir(), Console: &output, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer jsRuntime.Close()

	if err := jsRuntime.Call("verify"); err != nil {
		t.Fatalf("exit/close ordering failed: %v (console: %s)", err, output.String())
	}
}

// TestSpawnLargeOutputAndExitOrdering checks that close still fires after all
// output, with the correct exit code and a single exit/close pair.
func TestSpawnLargeOutputAndExitOrdering(t *testing.T) {
	jsRuntime, err := New(`
		function verify(command, environment) {
			return new Promise((resolve) => {
				const child = require("child_process").spawn(
					command,
					["-test.run=^TestNodeChildProcessHelper$"],
					{ env: environment }
				);
				let size = 0;
				const order = [];
				child.stdout.on("data", (chunk) => { size += chunk.length; });
				child.on("exit", (code) => { order.push("exit:" + code); });
				child.on("close", (code) => {
					order.push("close:" + code);
					resolve(order.join(",") === "exit:0,close:0" && size === 262144);
				});
			});
		}
	`, Options{NodeJS: true, AllowExec: true, BaseDir: t.TempDir(), Console: io.Discard, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer jsRuntime.Close()

	if err := jsRuntime.Call("verify", os.Args[0], childHelperEnvironment("output-large")); err != nil {
		t.Fatalf("large output or event ordering failed: %v", err)
	}
}

// TestSpawnNonZeroExitOrdering keeps exit codes and event ordering intact for
// failing commands.
func TestSpawnNonZeroExitOrdering(t *testing.T) {
	jsRuntime, err := New(`
		function verify(command, environment) {
			return new Promise((resolve) => {
				const child = require("child_process").spawn(
					command,
					["-test.run=^TestNodeChildProcessHelper$"],
					{ env: environment }
				);
				const order = [];
				child.on("exit", (code) => { order.push("exit:" + code); });
				child.on("close", (code) => {
					order.push("close:" + code);
					resolve(order.join(",") === "exit:7,close:7");
				});
			});
		}
	`, Options{NodeJS: true, AllowExec: true, BaseDir: t.TempDir(), Console: io.Discard, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer jsRuntime.Close()

	if err := jsRuntime.Call("verify", os.Args[0], childHelperEnvironment("exit")); err != nil {
		t.Fatalf("non-zero exit ordering failed: %v", err)
	}
}

// TestRuntimeCloseTerminatesSpawnedChild checks the shutdown path for async
// spawn: Close must kill the child instead of waiting for it.
func TestRuntimeCloseTerminatesSpawnedChild(t *testing.T) {
	jsRuntime, err := New(`
		function start(command, environment) {
			const child = require("child_process").spawn(
				command,
				["-test.run=^TestNodeChildProcessHelper$"],
				{ env: environment }
			);
			child.on("error", () => {});
			return true;
		}
	`, Options{NodeJS: true, AllowExec: true, BaseDir: t.TempDir(), Console: io.Discard, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}

	if err := jsRuntime.Call("start", os.Args[0], childHelperEnvironment("sleep")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	closeStarted := time.Now()
	jsRuntime.Close()
	if elapsed := time.Since(closeStarted); elapsed > time.Second {
		t.Fatalf("Runtime.Close blocked for %s with a spawned child", elapsed)
	}
}
