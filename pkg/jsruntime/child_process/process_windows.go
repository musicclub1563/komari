//go:build windows

package child_process

import (
	"os"
	"os/exec"
)

// configureChildProcess is a no-op on Windows, where process groups are not
// used to terminate the tree. WaitDelay bounds any I/O wait after a kill.
func configureChildProcess(cmd *exec.Cmd) {}

// killChildProcess terminates the direct child process.
func killChildProcess(process *os.Process) error {
	if process == nil {
		return nil
	}
	return process.Kill()
}
