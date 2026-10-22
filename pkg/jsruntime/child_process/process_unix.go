//go:build !windows

package child_process

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// configureChildProcess starts the command in its own process group so the
// whole tree can be terminated together.
func configureChildProcess(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killChildProcess terminates the process group. A plain Process.Kill only
// reaps the direct child and leaves grandchildren (for example the background
// process of `sh -c '... &'`) holding stdout/stderr open.
func killChildProcess(process *os.Process) error {
	if process == nil {
		return nil
	}
	if err := syscall.Kill(-process.Pid, syscall.SIGKILL); err == nil || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return process.Kill()
}
