package child_process

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/Calcium-Ion/moejs"
	"github.com/Calcium-Ion/moejs/engine"
	"github.com/komari-monitor/komari/pkg/jsruntime/buffer"
	"github.com/komari-monitor/komari/pkg/jsruntime/events"
	"github.com/komari-monitor/komari/pkg/jsruntime/fs"
	"github.com/komari-monitor/komari/pkg/jsruntime/internal/bridge"
	"github.com/komari-monitor/komari/pkg/jsruntime/internal/writequeue"
	"github.com/komari-monitor/komari/pkg/jsruntime/native"
	"github.com/komari-monitor/komari/pkg/jsruntime/require"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// childProcessWaitDelay bounds how long Wait keeps waiting for stdout/stderr
// I/O after the process has been signalled. A grandchild that inherited the
// pipes must not be able to block cancellation or runtime shutdown forever.
const childProcessWaitDelay = 200 * time.Millisecond

type childCommandOptions struct {
	cwd       string
	env       []string
	shell     bool
	timeout   time.Duration
	encoding  string
	maxBuffer int
}
type childOutputLimitError struct {
	stream string
}

func (e *childOutputLimitError) Error() string {
	return fmt.Sprintf("%s maxBuffer length exceeded", e.stream)
}

type childOutputBuffer struct {
	buffer bytes.Buffer
	limit  int
	stream string
	cancel context.CancelFunc
	err    error
	once   sync.Once
}

func (b *childOutputBuffer) Write(data []byte) (int, error) {
	if b.err != nil {
		return len(data), nil
	}
	remaining := b.limit - b.Len()
	if remaining >= len(data) {
		_, _ = b.buffer.Write(data)
		return len(data), nil
	}
	if remaining > 0 {
		_, _ = b.buffer.Write(data[:remaining])
	}
	b.err = &childOutputLimitError{stream: b.stream}
	b.once.Do(b.cancel)
	return len(data), nil
}
func (b *childOutputBuffer) Len() int {
	return b.buffer.Len()
}
func (b *childOutputBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}

type Module struct {
	runtime    *bridge.Runtime
	filesystem *fs.Module
	allowExec  bool
	maxOutput  int
}

func New(runtime *bridge.Runtime, filesystem *fs.Module, allowExec bool, maxOutput int) *Module {
	return &Module{runtime: runtime, filesystem: filesystem, allowExec: allowExec, maxOutput: maxOutput}
}
func (m *Module) Load(vm *moejs.Runtime, module *engine.Object) {
	if !m.allowExec {
		panic(native.GoError(vm, fmt.Errorf("child_process requires AllowExec")))
	}
	exports := vm.Realm().NewObject()
	_ = native.Set(vm, exports, "spawn", native.Bind(vm, "", 0, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		command, arguments, options := m.childCommandArguments(vm, args, false)
		return native.From(vm, m.spawnChild(vm, command, arguments, options)), nil
	}))
	_ = native.Set(vm, exports, "exec", native.Bind(vm, "", 0, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		command := native.String(vm, moejs.Arg(args, 0))
		optionsValue, callbackValue := moejs.Arg(args, 1), moejs.Arg(args, 2)
		if _, ok := checkedFunction(optionsValue); ok {
			callbackValue, optionsValue = optionsValue, moejs.Undefined()
		}
		callback, ok := checkedFunction(callbackValue)
		if !ok {
			panic(native.TypeError(vm, "callback must be a function"))
		}
		options := m.childOptions(vm, optionsValue)
		options.shell = true
		return native.From(vm, m.execChild(vm, command, nil, options, callback)), nil
	}))
	_ = native.Set(vm, exports, "execFile", native.Bind(vm, "", 0, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		command, arguments, options := m.childCommandArguments(vm, args, true)
		callbackIndex := 1
		if _, ok := native.Export(vm, moejs.Arg(args, 1)).([]any); ok {
			callbackIndex = 2
		}
		callbackValue := moejs.Arg(args, callbackIndex)
		if _, ok := checkedFunction(callbackValue); !ok {
			callbackValue = moejs.Arg(args, callbackIndex+1)
		}
		callback, ok := checkedFunction(callbackValue)
		if !ok {
			panic(native.TypeError(vm, "callback must be a function"))
		}
		return native.From(vm, m.execChild(vm, command, arguments, options, callback)), nil
	}))
	_ = native.Set(vm, exports, "spawnSync", native.Bind(vm, "", 0, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		command, arguments, options := m.childCommandArguments(vm, args, false)
		return native.From(vm, m.spawnChildSync(vm, command, arguments, options)), nil
	}))
	_ = native.Set(vm, exports, "execFileSync", native.Bind(vm, "", 0, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		command, arguments, options := m.childCommandArguments(vm, args, false)
		result := m.runChildSync(command, arguments, options)
		if result.err != nil {
			panic(engine.ObjectValue(childProcessError(vm, result.err, result.exitCode, result.stdout, result.stderr)))
		}
		return native.From(vm, encodeChildOutput(vm, result.stdout, options.encoding)), nil
	}))
	_ = native.Set(vm, exports, "execSync", native.Bind(vm, "", 0, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		options := m.childOptions(vm, moejs.Arg(args, 1))
		options.shell = true
		result := m.runChildSync(native.String(vm, moejs.Arg(args, 0)), nil, options)
		if result.err != nil {
			panic(engine.ObjectValue(childProcessError(vm, result.err, result.exitCode, result.stdout, result.stderr)))
		}
		return native.From(vm, encodeChildOutput(vm, result.stdout, options.encoding)), nil
	}))
	_ = native.Set(vm, exports, "fork", native.Bind(vm, "", 0, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		panic(native.GoError(vm, fmt.Errorf("child_process.fork is unavailable because this runtime is not a Node executable")))
	}))
	_ = native.Set(vm, module, "exports", exports)
}
func (m *Module) childCommandArguments(vm *moejs.Runtime, args []moejs.Value, callbackExpected bool) (string, []string, childCommandOptions) {
	command := native.String(vm, moejs.Arg(args, 0))
	arguments := []string{}
	optionsIndex := 1
	if value := moejs.Arg(args, 1); !value.IsUndefined() && !value.IsNull() {
		var exported []string
		if err := native.ExportTo(vm, value, &exported); err == nil {
			arguments = exported
			optionsIndex = 2
		}
	}
	options := m.childOptions(vm, moejs.Arg(args, optionsIndex))
	_ = callbackExpected
	return command, arguments, options
}
func (m *Module) childOptions(vm *moejs.Runtime, value moejs.Value) childCommandOptions {
	options := childCommandOptions{cwd: m.filesystem.Cwd(), env: os.Environ(), maxBuffer: m.maxOutput}
	if native.IsNil(value) || value.IsUndefined() || value.IsNull() {
		return options
	}
	object := native.Object(vm, value)
	if cwd := native.Get(vm, object, "cwd"); !native.IsNil(cwd) && !cwd.IsUndefined() && !cwd.IsNull() {
		resolved, err := m.filesystem.Resolve(native.String(vm, cwd), false)
		if err != nil {
			panic(native.GoError(vm, err))
		}
		options.cwd = resolved
	}
	if environment := native.Get(vm, object, "env"); !native.IsNil(environment) && !environment.IsUndefined() && !environment.IsNull() {
		var values map[string]string
		if err := native.ExportTo(vm, environment, &values); err != nil {
			panic(native.TypeError(vm, "env must be an object"))
		}
		options.env = make([]string, 0, len(values))
		for name, value := range values {
			options.env = append(options.env, name+"="+value)
		}
	}
	if shell := native.Get(vm, object, "shell"); !native.IsNil(shell) {
		options.shell = native.Bool(shell)
	}
	if timeoutValue := native.Get(vm, object, "timeout"); !native.IsNil(timeoutValue) && native.Int(vm, timeoutValue) > 0 {
		timeout := native.Int(vm, timeoutValue)
		options.timeout = time.Duration(timeout) * time.Millisecond
	}
	if encoding := native.Get(vm, object, "encoding"); !native.IsNil(encoding) && !encoding.IsUndefined() && !encoding.IsNull() {
		options.encoding = native.String(vm, encoding)
	}
	if maxBuffer := native.Get(vm, object, "maxBuffer"); !native.IsNil(maxBuffer) {
		requested := native.Int(vm, maxBuffer)
		if requested > 0 && requested < int64(options.maxBuffer) {
			options.maxBuffer = int(requested)
		}
	}
	return options
}
// childCommandDeadline combines an explicit command timeout with the deadline
// inherited from the running JavaScript call, keeping whichever comes first.
// Both inputs are absolute points in time: recomputing a full duration here
// would restart the budget and let a command outlive the call that started it.
func childCommandDeadline(options childCommandOptions, inherited time.Time) time.Time {
	deadline := inherited
	if options.timeout > 0 {
		explicit := time.Now().Add(options.timeout)
		if deadline.IsZero() || explicit.Before(deadline) {
			deadline = explicit
		}
	}
	return deadline
}

func childExecCommand(command string, arguments []string, options childCommandOptions, deadline time.Time) (*exec.Cmd, context.CancelFunc) {
	// Always create a cancellable context. Previously a command without an
	// explicit timeout got a no-op cancel func, so maxBuffer overruns and
	// runtime shutdown could not terminate it. A deadline inherited from the
	// JavaScript call additionally cancels the command when Runtime.Call times
	// out, even if the script never calls Runtime.Close.
	var ctx context.Context
	var cancel context.CancelFunc
	if deadline.IsZero() {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
	}

	var cmd *exec.Cmd
	if options.shell {
		line := command
		if len(arguments) > 0 {
			line += " " + strings.Join(arguments, " ")
		}
		if runtime.GOOS == "windows" {
			cmd = exec.CommandContext(ctx, "cmd.exe", "/d", "/s", "/c", line)
		} else {
			cmd = exec.CommandContext(ctx, "/bin/sh", "-c", line)
		}
	} else {
		cmd = exec.CommandContext(ctx, command, arguments...)
	}

	configureChildProcess(cmd)
	cmd.WaitDelay = childProcessWaitDelay
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return killChildProcess(cmd.Process)
	}
	return cmd, cancel
}
func (m *Module) childOutputLimit(options childCommandOptions) int {
	if options.maxBuffer > 0 && options.maxBuffer < m.maxOutput {
		return options.maxBuffer
	}
	return m.maxOutput
}
func (m *Module) spawnChild(vm *moejs.Runtime, command string, arguments []string, options childCommandOptions) *engine.Object {
	child := events.NewEmitter(vm)
	cmd, cancel := childExecCommand(command, arguments, options, childCommandDeadline(options, time.Time{}))
	cmd.Dir = options.cwd
	cmd.Env = options.env
	stdin, stdinErr := cmd.StdinPipe()
	// Use explicit pipes instead of StdoutPipe/StderrPipe: those are closed by
	// cmd.Wait, which would force us to finish reading before knowing the exit
	// status. Owning the fds lets exit and close be reported independently.
	stdoutReader, stdoutWriter, stdoutErr := os.Pipe()
	stderrReader, stderrWriter, stderrErr := os.Pipe()
	if err := errors.Join(stdinErr, stdoutErr, stderrErr); err != nil {
		panic(native.GoError(vm, err))
	}
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter
	stdinStream, stdout, stderr := m.childStreams(vm, stdin)
	_ = native.Set(vm, child, "stdout", stdout)
	_ = native.Set(vm, child, "stderr", stderr)
	_ = native.Set(vm, child, "stdin", stdinStream)
	_ = native.Set(vm, child, "stdio", []any{stdinStream, stdout, stderr})
	_ = native.Set(vm, child, "pid", moejs.Undefined())
	_ = native.Set(vm, child, "exitCode", moejs.Null())
	_ = native.Set(vm, child, "signalCode", moejs.Null())
	_ = native.Set(vm, child, "killed", false)
	_ = native.Set(vm, child, "connected", false)
	if err := cmd.Start(); err != nil {
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
		cancel()
		m.runtime.Loop().SetTimeout(func(vm *moejs.Runtime) {
			_ = m.runtime.RunJob(vm, "child_process.spawn", func() error {
				return events.Emit(vm, child, "error", native.GoError(vm, err))
			})
		}, 0)
		return child
	}
	// The parent must not keep the write ends open, otherwise the readers never
	// see EOF after the command tree exits.
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	_ = native.Set(vm, child, "pid", cmd.Process.Pid)
	resourceID := m.runtime.AddResource(func() {
		cancel()
		_ = killChildProcess(cmd.Process)
		// Closing the read ends unblocks the output pumps so close can still be
		// reported when a surviving grandchild holds the pipes.
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
	})
	if resourceID == 0 {
		_ = stdin.Close()
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
		go func() {
			_ = cmd.Wait()
		}()
		return child
	}
	_ = native.Set(vm, child, "kill", native.Bind(vm, "", 1, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		signal := native.String(vm, moejs.Arg(args, 0))
		if cmd.Process == nil {
			return native.From(vm, false), nil
		}
		var err error
		if signal == "SIGKILL" {
			err = cmd.Process.Kill()
		} else {
			err = cmd.Process.Signal(os.Interrupt)
		}
		if err == nil {
			_ = native.Set(vm, child, "killed", true)
		}
		return native.From(vm, err == nil), nil
	}))
	_ = native.Set(vm, child, "ref", native.Bind(vm, "", 0, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		panic(native.GoError(vm, fmt.Errorf("child_process.ChildProcess.ref is not supported by jsruntime; the event loop is host-driven")))
	}))
	_ = native.Set(vm, child, "unref", native.Bind(vm, "", 0, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		panic(native.GoError(vm, fmt.Errorf("child_process.ChildProcess.unref is not supported by jsruntime; the event loop is host-driven")))
	}))
	_ = native.Set(vm, child, "disconnect", native.Bind(vm, "", 0, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		_ = events.Emit(vm, child, "disconnect")
		return moejs.Undefined(), nil
	}))
	_ = native.Set(vm, child, "send", native.Bind(vm, "", 0, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		if callback, ok := checkedFunction(moejs.Arg(args, len(args)-1)); ok {
			_, _ = native.Call(vm, callback, moejs.Undefined(), native.GoError(vm, fmt.Errorf("IPC is not enabled")))
		}
		return native.From(vm, false), nil
	}))
	var output sync.WaitGroup
	output.Add(2)
	m.pipeChildOutput(vm, stdoutReader, stdout, options.encoding, &output)
	m.pipeChildOutput(vm, stderrReader, stderr, options.encoding, &output)
	go func() {
		// Wait returns when the direct child exits: stdout/stderr are files we
		// own, so exec does not copy them and does not wait for the pipes to
		// drain. That keeps "exit" tied to the direct child.
		waitErr := cmd.Wait()
		cancel()

		exitCode := 0
		if waitErr != nil {
			var exitError *exec.ExitError
			if errors.As(waitErr, &exitError) {
				exitCode = exitError.ExitCode()
			} else {
				exitCode = -1
			}
		}

		m.runtime.RunOnLoop(func(vm *moejs.Runtime) {
			_ = m.runtime.RunJob(vm, "child_process exit", func() error {
				_ = native.Set(vm, child, "exitCode", exitCode)
				return events.Emit(vm, child, "exit", exitCode, moejs.Null())
			})
		})

		// "close" waits for stdout/stderr EOF, so it fires after all data and
		// end events, even when a surviving grandchild keeps the pipes open.
		output.Wait()
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
		m.runtime.RemoveResource(resourceID)

		m.runtime.RunOnLoop(func(vm *moejs.Runtime) {
			_ = m.runtime.RunJob(vm, "child_process close", func() error {
				return events.Emit(vm, child, "close", exitCode, moejs.Null())
			})
		})
	}()
	return child
}

//go:embed stdio.js
var childStdioSource string

func (m *Module) childStreams(vm *moejs.Runtime, stdin io.WriteCloser) (*engine.Object, *engine.Object, *engine.Object) {
	factoryValue, err := native.Run(vm, childStdioSource)
	if err != nil {
		panic(native.GoError(vm, fmt.Errorf("load child_process stdio: %w", err)))
	}
	factory, _ := checkedFunction(factoryValue)
	hooks := vm.Realm().NewObject()
	var writes writequeue.Queue
	_ = native.Set(vm, hooks, "stdinWrite", native.Bind(vm, "", 2, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		chunk := moejs.Arg(args, 0)
		callback := moejs.Arg(args, 1)
		data := append([]byte(nil), buffer.Bytes(vm, chunk)...)
		writes.Submit(func() {
			_, err := stdin.Write(data)
			if native.IsNil(callback) {
				return
			}
			m.runtime.RunOnLoop(func(vm *moejs.Runtime) {
				_ = m.runtime.RunJob(vm, "child_process.stdin.write", func() error {
					if err != nil {
						_, callbackErr := native.Call(vm, callback, moejs.Undefined(), native.GoError(vm, err))
						return callbackErr
					}
					_, callbackErr := native.Call(vm, callback, moejs.Undefined())
					return callbackErr
				})
			})
		})
		return moejs.Undefined(), nil
	}))
	_ = native.Set(vm, hooks, "stdinEnd", native.Bind(vm, "", 1, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		callback := moejs.Arg(args, 0)
		writes.Submit(func() {
			err := stdin.Close()
			m.runtime.RunOnLoop(func(vm *moejs.Runtime) {
				_ = m.runtime.RunJob(vm, "child_process.stdin.end", func() error {
					if !native.IsNil(callback) {
						if err != nil {
							_, callbackErr := native.Call(vm, callback, moejs.Undefined(), native.GoError(vm, err))
							return callbackErr
						}
						_, callbackErr := native.Call(vm, callback, moejs.Undefined())
						return callbackErr
					}
					return nil
				})
			})
		})
		return moejs.Undefined(), nil
	}))
	_ = native.Set(vm, hooks, "stdinDestroy", native.Bind(vm, "", 0, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		go func() {
			_ = stdin.Close()
		}()
		return moejs.Undefined(), nil
	}))
	streams, err := native.Call(vm, factory, moejs.Undefined(), require.Require(vm, "stream"), engine.ObjectValue(hooks))
	if err != nil {
		panic(err)
	}
	streamsObject := native.Object(vm, streams)
	createStdin, _ := checkedFunction(native.Get(vm, streamsObject, "createStdin"))
	createOutput, _ := checkedFunction(native.Get(vm, streamsObject, "createOutput"))
	if native.IsNil(createStdin) || native.IsNil(createOutput) {
		panic(native.GoError(vm, fmt.Errorf("child_process stdio factory is incomplete")))
	}
	stdinValue, err := native.Call(vm, createStdin, moejs.Undefined())
	if err != nil {
		panic(err)
	}
	stdoutValue, err := native.Call(vm, createOutput, moejs.Undefined())
	if err != nil {
		panic(err)
	}
	stderrValue, err := native.Call(vm, createOutput, moejs.Undefined())
	if err != nil {
		panic(err)
	}
	return native.Object(vm, stdinValue), native.Object(vm, stdoutValue), native.Object(vm, stderrValue)
}
func childCallback(args []moejs.Value) moejs.Value {
	for index := len(args) - 1; index >= 0; index-- {
		if callback, ok := checkedFunction(args[index]); ok {
			return callback
		}
	}
	return moejs.Undefined()
}
func (m *Module) pipeChildOutput(vm *moejs.Runtime, reader io.Reader, stream *engine.Object, encoding string, done *sync.WaitGroup) {
	push, _ := checkedFunction(native.Get(vm, stream, "push"))
	setEncoding, _ := checkedFunction(native.Get(vm, stream, "setEncoding"))
	if encoding != "" && !native.IsNil(setEncoding) {
		_, _ = native.Call(vm, setEncoding, engine.ObjectValue(stream), native.From(vm, encoding))
	}
	go func() {
		defer done.Done()
		data := make([]byte, 32*1024)
		for {
			count, err := reader.Read(data)
			if count > 0 {
				chunk := append([]byte(nil), data[:count]...)
				delivered := make(chan struct {
				})
				if !m.runtime.RunOnLoop(func(vm *moejs.Runtime) {
					defer close(delivered)
					_ = m.runtime.RunJob(vm, "child_process stream", func() error {
						_, pushErr := native.Call(vm, push, engine.ObjectValue(stream), engine.ObjectValue(buffer.WrapBytes(vm, chunk)))
						return pushErr
					})
				}) {
					return
				}
				<-delivered
			}
			if err != nil {
				m.runtime.RunOnLoop(func(vm *moejs.Runtime) {
					_ = m.runtime.RunJob(vm, "child_process stream close", func() error {
						_, pushErr := native.Call(vm, push, engine.ObjectValue(stream), moejs.Null())
						return pushErr
					})
				})
				return
			}
		}
	}()
}
func (m *Module) execChild(vm *moejs.Runtime, command string, arguments []string, options childCommandOptions, callback moejs.Value) *engine.Object {
	child := events.NewEmitter(vm)
	_ = native.Set(vm, child, "pid", moejs.Undefined())
	_ = native.Set(vm, child, "killed", false)
	cmd, cancel := childExecCommand(command, arguments, options, childCommandDeadline(options, time.Time{}))
	cmd.Dir, cmd.Env = options.cwd, options.env
	outputLimit := m.childOutputLimit(options)
	stdout := &childOutputBuffer{limit: outputLimit, stream: "stdout", cancel: cancel}
	stderr := &childOutputBuffer{limit: outputLimit, stream: "stderr", cancel: cancel}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		cancel()
		m.runtime.Loop().SetTimeout(func(vm *moejs.Runtime) {
			_ = m.runtime.RunJob(vm, "child_process.exec", func() error {
				if _, callbackErr := native.Call(vm, callback, moejs.Undefined(), engine.ObjectValue(childProcessError(vm, err, -1, nil, nil)), moejs.Undefined(), moejs.Undefined()); callbackErr != nil {
					return callbackErr
				}
				return events.Emit(vm, child, "error", native.GoError(vm, err))
			})
		}, 0)
		return child
	}
	_ = native.Set(vm, child, "pid", cmd.Process.Pid)
	resourceID := m.runtime.AddResource(func() {
		cancel()
		_ = killChildProcess(cmd.Process)
	})
	if resourceID == 0 {
		go func() {
			_ = cmd.Wait()
		}()
		return child
	}
	_ = native.Set(vm, child, "kill", native.Bind(vm, "", 0, func(_ *moejs.Realm, this moejs.Value, args []moejs.Value) (moejs.Value, error) {
		err := cmd.Process.Kill()
		if err == nil {
			_ = native.Set(vm, child, "killed", true)
		}
		return native.From(vm, err == nil), nil
	}))
	go func() {
		err := cmd.Wait()
		err = errors.Join(err, stdout.err, stderr.err)
		cancel()
		m.runtime.RemoveResource(resourceID)
		exitCode := 0
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		} else if err != nil {
			exitCode = -1
		}
		m.runtime.RunOnLoop(func(vm *moejs.Runtime) {
			_ = m.runtime.RunJob(vm, "child_process.exec", func() error {
				stdoutValue := encodeChildOutput(vm, stdout.Bytes(), options.encoding)
				stderrValue := encodeChildOutput(vm, stderr.Bytes(), options.encoding)
				var errorValue moejs.Value = moejs.Null()
				if err != nil {
					errorValue = engine.ObjectValue(childProcessError(vm, err, exitCode, stdout.Bytes(), stderr.Bytes()))
				}
				if _, callbackErr := native.Call(vm, callback, moejs.Undefined(), errorValue, stdoutValue, stderrValue); callbackErr != nil {
					return callbackErr
				}
				_ = native.Set(vm, child, "exitCode", exitCode)
				_ = events.Emit(vm, child, "exit", exitCode, moejs.Null())
				return events.Emit(vm, child, "close", exitCode, moejs.Null())
			})
		})
	}()
	return child
}

type childSyncResult struct {
	stdout   []byte
	stderr   []byte
	err      error
	exitCode int
	pid      int
}

func (m *Module) runChildSync(command string, arguments []string, options childCommandOptions) childSyncResult {
	// Synchronous commands block the JavaScript turn, so they must also honour
	// the deadline of that turn: a Runtime.Call timeout cancels the child even
	// when the script never closes the runtime.
	inherited, _ := m.runtime.Deadline()
	cmd, cancel := childExecCommand(command, arguments, options, childCommandDeadline(options, inherited))
	defer cancel()
	cmd.Dir, cmd.Env = options.cwd, options.env
	outputLimit := m.childOutputLimit(options)
	stdout := &childOutputBuffer{limit: outputLimit, stream: "stdout", cancel: cancel}
	stderr := &childOutputBuffer{limit: outputLimit, stream: "stderr", cancel: cancel}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		return childSyncResult{err: err, exitCode: -1}
	}
	// Register the process with the runtime so Runtime.Close (or a cancelled
	// call) terminates it instead of waiting for it to finish on its own.
	resourceID := m.runtime.AddResource(func() {
		cancel()
		_ = killChildProcess(cmd.Process)
	})
	if resourceID != 0 {
		defer m.runtime.RemoveResource(resourceID)
	}
	err := cmd.Wait()
	err = errors.Join(err, stdout.err, stderr.err)
	result := childSyncResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), err: err, exitCode: 0}
	if cmd.Process != nil {
		result.pid = cmd.Process.Pid
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.exitCode = exitError.ExitCode()
	} else if err != nil {
		result.exitCode = -1
	}
	return result
}
func (m *Module) spawnChildSync(vm *moejs.Runtime, command string, arguments []string, options childCommandOptions) *engine.Object {
	result := m.runChildSync(command, arguments, options)
	object := vm.Realm().NewObject()
	_ = native.Set(vm, object, "pid", result.pid)
	_ = native.Set(vm, object, "status", result.exitCode)
	_ = native.Set(vm, object, "signal", moejs.Null())
	_ = native.Set(vm, object, "stdout", encodeChildOutput(vm, result.stdout, options.encoding))
	_ = native.Set(vm, object, "stderr", encodeChildOutput(vm, result.stderr, options.encoding))
	_ = native.Set(vm, object, "output", []any{moejs.Null(), encodeChildOutput(vm, result.stdout, options.encoding), encodeChildOutput(vm, result.stderr, options.encoding)})
	if result.err != nil {
		_ = native.Set(vm, object, "error", childProcessError(vm, result.err, result.exitCode, result.stdout, result.stderr))
	}
	return object
}
func encodeChildOutput(vm *moejs.Runtime, data []byte, encoding string) moejs.Value {
	if encoding == "" || encoding == "buffer" {
		return engine.ObjectValue(buffer.WrapBytes(vm, append([]byte(nil), data...)))
	}
	return buffer.EncodeBytes(vm, data, native.From(vm, encoding))
}
func childProcessError(vm *moejs.Runtime, err error, exitCode int, stdout, stderr []byte) *engine.Object {
	object := native.Object(vm, native.GoError(vm, err))
	var limitError *childOutputLimitError
	if errors.As(err, &limitError) {
		_ = native.Set(vm, object, "code", "ERR_CHILD_PROCESS_STDIO_MAXBUFFER")
	} else {
		_ = native.Set(vm, object, "code", exitCode)
	}
	_ = native.Set(vm, object, "killed", false)
	_ = native.Set(vm, object, "signal", moejs.Null())
	_ = native.Set(vm, object, "stdout", encodeChildOutput(vm, stdout, ""))
	_ = native.Set(vm, object, "stderr", encodeChildOutput(vm, stderr, ""))
	return object
}
func checkedFunction(v moejs.Value) (moejs.Value, bool) { return v, engine.IsCallable(v) }
