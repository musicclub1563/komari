package terminal

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/web/connection"
)

// errTerminalCredentialRevoked 表示建立终端时使用的凭据已被删除、过期或轮换。
var errTerminalCredentialRevoked = errors.New("terminal credential revoked")

// errForwardSuperseded 表示本轮转发已不再持有当前浏览器连接（被替换或挂起）。
// 它只用于让本轮 goroutine 退出，清理时不得触碰新的会话连接。
var errForwardSuperseded = errors.New("terminal forwarding superseded")

const (
	// terminalAgentCloseWriteWait 限制给 agent 发送关闭通知的单次写操作。
	terminalAgentCloseWriteWait = time.Second
	// terminalAgentCloseNotifyWait 限制撤权路径等待关闭通知的总时长。超时后
	// 直接关闭 agent 连接，绝不阻塞浏览器断开。
	terminalAgentCloseNotifyWait = time.Second
)

// ForwardTerminal 是保持向后兼容的入口；转发生命周期由 done 管理。
func ForwardTerminal(id string, browser, agent *connection.SafeConn) {
	generation := uint64(0)
	TerminalSessionsMutex.Lock()
	if session := TerminalSessions[id]; session != nil {
		generation = session.generation
	}
	TerminalSessionsMutex.Unlock()
	done := make(chan struct{})
	go forwardTerminal(id, browser, agent, generation, done)
}

// forwardTerminal runs one forwarding round. A round is tied to a browser
// connection (generation); replacing the agent does NOT restart the round:
// both pumps resolve the session's current agent before every transfer, so a
// replaced agent is picked up without a handoff window that could swallow the
// browser's next input.
func forwardTerminal(id string, browser, agent *connection.SafeConn, generation uint64, done chan struct{}) {
	defer close(done)
	defer clearForwarding(id, generation, done)
	if browser == nil {
		return
	}

	TerminalSessionsMutex.Lock()
	session := TerminalSessions[id]
	requesterIp, userUUID := "", ""
	var credential *terminalCredential
	valid := session != nil && session.Browser == browser && session.generation == generation
	if valid {
		requesterIp, userUUID = session.RequesterIp, session.UserUUID
		credential = session.Credential
	}
	TerminalSessionsMutex.Unlock()
	if !valid || requesterIp == "" {
		return
	}
	if credential == nil {
		// 无法追溯授权来源的会话不允许转发（例如升级前建立的会话）。
		suspendSession(id, browser, agent)
		return
	}

	auditlog.Log(requesterIp, userUUID, "established, terminal id:"+id, "terminal")
	establishedTime := time.Now()
	errChan := make(chan error, 1)
	// stop 通知所有转发 goroutine 退出；done 在它们全部退出后才关闭。
	stop := make(chan struct{})
	var wg sync.WaitGroup
	reportErr := func(err error) {
		select {
		case errChan <- err:
		default:
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		browserPump(id, browser, generation, credential, stop, reportErr)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		agentPump(id, browser, generation, stop, reportErr)
	}()

	// 空闲连接也需要撤销：用户不再输入时，输出方向仍可能持续泄露，
	// 因此周期复核凭据并在失效后主动关闭两端。
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(terminalCredentialRecheckInterval())
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if !credential.valid() {
					reportErr(errTerminalCredentialRevoked)
					return
				}
			}
		}
	}()

	fatalErr := <-errChan
	close(stop)

	if errors.Is(fatalErr, errTerminalCredentialRevoked) {
		// 撤权：先删除会话并关闭浏览器（不依赖 agent 收到通知），再给 agent
		// 一次有界的关闭通知，最后关闭 agent 连接。
		revokedAgent := revokeRound(id, browser, generation)
		if revokedAgent != nil {
			notifyAgentClose(revokedAgent, terminalAgentCloseNotifyWait)
			_ = revokedAgent.Close()
		}
	} else if !errors.Is(fatalErr, errForwardSuperseded) {
		suspendRound(id, browser, generation)
	}

	wg.Wait()
	disconnectTime := time.Now()
	auditlog.Log(requesterIp, userUUID, "disconnected, terminal id:"+id+", duration:"+disconnectTime.Sub(establishedTime).String(), "terminal")
}

// browserPump reads browser input and writes it to the session's current
// agent. Only one pump exists per browser connection, so an agent replacement
// never creates a second reader that could consume (and lose) the next frame.
func browserPump(
	id string,
	browser *connection.SafeConn,
	generation uint64,
	credential *terminalCredential,
	stop <-chan struct{},
	reportErr func(error),
) {
	for {
		select {
		case <-stop:
			return
		default:
		}

		messageType, data, err := browser.ReadMessage()
		if err != nil {
			reportErr(err)
			return
		}

		// 取当前 agent：交接期间可能已经被替换。
		TerminalSessionsMutex.Lock()
		session, ok := TerminalSessions[id]
		if !ok || session == nil || session.Browser != browser || session.generation != generation {
			TerminalSessionsMutex.Unlock()
			reportErr(errForwardSuperseded)
			return
		}
		agent := session.Agent
		TerminalSessionsMutex.Unlock()
		if agent == nil {
			reportErr(errForwardSuperseded)
			return
		}

		// 输入转发前重新校验建立终端时使用的凭据：Session 删除/过期、
		// API Key 轮换后立即停止，不能只依赖握手时的身份。
		if !credential.valid() {
			reportErr(errTerminalCredentialRevoked)
			return
		}

		if messageType == websocket.TextMessage {
			var control struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(data, &control) == nil {
				if control.Type == "heartbeat" {
					continue
				}
				if control.Type == "close" {
					// 通知 agent 终止远端 PTY；有界等待，失败也继续本地清理。
					notifyAgentClose(agent, terminalAgentCloseNotifyWait)
					closeSession(id)
					reportErr(nil)
					return
				}
			}
			if len(data) > 0 && data[0] == '{' {
				err = agent.WriteMessage(websocket.TextMessage, data)
			} else {
				err = agent.WriteMessage(websocket.BinaryMessage, data)
			}
		} else {
			err = agent.WriteMessage(websocket.BinaryMessage, data)
		}

		if err != nil {
			reportErr(err)
			return
		}
	}
}

// agentPump reads the session's current agent and writes output to the browser.
// When the agent connection is replaced, the old read fails and this pump
// switches to the new connection instead of ending the round.
func agentPump(
	id string,
	browser *connection.SafeConn,
	generation uint64,
	stop <-chan struct{},
	reportErr func(error),
) {
	for {
		select {
		case <-stop:
			return
		default:
		}

		TerminalSessionsMutex.Lock()
		session, ok := TerminalSessions[id]
		if !ok || session == nil || session.Browser != browser || session.generation != generation {
			TerminalSessionsMutex.Unlock()
			reportErr(errForwardSuperseded)
			return
		}
		agent := session.Agent
		TerminalSessionsMutex.Unlock()
		if agent == nil {
			reportErr(errForwardSuperseded)
			return
		}

		_, data, err := agent.ReadMessage()
		if err != nil {
			// 判断出错的是否仍是当前 agent：被替换时继续读新连接，避免把
			// 交接误判成会话结束。
			TerminalSessionsMutex.Lock()
			session, ok = TerminalSessions[id]
			current := ok && session != nil && session.Browser == browser &&
				session.generation == generation && session.Agent != nil && session.Agent != agent
			TerminalSessionsMutex.Unlock()
			if current {
				continue
			}
			reportErr(err)
			return
		}
		if err := browser.WriteMessage(websocket.BinaryMessage, data); err != nil {
			reportErr(err)
			return
		}
	}
}

// suspendRound tears down the current connections of one browser generation.
// A stale round (browser replaced) must not close the new session's agent.
func suspendRound(id string, browser *connection.SafeConn, generation uint64) {
	TerminalSessionsMutex.Lock()
	session, ok := TerminalSessions[id]
	if !ok || session == nil || session.Browser != browser || session.generation != generation {
		TerminalSessionsMutex.Unlock()
		return
	}
	agent := session.Agent
	session.Browser = nil
	session.Agent = nil
	session.Forwarding = false
	scheduleCleanup(id, session)
	TerminalSessionsMutex.Unlock()

	_ = browser.Close()
	if agent != nil {
		_ = agent.Close()
	}
}

// revokeRound removes the session permanently (so it cannot be reattached) and
// closes the browser before returning the agent connection for a bounded close
// notification.
func revokeRound(id string, browser *connection.SafeConn, generation uint64) *connection.SafeConn {
	TerminalSessionsMutex.Lock()
	session, ok := TerminalSessions[id]
	if !ok || session == nil || session.Browser != browser || session.generation != generation {
		TerminalSessionsMutex.Unlock()
		return nil
	}
	agent := session.Agent
	stopCleanup(session)
	session.Revoked = true
	session.Browser = nil
	session.Agent = nil
	session.Forwarding = false
	delete(TerminalSessions, id)
	TerminalSessionsMutex.Unlock()

	// 浏览器必须立即断开，不能等待 agent 接收关闭通知。
	_ = browser.Close()
	return agent
}

// notifyAgentClose asks the agent to terminate the remote PTY. It is bounded:
// a stuck write (peer stopped reading) must not delay teardown. The caller
// closes the agent connection afterwards, which unblocks the write.
func notifyAgentClose(agent *connection.SafeConn, wait time.Duration) {
	if agent == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = agent.WriteJSONWithDeadline(gin.H{"type": "close"}, time.Now().Add(terminalAgentCloseWriteWait))
	}()
	select {
	case <-done:
	case <-time.After(wait):
	}
}

// clearForwarding releases the round-owned forwarding flag when this round is
// still the current one.
func clearForwarding(id string, generation uint64, done chan struct{}) {
	TerminalSessionsMutex.Lock()
	session, ok := TerminalSessions[id]
	if ok && session != nil && session.generation == generation && session.forwardDone == done {
		session.Forwarding = false
	}
	TerminalSessionsMutex.Unlock()
}
