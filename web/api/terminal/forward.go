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

// ForwardTerminal 是保持向后兼容的入口；转发生命周期由 done 管理。
func ForwardTerminal(id string, browser, agent *connection.SafeConn) {
	forwardTerminal(id, browser, agent, make(chan struct{}))
}

func forwardTerminal(id string, browser, agent *connection.SafeConn, done chan struct{}) {
	defer close(done)
	if browser == nil || agent == nil {
		return
	}
	TerminalSessionsMutex.Lock()
	session := TerminalSessions[id]
	requesterIp, userUUID := "", ""
	var credential *terminalCredential
	if session != nil && session.Browser == browser && session.Agent == agent {
		requesterIp, userUUID = session.RequesterIp, session.UserUUID
		credential = session.Credential
	}
	TerminalSessionsMutex.Unlock()
	if requesterIp == "" {
		return
	}
	if credential == nil {
		// 无法追溯授权来源的会话不允许转发（例如升级前建立的会话）。
		suspendSession(id, browser, agent)
		return
	}

	auditlog.Log(requesterIp, userUUID, "established, terminal id:"+id, "terminal")
	established_time := time.Now()
	errChan := make(chan error, 1)
	// stop 通知所有转发 goroutine 退出；done 在它们全部退出后才关闭，
	// 供连接替换路径等待，避免并发读同一个 agent 连接。
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 非阻塞上报，避免主 goroutine 已退出后其它 goroutine 永久阻塞在发送上。
	reportErr := func(err error) {
		select {
		case errChan <- err:
		default:
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			messageType, data, err := browser.ReadMessage()
			if err != nil {
				reportErr(err)
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
						_ = agent.WriteJSON(gin.H{"type": "close"})
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
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			_, data, err := agent.ReadMessage()
			if err != nil {
				reportErr(err)
				return
			}
			if err := browser.WriteMessage(websocket.BinaryMessage, data); err != nil {
				reportErr(err)
				return
			}
		}
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

	// 等待错误或主动关闭
	<-errChan
	close(stop)
	suspendSession(id, browser, agent)
	// 等所有 goroutine 退出后再关闭 done，确保下一轮转发不会并发读 agent。
	wg.Wait()
	disconnect_time := time.Now()
	auditlog.Log(requesterIp, userUUID, "disconnected, terminal id:"+id+", duration:"+disconnect_time.Sub(established_time).String(), "terminal")
}
