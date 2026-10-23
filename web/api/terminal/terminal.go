package terminal

import (
	"crypto/subtle"
	"sync"
	"sync/atomic"
	"time"

	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/web/connection"
)

type TerminalSession struct {
	UUID         string
	UserUUID     string
	Browser      *connection.SafeConn
	Agent        *connection.SafeConn
	RequesterIp  string
	Forwarding   bool
	CleanupTimer *time.Timer
	// Credential 记录建立或重新附着该终端时实际使用的凭据。
	// 只持有复核所需的字符串，不持有 gin.Context。
	Credential *terminalCredential
	// forwardDone 在上一轮转发完全退出后关闭。连接替换时新的转发必须等它，
	// 否则两个 goroutine 会并发读同一个 agent 连接。
	forwardDone chan struct{}
}

// terminalCredential 是终端连接凭据的独立快照。
//
// 仅保存 UserUUID 无法区分“凭据已撤销”，API Key 又共用占位 UUID，所以转发
// 前必须用建立连接时真正使用的 session token / API key 重新校验。
type terminalCredential struct {
	sessionToken string
	apiKey       string
	userUUID     string
}

// valid 重新校验凭据当前是否仍然有效。
// 会话走 GetSession（含过期检查与过期清理），API Key 与当前配置比对。
func (c *terminalCredential) valid() bool {
	if c == nil {
		return false
	}
	if c.apiKey != "" {
		key, err := config.GetAs[string](config.ApiKeyKey, "")
		if err != nil || key == "" {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(key), []byte(c.apiKey)) == 1
	}
	if c.sessionToken != "" {
		uuid, err := accounts.GetSession(c.sessionToken)
		return err == nil && uuid != "" && uuid == c.userUUID
	}
	return false
}

// terminalCredentialRecheckNanos 允许测试缩短空闲连接的复核周期。
// 0 表示使用默认值；用原子值避免后台 goroutine 与测试之间产生竞态。
var terminalCredentialRecheckNanos atomic.Int64

const defaultTerminalCredentialRecheck = 5 * time.Second

func terminalCredentialRecheckInterval() time.Duration {
	if n := terminalCredentialRecheckNanos.Load(); n > 0 {
		return time.Duration(n)
	}
	return defaultTerminalCredentialRecheck
}

var TerminalSessionsMutex = &sync.Mutex{}
var TerminalSessions = make(map[string]*TerminalSession)

// 与 v2 事件队列 TTL 对齐，被控端短暂离线后会话仍可恢复。
const terminalSessionRetention = 5 * time.Minute

func scheduleCleanup(id string, session *TerminalSession) {
	if session.CleanupTimer != nil {
		session.CleanupTimer.Stop()
	}
	session.CleanupTimer = time.AfterFunc(terminalSessionRetention, func() {
		var browser, agent *connection.SafeConn

		TerminalSessionsMutex.Lock()
		if current, ok := TerminalSessions[id]; !ok || current != session {
			TerminalSessionsMutex.Unlock()
			return
		}
		browser, agent = session.Browser, session.Agent
		delete(TerminalSessions, id)
		TerminalSessionsMutex.Unlock()

		if browser != nil {
			_ = browser.Close()
		}
		if agent != nil {
			_ = agent.Close()
		}
	})
}

func stopCleanup(session *TerminalSession) {
	if session.CleanupTimer != nil {
		session.CleanupTimer.Stop()
		session.CleanupTimer = nil
	}
}

func suspendSession(id string, browser, agent *connection.SafeConn) {
	var otherBrowser, otherAgent *connection.SafeConn

	TerminalSessionsMutex.Lock()
	session, ok := TerminalSessions[id]
	if !ok || session == nil ||
		(browser != nil && session.Browser != browser) ||
		(agent != nil && session.Agent != agent) {
		TerminalSessionsMutex.Unlock()
		return
	}
	otherBrowser, otherAgent = session.Browser, session.Agent
	session.Browser = nil
	session.Agent = nil
	session.Forwarding = false
	scheduleCleanup(id, session)
	TerminalSessionsMutex.Unlock()

	if otherBrowser != nil {
		_ = otherBrowser.Close()
	}
	if otherAgent != nil {
		_ = otherAgent.Close()
	}
}

func closeSession(id string) {
	var browser, agent *connection.SafeConn

	TerminalSessionsMutex.Lock()
	if session, ok := TerminalSessions[id]; ok && session != nil {
		stopCleanup(session)
		browser, agent = session.Browser, session.Agent
		delete(TerminalSessions, id)
	}
	TerminalSessionsMutex.Unlock()

	if browser != nil {
		_ = browser.Close()
	}
	if agent != nil {
		_ = agent.Close()
	}
}

func attachBrowser(id, userUUID string, credential *terminalCredential, conn *connection.SafeConn) (*TerminalSession, bool) {
	TerminalSessionsMutex.Lock()
	session, ok := TerminalSessions[id]
	if !ok || session == nil {
		TerminalSessionsMutex.Unlock()
		return nil, false
	}
	if credential == nil {
		TerminalSessionsMutex.Unlock()
		return nil, false
	}
	isAPIKey := credential.apiKey != ""
	if !isAPIKey && session.UserUUID != userUUID {
		TerminalSessionsMutex.Unlock()
		return nil, false
	}
	// 重新附着使用当前请求的凭据，替换掉旧快照；旧 request_id 不能借此
	// 继续沿用已撤销的凭据。
	session.Credential = credential
	oldBrowser := session.Browser
	oldAgent := session.Agent
	session.Browser = conn
	// 旧 agent 连接与旧转发 goroutine 必须一起结束，否则两轮转发会并发读
	// 同一个 agent 连接。重新附着的 handler 会再次派发 terminal 请求事件，
	// agent 收到后会重新连接。
	session.Agent = nil
	session.Forwarding = false
	if oldBrowser != nil || oldAgent != nil {
		stopCleanup(session)
	}
	TerminalSessionsMutex.Unlock()
	if oldBrowser != nil && oldBrowser != conn {
		_ = oldBrowser.Close()
	}
	if oldAgent != nil {
		_ = oldAgent.Close()
	}
	return session, true
}

func attachAgent(id string, conn *connection.SafeConn) (*TerminalSession, bool) {
	TerminalSessionsMutex.Lock()
	session, ok := TerminalSessions[id]
	if !ok || session == nil {
		TerminalSessionsMutex.Unlock()
		return nil, false
	}
	oldAgent := session.Agent
	session.Agent = conn
	session.Forwarding = false
	if session.Browser != nil {
		stopCleanup(session)
	}
	TerminalSessionsMutex.Unlock()
	if oldAgent != nil && oldAgent != conn {
		_ = oldAgent.Close()
	}
	return session, true
}

func maybeStartForwarding(id string) {
	TerminalSessionsMutex.Lock()
	session, ok := TerminalSessions[id]
	if !ok || session == nil || session.Browser == nil || session.Agent == nil || session.Forwarding {
		TerminalSessionsMutex.Unlock()
		return
	}
	session.Forwarding = true
	browser, agent := session.Browser, session.Agent
	previous := session.forwardDone
	TerminalSessionsMutex.Unlock()

	// 上一轮转发（通常因浏览器/agent 被替换而退出）必须先结束，避免新旧
	// goroutine 并发读同一个 agent 连接。超时则放弃启动，等待下一次事件。
	if previous != nil {
		select {
		case <-previous:
		case <-time.After(2 * time.Second):
			TerminalSessionsMutex.Lock()
			if current, exists := TerminalSessions[id]; exists && current == session {
				session.Forwarding = false
			}
			TerminalSessionsMutex.Unlock()
			return
		}
	}

	done := make(chan struct{})
	TerminalSessionsMutex.Lock()
	current, exists := TerminalSessions[id]
	if !exists || current != session {
		TerminalSessionsMutex.Unlock()
		close(done)
		return
	}
	if session.Browser != browser || session.Agent != agent {
		// 等待期间连接又被替换：放弃本次启动，允许下一次事件重试。
		session.Forwarding = false
		TerminalSessionsMutex.Unlock()
		close(done)
		return
	}
	session.forwardDone = done
	TerminalSessionsMutex.Unlock()

	go forwardTerminal(id, browser, agent, done)
}
