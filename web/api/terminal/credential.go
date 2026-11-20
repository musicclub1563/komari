package terminal

import (
	"crypto/subtle"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/pkg/rpc"
	"github.com/komari-monitor/komari/web/api"
	"github.com/komari-monitor/komari/web/connection"
)

// terminalCredential 是终端连接凭据的独立快照。
//
// 仅保存 UserUUID 无法区分“凭据已撤销”，API Key 又共用占位 UUID，所以会话存续
// 期间必须用建立连接时真正使用的 session token / API key 重新校验。
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

// terminalCredentialRecheckNanos 允许测试缩短复核周期。
// 0 表示使用默认值；用原子值避免后台 goroutine 与测试之间产生竞态。
var terminalCredentialRecheckNanos atomic.Int64

const defaultTerminalCredentialRecheck = 5 * time.Second

func terminalCredentialRecheckInterval() time.Duration {
	if n := terminalCredentialRecheckNanos.Load(); n > 0 {
		return time.Duration(n)
	}
	return defaultTerminalCredentialRecheck
}

// captureTerminalCredential 把当前请求的凭据固化成独立快照。
//
// 终端 handler 返回后 gin.Context 会被复用，后台转发 goroutine 不能持有它；
// 同时授权必须能追溯到建立连接时实际使用的凭据，而不是 UserUUID（API Key
// 共用占位 UUID，无法据此判断密钥是否已轮换）。
func captureTerminalCredential(c *gin.Context) *terminalCredential {
	p := api.IdentifyPrincipal(c)
	switch p.Type {
	case rpc.PrincipalAPIKey:
		const bearerPrefix = "Bearer "
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, bearerPrefix) {
			return nil
		}
		key := strings.TrimSpace(strings.TrimPrefix(auth, bearerPrefix))
		if key == "" {
			return nil
		}
		return &terminalCredential{apiKey: key}
	case rpc.PrincipalUser:
		token, err := c.Cookie("session_token")
		if err != nil || token == "" {
			return nil
		}
		return &terminalCredential{sessionToken: token, userUUID: p.UserUUID}
	default:
		return nil
	}
}

// setTerminalCredential 记录（或刷新）会话的授权快照。
// browser 非空时只在该浏览器仍是会话的当前浏览器时写入，避免并发换代时写错会话。
func setTerminalCredential(id string, browser *connection.SafeConn, credential *terminalCredential) {
	if credential == nil {
		return
	}
	TerminalSessionsMutex.Lock()
	session := TerminalSessions[id]
	if session != nil && (browser == nil || session.Browser == browser) {
		session.Credential = credential
	}
	TerminalSessionsMutex.Unlock()
}

// watchTerminalCredential 定期复核会话凭据：登出、会话过期或 API Key 轮换后，
// 已建立的终端必须在有限时间内被关闭，而不是一直持有授权。
func watchTerminalCredential(id string, browser *connection.SafeConn) {
	interval := terminalCredentialRecheckInterval()
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		TerminalSessionsMutex.Lock()
		session := TerminalSessions[id]
		if session == nil || (browser != nil && session.Browser != browser) {
			TerminalSessionsMutex.Unlock()
			return
		}
		credential := session.Credential
		TerminalSessionsMutex.Unlock()
		if credential == nil {
			// 未记录凭据的会话（升级前建立）保持原有行为。
			continue
		}
		if !credential.valid() {
			closeSession(id)
			return
		}
	}
}
