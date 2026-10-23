package api

// principal.go
// 统一身份识别。IdentifyPrincipal 是全局唯一的主体识别入口,替代此前散落在
// IdentityMiddleware / transport.detectPermissionGroup / transport.buildContextMeta
// 三处的重复逻辑。识别优先级:API Key > Session(用户) > Client Token(agent) > 匿名。

import (
	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/clients"
	"github.com/komari-monitor/komari/pkg/rpc"
)

// principalContextKey 是 principal 在 gin.Context 中的存储键。
const principalContextKey = "principal"

// IdentifyPrincipal 识别当前请求的调用主体。不写入任何状态,可安全多次调用。
// 识别优先级与历史 IdentityMiddleware 一致:API Key > Session > Client Token > 匿名。
func IdentifyPrincipal(c *gin.Context) *rpc.Principal {
	// 1. API Key(Authorization: Bearer <key>)
	if isApiKeyValid(c.GetHeader("Authorization")) {
		return rpc.NewAPIKeyPrincipal()
	}

	// 2. Session(管理员用户)
	if session, err := c.Cookie("session_token"); err == nil && session != "" {
		if uuid, err := accounts.GetSession(session); err == nil && uuid != "" {
			return rpc.NewUserPrincipal(uuid)
		}
	}

	// 3. Client Token(agent 客户端)
	if token := extractClientToken(c); token != "" {
		if uuid, err := clients.GetClientUUIDByToken(token); err == nil {
			return rpc.NewAgentPrincipal(uuid)
		}
	}

	// 4. 匿名访客
	return rpc.NewAnonymousPrincipal()
}

// SetPrincipal 将已识别的主体写入 gin.Context,供下游(RPC 边界等)复用。
func SetPrincipal(c *gin.Context, p *rpc.Principal) {
	c.Set(principalContextKey, p)
}

// GetPrincipal 读取已识别的主体;若中间件未运行则返回 nil。
func GetPrincipal(c *gin.Context) *rpc.Principal {
	p, _ := c.Get(principalContextKey)
	principal, _ := p.(*rpc.Principal)
	return principal
}

// RefreshPrincipal 用最新识别结果覆盖 gin.Context 中的身份缓存,并重建兼容键。
//
// HTTP 请求每次都会重新跑 IdentityMiddleware,但 WebSocket 长连接在握手后复用
// 同一个 gin.Context:凭据被撤销时缓存中的旧 Principal、role、uuid、api_key
// 仍会继续生效。复核路径必须先调用 IdentifyPrincipal(不读缓存),再用本函数
// 覆盖缓存,否则下游 handler 仍可能读到握手时的身份。
func RefreshPrincipal(c *gin.Context, p *rpc.Principal) {
	if p == nil {
		p = rpc.NewAnonymousPrincipal()
	}
	SetPrincipal(c, p)
	c.Set("role", p.PrimaryRole())
	// 清除上一次识别可能遗留的凭据键,避免降级为匿名后旧字段仍被读到。
	delete(c.Keys, "uuid")
	delete(c.Keys, "api_key")
	delete(c.Keys, "session")
	delete(c.Keys, "client_uuid")

	switch p.Type {
	case rpc.PrincipalAPIKey:
		// 与 IdentityMiddleware 保持一致:记录裸 key 与固定占位 UUID。
		if auth := c.GetHeader("Authorization"); len(auth) > len("Bearer ") {
			c.Set("api_key", auth[len("Bearer "):])
		}
		c.Set("uuid", "00000000-0000-0000-0000-000000000000")
	case rpc.PrincipalUser:
		if session, err := c.Cookie("session_token"); err == nil && session != "" {
			c.Set("session", session)
		}
		c.Set("uuid", p.UserUUID)
	case rpc.PrincipalAgent:
		c.Set("client_uuid", p.ClientUUID)
	}
}
