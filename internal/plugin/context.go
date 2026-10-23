package plugin

import (
	"net/http"

	"github.com/Calcium-Ion/moejs"
	"github.com/Calcium-Ion/moejs/engine"
	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/pkg/jsruntime/native"
	"github.com/komari-monitor/komari/pkg/rpc"
)

// principalContextKey stays in sync with web/api/principal.go:
// IdentityMiddleware stores the resolved principal under this gin key.
const principalContextKey = "principal"

// routeRequestContext builds the JS request context with the caller identity
// resolved by IdentityMiddleware. Raw credentials (session/client tokens) are
// intentionally not exposed.
func routeRequestContext(vm *moejs.Runtime, c *gin.Context) *engine.Object {
	ctx := vm.Realm().NewObject()
	principal := rpcPrincipalFromGin(c)
	p := vm.Realm().NewObject()
	if principal != nil {
		_ = native.Set(vm, p, "type", principalTypeString(principal.Type))
		_ = native.Set(vm, p, "roles", principal.Roles)
		_ = native.Set(vm, p, "user_uuid", principal.UserUUID)
		_ = native.Set(vm, p, "client_uuid", principal.ClientUUID)
		_ = native.Set(vm, p, "is_api_key", principal.IsAPIKey)
	}
	_ = native.Set(vm, ctx, "principal", p)
	if role, ok := c.Get("role"); ok {
		if s, ok := role.(string); ok {
			_ = native.Set(vm, ctx, "role", s)
		}
	}
	if uuid, ok := c.Get("uuid"); ok {
		_ = native.Set(vm, ctx, "user_uuid", uuid)
	}
	if clientUUID, ok := c.Get("client_uuid"); ok {
		_ = native.Set(vm, ctx, "client_uuid", clientUUID)
	}
	_ = native.Set(vm, ctx, "remote_ip", c.ClientIP())
	_ = native.Set(vm, ctx, "user_agent", c.GetHeader("User-Agent"))
	return ctx
}

// hookRequestContext builds the JS request context at the raw HTTP layer
// (before the gin identity middleware runs): only network metadata is
// available there.
func hookRequestContext(vm *moejs.Runtime, r *http.Request) *engine.Object {
	ctx := vm.Realm().NewObject()
	_ = native.Set(vm, ctx, "remote_ip", remoteIP(r))
	_ = native.Set(vm, ctx, "user_agent", r.Header.Get("User-Agent"))
	return ctx
}

func rpcPrincipalFromGin(c *gin.Context) *rpc.Principal {
	value, ok := c.Get(principalContextKey)
	if !ok {
		return nil
	}
	principal, _ := value.(*rpc.Principal)
	return principal
}

func principalTypeString(t rpc.PrincipalType) string {
	switch t {
	case rpc.PrincipalAgent:
		return "agent"
	case rpc.PrincipalUser:
		return "user"
	case rpc.PrincipalAPIKey:
		return "api_key"
	default:
		return "anonymous"
	}
}

// remoteIP resolves the client address for the raw HTTP hook layer with the
// same policy as gin's ClientIP, via pkg/clientip. Forwarded headers are only
// honoured when the connection itself comes from a configured trusted proxy,
// and a malformed chain falls back to the connection address instead of
// accepting an attacker-chosen entry. Otherwise any caller could choose the IP
// that plugins observe.
func remoteIP(r *http.Request) string {
	return resolveClientIP(r)
}
