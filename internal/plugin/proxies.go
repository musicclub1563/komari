package plugin

import (
	"net/http"
	"sync"

	"github.com/komari-monitor/komari/pkg/clientip"
)

// 原始 HTTP 层的插件钩子在 gin 中间件之前执行，无法使用 c.ClientIP()，
// 因此这里复用 pkg/clientip 的可信代理解析：只有来自可信代理的连接才允许
// 通过 X-Forwarded-For / X-Real-IP 指定客户端 IP，解析规则与 gin 保持一致。
var (
	trustedProxyMu sync.RWMutex
	resolver       *clientip.Resolver
)

// SetTrustedProxies replaces the trusted proxy list used by remoteIP. An empty
// list disables forwarded header trust entirely. Entries may be IPs or CIDRs;
// any invalid entry is rejected and leaves the previous list in place.
func SetTrustedProxies(entries []string) error {
	parsed, err := clientip.New(entries)
	if err != nil {
		return err
	}
	trustedProxyMu.Lock()
	resolver = parsed
	trustedProxyMu.Unlock()
	return nil
}

// clientIPResolver returns the current resolver. A nil result is safe: it
// trusts nothing and always reports the connection peer.
func clientIPResolver() *clientip.Resolver {
	trustedProxyMu.RLock()
	defer trustedProxyMu.RUnlock()
	return resolver
}

// resolveClientIP applies the shared policy to a raw request.
func resolveClientIP(r *http.Request) string {
	return clientIPResolver().Resolve(r.RemoteAddr, r.Header)
}
