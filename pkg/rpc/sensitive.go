package rpc

// sensitive.go
// 敏感操作登记表。被标记的方法（如 admin:exec）在通过角色鉴权后，仍需额外的
// 敏感操作二次验证（sensitive 2FA）。登记与传输无关，由 RPC 边界统一判定，
// 确保所有调用入口行为一致。

import "sync"

var (
	muSensitive      sync.RWMutex
	sensitiveMethods = map[string]bool{}

	muPluginForbidden      sync.RWMutex
	pluginForbiddenMethods = map[string]bool{}
)

// MarkSensitive 标记某方法为敏感操作。method 为完整方法名（如 "admin:exec"）。
// 重复标记是幂等的。供方法注册处声明。
func MarkSensitive(method string) {
	muSensitive.Lock()
	defer muSensitive.Unlock()
	sensitiveMethods[method] = true
}

// IsSensitive 判断方法是否被标记为敏感操作。
func IsSensitive(method string) bool {
	muSensitive.RLock()
	defer muSensitive.RUnlock()
	return sensitiveMethods[method]
}

// MarkPluginForbidden 标记某方法禁止插件通过 server.call 调用。
//
// 插件运行的是从 ZIP 安装的不可信代码，即使被授予 allowSystemRPC，也不应
// 获得直接操作数据库等系统级能力；这类方法只允许通过 HTTP/WebSocket
// 传输层由管理员本人调用（其中敏感方法还需二次验证）。
func MarkPluginForbidden(method string) {
	muPluginForbidden.Lock()
	defer muPluginForbidden.Unlock()
	pluginForbiddenMethods[method] = true
}

// IsPluginForbidden 判断方法是否禁止插件调用。
func IsPluginForbidden(method string) bool {
	muPluginForbidden.RLock()
	defer muPluginForbidden.RUnlock()
	return pluginForbiddenMethods[method]
}
