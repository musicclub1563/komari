package server

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/internal/plugin"
	"github.com/komari-monitor/komari/pkg/clientip"
	logger "github.com/komari-monitor/komari/utils/log"
)

// envTrustedProxies overrides the stored setting so container deployments can
// configure the proxy without a database write.
const envTrustedProxies = "KOMARI_TRUSTED_PROXIES"

// splitTrustedProxies splits a comma separated list into raw entries.
func splitTrustedProxies(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

// parseTrustedProxies validates a comma separated list of IPs/CIDRs and returns
// the normalized CIDR form. An empty list means "trust no proxy header".
func parseTrustedProxies(raw string) ([]string, error) {
	resolver, err := clientip.New(splitTrustedProxies(raw))
	if err != nil {
		return nil, err
	}
	return resolver.Entries(), nil
}

// applyTrustedProxies configures gin's client IP resolution and the plugin
// hook layer with the same policy. Without this, gin trusts X-Forwarded-For
// from every peer, so any caller can choose the IP recorded in audit logs,
// login sessions, terminal requests and plugin contexts.
//
// The value comes from the setting or, when that is empty, from the
// KOMARI_TRUSTED_PROXIES environment variable. An empty result means headers
// are ignored and the connection's remote address is used.
//
// Both layers are fed the same normalized list so their parsing rules cannot
// drift; the equivalence itself is asserted by TestRemoteIPMatchesGinClientIP.
func applyTrustedProxies(engine *gin.Engine, configured string) error {
	raw := strings.TrimSpace(configured)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv(envTrustedProxies))
	}
	entries, err := parseTrustedProxies(raw)
	if err != nil {
		// Never fall back to trusting every peer: an invalid configuration is
		// reported and the safe default (no header trust) is applied.
		logger.Errorf("server", "Invalid trusted proxy configuration, ignoring proxy headers: %v", err)
		entries = nil
	}
	if len(entries) == 0 {
		entries = nil // explicit "trust nothing" for both layers
	}
	if engine != nil {
		if err := engine.SetTrustedProxies(entries); err != nil {
			logger.Errorf("server", "Failed to apply trusted proxies: %v", err)
		}
	}
	if err := plugin.SetTrustedProxies(entries); err != nil {
		logger.Errorf("server", "Failed to apply trusted proxies to plugin hooks: %v", err)
	}
	if len(entries) == 0 {
		logger.Infof("server", "Trusted proxies: none (forwarded client IP headers are ignored)")
	} else {
		logger.Infof("server", "Trusted proxies: %s", strings.Join(entries, ", "))
	}
	return nil
}
