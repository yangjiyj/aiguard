package handler

import (
	"context"
	"encoding/json"
	"net"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// ProxyConfig represents the proxy access configuration for a model.
type ProxyConfig struct {
	Enabled         bool     `json:"enabled"`
	AuthMode        string   `json:"auth_mode"` // "ip_allowlist", "origin", "public"
	IPAllowlist     []string `json:"ip_allowlist"`
	OriginAllowlist []string `json:"origin_allowlist"`
	RPM             int      `json:"rpm_per_ip"`    // Per-IP RPM limit
	GlobalRPM       int      `json:"rpm_global"`    // Global RPM limit
	DailyCap        int      `json:"daily_cap"`     // Daily request cap
	Concurrency     int      `json:"concurrency"`
}

// DefaultProxyConfig returns a ProxyConfig with safe defaults.
func DefaultProxyConfig() ProxyConfig {
	return ProxyConfig{
		Enabled:     false,
		AuthMode:    "ip_allowlist",
		IPAllowlist: []string{},
		RPM:         10,
		GlobalRPM:   1000,
		DailyCap:    10000,
		Concurrency: 5,
	}
}

// ParseProxyConfig extracts ProxyConfig from model record's proxy_config JSON field.
func ParseProxyConfig(model *modelrouter.ModelRecord) ProxyConfig {
	cfg := DefaultProxyConfig()

	if model == nil || model.ProxyConfig == "" {
		return cfg
	}

	if err := json.Unmarshal([]byte(model.ProxyConfig), &cfg); err != nil {
		return cfg
	}

	return cfg
}

// isProxyRequest checks whether the current request is a proxy (no-token) request.
func isProxyRequest(ctx context.Context) bool {
	v := ctx.Value(auth.ProxyRequestKey)
	if v == nil {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// getClientIP extracts the client IP from the request context.
func getClientIP(ctx context.Context) string {
	v := ctx.Value(auth.ClientIPKey)
	if v == nil {
		return ""
	}
	return v.(string)
}

// matchIPAllowlist checks if a client IP matches any CIDR in the allowlist.
func matchIPAllowlist(clientIP string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return true // No allowlist means all IPs allowed
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	for _, cidr := range allowlist {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// matchOriginAllowlist checks if an Origin header matches any entry in the allowlist.
func matchOriginAllowlist(origin string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return true // No allowlist means all origins allowed
	}

	for _, allowed := range allowlist {
		allowed = strings.TrimSpace(allowed)
		// Wildcard: *.example.com matches any subdomain
		if strings.HasPrefix(allowed, "*.") {
			suffix := strings.TrimPrefix(allowed, "*")
			if strings.HasSuffix(strings.ToLower(origin), strings.ToLower(suffix)) {
				return true
			}
			continue
		}
		if strings.EqualFold(origin, allowed) {
			return true
		}
	}
	return false
}
