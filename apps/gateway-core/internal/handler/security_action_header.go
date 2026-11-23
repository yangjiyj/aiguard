package handler

import (
	"context"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

const SecurityActionHeader = "X-Security-Action"

var securityActionRank = map[string]int{"audit": 1, "mask": 2, "reply": 3, "block": 4}

func strongerSecurityAction(a, b string) string {
	if securityActionRank[b] > securityActionRank[a] {
		return b
	}
	return a
}

func setSecurityActionHeader(w http.ResponseWriter, action string, enabled bool) {
	if !enabled || securityActionRank[action] == 0 {
		return
	}
	w.Header().Set(SecurityActionHeader, action)
}

func securityActionHeaderEnabled(cfg *config.Config) bool {
	return cfg != nil && cfg.SecurityActionHeaderEnabled(cfg.SecurityAuditOnly)
}

func securityActionHeaderEnabledForRuntime(ctx context.Context, cfg *config.Config, client *ToolRiskClient) bool {
	if cfg == nil {
		return false
	}
	auditOnly := cfg.SecurityAuditOnly
	if client != nil {
		auditOnly = client.SecurityAuditOnly(ctx, auditOnly)
	}
	return cfg.SecurityActionHeaderEnabled(auditOnly)
}

func outputActionOf(a *AuditResult) string {
	if a == nil || a.OutputAction == "" || a.OutputAction == "allow" {
		return ""
	}
	return a.OutputAction
}
