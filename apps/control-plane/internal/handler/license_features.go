package handler

import (
	"net/http"
	"strings"

	entlicense "github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
)

var licenseFeatureRoutes = []struct {
	prefix  string
	feature string
}{
	{prefix: "/admin/v1/agent/", feature: "agent_security"},
	{prefix: "/admin/v1/agent-sessions", feature: "agent_audit"},
	{prefix: "/admin/v1/stats/agents", feature: "agent_audit"},
	{prefix: "/admin/v1/audit/agents", feature: "agent_audit"},
	{prefix: "/admin/v1/agentguard", feature: "agent_audit"},
	{prefix: "/admin/v1/audit/tools", feature: "agent_audit"},
	{prefix: "/admin/v1/tools/config", feature: "agent_audit"},
	{prefix: "/admin/v1/audit/access-retention", feature: "content_retention"},
	{prefix: "/admin/v1/proxy/forward-access", feature: "content_retention"},
	{prefix: "/admin/v1/proxy/whitelist", feature: "ide_proxy"},
	{prefix: "/admin/v1/reverse-proxy", feature: "ide_proxy"},
	{prefix: "/admin/v1/proxy-access-keys", feature: "ide_proxy"},
	{prefix: "/admin/v1/content-security", feature: "sensitive_data_guard"},
	{prefix: "/admin/v1/security/test", feature: "sensitive_data_guard"},
	{prefix: "/admin/v1/rule-sets", feature: "sensitive_data_guard"},
	{prefix: "/admin/v1/rules", feature: "sensitive_data_guard"},
	{prefix: "/admin/v1/detectors", feature: "sensitive_data_guard"},
	{prefix: "/admin/v1/providers", feature: "web_ai"},
	{prefix: "/admin/v1/models", feature: "web_ai"},
	{prefix: "/admin/v1/keys", feature: "web_ai"},
	{prefix: "/admin/v1/projects", feature: "web_ai"},
}

func requiredLicenseFeature(path string) string {
	for _, route := range licenseFeatureRoutes {
		if strings.HasPrefix(path, route.prefix) {
			return route.feature
		}
	}
	return ""
}

func licenseHasFeature(status entlicense.Status, feature string) bool {
	if feature == "" {
		return true
	}
	for _, licensed := range status.Features {
		if licensed == feature {
			return true
		}
	}
	return false
}

func enforceLicensedFeature(w http.ResponseWriter, r *http.Request, status entlicense.Status) bool {
	feature := requiredLicenseFeature(r.URL.Path)
	if licenseHasFeature(status, feature) {
		return true
	}
	writeErrorWithStatus(w, http.StatusPaymentRequired, "license_feature_required", "feature is not licensed: "+feature)
	return false
}
