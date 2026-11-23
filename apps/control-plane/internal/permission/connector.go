package permission

import "net/http"

// This exact API contract cannot be expanded by administrator grants.
// Each handler scopes data to the authenticated gateway tenant.
func connectorRouteAllowed(r *http.Request) bool {
	key := r.Method + " " + normalizePathToTemplate(r.URL.Path)
	switch key {
	case "GET /admin/v1/integration/agent-credentials/{id}",
		"PATCH /admin/v1/integration/agent-credentials/{id}",
		"GET /admin/v1/integration/dlp-status",
		"GET /admin/v1/integration/credential-hits",
		"GET /admin/v1/integration/retention-status",
		"GET /admin/v1/security/policies/capabilities",
		"POST /admin/v1/integration/agent-credentials",
		"GET /admin/v1/integration/agent-credentials",
		"POST /admin/v1/integration/agent-credentials/{id}/rotate",
		"POST /admin/v1/integration/agent-credentials/{id}/revoke",
		"POST /admin/v1/integration/agent-policies",
		"PUT /admin/v1/integration/agent-policies/{id}",
		"GET /admin/v1/integration/agent-policies",
		"GET /admin/v1/integration/enforcement-status",
		"GET /admin/v1/integration/audit-events",
		"GET /admin/v1/integration/upstreams",
		"GET /admin/v1/integration/projects",
		"GET /admin/v1/me",
		"GET /admin/v1/security/policies",
		"POST /admin/v1/security/policies",
		"PATCH /admin/v1/security/policies/{id}",
		"GET /admin/v1/security/policy-assets",
		"PUT /admin/v1/security/policy-assets/{id}",
		"GET /admin/v1/agentguard/policies",
		"POST /admin/v1/agentguard/policies",
		"PUT /admin/v1/agentguard/policies/{id}",
		"GET /admin/v1/mcp-policies",
		"POST /admin/v1/mcp-policies",
		"PUT /admin/v1/mcp-policies/{id}",
		// Risk metadata scope (P0 2026-10-02): read-only, same-tenant security
		// events projected to minimal metadata by connectorRiskMetadata; no
		// content, no matched_summary, no dispositions, no audit operations.
		"GET /admin/v1/audit/events",
		// Capability probe for the platform connector (static, read-only).
		"GET /admin/v1/integration/capabilities":
		return true
	}
	return false
}
