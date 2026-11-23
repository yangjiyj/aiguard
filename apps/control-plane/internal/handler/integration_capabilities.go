package handler

import (
	"encoding/json"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
)

// IntegrationCapabilities is the platform-connector capability probe
// (proposed contract 二/合同一). It reports what the dedicated machine
// identity may do; "configured" never implies "execution verified" — the
// platform must still validate real enforcement per action.
func IntegrationCapabilities(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeError(w, "unauthorized", "service identity required")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"product":   "jjdguard",
			"tenant_id": user.TenantID,
			"scope":     "risk_metadata_projection",
			"capabilities": map[string]interface{}{
				"credential_hits":    map[string]any{"enabled": true, "route": "GET /admin/v1/integration/credential-hits"},
				"retention_status":   map[string]any{"enabled": true, "route": "GET /admin/v1/integration/retention-status"},
				"projects_read":      map[string]any{"enabled": true, "route": "GET /admin/v1/integration/projects", "projection": "id_name_status"},
				"agent_credentials":  map[string]any{"enabled": true, "issue": true, "rotate": true, "revoke": true, "model_allowlist": true, "get_by_id": true, "update": true, "enforcement": true},
				"dlp_receipt":        map[string]any{"enabled": true, "route": "GET /admin/v1/integration/dlp-status"},
				"agent_policies":     map[string]any{"enabled": true, "actions": []string{"block_model_egress", "disable_mcp"}},
				"enforcement_status": map[string]any{"enabled": true, "schema_version": "gateway-enforcement/v1"},
				"request_events":     map[string]any{"enabled": true, "route": "GET /admin/v1/integration/audit-events"},
				"upstreams":          map[string]any{"enabled": true, "route": "GET /admin/v1/integration/upstreams"},
				"risk_metadata": map[string]interface{}{
					"enabled":          true,
					"route":            "GET /admin/v1/audit/events",
					"projection":       "minimal_metadata",
					"content_evidence": false,
					"note":             "metadata only: ids, type, severity, rule, action, principal key, timestamps",
				},
				"policy_write": map[string]interface{}{
					"enabled": true,
					"routes": []string{
						"GET|POST /admin/v1/security/policies",
						"PATCH /admin/v1/security/policies/{id}",
						"GET /admin/v1/security/policy-assets",
						"PUT /admin/v1/security/policy-assets/{id}",
						"GET|POST /admin/v1/agentguard/policies",
						"PUT /admin/v1/agentguard/policies/{id}",
						"GET|POST /admin/v1/mcp-policies",
						"PUT /admin/v1/mcp-policies/{id}",
					},
				},
				"risk_disposition": map[string]interface{}{
					"enabled": false,
					"note":    "audit operations and risk dispositions remain denied for the sealed connector",
				},
			},
		})
	}
}
