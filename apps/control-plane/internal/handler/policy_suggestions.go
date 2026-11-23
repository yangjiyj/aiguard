package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const policySuggestionMaxBytes = 64 << 10
const policySuggestionMaxRegexBytes = 256

type policySuggestion struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id"`
	ExternalID     string          `json:"external_id"`
	Source         string          `json:"source"`
	Type           string          `json:"type"`
	Action         string          `json:"action"`
	Payload        json.RawMessage `json:"payload"`
	Status         string          `json:"status"`
	RuleSetID      *string         `json:"rule_set_id,omitempty"`
	RuleSetVersion *string         `json:"rule_set_version,omitempty"`
	Reviewer       *string         `json:"reviewer,omitempty"`
	ReviewNote     *string         `json:"review_note,omitempty"`
	CreatedAt      string          `json:"created_at"`
	UpdatedAt      string          `json:"updated_at"`
}

type policySuggestionInput struct {
	ExternalID string          `json:"external_id"`
	Source     string          `json:"source"`
	Type       string          `json:"type"`
	Action     string          `json:"action"`
	Payload    json.RawMessage `json:"payload"`
}

func decodePolicySuggestionPayload(raw json.RawMessage) (map[string]any, error) {
	var payload map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload == nil {
		return nil, errors.New("payload must be a JSON object with allowed fields")
	}
	allowed := map[string]bool{"regex": true, "keywords": true, "field_names": true, "examples": true, "source_finding": true, "estimated_impact": true}
	for key := range payload {
		if !allowed[key] {
			return nil, errors.New("payload contains unsupported field: " + key)
		}
	}
	matcherCount := 0
	if regexValue, ok := payload["regex"]; ok {
		matcherCount++
		pattern, ok := regexValue.(string)
		if !ok || len(pattern) == 0 || len(pattern) > policySuggestionMaxRegexBytes {
			return nil, errors.New("regex must be a non-empty string of at most 256 bytes")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return nil, errors.New("regex is invalid")
		}
	}
	for _, key := range []string{"keywords", "field_names"} {
		if raw, ok := payload[key]; ok {
			matcherCount++
			values, ok := raw.([]any)
			if !ok || len(values) == 0 || len(values) > 100 {
				return nil, errors.New(key + " must be an array with 1 to 100 values")
			}
			for _, value := range values {
				if text, ok := value.(string); !ok || strings.TrimSpace(text) == "" || len(text) > 256 {
					return nil, errors.New(key + " contains an invalid value")
				}
			}
		}
	}
	if matcherCount > 1 {
		return nil, errors.New("payload must contain exactly one matcher type")
	}
	return payload, nil
}

func decodePolicySuggestionRequest(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, policySuggestionMaxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("request body must contain exactly one JSON object")
	}
	return nil
}

func CreateEvalIntegrationPolicySuggestion(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(r.Header.Get(evalIntegrationTenantHeader))
		if tenantID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "tenant_required", "X-JJDGuard-Tenant-Id header is required")
			return
		}
		var req policySuggestionInput
		if err := decodePolicySuggestionRequest(w, r, &req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON or request fields")
			return
		}
		req.ExternalID = strings.TrimSpace(req.ExternalID)
		if req.ExternalID == "" || len(req.ExternalID) > 200 || req.Source != "lse" || req.Type == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "external_id (max 200 bytes), source=lse and type are required")
			return
		}
		if req.Action != "block" && req.Action != "alert" && req.Action != "mask" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_action", "action must be block, alert or mask")
			return
		}
		if _, err := decodePolicySuggestionPayload(req.Payload); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_payload", err.Error())
			return
		}
		var item policySuggestion
		item.ID = "ps_" + uuid.NewString()
		item.TenantID, item.ExternalID, item.Source = tenantID, req.ExternalID, "lse"
		item.Type, item.Action, item.Payload, item.Status = req.Type, req.Action, req.Payload, "pending_approval"
		err := deps.DB.QueryRow(r.Context(), `INSERT INTO policy_suggestions(id,tenant_id,external_id,source,type,action,payload) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb) ON CONFLICT(tenant_id,external_id) DO UPDATE SET external_id=EXCLUDED.external_id RETURNING id,tenant_id,external_id,source,type,action,payload,status,rule_set_id,rule_set_version,reviewer,review_note,created_at::text,updated_at::text`, item.ID, tenantID, req.ExternalID, "lse", req.Type, req.Action, string(req.Payload)).Scan(&item.ID, &item.TenantID, &item.ExternalID, &item.Source, &item.Type, &item.Action, &item.Payload, &item.Status, &item.RuleSetID, &item.RuleSetVersion, &item.Reviewer, &item.ReviewNote, &item.CreatedAt, &item.UpdatedAt)
		if err != nil {
			writeError(w, "internal_error", "failed to store policy suggestion")
			return
		}
		if deps.AuditAppender != nil {
			deps.AuditAppender.Enqueue(tenantID, "policy_suggestion.received", item.ID, map[string]any{"external_id": item.ExternalID, "source": item.Source, "type": item.Type, "action": item.Action, "status": item.Status})
		}
		writeJSON(w, item)
	}
}

func GetEvalIntegrationPolicySuggestion(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(r.Header.Get(evalIntegrationTenantHeader))
		if tenantID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "tenant_required", "X-JJDGuard-Tenant-Id header is required")
			return
		}
		var item policySuggestion
		err := deps.DB.QueryRow(r.Context(), `SELECT id,tenant_id,external_id,source,type,action,payload,status,rule_set_id,rule_set_version,reviewer,review_note,created_at::text,updated_at::text FROM policy_suggestions WHERE tenant_id=$1 AND (id=$2 OR external_id=$2)`, tenantID, chi.URLParam(r, "id")).Scan(&item.ID, &item.TenantID, &item.ExternalID, &item.Source, &item.Type, &item.Action, &item.Payload, &item.Status, &item.RuleSetID, &item.RuleSetVersion, &item.Reviewer, &item.ReviewNote, &item.CreatedAt, &item.UpdatedAt)
		if err != nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "policy suggestion not found")
			return
		}
		writeJSON(w, item)
	}
}

func ListPolicySuggestions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		rows, err := deps.DB.Query(r.Context(), `SELECT id,tenant_id,external_id,source,type,action,payload,status,rule_set_id,rule_set_version,reviewer,review_note,created_at::text,updated_at::text FROM policy_suggestions WHERE tenant_id=$1 AND status='pending_approval' ORDER BY created_at`, user.TenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to list policy suggestions")
			return
		}
		defer rows.Close()
		items := make([]policySuggestion, 0)
		for rows.Next() {
			var item policySuggestion
			if rows.Scan(&item.ID, &item.TenantID, &item.ExternalID, &item.Source, &item.Type, &item.Action, &item.Payload, &item.Status, &item.RuleSetID, &item.RuleSetVersion, &item.Reviewer, &item.ReviewNote, &item.CreatedAt, &item.UpdatedAt) != nil {
				writeError(w, "internal_error", "failed to read policy suggestions")
				return
			}
			items = append(items, item)
		}
		writeJSON(w, map[string]any{"data": items, "total": len(items)})
	}
}

func ReviewPolicySuggestion(deps *Dependencies, approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		// 审批会发布安全规则，属 SoD 的 security_write：安全员与系统管理员都能做，tenant_owner 保持原有权限。
		if !roles.CanManageSecurityPolicy(user.Role) && user.Role != "tenant_owner" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can review policy suggestions")
			return
		}
		id := chi.URLParam(r, "id")
		var current struct {
			Type, Action string
			Payload      []byte
			Status       string
		}
		err := deps.DB.QueryRow(r.Context(), `SELECT type,action,payload,status FROM policy_suggestions WHERE id=$1 AND tenant_id=$2`, id, user.TenantID).Scan(&current.Type, &current.Action, &current.Payload, &current.Status)
		if err != nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "policy suggestion not found")
			return
		}
		if current.Status != "pending_approval" {
			writeErrorWithStatus(w, http.StatusConflict, "invalid_status", "policy suggestion is no longer pending")
			return
		}
		var req struct {
			RuleSetID  string `json:"rule_set_id"`
			ReviewNote string `json:"review_note"`
			Name       string `json:"name"`
		}
		if err := decodePolicySuggestionRequest(w, r, &req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON or request fields")
			return
		}
		if !approve {
			req.ReviewNote = strings.TrimSpace(req.ReviewNote)
			if req.ReviewNote == "" {
				writeErrorWithStatus(w, http.StatusBadRequest, "review_note_required", "review_note is required")
				return
			}
			_, err = deps.DB.Exec(r.Context(), `UPDATE policy_suggestions SET status='rejected',reviewer=$1,review_note=$2,updated_at=now() WHERE id=$3 AND tenant_id=$4 AND status='pending_approval'`, user.ID, req.ReviewNote, id, user.TenantID)
			if err != nil {
				writeError(w, "internal_error", "failed to reject policy suggestion")
				return
			}
			logAudit(r, deps, "policy_suggestion.reject", map[string]any{"id": id, "reason": req.ReviewNote}, "policy_suggestion", id)
			writeJSON(w, map[string]any{"id": id, "status": "rejected"})
			return
		}
		payload, err := decodePolicySuggestionPayload(current.Payload)
		if err != nil {
			writeError(w, "invalid_payload", "stored suggestion payload is invalid")
			return
		}
		if current.Type != "sensitive_data" && current.Type != "content_category" && current.Type != "prompt_injection" {
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "unsupported_suggestion_type", "suggestion type cannot be represented by the current rule model")
			return
		}
		ruleType, matcherConfig := "", map[string]any{}
		if matcher, ok := payload["regex"].(string); ok && matcher != "" {
			ruleType, matcherConfig["regex"] = "regex", matcher
		} else if values, ok := payload["keywords"].([]any); ok && len(values) > 0 {
			ruleType, matcherConfig["keywords"] = "keyword", values
		} else if values, ok := payload["field_names"].([]any); ok && len(values) > 0 {
			ruleType, matcherConfig["field_names"] = "field_name", values
		} else {
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "unsupported_suggestion_type", "suggestion payload must contain regex, keywords or field_names")
			return
		}
		matcherConfig["category"] = "lse_" + current.Type
		rsID := strings.TrimSpace(req.RuleSetID)
		if rsID == "" {
			rsID = "rs_" + uuid.NewString()[:8]
			if err := deps.RuleSetRepo.Create(r.Context(), user.TenantID, &repository.RuleSet{ID: rsID, Name: "LSE 策略建议", Version: "1.0.0", SourceType: "lse", Published: false, CreatedBy: user.ID}); err != nil {
				writeError(w, "internal_error", "failed to create draft rule set")
				return
			}
		} else {
			rs, err := deps.RuleSetRepo.GetByID(r.Context(), user.TenantID, rsID)
			if err != nil || rs == nil || rs.Published {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_rule_set", "rule_set_id must identify an unpublished rule set owned by this tenant")
				return
			}
		}
		matchConfig, _ := json.Marshal(matcherConfig)
		action := current.Action
		if action == "alert" {
			action = "audit"
		}
		rule := &repository.Rule{RuleSetID: rsID, RuleType: ruleType, Name: strings.TrimSpace(req.Name), Priority: 100, Severity: "high", MatchConfigJSON: matchConfig, Action: action, Enabled: true, Description: "经人工审批的 LSE 策略建议"}
		if rule.Name == "" {
			rule.Name = "LSE policy suggestion"
		}
		if err := deps.RuleRepo.Create(r.Context(), user.TenantID, rule); err != nil {
			writeError(w, "internal_error", "failed to create draft rule")
			return
		}
		if err := deps.RuleSetRepo.Publish(r.Context(), user.TenantID, rsID); err != nil {
			writeError(w, "internal_error", "failed to publish rule set")
			return
		}
		var version string
		if err := deps.DB.QueryRow(r.Context(), `SELECT version FROM rule_sets WHERE id=$1 AND tenant_id=$2`, rsID, user.TenantID).Scan(&version); err != nil {
			writeError(w, "internal_error", "failed to read published version")
			return
		}
		_, err = deps.DB.Exec(r.Context(), `UPDATE policy_suggestions SET status='published',rule_set_id=$1,rule_set_version=$2,reviewer=$3,review_note=$4,updated_at=now() WHERE id=$5 AND tenant_id=$6 AND status='pending_approval'`, rsID, version, user.ID, strings.TrimSpace(req.ReviewNote), id, user.TenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to update policy suggestion")
			return
		}
		logAudit(r, deps, "policy_suggestion.publish", map[string]any{"id": id, "rule_set_id": rsID, "rule_set_version": version, "rule_id": rule.ID}, "policy_suggestion", id)
		writeJSON(w, map[string]any{"id": id, "status": "published", "rule_set_id": rsID, "rule_set_version": version})
	}
}
