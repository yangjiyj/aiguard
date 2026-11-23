package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

const (
	securityReplyPolicySchemaVersion = 1
	maxSecurityReplyTemplateRunes    = 1000
	maxSecurityReplyPolicyBodyBytes  = 16 << 10
)

var securityReplyTemplateKeys = []string{"default", "prompt_injection", "content_safety", "data_leak"}

type SecurityReplyPolicy struct {
	SchemaVersion int               `json:"schema_version"`
	Enabled       bool              `json:"enabled"`
	Templates     map[string]string `json:"templates"`
}

type securityReplyPolicyUpdate struct {
	Enabled   bool              `json:"enabled"`
	Templates map[string]string `json:"templates"`
}

func defaultSecurityReplyPolicy() SecurityReplyPolicy {
	return SecurityReplyPolicy{
		SchemaVersion: securityReplyPolicySchemaVersion,
		Enabled:       false,
		Templates: map[string]string{
			"default":          "请求已被安全策略拦截。",
			"prompt_injection": "抱歉，您的输入包含异常指令，已记录本次操作。",
			"content_safety":   "无法处理含有违规内容的请求。",
			"data_leak":        "无法处理含有敏感信息的内容。",
		},
	}
}

func securityReplyPolicySettingKey(tenantID string) string {
	return "security_reply_policy:" + tenantID
}

func normalizeSecurityReplyPolicy(policy SecurityReplyPolicy) (SecurityReplyPolicy, error) {
	if policy.SchemaVersion != securityReplyPolicySchemaVersion {
		return SecurityReplyPolicy{}, errors.New("unsupported security reply policy schema")
	}
	if len(policy.Templates) != len(securityReplyTemplateKeys) {
		return SecurityReplyPolicy{}, errors.New("security reply templates must contain every supported category")
	}
	normalized := SecurityReplyPolicy{SchemaVersion: securityReplyPolicySchemaVersion, Enabled: policy.Enabled, Templates: make(map[string]string, len(securityReplyTemplateKeys))}
	for _, key := range securityReplyTemplateKeys {
		value, ok := policy.Templates[key]
		if !ok {
			return SecurityReplyPolicy{}, errors.New("security reply template is missing")
		}
		value = strings.TrimSpace(value)
		if value == "" || len([]rune(value)) > maxSecurityReplyTemplateRunes {
			return SecurityReplyPolicy{}, errors.New("security reply template length is invalid")
		}
		normalized.Templates[key] = value
	}
	return normalized, nil
}

func decodeStoredSecurityReplyPolicy(raw string) (SecurityReplyPolicy, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy SecurityReplyPolicy
	if err := decoder.Decode(&policy); err != nil {
		return SecurityReplyPolicy{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return SecurityReplyPolicy{}, err
	}
	return normalizeSecurityReplyPolicy(policy)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func loadSecurityReplyPolicyContext(ctx context.Context, deps *Dependencies, tenantID string) (SecurityReplyPolicy, error) {
	if deps == nil || deps.SystemRepo == nil {
		return SecurityReplyPolicy{}, errors.New("security reply policy repository is unavailable")
	}
	setting, err := deps.SystemRepo.Get(ctx, securityReplyPolicySettingKey(tenantID))
	if err != nil {
		return SecurityReplyPolicy{}, err
	}
	if setting == nil || strings.TrimSpace(setting.Value) == "" {
		return defaultSecurityReplyPolicy(), nil
	}
	return decodeStoredSecurityReplyPolicy(setting.Value)
}

func loadSecurityReplyPolicy(r *http.Request, deps *Dependencies, tenantID string) (SecurityReplyPolicy, error) {
	return loadSecurityReplyPolicyContext(r.Context(), deps, tenantID)
}

func GetSecurityReplyPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if !isFullTenantRole(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		policy, err := loadSecurityReplyPolicy(r, deps, user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "security_reply_policy_unavailable", "security reply policy is unavailable")
			return
		}
		projection, projectionErr := buildSemanticEngineProjection(r.Context(), deps)
		if projectionErr != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "security_reply_policy_unavailable", "security runtime mode is unavailable")
			return
		}
		auditOnly, ok := projection["security_audit_only"].(bool)
		if !ok {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "security_reply_policy_unavailable", "security runtime mode is unavailable")
			return
		}
		response := struct {
			SecurityReplyPolicy
			SecurityAuditOnly bool `json:"security_audit_only"`
		}{SecurityReplyPolicy: policy, SecurityAuditOnly: auditOnly}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}

func PutSecurityReplyPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		if deps == nil || deps.SystemRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "security_reply_policy_unavailable", "security reply policy is unavailable")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxSecurityReplyPolicyBodyBytes)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var update securityReplyPolicyUpdate
		if err := decoder.Decode(&update); err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "request_too_large", "security reply policy request is too large")
				return
			}
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_security_reply_policy", "security reply policy payload is invalid")
			return
		}
		if err := requireJSONEOF(decoder); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_security_reply_policy", "security reply policy payload is invalid")
			return
		}
		policy, err := normalizeSecurityReplyPolicy(SecurityReplyPolicy{SchemaVersion: securityReplyPolicySchemaVersion, Enabled: update.Enabled, Templates: update.Templates})
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_security_reply_policy", "security reply policy payload is invalid")
			return
		}
		previous, _ := loadSecurityReplyPolicy(r, deps, user.TenantID)
		encoded, _ := json.Marshal(policy)
		key := securityReplyPolicySettingKey(user.TenantID)
		if err := deps.SystemRepo.Set(r.Context(), key, string(bytes.TrimSpace(encoded))); err != nil {
			writeError(w, "internal_error", "failed to save security reply policy")
			return
		}
		changedKeys := make([]string, 0, len(securityReplyTemplateKeys))
		for _, templateKey := range securityReplyTemplateKeys {
			if previous.Templates[templateKey] != policy.Templates[templateKey] {
				changedKeys = append(changedKeys, templateKey)
			}
		}
		sort.Strings(changedKeys)
		logAudit(r, deps, "security_reply_policy.update", map[string]any{"enabled": policy.Enabled, "changed_template_keys": changedKeys}, "system", key)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(policy)
	}
}
