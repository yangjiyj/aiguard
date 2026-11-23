package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
)

const defaultContentRuleSetID = "ruleset_default"
const contentFilePolicySettingKey = "content_file_policy_json"

func contentRuleSetID(tenantID string) string {
	return tenantDefaultRuleSetID(tenantID)
}

func tenantDefaultRuleSetID(tenantID string) string {
	return repository.DefaultSecurityRuleSetID(tenantID)
}

func ensureContentRuleSet(r *http.Request, deps *Dependencies, user *repository.User) bool {
	ruleSetID := contentRuleSetID(user.TenantID)
	_, _, err := deps.RuleSetRepo.Ensure(r.Context(), user.TenantID, &repository.RuleSet{
		ID:         ruleSetID,
		TenantID:   user.TenantID,
		Name:       "默认安全策略",
		Version:    "1.0.0",
		SourceType: "system",
		Published:  true,
		CreatedBy:  user.ID,
	})
	return err == nil
}

func requireContentSecurityAdmin(w http.ResponseWriter, r *http.Request) *repository.User {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "user not found")
		return nil
	}
	if !roles.CanManageSecurityPolicy(user.Role) && user.Role != "tenant_owner" {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can manage content security")
		return nil
	}
	return user
}

func ListContentSecurityRules(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if !ensureContentRuleSet(r, deps, user) {
			writeError(w, "internal_error", "failed to prepare default rule set")
			return
		}
		rulesList, err := deps.RuleSetRepo.ListRules(r.Context(), user.TenantID, contentRuleSetID(user.TenantID))
		if err != nil {
			writeError(w, "internal_error", "failed to list content security rules")
			return
		}
		data := make([]any, 0)
		for _, rule := range rulesList {
			if !isContentSecurityRuleType(rule.RuleType) {
				continue
			}
			data = append(data, mapRuleToInfo(rule))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": data, "total": len(data)})
	}
}

type createSensitiveRuleRequest struct {
	Name       string   `json:"name"`
	Regex      string   `json:"regex"`
	Category   string   `json:"category"`
	Severity   string   `json:"severity"`
	Action     string   `json:"action"`
	Keywords   []string `json:"keywords"`
	FieldNames []string `json:"field_names"`
}

type normalizedSensitiveRuleRequest struct {
	name        string
	ruleType    string
	category    string
	severity    string
	action      string
	matchConfig map[string]any
}

func isContentSecurityRuleType(ruleType string) bool {
	switch ruleType {
	case "regex", "keyword", "field_name", "data_leak":
		return true
	default:
		return false
	}
}

func cleanStringList(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			cleaned = append(cleaned, value)
		}
	}
	return cleaned
}

func normalizeSensitiveRuleRequest(req createSensitiveRuleRequest) (normalizedSensitiveRuleRequest, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Regex = strings.TrimSpace(req.Regex)
	cleanKeywords := cleanStringList(req.Keywords)
	cleanFieldNames := cleanStringList(req.FieldNames)
	if req.Name == "" {
		return normalizedSensitiveRuleRequest{}, errors.New("name is required")
	}

	hasRegex := req.Regex != ""
	hasKeywords := len(cleanKeywords) > 0
	hasFieldNames := len(cleanFieldNames) > 0

	ruleType := ""
	switch {
	case hasRegex:
		ruleType = "regex"
	case hasKeywords:
		ruleType = "keyword"
	case hasFieldNames:
		ruleType = "field_name"
	default:
		return normalizedSensitiveRuleRequest{}, errors.New("regex/keywords/field_names must contain at least one matcher")
	}

	category := strings.TrimSpace(req.Category)
	if category == "" {
		category = "customer_sensitive_data"
	}
	severity := strings.TrimSpace(req.Severity)
	if severity == "" {
		severity = "high"
	}
	action := strings.TrimSpace(req.Action)
	if action == "" {
		action = "audit"
	}

	matchConfig := map[string]any{"category": category}
	if hasRegex {
		matchConfig["regex"] = req.Regex
	}
	if hasKeywords {
		matchConfig["keywords"] = cleanKeywords
	}
	if hasFieldNames {
		matchConfig["field_names"] = cleanFieldNames
	}

	return normalizedSensitiveRuleRequest{
		name:        req.Name,
		ruleType:    ruleType,
		category:    category,
		severity:    severity,
		action:      action,
		matchConfig: matchConfig,
	}, nil
}

func CreateContentSensitiveRule(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := requireContentSecurityAdmin(w, r)
		if user == nil {
			return
		}
		var req createSensitiveRuleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		normalized, err := normalizeSensitiveRuleRequest(req)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if !ensureContentRuleSet(r, deps, user) {
			writeError(w, "internal_error", "failed to prepare default rule set")
			return
		}
		matchConfig, _ := json.Marshal(normalized.matchConfig)
		rule := &repository.Rule{RuleSetID: contentRuleSetID(user.TenantID), RuleType: normalized.ruleType, Name: normalized.name, Priority: 100, Severity: normalized.severity, MatchConfigJSON: matchConfig, Action: normalized.action, Enabled: true, Description: "客户自定义敏感数据规则"}
		if err := deps.RuleRepo.Create(r.Context(), user.TenantID, rule); err != nil {
			writeError(w, "internal_error", "failed to create sensitive data rule")
			return
		}
		logAudit(r, deps, "content_sensitive_rule.create", map[string]any{"rule_id": rule.ID, "name": rule.Name, "category": normalized.category}, "rule", rule.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(mapRuleToInfo(rule))
	}
}

func ListContentAuditExceptions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		exceptions, err := deps.RuleRepo.ListContentAuditExceptionsByTenant(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to list content audit exceptions")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": exceptions, "total": len(exceptions)})
	}
}

type createContentExceptionRequest struct {
	ScopeType       string `json:"scope_type"`
	ScopeRef        string `json:"scope_ref"`
	IncludeChildren bool   `json:"include_children"`
	RuleID          string `json:"rule_id"`
	RuleRef         string `json:"rule_ref"`
	Decision        string `json:"decision"`
	Reason          string `json:"reason"`
	ExpiresAt       string `json:"expires_at"`
}

const maxContentExceptionRequestBytes = 16 << 10

func CreateContentAuditException(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := requireContentSecurityAdmin(w, r)
		if user == nil {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxContentExceptionRequestBytes)
		var req createContentExceptionRequest
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&req); err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "request_too_large", "content exception payload is too large")
				return
			}
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "request_too_large", "content exception payload is too large")
				return
			}
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "request body must contain exactly one JSON object")
			return
		}
		// 有效期：空串=旧默认 7 天（旧前端语义不变）；"never"=永久（NULL）；否则 RFC3339
		var expiresAt *time.Time
		switch strings.TrimSpace(req.ExpiresAt) {
		case "":
			t := time.Now().Add(7 * 24 * time.Hour)
			expiresAt = &t
		case "never", "permanent":
			expiresAt = nil
		default:
			parsed, err := time.Parse(time.RFC3339, req.ExpiresAt)
			if err != nil {
				writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_expires_at", "expires_at must be RFC3339 or \"never\"")
				return
			}
			expiresAt = &parsed
		}
		exception := &repository.ContentAuditException{TenantID: user.TenantID, ScopeType: req.ScopeType, ScopeRef: req.ScopeRef, IncludeChildren: req.IncludeChildren, RuleID: req.RuleID, RuleRef: strings.TrimSpace(req.RuleRef), Decision: req.Decision, Reason: strings.TrimSpace(req.Reason), ExpiresAt: expiresAt, Enabled: true, CreatedBy: user.ID}
		if err := repository.NormalizeAndValidateContentAuditException(exception); err != nil {
			message := strings.TrimSpace(strings.TrimPrefix(err.Error(), repository.ErrInvalidContentAuditException.Error()+":"))
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_exception", message)
			return
		}
		if !validateContentExceptionScopeOwnership(w, r, deps, exception) {
			return
		}
		if deps == nil || deps.RuleRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "content_exception_unavailable", "content exception storage is unavailable")
			return
		}
		if err := deps.RuleRepo.CreateContentAuditException(r.Context(), exception); err != nil {
			if errors.Is(err, repository.ErrInvalidContentAuditException) {
				message := strings.TrimSpace(strings.TrimPrefix(err.Error(), repository.ErrInvalidContentAuditException.Error()+":"))
				writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_exception", message)
				return
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to create content audit exception")
			return
		}
		logAudit(r, deps, "content_exception.create", map[string]any{
			"exception_id":     exception.ID,
			"scope_type":       exception.ScopeType,
			"scope_ref":        exception.ScopeRef,
			"include_children": exception.IncludeChildren,
			"rule_id":          exception.RuleID,
			"rule_ref":         exception.RuleRef,
			"expires_at":       exception.ExpiresAt,
		}, "content_audit_exception", exception.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(exception)
	}
}

func validateContentExceptionScopeOwnership(
	w http.ResponseWriter,
	r *http.Request,
	deps *Dependencies,
	exception *repository.ContentAuditException,
) bool {
	switch exception.ScopeType {
	case "key_v1":
		var lookup ContentExceptionKeyLookup
		if deps != nil {
			lookup = deps.ContentExceptionKeyLookup
			if lookup == nil {
				lookup = deps.QuotaKeyLookup
			}
			if lookup == nil && deps.KeyRepo != nil {
				lookup = deps.KeyRepo
			}
		}
		if lookup == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "content_exception_scope_unavailable", "key scope validation is unavailable")
			return false
		}
		key, err := lookup.GetByID(r.Context(), exception.TenantID, exception.ScopeRef)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to validate exception key scope")
			return false
		}
		if key == nil || key.ID != exception.ScopeRef || key.TenantID != exception.TenantID {
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_scope_ref", "key scope_ref does not belong to the current tenant")
			return false
		}
	case "actor_department_v1":
		var lookup ContentExceptionTeamLookup
		if deps != nil {
			lookup = deps.ContentExceptionTeamLookup
			if lookup == nil && deps.TeamRepo != nil {
				lookup = deps.TeamRepo
			}
		}
		if lookup == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "content_exception_scope_unavailable", "department scope validation is unavailable")
			return false
		}
		team, err := lookup.GetByID(r.Context(), exception.ScopeRef)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to validate exception department scope")
			return false
		}
		if team == nil || team.ID != exception.ScopeRef || team.TenantID != exception.TenantID {
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_scope_ref", "department scope_ref does not belong to the current tenant")
			return false
		}
	}
	return true
}

func DeleteContentAuditException(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := requireContentSecurityAdmin(w, r)
		if user == nil {
			return
		}
		exceptionID := chi.URLParam(r, "id")
		deleted, err := deps.RuleRepo.DisableContentAuditException(r.Context(), user.TenantID, exceptionID)
		if err != nil {
			writeError(w, "internal_error", "failed to delete content audit exception")
			return
		}
		if !deleted {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "content audit exception not found")
			return
		}
		logAudit(r, deps, "content_exception.delete", map[string]any{"exception_id": exceptionID}, "content_audit_exception", exceptionID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// defaultContentFilePolicy 是租户没有保存文件策略时的默认值：控制台和门户的文件策略接口展示它，
// 门户上传在控制面侧按它的大小上限检查。此时规则包不带 file_policy，引擎按自身缺省执行：不用
// 允许、复核名单，大小与压缩包上限取引擎环境变量，可执行、伪装、脚本、未知类型、压缩炸弹按各自
// 处置字段的缺省（告警放行）。两边都不按类型阻断，所以这里不列阻断类型（2.9.22 审查第 2 项）；
// 允许、复核名单要保存后才下发给引擎。已保存策略里的 blocked_types 属于管理员显式配置，原样保留。
func defaultContentFilePolicy() rules.FilePolicy {
	return rules.FilePolicy{
		AllowedTypes: []string{"pdf", "png", "jpeg", "webp"}, BlockedTypes: []string{}, ReviewTypes: []string{"zip", "gzip", "rar", "7z", "unknown"}, MaxFileMB: 20, MaxZipRatio: 100, MaxAttachments: 10,
		ExecutableAction: defaultFileRiskAction, DisguisedExecutableAction: defaultFileRiskAction, ScriptAction: defaultFileRiskAction,
		UnknownAction: defaultFileRiskAction, ZipBombAction: defaultFileRiskAction,
		UnverifiedFileReferenceAction: defaultFileRiskAction, FileReferenceLookupFailureAction: defaultFileRiskAction,
	}
}

func GetContentFilePolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		policy := defaultContentFilePolicy()
		if deps == nil || deps.SystemRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "file_policy_unavailable", "file policy is unavailable")
			return
		}
		key := contentFilePolicySettingKeyForTenant(user.TenantID)
		setting, err := deps.SystemRepo.Get(r.Context(), key)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "file_policy_unavailable", "file policy is unavailable")
			return
		}
		if setting != nil && strings.TrimSpace(setting.Value) != "" {
			policy, err = decodeAndNormalizeFilePolicy([]byte(setting.Value))
			if err != nil {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "file_policy_invalid", "stored file policy is invalid")
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(filePolicyResponse(policy))
	}
}

func UpdateContentFilePolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := requireContentSecurityAdmin(w, r)
		if user == nil {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxFilePolicyBytes)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_file_policy", "file policy payload is invalid")
			return
		}
		policy, err := decodeAndNormalizeFilePolicy(raw)
		if err != nil {
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_file_policy", "file policy payload is invalid")
			return
		}
		encoded, _ := json.Marshal(policy)
		key := contentFilePolicySettingKeyForTenant(user.TenantID)
		if deps == nil || deps.SystemRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "file_policy_unavailable", "file policy is unavailable")
			return
		}
		if err := deps.SystemRepo.Set(r.Context(), key, string(encoded)); err != nil {
			writeError(w, "internal_error", "failed to save file policy")
			return
		}
		logAudit(r, deps, "content_file_policy.update", map[string]any{"policy": policy}, "system", key)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(filePolicyResponse(policy))
	}
}

// filePolicyResponse 把文件策略写成响应：三个类型名单即使为空也明确输出空数组。
// 存储与规则包仍用 rules.FilePolicy 原样（omitempty）；只是控制台在字段缺失时会回落到
// 它自己的默认名单（含 executable、script 阻断），原样保存就会多出类型阻断（2.9.22 审查第 2 项）。
func filePolicyResponse(policy rules.FilePolicy) map[string]any {
	encoded, _ := json.Marshal(policy)
	out := map[string]any{}
	_ = json.Unmarshal(encoded, &out)
	for key, values := range map[string][]string{
		"allowed_types": policy.AllowedTypes, "blocked_types": policy.BlockedTypes, "review_types": policy.ReviewTypes,
	} {
		if values == nil {
			values = []string{}
		}
		out[key] = values
	}
	return out
}
