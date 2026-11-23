package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrSecurityPolicyNotFound     = errors.New("security policy not found")
	ErrInvalidSecurityPolicy      = errors.New("invalid security policy")
	ErrPolicyDetectionRequired    = errors.New("policy detection basis is required")
	ErrPolicyDetectionConflict    = errors.New("policy matcher and capabilities cannot be configured together")
	ErrPolicyRuntimeValidation    = errors.New("policy matcher runtime validation is required")
	ErrPolicyActionUnsupported    = errors.New("policy action is not supported")
	ErrSystemPolicyFieldReadOnly  = errors.New("system policy field is read-only")
	ErrInvalidSubjectBinding      = errors.New("security policy subject binding is invalid")
	ErrSecurityPolicyNotDeletable = errors.New("built-in security policy cannot be deleted")
)

// securityPolicyDeletedKey marks a deleted organization policy inside rules.scope_json.
// security_events.rule_id references rules(id), so the row stays as a tombstone: disabled (never
// compiled for the engine), hidden from every policy listing, but still resolvable by the audit
// joins that print the policy name next to historical alerts.
const securityPolicyDeletedKey = "deleted_at"

// ruleNotDeletedSQL keeps tombstones out of a query over `rules r`.
const ruleNotDeletedSQL = `NOT jsonb_exists(COALESCE(r.scope_json,'{}'::jsonb),'` + securityPolicyDeletedKey + `')`

type SecurityPolicyCapability struct {
	ID               string   `json:"-"`
	Category         string   `json:"category"`
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	Component        string   `json:"-"`
	Enabled          bool     `json:"enabled"`
	BindingMode      string   `json:"binding_mode"`
	SupportedStages  []string `json:"supported_stages"`
	AllowedActions   []string `json:"allowed_actions"`
	MaskCapable      bool     `json:"mask_capable"`
	BoundPolicyCount int      `json:"bound_policy_count,omitempty"`
}

type SecurityPolicy struct {
	Redaction *SecurityPolicyRedaction `json:"redaction,omitempty"`
	// SemanticAction 是控制台「智能分析命中时」：audit（缺省）/block/observe，只作用于语义裁判 finding。
	SemanticAction     string `json:"semantic_action"`
	ID                 string `json:"id"`
	PolicyCode         string `json:"-"`
	RuleType           string `json:"rule_type"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	Scene              string `json:"scene"`
	Severity           string `json:"severity"`
	DefaultSeverity    string `json:"default_severity"`
	SeverityOverridden bool   `json:"severity_overridden"`
	// PreviousSeverity / UpdatedSeverity 是 UpdateSecurityPolicy 在同一事务内（已持锁）读到的
	// 改前与改后生效级别，仅供审计，不对外序列化。
	PreviousSeverity    string                     `json:"-"`
	UpdatedSeverity     string                     `json:"-"`
	Action              string                     `json:"action"`
	Enabled             bool                       `json:"enabled"`
	Source              string                     `json:"source"`
	Ownership           string                     `json:"ownership"`
	Origin              string                     `json:"origin"`
	Industry            string                     `json:"industry"`
	DetectionBasis      string                     `json:"detection_basis"`
	DetectionConfigured bool                       `json:"detection_configured"`
	DetectionReady      bool                       `json:"detection_ready"`
	DetectionIssue      string                     `json:"detection_issue,omitempty"`
	UnavailableCount    int                        `json:"unavailable_capability_count"`
	Capabilities        []SecurityPolicyCapability `json:"capabilities"`
	MatchConfigJSON     json.RawMessage            `json:"matcher,omitempty"`
	// InternalMatchConfigJSON is available to trusted control-plane handlers
	// for exact-runtime re-attestation. It is never serialized to customers.
	InternalMatchConfigJSON json.RawMessage               `json:"-"`
	SubjectBinding          *SecurityPolicySubjectBinding `json:"subject_binding,omitempty"`
	Authoring               *SecurityPolicyAuthoring      `json:"authoring,omitempty"`
}

type SecurityPolicyAuthoring struct {
	Source         string                        `json:"source,omitempty"`
	Version        int                           `json:"version"`
	Kind           string                        `json:"kind"`
	MatcherPattern string                        `json:"matcher_pattern"`
	Segments       []SecurityPolicyNumberSegment `json:"segments"`
}

type SecurityPolicyNumberSegment struct {
	Kind   string `json:"kind"`
	Value  string `json:"value,omitempty"`
	Length int    `json:"length,omitempty"`
}

type SecurityPolicySubjectBinding struct {
	TenantIDs                          []string `json:"tenant_ids,omitempty"`
	ActorUserIDs                       []string `json:"actor_user_ids,omitempty"`
	KeyOwnerUserIDs                    []string `json:"key_owner_user_ids,omitempty"`
	PersonnelDepartmentIDs             []string `json:"personnel_department_ids,omitempty"`
	PersonnelDepartmentIncludeChildren bool     `json:"personnel_department_include_children,omitempty"`
	ProjectIDs                         []string `json:"project_ids,omitempty"`
	ApplicationDepartmentIDs           []string `json:"application_department_ids,omitempty"`
	KeyIDs                             []string `json:"key_ids,omitempty"`
	Protocols                          []string `json:"protocols,omitempty"`
	EntryPoints                        []string `json:"entry_points,omitempty"`
	ModelIDs                           []string `json:"model_ids,omitempty"`
}

type SecurityPolicyMatcherInput struct {
	Type             string          `json:"type"`
	ConfigJSON       json.RawMessage `json:"config"`
	RuntimeValidated bool            `json:"-"`
}

type CreateSecurityPolicyInput struct {
	Redaction            *SecurityPolicyRedaction
	SemanticAction       string
	Name                 string
	Description          string
	Scene                string
	Severity             string
	Action               string
	Enabled              bool
	Matcher              *SecurityPolicyMatcherInput
	CapabilityCategories []string
	BindingMode          string
	SubjectBinding       *SecurityPolicySubjectBinding
	Authoring            *SecurityPolicyAuthoring
}

type SecurityPolicyUpdate struct {
	Redaction            *SecurityPolicyRedaction
	SemanticAction       *string
	Name                 *string
	Description          *string
	Scene                *string
	Severity             *string
	Action               *string
	Enabled              *bool
	Matcher              *SecurityPolicyMatcherInput
	ClearMatcher         bool
	CapabilityCategories *[]string
	BindingMode          *string
	// RuntimeValidated is an internal attestation signal used to stamp an
	// existing built-in regex after the exact Python runtime accepted it.
	RuntimeValidated    bool
	SubjectBinding      *SecurityPolicySubjectBinding
	ClearSubjectBinding bool
	Authoring           *SecurityPolicyAuthoring
}

type SecurityPolicyBatchUpdate struct {
	ID     string
	Update SecurityPolicyUpdate
}

type securityPolicyQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func invalidSecurityPolicy(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSecurityPolicy, fmt.Sprintf(format, args...))
}

func validPolicyScene(scene string) bool {
	scene = strings.TrimSpace(scene)
	if len(scene) < 2 || len(scene) > 64 {
		return false
	}
	for index, ch := range scene {
		if ch >= 'a' && ch <= 'z' {
			continue
		}
		if index > 0 && (ch == '_' || ch >= '0' && ch <= '9') {
			continue
		}
		return false
	}
	return true
}

func defaultPolicyScene(ruleType string) string {
	if _, exists := defaultSubRules[ruleType]; exists {
		return ruleType
	}
	switch ruleType {
	case "regex", "keyword", "field_name":
		return "custom_rules"
	default:
		return "unclassified"
	}
}

func policyScene(ruleType string, scopeJSON []byte) string {
	var scope map[string]any
	if json.Unmarshal(scopeJSON, &scope) == nil {
		if scene, ok := scope["scene"].(string); ok && validPolicyScene(scene) {
			return strings.TrimSpace(scene)
		}
	}
	return defaultPolicyScene(ruleType)
}

func scopeWithScene(scopeJSON []byte, scene string) ([]byte, error) {
	scope := map[string]any{}
	if len(scopeJSON) > 0 && string(scopeJSON) != "null" {
		if err := json.Unmarshal(scopeJSON, &scope); err != nil {
			return nil, invalidSecurityPolicy("scope is invalid JSON")
		}
	}
	scope["scene"] = strings.TrimSpace(scene)
	return json.Marshal(scope)
}

func normalizeBindingValues(values []string, lower bool) ([]string, error) {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if lower {
			value = strings.ToLower(value)
		}
		if value == "" || utf8.RuneCountInString(value) > 256 {
			return nil, ErrInvalidSubjectBinding
		}
		if lower {
			for index, ch := range value {
				if ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || index > 0 && (ch == '_' || ch == '-' || ch == '.' || ch == ':') {
					continue
				}
				return nil, ErrInvalidSubjectBinding
			}
		}
		seen[value] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func NormalizeSecurityPolicySubjectBinding(input *SecurityPolicySubjectBinding) (*SecurityPolicySubjectBinding, error) {
	if input == nil {
		return nil, nil
	}
	out := *input
	var err error
	for values, target := range map[*[]string]bool{
		&out.TenantIDs: false, &out.ActorUserIDs: false, &out.KeyOwnerUserIDs: false,
		&out.PersonnelDepartmentIDs: false, &out.ProjectIDs: false,
		&out.ApplicationDepartmentIDs: false, &out.KeyIDs: false,
		&out.Protocols: true, &out.EntryPoints: true, &out.ModelIDs: false,
	} {
		*values, err = normalizeBindingValues(*values, target)
		if err != nil {
			return nil, err
		}
	}
	if len(out.TenantIDs)+len(out.ActorUserIDs)+len(out.KeyOwnerUserIDs)+len(out.PersonnelDepartmentIDs)+len(out.ProjectIDs)+len(out.ApplicationDepartmentIDs)+len(out.KeyIDs)+len(out.Protocols)+len(out.EntryPoints)+len(out.ModelIDs) == 0 {
		if out.PersonnelDepartmentIncludeChildren {
			return nil, ErrInvalidSubjectBinding
		}
		return nil, nil
	}
	return &out, nil
}

func ParseSecurityPolicySubjectBinding(scopeJSON []byte) (*SecurityPolicySubjectBinding, bool) {
	trimmed := strings.TrimSpace(string(scopeJSON))
	if trimmed == "" || trimmed == "null" {
		return nil, true
	}
	var scope struct {
		SubjectBinding json.RawMessage `json:"subject_binding"`
	}
	if json.Unmarshal(scopeJSON, &scope) != nil || len(scope.SubjectBinding) == 0 || string(scope.SubjectBinding) == "null" {
		return nil, json.Valid(scopeJSON)
	}
	decoder := json.NewDecoder(strings.NewReader(string(scope.SubjectBinding)))
	decoder.DisallowUnknownFields()
	var binding SecurityPolicySubjectBinding
	if decoder.Decode(&binding) != nil {
		return nil, false
	}
	normalized, err := NormalizeSecurityPolicySubjectBinding(&binding)
	return normalized, err == nil
}

func scopeWithSubjectBinding(scopeJSON []byte, binding *SecurityPolicySubjectBinding) ([]byte, error) {
	var scope map[string]any
	if err := json.Unmarshal(scopeJSON, &scope); err != nil {
		return nil, ErrInvalidSubjectBinding
	}
	if binding == nil {
		delete(scope, "subject_binding")
	} else {
		scope["subject_binding"] = binding
	}
	return json.Marshal(scope)
}

const authoringScopeKey = "_authoring"

func numberSegmentPattern(segments []SecurityPolicyNumberSegment) (string, bool) {
	if len(segments) == 0 || len(segments) > 32 {
		return "", false
	}
	var pattern strings.Builder
	pattern.WriteString(`(?<![A-Za-z0-9_])`)
	total, variable := 0, false
	for _, segment := range segments {
		switch segment.Kind {
		case "fixed":
			if segment.Value == "" || (segment.Length != 0 && segment.Length != len(segment.Value)) {
				return "", false
			}
			for _, char := range segment.Value {
				if char >= 128 || !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-", char) {
					return "", false
				}
				if strings.ContainsRune(`\.+*?^$()[]{}|`, char) {
					pattern.WriteByte(92)
				}
				pattern.WriteRune(char)
			}
			total += len(segment.Value)
		case "digits", "letters":
			if segment.Value != "" || segment.Length < 1 || segment.Length > 18 {
				return "", false
			}
			variable = true
			total += segment.Length
			if segment.Kind == "digits" {
				pattern.WriteString(`[0-9]{`)
			} else {
				pattern.WriteString(`[A-Za-z]{`)
			}
			pattern.WriteString(fmt.Sprint(segment.Length))
			pattern.WriteByte(125)
		default:
			return "", false
		}
	}
	if !variable || total < 6 || total > 32 {
		return "", false
	}
	pattern.WriteString(`(?![A-Za-z0-9_])`)
	return pattern.String(), true
}

func validSecurityPolicyAuthoring(authoring *SecurityPolicyAuthoring, ruleType string, canonical []byte) bool {
	if authoring.IsAgentShield() {
		return true
	}
	if authoring == nil || authoring.Source != "" || authoring.Version != 1 || authoring.Kind != "number" || ruleType != "regex" {
		return false
	}
	pattern, valid := numberSegmentPattern(authoring.Segments)
	matcher, ok := NormalizeRuntimeMatcher(ruleType, canonical)
	return valid && ok && authoring.MatcherPattern == pattern && matcher.Regex == pattern
}

func scopeWithAuthoring(scopeJSON []byte, authoring *SecurityPolicyAuthoring, ruleType string, canonical []byte) ([]byte, error) {
	scope := map[string]any{}
	if err := json.Unmarshal(scopeJSON, &scope); err != nil {
		return nil, invalidSecurityPolicy("scope is invalid JSON")
	}
	delete(scope, authoringScopeKey)
	delete(scope, "number_segments")
	if authoring != nil {
		if !validSecurityPolicyAuthoring(authoring, ruleType, canonical) {
			return nil, invalidSecurityPolicy("authoring must match the regex matcher")
		}
		scope[authoringScopeKey] = authoring
	}
	return json.Marshal(scope)
}

func parseSecurityPolicyAuthoring(scopeJSON []byte, ruleType string, canonical []byte) *SecurityPolicyAuthoring {
	var scope struct {
		Authoring json.RawMessage `json:"_authoring"`
	}
	if json.Unmarshal(scopeJSON, &scope) != nil || len(scope.Authoring) == 0 || string(scope.Authoring) == "null" {
		return nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(scope.Authoring)))
	decoder.DisallowUnknownFields()
	var authoring SecurityPolicyAuthoring
	if decoder.Decode(&authoring) != nil || !validSecurityPolicyAuthoring(&authoring, ruleType, canonical) {
		return nil
	}
	return &authoring
}

func validateBindingOwnership(ctx context.Context, tx pgx.Tx, tenantID string, binding *SecurityPolicySubjectBinding) error {
	if binding == nil {
		return nil
	}
	for _, id := range binding.TenantIDs {
		if id != tenantID {
			return ErrInvalidSubjectBinding
		}
	}
	checks := []struct {
		table string
		ids   []string
	}{
		{"users", binding.ActorUserIDs}, {"users", binding.KeyOwnerUserIDs},
		{"teams", binding.PersonnelDepartmentIDs}, {"projects", binding.ProjectIDs},
		{"teams", binding.ApplicationDepartmentIDs}, {"internal_keys", binding.KeyIDs},
	}
	for _, check := range checks {
		if len(check.ids) == 0 {
			continue
		}
		var count int
		query := fmt.Sprintf(`SELECT COUNT(DISTINCT id) FROM %s WHERE tenant_id=$1 AND id=ANY($2)`, check.table)
		if err := tx.QueryRow(ctx, query, tenantID, check.ids).Scan(&count); err != nil || count != len(check.ids) {
			return ErrInvalidSubjectBinding
		}
	}
	return nil
}

func validatePolicyName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 255 {
		return invalidSecurityPolicy("name must contain 1-255 characters")
	}
	return nil
}

func validatePolicyDescription(description string) error {
	if utf8.RuneCountInString(description) > 4096 {
		return invalidSecurityPolicy("description exceeds 4096 characters")
	}
	return nil
}

func validPolicySeverity(severity string) bool {
	switch severity {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func validPolicyAction(action string) bool {
	switch action {
	case "audit", "mask", "block":
		return true
	default:
		return false
	}
}

func validBindingMode(mode string) bool {
	return mode == "any" || mode == "all"
}

const maxSecurityPolicyMatcherJSONBytes = 16 * 1024

func canonicalMatcherJSON(ruleType string, matcher RuntimeMatcher) ([]byte, error) {
	var value any
	switch ruleType {
	case "regex":
		value = struct {
			Regex string `json:"regex"`
		}{Regex: matcher.Regex}
	case "keyword":
		value = struct {
			Keywords []string `json:"keywords"`
		}{Keywords: matcher.Keywords}
	case "field_name":
		value = struct {
			FieldNames []string `json:"field_names"`
		}{FieldNames: matcher.FieldNames}
	default:
		return nil, invalidSecurityPolicy("matcher type is unsupported")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, invalidSecurityPolicy("matcher cannot be encoded")
	}
	return encoded, nil
}

func normalizeMatcher(input *SecurityPolicyMatcherInput) (string, []byte, error) {
	if input == nil {
		return "", nil, nil
	}
	ruleType := strings.TrimSpace(input.Type)
	config := []byte(input.ConfigJSON)
	if len(config) > maxSecurityPolicyMatcherJSONBytes {
		return "", nil, invalidSecurityPolicy("matcher configuration exceeds 16 KiB")
	}
	matcher, ok := NormalizeRuntimeMatcher(ruleType, config)
	if !ok {
		return "", nil, invalidSecurityPolicy("matcher must be a supported regex, keyword, or field_name configuration")
	}
	switch ruleType {
	case "regex":
		if !IsSafeRuntimeRegex(matcher.Regex) {
			return "", nil, invalidSecurityPolicy("regex does not satisfy the runtime safety contract")
		}
	case "keyword":
		if len(matcher.Keywords) > 100 {
			return "", nil, invalidSecurityPolicy("keyword matcher exceeds 100 values")
		}
		for _, keyword := range matcher.Keywords {
			if utf8.RuneCountInString(keyword) > 256 {
				return "", nil, invalidSecurityPolicy("keyword exceeds 256 characters")
			}
		}
	case "field_name":
		if len(matcher.FieldNames) > 100 {
			return "", nil, invalidSecurityPolicy("field_name matcher exceeds 100 values")
		}
		for _, fieldName := range matcher.FieldNames {
			if utf8.RuneCountInString(fieldName) > 128 {
				return "", nil, invalidSecurityPolicy("field name exceeds 128 characters")
			}
		}
	}
	encoded, err := canonicalMatcherJSON(ruleType, matcher)
	if err != nil {
		return "", nil, err
	}
	return ruleType, encoded, nil
}

func rawMatcherPresent(raw []byte) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "{}" && trimmed != "null"
}

const matcherValidationRuntime = "python_re_v1"

func matcherValidationDigest(canonical []byte) string {
	sum := sha256.Sum256(append([]byte("regex\x00"), canonical...))
	return hex.EncodeToString(sum[:])
}

func scopeWithMatcherValidation(scopeJSON []byte, ruleType string, canonical []byte, validated bool) ([]byte, error) {
	scope := map[string]any{}
	if len(scopeJSON) > 0 && string(scopeJSON) != "null" {
		if err := json.Unmarshal(scopeJSON, &scope); err != nil {
			return nil, invalidSecurityPolicy("scope is invalid JSON")
		}
	}
	delete(scope, "matcher_validation")
	if ruleType == "regex" && validated {
		scope["matcher_validation"] = map[string]any{
			"runtime": matcherValidationRuntime,
			"sha256":  matcherValidationDigest(canonical),
		}
	}
	return json.Marshal(scope)
}

func matcherValidationMatches(scopeJSON, canonical []byte) bool {
	var scope struct {
		Validation struct {
			Runtime string `json:"runtime"`
			SHA256  string `json:"sha256"`
		} `json:"matcher_validation"`
	}
	if json.Unmarshal(scopeJSON, &scope) != nil {
		return false
	}
	return scope.Validation.Runtime == matcherValidationRuntime &&
		scope.Validation.SHA256 == matcherValidationDigest(canonical)
}

func storedMatcherState(ruleType string, raw, scopeJSON []byte) (canonical []byte, present, ready bool, issue string) {
	matcher, ok := NormalizeRuntimeMatcher(ruleType, raw)
	if !ok {
		if rawMatcherPresent(raw) {
			return nil, true, false, "invalid_matcher"
		}
		return nil, false, false, ""
	}
	canonical, err := canonicalMatcherJSON(ruleType, matcher)
	if err != nil {
		return nil, true, false, "invalid_matcher"
	}
	if ruleType == "regex" && !IsSafeRuntimeRegex(matcher.Regex) {
		return canonical, true, false, "unsafe_regex"
	}
	if ruleType == "regex" && !matcherValidationMatches(scopeJSON, canonical) {
		return canonical, true, false, "runtime_validation_required"
	}
	return canonical, true, true, ""
}

func decodeStringArray(raw []byte) []string {
	var values []string
	if json.Unmarshal(raw, &values) != nil {
		return []string{}
	}
	if values == nil {
		return []string{}
	}
	return values
}

func decodePolicyCapabilities(raw []byte) ([]SecurityPolicyCapability, error) {
	if len(raw) == 0 {
		return []SecurityPolicyCapability{}, nil
	}
	var values []struct {
		ID              string          `json:"id"`
		Category        string          `json:"category"`
		Name            string          `json:"name"`
		Kind            string          `json:"kind"`
		Component       string          `json:"component"`
		Enabled         bool            `json:"enabled"`
		BindingMode     string          `json:"binding_mode"`
		SupportedStages json.RawMessage `json:"supported_stages"`
		AllowedActions  json.RawMessage `json:"allowed_actions"`
		MaskCapable     bool            `json:"mask_capable"`
	}
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("decode policy capabilities: %w", err)
	}
	result := make([]SecurityPolicyCapability, 0, len(values))
	for _, value := range values {
		result = append(result, SecurityPolicyCapability{
			ID: value.ID, Category: value.Category, Name: value.Name, Kind: value.Kind,
			Component: value.Component, Enabled: value.Enabled, BindingMode: value.BindingMode,
			SupportedStages: decodeStringArray(value.SupportedStages),
			AllowedActions:  decodeStringArray(value.AllowedActions),
			MaskCapable:     value.MaskCapable,
		})
	}
	return result, nil
}

func capabilityBindingsState(capabilities []SecurityPolicyCapability) (bool, string) {
	if len(capabilities) == 0 {
		return false, ""
	}
	mode := capabilities[0].BindingMode
	if !validBindingMode(mode) {
		return false, "binding_mode_conflict"
	}
	for _, capability := range capabilities[1:] {
		if capability.BindingMode != mode {
			return false, "binding_mode_conflict"
		}
	}
	if mode == "all" {
		for _, capability := range capabilities {
			if !capability.Enabled {
				return false, "capability_unavailable"
			}
		}
		return true, ""
	}
	available := false
	unavailable := false
	for _, capability := range capabilities {
		available = available || capability.Enabled
		unavailable = unavailable || !capability.Enabled
	}
	if available {
		if unavailable {
			return true, "capability_unavailable"
		}
		return true, ""
	}
	return false, "capability_unavailable"
}

func capabilityRuntimeState(capabilities []SecurityPolicyCapability) (bool, string) {
	// This is detector-chain readiness only. The compiler and engine consume the
	// same category/stage/action contract; whether a live node actually loaded
	// the resulting policy is reported separately as runtime_active from receipts.
	return capabilityBindingsState(capabilities)
}

func combineDetectionIssue(ready bool, matcherIssue, capabilityIssue string) string {
	if ready && (matcherIssue != "" || capabilityIssue != "") {
		return "partial_unavailable"
	}
	if matcherIssue != "" {
		return matcherIssue
	}
	return capabilityIssue
}

const securityPoliciesSelect = `
	SELECT r.id, COALESCE(r.policy_code,''), r.rule_type, r.name, COALESCE(r.description,''),
	       COALESCE(bro.severity,r.severity), COALESCE(bro.action,r.action), COALESCE(bro.enabled,r.enabled),
	       CASE WHEN bro.semantic_action IS NULL THEN (CASE WHEN bro.redaction_json IS NULL THEN r.scope_json ELSE COALESCE(r.scope_json,'{}'::jsonb) || jsonb_build_object('redaction',bro.redaction_json) END) ELSE COALESCE((CASE WHEN bro.redaction_json IS NULL THEN r.scope_json ELSE COALESCE(r.scope_json,'{}'::jsonb) || jsonb_build_object('redaction',bro.redaction_json) END),'{}'::jsonb) || jsonb_build_object('semantic_action',bro.semantic_action) END, r.match_config_json,
	       CASE WHEN rs.tenant_id=$1 THEN 'tenant' ELSE 'system' END,
	       COALESCE(rs.industry,'generic'),
	       COALESCE(effective_bindings.capabilities,'[]'::jsonb),
	       CASE WHEN rs.tenant_id=$1 THEN '' ELSE r.severity END, (bro.severity IS NOT NULL)
	FROM rules r
	JOIN rule_sets rs ON rs.id=r.rule_set_id
	JOIN tenants requester ON requester.id=$1
	LEFT JOIN builtin_rule_overrides bro ON bro.tenant_id=$1 AND bro.rule_id=r.id
	LEFT JOIN LATERAL (
	  SELECT jsonb_agg(
	           jsonb_build_object(
	             'id',selected.id,'category',selected.category,'name',selected.name,
	             'kind',selected.capability_kind,'component',selected.component,
	             'enabled',selected.enabled,'binding_mode',selected.binding_mode,
	             'supported_stages',selected.supported_stages,
	             'allowed_actions',selected.allowed_actions,'mask_capable',selected.mask_capable
	           ) ORDER BY selected.priority DESC,selected.category
	         ) AS capabilities
	  FROM (
	    SELECT cap.id,cap.category,cap.name,cap.capability_kind,cap.component,cap.enabled,
	           binding.binding_mode,binding.priority,cap.supported_stages,
	           cap.allowed_actions,cap.mask_capable
	    FROM rule_capability_bindings binding
	    JOIN security_capabilities cap ON cap.id=binding.capability_id
	    WHERE binding.rule_id=r.id AND bro.capability_categories IS NULL
	    UNION ALL
	    SELECT cap.id,cap.category,cap.name,cap.capability_kind,cap.component,cap.enabled,
	           bro.binding_mode,0,cap.supported_stages,cap.allowed_actions,cap.mask_capable
	    FROM security_capabilities cap
	    WHERE bro.capability_categories IS NOT NULL
	      AND bro.capability_categories ? cap.category
	  ) selected
	) effective_bindings ON TRUE
	WHERE rs.published=TRUE
	  AND NOT jsonb_exists(COALESCE(r.scope_json,'{}'::jsonb),'deleted_at')
	  AND ($2::text='' OR r.id=$2)
	  AND (
	    rs.tenant_id=$1
	    OR (
	      rs.tenant_id=$3 AND rs.source_type='builtin'
	      AND COALESCE(rs.industry,'generic') IN (
	        'generic',COALESCE(NULLIF(BTRIM(requester.industry),''),'generic')
	      )
	    )
	  )
	ORDER BY CASE WHEN rs.tenant_id=$1 THEN 0 ELSE 1 END,
	         COALESCE(rs.industry,'generic'),r.priority DESC,r.created_at,r.id`

func querySecurityPolicies(ctx context.Context, queryer securityPolicyQuerier, tenantID, policyID string) ([]SecurityPolicy, error) {
	rows, err := queryer.Query(ctx, securityPoliciesSelect, tenantID, policyID, SystemTenantID)
	if err != nil {
		return nil, fmt.Errorf("list security policies: %w", err)
	}
	defer rows.Close()
	policies := make([]SecurityPolicy, 0)
	for rows.Next() {
		var policy SecurityPolicy
		var scopeJSON, matchJSON, capabilityJSON []byte
		if err := rows.Scan(
			&policy.ID, &policy.PolicyCode, &policy.RuleType, &policy.Name, &policy.Description,
			&policy.Severity, &policy.Action, &policy.Enabled, &scopeJSON, &matchJSON,
			&policy.Source, &policy.Industry, &capabilityJSON,
			&policy.DefaultSeverity, &policy.SeverityOverridden,
		); err != nil {
			return nil, fmt.Errorf("scan security policy: %w", err)
		}
		capabilities, err := decodePolicyCapabilities(capabilityJSON)
		if err != nil {
			return nil, err
		}
		policy.Capabilities = capabilities
		if policy.Source == "system" {
			policy.Ownership = "platform"
		} else {
			policy.Ownership = "organization"
		}
		if policy.Source == "system" || strings.HasPrefix(policy.PolicyCode, "builtin.") || strings.HasPrefix(policy.PolicyCode, "system.") {
			policy.Origin = "preloaded"
		} else {
			policy.Origin = "organization_created"
		}
		policy.Scene = policyScene(policy.RuleType, scopeJSON)
		policy.SubjectBinding, _ = ParseSecurityPolicySubjectBinding(scopeJSON)
		policy.Redaction, _ = ParseSecurityPolicyRedaction(scopeJSON)
		policy.SemanticAction = ParseSecurityPolicySemanticAction(scopeJSON)
		if policy.Source == "tenant" {
			policy.Authoring = parseSecurityPolicyAuthoring(scopeJSON, policy.RuleType, matchJSON)
		}
		canonicalMatcher, matcherPresent, matcherReady, matcherIssue := storedMatcherState(policy.RuleType, matchJSON, scopeJSON)
		if matcherPresent && len(canonicalMatcher) > 0 {
			policy.InternalMatchConfigJSON = append(json.RawMessage(nil), canonicalMatcher...)
		}
		capabilityReady, capabilityIssue := capabilityRuntimeState(capabilities)
		switch {
		case matcherPresent && len(capabilities) > 0:
			policy.DetectionBasis = "conflict"
		case matcherPresent:
			policy.DetectionBasis = "matcher"
		case len(capabilities) > 0:
			policy.DetectionBasis = "capability"
		default:
			policy.DetectionBasis = "none"
		}
		for _, capability := range capabilities {
			if !capability.Enabled {
				policy.UnavailableCount++
			}
		}
		policy.DetectionConfigured = matcherPresent || len(capabilities) > 0
		if policy.DetectionBasis == "conflict" {
			policy.DetectionReady = false
			policy.DetectionIssue = "conflicting_detection_basis"
		} else {
			policy.DetectionReady = matcherReady || capabilityReady
			policy.DetectionIssue = combineDetectionIssue(policy.DetectionReady, matcherIssue, capabilityIssue)
		}
		if policy.Source == "tenant" && matcherPresent && len(canonicalMatcher) > 0 {
			policy.MatchConfigJSON = append(json.RawMessage(nil), canonicalMatcher...)
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate security policies: %w", err)
	}
	return policies, nil
}

func (r *RuleRepository) ListSecurityPolicies(ctx context.Context, tenantID string) ([]SecurityPolicy, error) {
	return querySecurityPolicies(ctx, r.db, tenantID, "")
}

func (r *RuleRepository) GetSecurityPolicy(ctx context.Context, tenantID, policyID string) (*SecurityPolicy, error) {
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil, ErrSecurityPolicyNotFound
	}
	policies, err := querySecurityPolicies(ctx, r.db, tenantID, policyID)
	if err != nil {
		return nil, err
	}
	if len(policies) == 0 {
		return nil, ErrSecurityPolicyNotFound
	}
	return &policies[0], nil
}

func (r *RuleRepository) ListSecurityCapabilities(ctx context.Context) ([]SecurityPolicyCapability, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id,category,name,capability_kind,component,enabled,
		       supported_stages,allowed_actions,mask_capable
		FROM security_capabilities
		ORDER BY capability_kind,category`)
	if err != nil {
		return nil, fmt.Errorf("list security capabilities: %w", err)
	}
	defer rows.Close()
	result := make([]SecurityPolicyCapability, 0)
	for rows.Next() {
		var capability SecurityPolicyCapability
		var stages, actions []byte
		if err := rows.Scan(
			&capability.ID, &capability.Category, &capability.Name, &capability.Kind,
			&capability.Component, &capability.Enabled, &stages, &actions, &capability.MaskCapable,
		); err != nil {
			return nil, fmt.Errorf("scan security capability: %w", err)
		}
		capability.SupportedStages = decodeStringArray(stages)
		capability.AllowedActions = decodeStringArray(actions)
		result = append(result, capability)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate security capabilities: %w", err)
	}
	return result, nil
}

type lockedSecurityPolicy struct {
	ID                     string
	OwnerTenant            string
	SourceType             string
	Industry               string
	PolicyCode             string
	RuleType               string
	Name                   string
	Description            string
	Severity               string
	BaseSeverity           string
	Action                 string
	Enabled                bool
	ScopeJSON              []byte
	MatchJSON              []byte
	CapabilityOverrideJSON []byte
	BindingModeOverride    *string
	SemanticActionOverride *string
}

func lockSecurityPolicy(ctx context.Context, tx pgx.Tx, tenantID, policyID string) (lockedSecurityPolicy, error) {
	var policy lockedSecurityPolicy
	err := tx.QueryRow(ctx, `
		SELECT r.id,rs.tenant_id,COALESCE(rs.source_type,''),COALESCE(rs.industry,'generic'),
		       COALESCE(r.policy_code,''),r.rule_type,r.name,COALESCE(r.description,''),
		       COALESCE(bro.severity,r.severity),COALESCE(bro.action,r.action),COALESCE(bro.enabled,r.enabled),
		       r.scope_json,r.match_config_json,bro.capability_categories,bro.binding_mode,bro.semantic_action,r.severity
		FROM rules r
		JOIN rule_sets rs ON rs.id=r.rule_set_id
		JOIN tenants requester ON requester.id=$1
		LEFT JOIN builtin_rule_overrides bro ON bro.tenant_id=$1 AND bro.rule_id=r.id
		WHERE r.id=$2 AND rs.published=TRUE
		  AND NOT jsonb_exists(COALESCE(r.scope_json,'{}'::jsonb),'deleted_at')
		  AND (
		    rs.tenant_id=$1
		    OR (
		      rs.tenant_id=$3 AND rs.source_type='builtin'
		      AND COALESCE(rs.industry,'generic') IN (
		        'generic',COALESCE(NULLIF(BTRIM(requester.industry),''),'generic')
		      )
		    )
		  )
		FOR UPDATE OF r`,
		tenantID, strings.TrimSpace(policyID), SystemTenantID,
	).Scan(
		&policy.ID, &policy.OwnerTenant, &policy.SourceType, &policy.Industry,
		&policy.PolicyCode, &policy.RuleType, &policy.Name, &policy.Description,
		&policy.Severity, &policy.Action, &policy.Enabled, &policy.ScopeJSON, &policy.MatchJSON,
		&policy.CapabilityOverrideJSON, &policy.BindingModeOverride, &policy.SemanticActionOverride,
		&policy.BaseSeverity,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedSecurityPolicy{}, ErrSecurityPolicyNotFound
	}
	if err != nil {
		return lockedSecurityPolicy{}, fmt.Errorf("lock security policy: %w", err)
	}
	return policy, nil
}

func loadRuleCapabilities(ctx context.Context, tx pgx.Tx, ruleID string) ([]SecurityPolicyCapability, error) {
	rows, err := tx.Query(ctx, `
		SELECT cap.id,cap.category,cap.name,cap.capability_kind,cap.component,cap.enabled,
		       binding.binding_mode,cap.supported_stages,cap.allowed_actions,cap.mask_capable
		FROM rule_capability_bindings binding
		JOIN security_capabilities cap ON cap.id=binding.capability_id
		WHERE binding.rule_id=$1
		ORDER BY binding.priority DESC,cap.category`, ruleID)
	if err != nil {
		return nil, fmt.Errorf("load policy capabilities: %w", err)
	}
	defer rows.Close()
	capabilities := make([]SecurityPolicyCapability, 0)
	for rows.Next() {
		var capability SecurityPolicyCapability
		var stages, actions []byte
		if err := rows.Scan(
			&capability.ID, &capability.Category, &capability.Name, &capability.Kind,
			&capability.Component, &capability.Enabled, &capability.BindingMode,
			&stages, &actions, &capability.MaskCapable,
		); err != nil {
			return nil, fmt.Errorf("scan policy capability: %w", err)
		}
		capability.SupportedStages = decodeStringArray(stages)
		capability.AllowedActions = decodeStringArray(actions)
		capabilities = append(capabilities, capability)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy capabilities: %w", err)
	}
	return capabilities, nil
}

func normalizeCapabilityCategories(categories []string) ([]string, error) {
	if len(categories) > 32 {
		return nil, invalidSecurityPolicy("a policy cannot bind more than 32 capabilities")
	}
	result := make([]string, 0, len(categories))
	seen := make(map[string]bool, len(categories))
	for _, category := range categories {
		category = strings.TrimSpace(category)
		if category == "" {
			return nil, invalidSecurityPolicy("capability category cannot be blank")
		}
		if seen[category] {
			return nil, invalidSecurityPolicy("duplicate capability category %s", category)
		}
		seen[category] = true
		result = append(result, category)
	}
	sort.Strings(result)
	return result, nil
}

func loadCapabilitiesByCategory(ctx context.Context, tx pgx.Tx, categories []string, bindingMode string, requireEnabled bool) ([]SecurityPolicyCapability, error) {
	categories, err := normalizeCapabilityCategories(categories)
	if err != nil {
		return nil, err
	}
	if len(categories) == 0 {
		return []SecurityPolicyCapability{}, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT id,category,name,capability_kind,component,enabled,
		       supported_stages,allowed_actions,mask_capable
		FROM security_capabilities
		WHERE category=ANY($1) AND (NOT $2 OR enabled=TRUE)
		ORDER BY category`, categories, requireEnabled)
	if err != nil {
		return nil, fmt.Errorf("validate policy capabilities: %w", err)
	}
	defer rows.Close()
	capabilities := make([]SecurityPolicyCapability, 0, len(categories))
	for rows.Next() {
		var capability SecurityPolicyCapability
		var stages, actions []byte
		if err := rows.Scan(
			&capability.ID, &capability.Category, &capability.Name, &capability.Kind,
			&capability.Component, &capability.Enabled, &stages, &actions, &capability.MaskCapable,
		); err != nil {
			return nil, fmt.Errorf("scan policy capability validation: %w", err)
		}
		capability.BindingMode = bindingMode
		capability.SupportedStages = decodeStringArray(stages)
		capability.AllowedActions = decodeStringArray(actions)
		capabilities = append(capabilities, capability)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy capability validation: %w", err)
	}
	if len(capabilities) != len(categories) {
		if requireEnabled {
			return nil, invalidSecurityPolicy("one or more capabilities are missing or disabled")
		}
		return nil, invalidSecurityPolicy("one or more configured capabilities are missing")
	}
	return capabilities, nil
}

func loadEnabledCapabilitiesByCategory(ctx context.Context, tx pgx.Tx, categories []string, bindingMode string) ([]SecurityPolicyCapability, error) {
	return loadCapabilitiesByCategory(ctx, tx, categories, bindingMode, true)
}

func loadEffectiveSystemCapabilities(ctx context.Context, tx pgx.Tx, policy lockedSecurityPolicy) ([]SecurityPolicyCapability, string, error) {
	if policy.CapabilityOverrideJSON == nil {
		capabilities, err := loadRuleCapabilities(ctx, tx, policy.ID)
		if err != nil {
			return nil, "", err
		}
		mode := "any"
		if len(capabilities) > 0 && validBindingMode(capabilities[0].BindingMode) {
			mode = capabilities[0].BindingMode
		}
		return capabilities, mode, nil
	}
	if policy.BindingModeOverride == nil || !validBindingMode(*policy.BindingModeOverride) {
		return nil, "", invalidSecurityPolicy("system policy capability override has an invalid binding mode")
	}
	var categories []string
	if err := json.Unmarshal(policy.CapabilityOverrideJSON, &categories); err != nil {
		return nil, "", invalidSecurityPolicy("system policy capability override is invalid")
	}
	categories, err := normalizeCapabilityCategories(categories)
	if err != nil {
		return nil, "", err
	}
	capabilities, err := loadCapabilitiesByCategory(ctx, tx, categories, *policy.BindingModeOverride, false)
	if err != nil {
		return nil, "", err
	}
	return capabilities, *policy.BindingModeOverride, nil
}

func capabilityAllowsAction(capability SecurityPolicyCapability, action string) bool {
	for _, allowed := range capability.AllowedActions {
		if allowed == action {
			return action != "mask" || capability.MaskCapable
		}
	}
	return false
}

func validateCapabilityAction(capabilities []SecurityPolicyCapability, action string) error {
	for _, capability := range capabilities {
		if !capabilityAllowsAction(capability, action) {
			return fmt.Errorf("%w: capability %s does not allow %s", ErrPolicyActionUnsupported, capability.Category, action)
		}
	}
	return nil
}

func validateMatcherAction(ruleType string, matcherPresent bool, action string) error {
	if matcherPresent && action == "mask" && ruleType != "regex" {
		return fmt.Errorf("%w: %s matcher cannot safely mask the matched value", ErrPolicyActionUnsupported, ruleType)
	}
	return nil
}

func replacePolicyBindings(ctx context.Context, tx pgx.Tx, ruleID string, capabilities []SecurityPolicyCapability, bindingMode string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM rule_capability_bindings WHERE rule_id=$1`, ruleID); err != nil {
		return fmt.Errorf("clear policy capability bindings: %w", err)
	}
	for index, capability := range capabilities {
		if _, err := tx.Exec(ctx, `
			INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
			VALUES($1,$2,$3,$4,'{}')`, ruleID, capability.ID, bindingMode, len(capabilities)-index); err != nil {
			return fmt.Errorf("insert policy capability binding: %w", err)
		}
	}
	return nil
}

// DefaultSecurityRuleSetID is the stable tenant-owned rule set used by both
// content-security bootstrap and policy creation.
func DefaultSecurityRuleSetID(tenantID string) string {
	if tenantID == "" || tenantID == "tenant_default" {
		return "ruleset_default"
	}
	sum := sha256.Sum256([]byte(tenantID))
	return "ruleset_content_" + hex.EncodeToString(sum[:8])
}

func (r *RuleRepository) CreateSecurityPolicy(ctx context.Context, tenantID string, input CreateSecurityPolicyInput) (*SecurityPolicy, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	input.Scene = strings.TrimSpace(input.Scene)
	input.Severity = strings.TrimSpace(input.Severity)
	input.Action = strings.TrimSpace(input.Action)
	if err := validatePolicyName(input.Name); err != nil {
		return nil, err
	}
	if err := validatePolicyDescription(input.Description); err != nil {
		return nil, err
	}
	if !validPolicyScene(input.Scene) {
		return nil, invalidSecurityPolicy("scene is invalid")
	}
	if !validPolicySeverity(input.Severity) {
		return nil, invalidSecurityPolicy("severity is invalid")
	}
	if !validPolicyAction(input.Action) {
		return nil, invalidSecurityPolicy("action is invalid")
	}
	matcherType, matcherJSON, err := normalizeMatcher(input.Matcher)
	if err != nil {
		return nil, err
	}
	mode := strings.TrimSpace(input.BindingMode)
	if len(input.CapabilityCategories) > 0 && mode == "" {
		mode = "any"
	}
	if len(input.CapabilityCategories) > 0 && !validBindingMode(mode) {
		return nil, invalidSecurityPolicy("binding mode must be any or all")
	}
	if matcherType != "" && len(input.CapabilityCategories) > 0 {
		return nil, ErrPolicyDetectionConflict
	}
	if err := validateMatcherAction(matcherType, matcherType != "", input.Action); err != nil {
		return nil, err
	}
	if input.Enabled && matcherType == "" && len(input.CapabilityCategories) == 0 {
		return nil, ErrPolicyDetectionRequired
	}
	subjectBinding, err := NormalizeSecurityPolicySubjectBinding(input.SubjectBinding)
	if err != nil {
		return nil, err
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create security policy: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := validateBindingOwnership(ctx, tx, tenantID, subjectBinding); err != nil {
		return nil, err
	}

	capabilities, err := loadEnabledCapabilitiesByCategory(ctx, tx, input.CapabilityCategories, mode)
	if err != nil {
		return nil, err
	}
	if err := validateCapabilityAction(capabilities, input.Action); err != nil {
		return nil, err
	}
	semanticAction, err := NormalizeSecurityPolicySemanticAction(input.SemanticAction)
	if err != nil {
		return nil, err
	}
	if err := validateSemanticActionCapabilities(capabilities, semanticAction); err != nil {
		return nil, err
	}
	ruleSetID := DefaultSecurityRuleSetID(tenantID)
	if err := tx.QueryRow(ctx, `
		SELECT id FROM rule_sets
		WHERE id=$1 AND tenant_id=$2 AND published=TRUE AND source_type <> 'builtin'
		FOR UPDATE`, ruleSetID, tenantID).Scan(&ruleSetID); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRuleSetNotFound
	} else if err != nil {
		return nil, fmt.Errorf("find tenant default rule set: %w", err)
	}
	scopeJSON, err := scopeWithScene([]byte(`{"catalog":"custom_policy","catalog_version":1}`), input.Scene)
	if err != nil {
		return nil, err
	}
	scopeJSON, err = scopeWithRedaction(scopeJSON, input.Redaction)
	if err != nil {
		return nil, err
	}
	scopeJSON, err = scopeWithSemanticAction(scopeJSON, semanticAction)
	if err != nil {
		return nil, err
	}
	scopeJSON, err = scopeWithSubjectBinding(scopeJSON, subjectBinding)
	if err != nil {
		return nil, err
	}
	scopeJSON, err = scopeWithAuthoring(scopeJSON, input.Authoring, matcherType, matcherJSON)
	if err != nil {
		return nil, err
	}
	ruleType := input.Scene
	matchConfig := []byte(`{}`)
	if matcherType != "" {
		ruleType = matcherType
		matchConfig = matcherJSON
	}
	scopeJSON, err = scopeWithMatcherValidation(
		scopeJSON, ruleType, matchConfig,
		input.Matcher != nil && input.Matcher.RuntimeValidated,
	)
	if err != nil {
		return nil, err
	}
	if input.Enabled && ruleType == "regex" && (input.Matcher == nil || !input.Matcher.RuntimeValidated) {
		return nil, ErrPolicyRuntimeValidation
	}
	ruleID := "rule_" + uuid.NewString()
	policyCode := "custom." + uuid.NewString()
	if _, err := tx.Exec(ctx, `
		INSERT INTO rules(
			id,rule_set_id,policy_code,rule_type,name,priority,severity,scope_json,
			match_config_json,action,enabled,description
		) VALUES($1,$2,$3,$4,$5,0,$6,$7,$8,$9,$10,$11)`,
		ruleID, ruleSetID, policyCode, ruleType, input.Name, input.Severity,
		scopeJSON, matchConfig, input.Action, input.Enabled, input.Description,
	); err != nil {
		return nil, fmt.Errorf("insert security policy: %w", err)
	}
	if err := replacePolicyBindings(ctx, tx, ruleID, capabilities, mode); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create security policy: %w", err)
	}
	return r.GetSecurityPolicy(ctx, tenantID, ruleID)
}

func updateHasSystemReadOnlyFields(update SecurityPolicyUpdate) bool {
	return update.Name != nil || update.Description != nil || update.Scene != nil ||
		update.Matcher != nil || update.ClearMatcher ||
		update.CapabilityCategories != nil || update.BindingMode != nil || update.SubjectBinding != nil || update.ClearSubjectBinding || update.Authoring != nil
}

// severityOnlySecurityPolicyUpdate 判断请求是否只改风险等级。只改级别不涉及动作与检测配置，
// 不应被存量动作配置不配套（例如旧数据里的 mask）连累而改不了级别。
func severityOnlySecurityPolicyUpdate(update SecurityPolicyUpdate) bool {
	return update.Severity != nil &&
		update.Name == nil && update.Description == nil && update.Scene == nil &&
		update.Action == nil && update.Enabled == nil &&
		update.Matcher == nil && !update.ClearMatcher &&
		update.CapabilityCategories == nil && update.BindingMode == nil &&
		update.SubjectBinding == nil && !update.ClearSubjectBinding &&
		update.Authoring == nil && update.Redaction == nil &&
		update.SemanticAction == nil && !update.RuntimeValidated
}

// auditOnlySecurityPolicyUpdate 允许“改为 audit”可附带风险等级：级别只影响告警分级，不影响处置。
func auditOnlySecurityPolicyUpdate(update SecurityPolicyUpdate) bool {
	return update.Action != nil &&
		strings.TrimSpace(*update.Action) == "audit" &&
		update.Name == nil &&
		update.Description == nil &&
		update.Scene == nil &&
		update.Enabled == nil &&
		update.Matcher == nil &&
		!update.ClearMatcher &&
		update.CapabilityCategories == nil &&
		update.BindingMode == nil &&
		update.SubjectBinding == nil &&
		!update.ClearSubjectBinding &&
		update.Authoring == nil && update.Redaction == nil &&
		update.SemanticAction == nil &&
		!update.RuntimeValidated
}

func (r *RuleRepository) updateSecurityPolicyTx(ctx context.Context, tx pgx.Tx, tenantID, policyID string, update SecurityPolicyUpdate) error {
	return r.updateSecurityPolicyLocked(ctx, tx, tenantID, policyID, update, nil)
}

// updateSecurityPolicyLocked 是 updateSecurityPolicyTx 的实现；加锁顺序固定为先 advisory 锁、后规则行锁。
// previousSeverity 非空时写入加锁后读到的改前生效级别，调用方无需另行预读（预读会反转锁顺序而死锁）。
func (r *RuleRepository) updateSecurityPolicyLocked(ctx context.Context, tx pgx.Tx, tenantID, policyID string, update SecurityPolicyUpdate, previousSeverity *string) error {
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return ErrSecurityPolicyNotFound
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, tenantID+":"+policyID); err != nil {
		return fmt.Errorf("lock security policy update: %w", err)
	}
	current, err := lockSecurityPolicy(ctx, tx, tenantID, policyID)
	if err != nil {
		return err
	}
	if previousSeverity != nil {
		*previousSeverity = current.Severity
	}
	if _, err := NormalizeSecurityPolicyRedaction(update.Redaction); err != nil {
		return err
	}
	var semanticActionUpdate string
	if update.SemanticAction != nil {
		semanticActionUpdate, err = NormalizeSecurityPolicySemanticAction(*update.SemanticAction)
		if err != nil {
			return err
		}
	}
	auditOnlyUpdate := auditOnlySecurityPolicyUpdate(update)
	severityOnlyUpdate := severityOnlySecurityPolicyUpdate(update)
	if current.OwnerTenant == SystemTenantID {
		// System-owned policies support tenant-scoped capability overrides via
		// builtin_rule_overrides; their definition fields remain immutable.
		if update.Name != nil || update.Description != nil || update.Scene != nil ||
			update.Matcher != nil || update.ClearMatcher ||
			update.SubjectBinding != nil || update.ClearSubjectBinding || update.Authoring != nil {
			return ErrSystemPolicyFieldReadOnly
		}
		capabilities, bindingMode, err := loadEffectiveSystemCapabilities(ctx, tx, current)
		if err != nil {
			return err
		}
		bindingsChanged := update.CapabilityCategories != nil || update.BindingMode != nil
		if update.BindingMode != nil {
			bindingMode = strings.TrimSpace(*update.BindingMode)
			if !validBindingMode(bindingMode) {
				return invalidSecurityPolicy("binding mode must be any or all")
			}
		}
		if update.CapabilityCategories != nil {
			capabilities, err = loadEnabledCapabilitiesByCategory(ctx, tx, *update.CapabilityCategories, bindingMode)
			if err != nil {
				return err
			}
		} else if update.BindingMode != nil {
			if len(capabilities) == 0 {
				return invalidSecurityPolicy("binding mode requires at least one capability")
			}
			categories := make([]string, 0, len(capabilities))
			for _, capability := range capabilities {
				categories = append(categories, capability.Category)
			}
			capabilities, err = loadEnabledCapabilitiesByCategory(ctx, tx, categories, bindingMode)
			if err != nil {
				return err
			}
		}
		if bindingsChanged {
			for index := range capabilities {
				capabilities[index].BindingMode = bindingMode
			}
		}
		_, matcherPresent, _, _ := storedMatcherState(current.RuleType, current.MatchJSON, current.ScopeJSON)
		if matcherPresent && len(capabilities) > 0 {
			return ErrPolicyDetectionConflict
		}
		if update.RuntimeValidated {
			canonical, present, _, _ := storedMatcherState(current.RuleType, current.MatchJSON, current.ScopeJSON)
			if current.RuleType != "regex" || !present || len(canonical) == 0 {
				return invalidSecurityPolicy("runtime attestation requires an existing regex matcher")
			}
			attestedScope, err := scopeWithMatcherValidation(current.ScopeJSON, current.RuleType, canonical, true)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE rules SET scope_json=$1 WHERE id=$2`, attestedScope, current.ID); err != nil {
				return fmt.Errorf("stamp system policy runtime validation: %w", err)
			}
			current.ScopeJSON = attestedScope
		}
		action := current.Action
		var actionOverride *string
		if update.Action != nil {
			action = strings.TrimSpace(*update.Action)
			if !validPolicyAction(action) {
				return invalidSecurityPolicy("action is invalid")
			}
			actionOverride = &action
		}
		if !severityOnlyUpdate {
			if err := validateMatcherAction(current.RuleType, matcherPresent, action); err != nil {
				return err
			}
		}
		enabled := current.Enabled
		var enabledOverride *bool
		if update.Enabled != nil {
			enabled = *update.Enabled
			enabledOverride = &enabled
		}
		if enabled && !auditOnlyUpdate && (update.Action != nil || update.Enabled != nil || bindingsChanged) {
			_, _, matcherReady, matcherIssue := storedMatcherState(current.RuleType, current.MatchJSON, current.ScopeJSON)
			if update.Enabled != nil && current.RuleType == "regex" && !matcherReady {
				if matcherIssue == "runtime_validation_required" {
					return ErrPolicyRuntimeValidation
				}
				return ErrPolicyDetectionRequired
			}
			capabilityReady, _ := capabilityBindingsState(capabilities)
			if !matcherReady && !capabilityReady {
				if matcherIssue == "runtime_validation_required" {
					return ErrPolicyRuntimeValidation
				}
				return ErrPolicyDetectionRequired
			}
		}
		if !severityOnlyUpdate && (update.Action != nil || bindingsChanged || enabled) {
			if err := validateCapabilityAction(capabilities, action); err != nil {
				return err
			}
		}
		semanticAction := ParseSecurityPolicySemanticAction(current.ScopeJSON)
		if current.SemanticActionOverride != nil {
			semanticAction, _ = NormalizeSecurityPolicySemanticAction(*current.SemanticActionOverride)
		}
		if update.SemanticAction != nil {
			semanticAction = semanticActionUpdate
		}
		if update.SemanticAction != nil || bindingsChanged {
			if err := validateSemanticActionCapabilities(capabilities, semanticAction); err != nil {
				return err
			}
		}
		// 提交的级别等于基准级别即“恢复默认”：清除覆盖而不是存一份等值覆盖，
		// 否则基准之后调整时该租户不会跟随。
		var severityOverride *string
		severityReset := false
		if update.Severity != nil {
			value := strings.TrimSpace(*update.Severity)
			if !validPolicySeverity(value) {
				return invalidSecurityPolicy("severity is invalid")
			}
			if value == current.BaseSeverity {
				severityReset = true
			} else {
				severityOverride = &value
			}
		}
		hasOverrideWrite := actionOverride != nil || enabledOverride != nil || bindingsChanged ||
			update.Redaction != nil || update.SemanticAction != nil || severityOverride != nil
		if !hasOverrideWrite && !severityReset {
			return nil
		}
		var capabilityOverrideJSON []byte
		var bindingModeOverride *string
		if bindingsChanged {
			categories := make([]string, 0, len(capabilities))
			for _, capability := range capabilities {
				categories = append(categories, capability.Category)
			}
			sort.Strings(categories)
			capabilityOverrideJSON, err = json.Marshal(categories)
			if err != nil {
				return fmt.Errorf("encode system policy capability override: %w", err)
			}
			bindingModeOverride = &bindingMode
		}
		if hasOverrideWrite {
			if _, err := tx.Exec(ctx, `
			INSERT INTO builtin_rule_overrides(
			  tenant_id,rule_id,action,enabled,capability_categories,binding_mode,redaction_json,semantic_action,severity,updated_at
			)
			VALUES($1,$2,$3,$4,$5,$6,$10,$12,$14,NOW())
			ON CONFLICT(tenant_id,rule_id)
			DO UPDATE SET
			  action=CASE WHEN $7 THEN EXCLUDED.action ELSE builtin_rule_overrides.action END,
			  enabled=CASE WHEN $8 THEN EXCLUDED.enabled ELSE builtin_rule_overrides.enabled END,
			  capability_categories=CASE WHEN $9 THEN EXCLUDED.capability_categories ELSE builtin_rule_overrides.capability_categories END,
			  binding_mode=CASE WHEN $9 THEN EXCLUDED.binding_mode ELSE builtin_rule_overrides.binding_mode END,
			  redaction_json=CASE WHEN $11 THEN EXCLUDED.redaction_json ELSE builtin_rule_overrides.redaction_json END,
			  semantic_action=CASE WHEN $13 THEN EXCLUDED.semantic_action ELSE builtin_rule_overrides.semantic_action END,
			  severity=CASE WHEN $15 THEN EXCLUDED.severity ELSE builtin_rule_overrides.severity END,
			  updated_at=NOW()`,
				tenantID, current.ID, actionOverride, enabledOverride,
				capabilityOverrideJSON, bindingModeOverride,
				actionOverride != nil, enabledOverride != nil, bindingsChanged,
				func() []byte {
					if update.Redaction == nil {
						return nil
					}
					data, _ := json.Marshal(update.Redaction)
					return data
				}(), update.Redaction != nil,
				func() *string {
					if update.SemanticAction == nil {
						return nil
					}
					return &semanticActionUpdate
				}(), update.SemanticAction != nil,
				severityOverride, severityOverride != nil,
			); err != nil {
				return fmt.Errorf("upsert system policy override: %w", err)
			}
		}
		if severityReset {
			// ck_builtin_rule_overrides_has_value 不允许全空行：只剩 severity 时删行，还有别的覆盖值就只清 severity。
			// 先 DELETE 后 UPDATE：此处的正确性靠前面的 DELETE 先把“只剩 severity”的行删掉；
			// UPDATE 仍带“还有其它覆盖值”的条件作防御，以后若有路径把其它列清成 NULL，也不会撞上 ck_builtin_rule_overrides_has_value。
			// UpsertBuiltinRuleAction 不取 advisory 锁，与本段交错的窗口依赖毫秒级时序，无法稳定复现，故不写交错测试。
			if _, err := tx.Exec(ctx, `
				DELETE FROM builtin_rule_overrides
				WHERE tenant_id=$1 AND rule_id=$2 AND severity IS NOT NULL
				  AND action IS NULL AND enabled IS NULL AND capability_categories IS NULL
				  AND redaction_json IS NULL AND semantic_action IS NULL`,
				tenantID, current.ID); err != nil {
				return fmt.Errorf("delete system policy severity override: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE builtin_rule_overrides SET severity=NULL,updated_at=NOW()
				WHERE tenant_id=$1 AND rule_id=$2 AND severity IS NOT NULL
				  AND (action IS NOT NULL OR enabled IS NOT NULL OR capability_categories IS NOT NULL
				       OR redaction_json IS NOT NULL OR semantic_action IS NOT NULL)`,
				tenantID, current.ID); err != nil {
				return fmt.Errorf("clear system policy severity override: %w", err)
			}
		}
		return nil
	}
	if (strings.HasPrefix(strings.TrimSpace(current.PolicyCode), "builtin.") ||
		strings.HasPrefix(strings.TrimSpace(current.PolicyCode), "system.")) && updateHasSystemReadOnlyFields(update) {
		// 预置策略的名称、场景和识别能力绑定构成产品身份；风险等级可由租户调整。
		// 租户只能独立配置启停、处置动作和风险等级，不能把预置策略改成另一个定义。
		return ErrSystemPolicyFieldReadOnly
	}

	name := current.Name
	description := current.Description
	scene := policyScene(current.RuleType, current.ScopeJSON)
	severity := current.Severity
	action := current.Action
	enabled := current.Enabled
	ruleType := current.RuleType
	matchJSON := append([]byte(nil), current.MatchJSON...)
	scopeJSON := append([]byte(nil), current.ScopeJSON...)
	if update.SemanticAction != nil {
		var err error
		scopeJSON, err = scopeWithSemanticAction(scopeJSON, semanticActionUpdate)
		if err != nil {
			return err
		}
	}
	if update.Redaction != nil {
		var err error
		scopeJSON, err = scopeWithRedaction(scopeJSON, update.Redaction)
		if err != nil {
			return err
		}
	}
	if update.Authoring != nil && !update.Authoring.IsAgentShield() && (update.Matcher == nil || update.ClearMatcher) {
		return invalidSecurityPolicy("authoring requires matcher replacement")
	}
	if update.SubjectBinding != nil && update.ClearSubjectBinding {
		return ErrInvalidSubjectBinding
	}
	if update.SubjectBinding != nil {
		subjectBinding, err := NormalizeSecurityPolicySubjectBinding(update.SubjectBinding)
		if err != nil {
			return err
		}
		if err := validateBindingOwnership(ctx, tx, tenantID, subjectBinding); err != nil {
			return err
		}
		scopeJSON, err = scopeWithSubjectBinding(scopeJSON, subjectBinding)
		if err != nil {
			return err
		}
	}
	if update.ClearSubjectBinding {
		var err error
		scopeJSON, err = scopeWithSubjectBinding(scopeJSON, nil)
		if err != nil {
			return err
		}
	}

	if update.Name != nil {
		name = strings.TrimSpace(*update.Name)
		if err := validatePolicyName(name); err != nil {
			return err
		}
	}
	if update.Description != nil {
		description = strings.TrimSpace(*update.Description)
		if err := validatePolicyDescription(description); err != nil {
			return err
		}
	}
	if update.Scene != nil {
		scene = strings.TrimSpace(*update.Scene)
		if !validPolicyScene(scene) {
			return invalidSecurityPolicy("scene is invalid")
		}
		var err error
		scopeJSON, err = scopeWithScene(scopeJSON, scene)
		if err != nil {
			return err
		}
	}
	if update.Severity != nil {
		severity = strings.TrimSpace(*update.Severity)
		if !validPolicySeverity(severity) {
			return invalidSecurityPolicy("severity is invalid")
		}
	}
	if update.Action != nil {
		action = strings.TrimSpace(*update.Action)
		if !validPolicyAction(action) {
			return invalidSecurityPolicy("action is invalid")
		}
	}
	if update.Enabled != nil {
		enabled = *update.Enabled
	}
	if update.Matcher != nil && update.ClearMatcher {
		return invalidSecurityPolicy("matcher cannot be replaced and cleared together")
	}
	if update.Matcher != nil {
		var err error
		ruleType, matchJSON, err = normalizeMatcher(update.Matcher)
		if err != nil {
			return err
		}
		scopeJSON, err = scopeWithMatcherValidation(scopeJSON, ruleType, matchJSON, update.Matcher.RuntimeValidated)
		if err != nil {
			return err
		}
	}
	if update.ClearMatcher {
		ruleType = scene
		matchJSON = []byte(`{}`)
		var err error
		scopeJSON, err = scopeWithMatcherValidation(scopeJSON, ruleType, matchJSON, false)
		if err != nil {
			return err
		}
	}
	scopeJSON, err = scopeWithScene(scopeJSON, scene)
	if err != nil {
		return err
	}
	if update.Matcher != nil || update.ClearMatcher || update.Authoring != nil {
		var err error
		scopeJSON, err = scopeWithAuthoring(scopeJSON, update.Authoring, ruleType, matchJSON)
		if err != nil {
			return err
		}
	}

	capabilities, err := loadRuleCapabilities(ctx, tx, current.ID)
	if err != nil {
		return err
	}
	bindingMode := "any"
	if len(capabilities) > 0 && validBindingMode(capabilities[0].BindingMode) {
		bindingMode = capabilities[0].BindingMode
	}
	bindingsChanged := update.CapabilityCategories != nil || update.BindingMode != nil
	if update.BindingMode != nil {
		bindingMode = strings.TrimSpace(*update.BindingMode)
		if !validBindingMode(bindingMode) {
			return invalidSecurityPolicy("binding mode must be any or all")
		}
	}
	if update.CapabilityCategories != nil {
		capabilities, err = loadEnabledCapabilitiesByCategory(ctx, tx, *update.CapabilityCategories, bindingMode)
		if err != nil {
			return err
		}
	} else if update.BindingMode != nil && len(capabilities) == 0 {
		return invalidSecurityPolicy("binding mode requires at least one capability")
	}
	if update.BindingMode != nil {
		for index := range capabilities {
			capabilities[index].BindingMode = bindingMode
		}
	}
	_, matcherPresent, _, _ := storedMatcherState(ruleType, matchJSON, scopeJSON)
	if matcherPresent && len(capabilities) > 0 {
		return ErrPolicyDetectionConflict
	}
	if !severityOnlyUpdate {
		if err := validateMatcherAction(ruleType, matcherPresent, action); err != nil {
			return err
		}
	}
	if !matcherPresent {
		ruleType = scene
	}

	configurationChanged := update.Matcher != nil || update.ClearMatcher || bindingsChanged
	_, _, matcherReady, matcherIssue := storedMatcherState(ruleType, matchJSON, scopeJSON)
	capabilityReady, _ := capabilityBindingsState(capabilities)
	if enabled && !auditOnlyUpdate && !severityOnlyUpdate && ruleType == "regex" && !matcherReady {
		if matcherIssue == "runtime_validation_required" {
			return ErrPolicyRuntimeValidation
		}
		return ErrPolicyDetectionRequired
	}
	hasReadyBasis := matcherReady || capabilityReady
	if (update.Enabled != nil && enabled || configurationChanged && enabled) && !hasReadyBasis {
		if matcherIssue == "runtime_validation_required" {
			return ErrPolicyRuntimeValidation
		}
		return ErrPolicyDetectionRequired
	}
	if !severityOnlyUpdate && (update.Action != nil || bindingsChanged || update.Enabled != nil && enabled) {
		if err := validateCapabilityAction(capabilities, action); err != nil {
			return err
		}
	}
	if update.SemanticAction != nil || bindingsChanged {
		if err := validateSemanticActionCapabilities(capabilities, ParseSecurityPolicySemanticAction(scopeJSON)); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE rules SET name=$1,description=$2,severity=$3,action=$4,enabled=$5,
		                 rule_type=$6,scope_json=$7,match_config_json=$8
		WHERE id=$9`,
		name, description, severity, action, enabled, ruleType, scopeJSON, matchJSON, current.ID,
	); err != nil {
		return fmt.Errorf("update tenant security policy: %w", err)
	}
	if bindingsChanged {
		if err := replacePolicyBindings(ctx, tx, current.ID, capabilities, bindingMode); err != nil {
			return err
		}
	}
	return nil
}

func (r *RuleRepository) UpdateSecurityPolicy(ctx context.Context, tenantID, policyID string, update SecurityPolicyUpdate) (*SecurityPolicy, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin update security policy: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// 改前级别由 updateSecurityPolicyLocked 在已持锁时带出，改后级别在同一事务内读出，
	// 审计 from/to 因此都来自事务内，且不会因预读先拿行锁而反转加锁顺序。
	previousSeverity := ""
	if err := r.updateSecurityPolicyLocked(ctx, tx, tenantID, policyID, update, &previousSeverity); err != nil {
		return nil, err
	}
	updatedSeverity := ""
	if update.Severity != nil {
		if err := tx.QueryRow(ctx, `
			SELECT COALESCE(bro.severity,r.severity)
			FROM rules r
			LEFT JOIN builtin_rule_overrides bro ON bro.tenant_id=$1 AND bro.rule_id=r.id
			WHERE r.id=$2`, tenantID, strings.TrimSpace(policyID)).Scan(&updatedSeverity); err != nil {
			return nil, fmt.Errorf("read updated security policy severity: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit update security policy: %w", err)
	}
	policy, err := r.GetSecurityPolicy(ctx, tenantID, policyID)
	if err != nil {
		return nil, err
	}
	policy.PreviousSeverity = previousSeverity
	policy.UpdatedSeverity = updatedSeverity
	return policy, nil
}

// isOrganizationPolicy mirrors the console's "organization_created" origin: owned by the requesting
// tenant and not one of the shipped builtin./system. policies.
func isOrganizationPolicy(policy lockedSecurityPolicy, tenantID string) bool {
	if policy.OwnerTenant != tenantID {
		return false
	}
	return !strings.HasPrefix(policy.PolicyCode, "builtin.") && !strings.HasPrefix(policy.PolicyCode, "system.")
}

// DeleteSecurityPolicy deletes an organization-created policy. Built-in policies can only be
// disabled, never deleted. Historical security events keep pointing at the retained tombstone row.
func (r *RuleRepository) DeleteSecurityPolicy(ctx context.Context, tenantID, policyID string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin delete security policy: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	policy, err := lockSecurityPolicy(ctx, tx, tenantID, policyID)
	if err != nil {
		return err
	}
	if !isOrganizationPolicy(policy, tenantID) {
		return ErrSecurityPolicyNotDeletable
	}
	if err := tombstoneRule(ctx, tx, policy.ID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delete security policy: %w", err)
	}
	return nil
}

type ruleExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// tombstoneRule retires a rule in one statement: the row stays (security_events points at it) but is
// disabled and marked deleted, and the exceptions that reference it go away exactly as the
// ON DELETE CASCADE of a real delete would remove them. Left behind, a permanent "allow" exception
// of a deleted policy would stay active, stay in the exception list and keep being shipped to the engine.
func tombstoneRule(ctx context.Context, db ruleExecer, ruleID string) error {
	if _, err := db.Exec(ctx, `
		WITH removed_exceptions AS (
			DELETE FROM content_audit_exceptions
			WHERE rule_id=$1::text OR rule_ref=$1::text
		)
		UPDATE rules
		SET enabled=FALSE,
		    scope_json=COALESCE(scope_json,'{}'::jsonb) ||
		               jsonb_build_object('`+securityPolicyDeletedKey+`',
		                                  to_char(NOW() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'))
		WHERE id=$1::text`, ruleID); err != nil {
		return fmt.Errorf("tombstone security policy: %w", err)
	}
	return nil
}

func (r *RuleRepository) BatchUpdateSecurityPolicies(ctx context.Context, tenantID string, updates []SecurityPolicyBatchUpdate) error {
	if len(updates) == 0 {
		return invalidSecurityPolicy("batch must contain at least one policy")
	}
	if len(updates) > 500 {
		return invalidSecurityPolicy("batch cannot exceed 500 policies")
	}
	ordered := append([]SecurityPolicyBatchUpdate(nil), updates...)
	for index := range ordered {
		ordered[index].ID = strings.TrimSpace(ordered[index].ID)
		if ordered[index].ID == "" {
			return invalidSecurityPolicy("policy id cannot be blank")
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for index := range ordered {
		if index > 0 && ordered[index-1].ID == ordered[index].ID {
			return invalidSecurityPolicy("duplicate policy id %s", ordered[index].ID)
		}
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin batch security policy update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, item := range ordered {
		if err := r.updateSecurityPolicyTx(ctx, tx, tenantID, item.ID, item.Update); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit batch security policy update: %w", err)
	}
	return nil
}

// 来源标记与数字规则编辑元数据互斥，不能借来源标记绕过数字规则校验。
func (a *SecurityPolicyAuthoring) IsAgentShield() bool {
	return a != nil && a.Source == "agentshield" && a.Version == 0 && a.Kind == "" && a.MatcherPattern == "" && len(a.Segments) == 0
}

func SecurityPolicyAuthoringSource(scope []byte) string {
	authoring := parseSecurityPolicyAuthoring(scope, "", nil)
	if authoring.IsAgentShield() {
		return "agentshield"
	}
	return ""
}
