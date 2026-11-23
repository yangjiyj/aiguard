// Package rules 实现「方案A：规则编译下发」。
//
// control-plane 把策略中心里租户配置的 rules 编译成一份运行时「规则包」
// （RulePack）。security-engine 无状态地消费该规则包做匹配，自身不连库。
// 权威的 ReDoS 安全校验在编译期（本包）完成：不安全的正则永不下发。
//
// 本包是纯函数（不依赖 *pgxpool.Pool），便于在无数据库环境下做单元测试。
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// IsSupportedRuntimeRuleAction is the cross-service action contract for rules
// compiled into the security engine. reply needs response-content semantics and
// alert/quarantine remain internal finding actions, so none are runtime rules.
func IsSupportedRuntimeRuleAction(action string) bool {
	switch action {
	case "allow", "audit", "mask", "block":
		return true
	default:
		return false
	}
}

// isSafeRegex 做编译期 ReDoS 启发式防护，行为与 Python is_safe_regex 对齐。
//
// 故意只做字符串级判断，不用 Go 的 regexp.Compile 校验语法：Go 的 RE2 与
// Python re 语法不兼容（RE2 不支持 lookahead / 反向引用），用 RE2 编译会误杀
// 客户面向 Python 引擎编写的合法正则。真正的语法编译校验由引擎侧（_compile_regex
// 的 try/except）承担。
func isSafeRegex(pattern string) bool {
	return repository.IsSafeRuntimeRegex(pattern)
}

// CompiledRule 是规则包中的单条规则。JSON 字段名与 security-engine
// app/custom_rules.py 的 CompiledRule(Pydantic, snake_case, 无 alias) 严格对齐，
// 任何字段名漂移都会导致引擎反序列化丢字段。
type CompiledRule struct {
	RuleID     string                 `json:"rule_id"`
	RuleName   string                 `json:"rule_name"`
	RuleType   string                 `json:"rule_type"`
	Category   string                 `json:"category"`
	Severity   string                 `json:"severity"`
	Action     string                 `json:"action"`
	Enabled    bool                   `json:"enabled"`
	Regex      string                 `json:"regex,omitempty"`
	Keywords   []string               `json:"keywords,omitempty"`
	FieldNames []string               `json:"field_names,omitempty"`
	Scope      map[string]interface{} `json:"scope,omitempty"`
}

type CompiledPolicyCapability struct {
	Category        string   `json:"category"`
	SupportedStages []string `json:"supported_stages"`
	AllowedActions  []string `json:"allowed_actions"`
	MaskCapable     bool     `json:"mask_capable"`
}

type CompiledPolicy struct {
	AuthoringSource string                              `json:"authoring_source,omitempty"`
	Redaction       *repository.SecurityPolicyRedaction `json:"redaction,omitempty"`
	// SemanticAction 只在非缺省（block/observe）时下发，旧引擎不会收到未知字段。
	SemanticAction string                                   `json:"semantic_action,omitempty"`
	Severity       string                                   `json:"severity,omitempty"`
	PolicyCode     string                                   `json:"policy_code"`
	PolicyID       string                                   `json:"policy_id"`
	PolicyName     string                                   `json:"policy_name"`
	PolicyType     string                                   `json:"policy_type"`
	Scene          string                                   `json:"scene"`
	MatcherRuleID  string                                   `json:"matcher_rule_id,omitempty"`
	Action         string                                   `json:"action"`
	Enabled        bool                                     `json:"enabled"`
	BindingMode    string                                   `json:"binding_mode"`
	Capabilities   []CompiledPolicyCapability               `json:"capabilities"`
	SubjectBinding *repository.SecurityPolicySubjectBinding `json:"subject_binding,omitempty"`
}

// FilePolicy 是租户文件策略（content_file_policy_json），随规则包下发给引擎。
type FilePolicy struct {
	AllowedTypes   []string `json:"allowed_types,omitempty"`
	BlockedTypes   []string `json:"blocked_types,omitempty"`
	ReviewTypes    []string `json:"review_types,omitempty"`
	MaxFileMB      int      `json:"max_file_mb,omitempty"`
	MaxZipRatio    int      `json:"max_zip_ratio,omitempty"`
	MaxAttachments int      `json:"max_attachments,omitempty"`
	// 文件内容 DLP（数据外发防护）：开启后对文本类附件正文做敏感数据检测。
	// 默认关；与 security-engine 的 SECURITY_FILE_CONTENT_DLP_ENABLED 部署总开关取 AND。
	ContentDlpEnabled bool `json:"content_dlp_enabled,omitempty"`
	// 2.9.22：文件风险类别的处置（allow / alert_allow / block，缺省 alert_allow），
	// 引擎执行前五项；文件引用两项由网关和独立代理执行。
	ExecutableAction                 string `json:"executable_action,omitempty"`
	DisguisedExecutableAction        string `json:"disguised_executable_action,omitempty"`
	ScriptAction                     string `json:"script_action,omitempty"`
	UnknownAction                    string `json:"unknown_action,omitempty"`
	ZipBombAction                    string `json:"zip_bomb_action,omitempty"`
	UnverifiedFileReferenceAction    string `json:"unverified_file_reference_action,omitempty"`
	FileReferenceLookupFailureAction string `json:"file_reference_lookup_failure_action,omitempty"`
	// 压缩包限制；0 表示未配置，引擎取部署环境变量缺省。
	MaxZipEntries        int `json:"max_zip_entries,omitempty"`
	MaxZipUncompressedMB int `json:"max_zip_uncompressed_mb,omitempty"`
	MaxZipNested         int `json:"max_zip_nested,omitempty"`
}

// CompiledException 是规则包中的单条例外（误报豁免）。随规则包一同下发，引擎在
// dedupe 之后、判定动作之前应用：把命中规则的 finding 动作降级为 decision
// （allow / audit），并标记 exception_id，finding 仍然记录进安全事件
// （已豁免，而非静默丢弃）。凭据、证件号等也不例外（2.9.22）。
type CompiledException struct {
	ExceptionID     string     `json:"exception_id"`
	ScopeType       string     `json:"scope_type"`
	ScopeRef        string     `json:"scope_ref,omitempty"`
	IncludeChildren bool       `json:"include_children"`
	RuleID          string     `json:"rule_id,omitempty"`
	Decision        string     `json:"decision"`
	Reason          string     `json:"reason,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}

// SkippedRule 记录被编译期丢弃的规则/例外及原因，保证「不静默截断」——
// 哪条因何没下发对运维可见（unsafe_regex / no_supported_matcher / disabled /
type SkippedRule struct {
	RuleID            string `json:"rule_id"`
	PolicyCode        string `json:"policy_code,omitempty"`
	RuleName          string `json:"rule_name,omitempty"`
	RuleType          string `json:"rule_type,omitempty"`
	Action            string `json:"action,omitempty"`
	Enabled           bool   `json:"enabled,omitempty"`
	Reason            string `json:"reason"`
	ConfiguredMatcher bool   `json:"configured_matcher,omitempty"`
}

const maxSkippedRuleDetails = 200

// RuleDiagnostics 只统计规则候选，不统计例外。CatalogCount 是已发布查询返回的
// 非空规则候选总数；每条候选最终恰好归入 CompiledCount 或 SkippedCount，
// SkipReasons 则按稳定原因标识聚合所有未编译规则。
type RuleDiagnostics struct {
	CatalogCount     int            `json:"catalog_count"`
	CompiledCount    int            `json:"compiled_count"`
	SkippedCount     int            `json:"skipped_count"`
	PendingCount     int            `json:"pending_count"`
	SkipReasons      map[string]int `json:"skip_reasons"`
	SkippedTruncated bool           `json:"skipped_truncated"`
}

type ReplyPolicy struct {
	SchemaVersion int               `json:"schema_version"`
	Enabled       bool              `json:"enabled"`
	Templates     map[string]string `json:"templates"`
}

// RulePack 是下发给引擎的规则包。GeneratedAt 留空，由 handler 在响应时盖上
// 时间戳，从而保持本包为纯函数、便于测试。
type RulePack struct {
	TenantID    string              `json:"tenant_id"`
	GeneratedAt string              `json:"generated_at,omitempty"`
	Version     string              `json:"version"`
	Rules       []CompiledRule      `json:"rules"`
	Policies    []CompiledPolicy    `json:"policies"`
	Exceptions  []CompiledException `json:"exceptions"`
	Skipped     []SkippedRule       `json:"skipped"`
	Diagnostics RuleDiagnostics     `json:"diagnostics"`
	Warnings    []string            `json:"warnings,omitempty"`
	Degraded    bool                `json:"degraded"`
	FilePolicy  *FilePolicy         `json:"file_policy,omitempty"`
	ReplyPolicy *ReplyPolicy        `json:"reply_policy,omitempty"`
}

// matchConfig contains only matcher-adjacent metadata. Executable matcher
// normalization is centralized in repository.NormalizeRuntimeMatcher.
type matchConfig struct {
	Category string `json:"category"`
}

func compiledPolicyScene(rule *repository.Rule) string {
	if rule == nil {
		return "unclassified"
	}
	var scope struct {
		Scene string `json:"scene"`
	}
	if json.Unmarshal(rule.ScopeJSON, &scope) == nil {
		if scene := strings.TrimSpace(scope.Scene); scene != "" {
			return scene
		}
	}
	if fallback := strings.TrimSpace(rule.RuleType); fallback != "" {
		return fallback
	}
	return "unclassified"
}

// Compile 把租户的规则与例外编译成规则包。纯函数，处理规则：
//   - disabled 规则跳过（纵深防御，即便仓储已做 enabled 过滤）
//   - 仅 regex / keyword / field_name 三类可执行，且类型必须匹配对应 matcher
//   - matcher 字符串去首尾空白，数组丢弃空白项；归一化后为空则跳过
//   - regex 触发 ReDoS 启发式 → skipped(unsafe_regex)，永不进入下发列表
//
// 例外处理见下方循环：启用、动作与作用域合法的例外全部下发，不按规则类别丢弃
// （2.9.22 设计 5.4：例外一律生效）。
//
// 客户自定义规则的 action 在此原样透传（权威），不被 severity 改写——
// 最终动作判定由引擎侧 builtin/custom 取秩最大值完成。
func Compile(tenantID string, rs []*repository.Rule, excs []*repository.ContentAuditException) RulePack {
	pack := RulePack{
		TenantID:   tenantID,
		Rules:      []CompiledRule{},
		Policies:   []CompiledPolicy{},
		Exceptions: []CompiledException{},
		Skipped:    []SkippedRule{},
		Diagnostics: RuleDiagnostics{
			SkipReasons: map[string]int{},
		},
	}
	seenPolicyCodes := map[string]bool{}
	for _, rule := range rs {
		if rule == nil {
			continue
		}
		pack.Diagnostics.CatalogCount++
		configuredMatcher := hasConfiguredRuntimeMatcher(rule)
		compiledRule, matcherReason, matcherOK := compileMatcherRule(rule)
		compiledPolicy, policyReason, policyOK := compileRuntimePolicy(rule, matcherOK)

		if strings.TrimSpace(rule.PolicyCode) != "" {
			if !policyOK {
				pack.skipRule(rule, policyReason, configuredMatcher)
				continue
			}
			if seenPolicyCodes[compiledPolicy.PolicyCode] {
				pack.skipRule(rule, "duplicate_policy_code", configuredMatcher)
				continue
			}
			seenPolicyCodes[compiledPolicy.PolicyCode] = true
			pack.Policies = append(pack.Policies, compiledPolicy)
			pack.Diagnostics.CompiledCount++
			if rule.Enabled && matcherOK && compiledPolicy.MatcherRuleID != "" {
				pack.Rules = append(pack.Rules, compiledRule)
			}
			continue
		}

		if !rule.Enabled {
			pack.skipRule(rule, "disabled", configuredMatcher)
			continue
		}
		if !matcherOK {
			pack.skipRule(rule, matcherReason, configuredMatcher)
			continue
		}
		pack.Rules = append(pack.Rules, compiledRule)
		pack.Diagnostics.CompiledCount++
	}

	for _, exception := range excs {
		if exception == nil {
			continue
		}
		if !exception.Enabled {
			pack.appendSkippedDetail(exception.ID, "exception_disabled")
			continue
		}
		if exception.Decision != "allow" && exception.Decision != "audit" {
			pack.appendSkippedDetail(exception.ID, "exception_invalid_decision")
			continue
		}
		if !isSupportedContentExceptionScope(exception.ScopeType) {
			pack.appendSkippedDetail(exception.ID, "exception_unknown_scope")
			continue
		}
		if exception.IncludeChildren && exception.ScopeType != "actor_department_v1" {
			pack.appendSkippedDetail(exception.ID, "exception_invalid_scope_configuration")
			continue
		}
		ruleRef := exception.RuleRef
		if ruleRef == "" {
			ruleRef = exception.RuleID
		}
		var expiresAt *time.Time
		if exception.ExpiresAt != nil {
			canonical := exception.ExpiresAt.UTC()
			expiresAt = &canonical
		}
		pack.Exceptions = append(pack.Exceptions, CompiledException{
			ExceptionID:     exception.ID,
			ScopeType:       exception.ScopeType,
			ScopeRef:        exception.ScopeRef,
			IncludeChildren: exception.IncludeChildren,
			RuleID:          ruleRef,
			Decision:        exception.Decision,
			Reason:          exception.Reason,
			ExpiresAt:       expiresAt,
		})
	}
	pack.Version = ContentVersion(pack)
	return pack
}

func isSupportedContentExceptionScope(scopeType string) bool {
	switch scopeType {
	case "tenant", "project", "user", "rule", "key_v1", "actor_department_v1":
		return true
	default:
		return false
	}
}

func compileMatcherRule(rule *repository.Rule) (CompiledRule, string, bool) {
	if !IsSupportedRuntimeRuleAction(rule.Action) {
		return CompiledRule{}, "unsupported_action", false
	}
	if !json.Valid(rule.MatchConfigJSON) {
		return CompiledRule{}, "invalid_match_config", false
	}
	matcher, ok := repository.NormalizeRuntimeMatcher(rule.RuleType, rule.MatchConfigJSON)
	if !ok {
		return CompiledRule{}, "no_supported_matcher", false
	}
	if matcher.Regex != "" && !isSafeRegex(matcher.Regex) {
		return CompiledRule{}, "unsafe_regex", false
	}
	var config matchConfig
	_ = json.Unmarshal(rule.MatchConfigJSON, &config)
	category := config.Category
	if category == "" {
		category = rule.RuleType
	}
	var scope map[string]interface{}
	if len(rule.ScopeJSON) > 0 {
		_ = json.Unmarshal(rule.ScopeJSON, &scope)
	}
	delete(scope, "number_segments")
	delete(scope, "_authoring")
	return CompiledRule{
		RuleID: rule.ID, RuleName: rule.Name, RuleType: rule.RuleType,
		Category: category, Severity: rule.Severity, Action: rule.Action, Enabled: true,
		Regex: matcher.Regex, Keywords: matcher.Keywords, FieldNames: matcher.FieldNames,
		Scope: scope,
	}, "", true
}

func compileRuntimePolicy(rule *repository.Rule, matcherOK bool) (CompiledPolicy, string, bool) {
	code := strings.TrimSpace(rule.PolicyCode)
	if code == "" {
		return CompiledPolicy{}, "", false
	}
	if rule.Action != "audit" && rule.Action != "mask" && rule.Action != "block" {
		return CompiledPolicy{}, "unsupported_policy_action", false
	}
	policy := CompiledPolicy{
		AuthoringSource: repository.SecurityPolicyAuthoringSource(rule.ScopeJSON),
		PolicyCode:      code, PolicyID: rule.ID, PolicyName: rule.Name,
		PolicyType: rule.RuleType, Scene: compiledPolicyScene(rule),
		Action: rule.Action, Enabled: rule.Enabled, Severity: rule.Severity,
		BindingMode: "any", Capabilities: []CompiledPolicyCapability{},
	}
	var redactionOK bool
	policy.Redaction, redactionOK = repository.ParseSecurityPolicyRedaction(rule.ScopeJSON)
	if !redactionOK {
		return CompiledPolicy{}, "invalid_redaction", false
	}
	var bindingOK bool
	policy.SubjectBinding, bindingOK = repository.ParseSecurityPolicySubjectBinding(rule.ScopeJSON)
	if !bindingOK {
		return CompiledPolicy{}, "invalid_subject_binding", false
	}
	// A policy must have exactly one executable selector. Silently preferring
	// capabilities here would drop a configured matcher while still letting the
	// policy appear in the runtime receipt as active.
	if matcherOK && len(rule.RuntimeCapabilities) > 0 {
		return CompiledPolicy{}, "hybrid_detection_basis_unsupported", false
	}
	if len(rule.RuntimeCapabilities) == 0 {
		if !matcherOK {
			return CompiledPolicy{}, "management_only", false
		}
		policy.MatcherRuleID = rule.ID
		return policy, "", true
	}

	mode := rule.RuntimeCapabilities[0].BindingMode
	if mode != "any" && mode != "all" {
		return CompiledPolicy{}, "invalid_binding_mode", false
	}
	policy.BindingMode = mode
	seenCategories := map[string]bool{}
	for _, capability := range rule.RuntimeCapabilities {
		if capability.BindingMode != mode {
			return CompiledPolicy{}, "binding_mode_conflict", false
		}
		if !capability.Enabled {
			if mode == "all" {
				return CompiledPolicy{}, "capability_unavailable", false
			}
			continue
		}
		category := strings.TrimSpace(capability.Category)
		if category == "" || seenCategories[category] {
			return CompiledPolicy{}, "invalid_capability_binding", false
		}
		seenCategories[category] = true
		stages, ok := normalizedContractValues(capability.SupportedStages, map[string]bool{"input": true, "agent": true, "output": true})
		if !ok {
			return CompiledPolicy{}, "invalid_capability_stage", false
		}
		actions, ok := normalizedContractValues(capability.AllowedActions, map[string]bool{"audit": true, "mask": true, "block": true})
		if !ok || !containsValue(actions, rule.Action) || (rule.Action == "mask" && !capability.MaskCapable) {
			return CompiledPolicy{}, "unsupported_policy_action", false
		}
		policy.Capabilities = append(policy.Capabilities, CompiledPolicyCapability{
			Category: category, SupportedStages: stages,
			AllowedActions: actions, MaskCapable: capability.MaskCapable,
		})
	}
	if len(policy.Capabilities) == 0 {
		return CompiledPolicy{}, "capability_unavailable", false
	}
	if action := repository.ParseSecurityPolicySemanticAction(rule.ScopeJSON); action != repository.SemanticActionAudit {
		policy.SemanticAction = action
	}
	sort.Slice(policy.Capabilities, func(i, j int) bool {
		return policy.Capabilities[i].Category < policy.Capabilities[j].Category
	})
	return policy, "", true
}

func normalizedContractValues(values []string, allowed map[string]bool) ([]string, bool) {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !allowed[value] || seen[value] {
			return nil, false
		}
		seen[value] = true
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, false
	}
	sort.Strings(result)
	return result, true
}

func containsValue(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func hasConfiguredRuntimeMatcher(rule *repository.Rule) bool {
	if rule == nil {
		return false
	}
	if json.Valid(rule.MatchConfigJSON) {
		_, ok := repository.NormalizeRuntimeMatcher(rule.RuleType, rule.MatchConfigJSON)
		return ok
	}
	trimmed := strings.TrimSpace(string(rule.MatchConfigJSON))
	return trimmed != "" && trimmed != "{}" && trimmed != "null"
}

func (pack *RulePack) skipRule(rule *repository.Rule, reason string, configuredMatcher bool) {
	enabledUnsupportedPolicy :=
		rule.Enabled &&
			strings.TrimSpace(rule.PolicyCode) != "" &&
			reason == "unsupported_policy_action"
	enabledInvalidBinding := rule.Enabled && reason == "invalid_subject_binding"
	if len(pack.Skipped) < maxSkippedRuleDetails {
		pack.Skipped = append(pack.Skipped, SkippedRule{
			RuleID:            rule.ID,
			PolicyCode:        rule.PolicyCode,
			RuleName:          rule.Name,
			RuleType:          rule.RuleType,
			Action:            rule.Action,
			Enabled:           rule.Enabled,
			Reason:            reason,
			ConfiguredMatcher: configuredMatcher,
		})
	} else {
		pack.Diagnostics.SkippedTruncated = true
	}
	pack.Diagnostics.SkippedCount++
	pack.Diagnostics.SkipReasons[reason]++
	if configuredMatcher || enabledUnsupportedPolicy || enabledInvalidBinding {
		pack.Diagnostics.PendingCount++
	}
	if enabledUnsupportedPolicy || enabledInvalidBinding {
		pack.Degraded = true
		warning := "enabled_policy_unsupported_action"
		if enabledInvalidBinding {
			warning = "enabled_policy_invalid_subject_binding"
		}
		pack.Warnings = appendUniqueWarning(pack.Warnings, warning)
	}
}

func appendUniqueWarning(warnings []string, warning string) []string {
	for _, existing := range warnings {
		if existing == warning {
			return warnings
		}
	}
	return append(warnings, warning)
}

func (pack *RulePack) appendSkippedDetail(ruleID, reason string) {
	if len(pack.Skipped) < maxSkippedRuleDetails {
		pack.Skipped = append(pack.Skipped, SkippedRule{RuleID: ruleID, Reason: reason})
		return
	}
	pack.Diagnostics.SkippedTruncated = true
}

// ContentVersion 返回规则包内容的确定性指纹（sha256 前 8 字节 → 16 位十六进制）。
// 仅覆盖会改变下发语义的字段（租户、规则、例外、文件策略），排序后再哈希以消除顺序与瞬时字段影响；
// 刻意排除 generated_at（盖戳时间）/Version（自身）/Skipped、Diagnostics、
// Warnings、Degraded（诊断信息）。
// 因此：同内容恒得同版本，内容任何变更（含回滚）都得到不同版本 → 引擎按相等性判断即可回滚安全地热更新。
func ContentVersion(pack RulePack) string {
	rules := append([]CompiledRule(nil), pack.Rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })
	policies := append([]CompiledPolicy(nil), pack.Policies...)
	sort.Slice(policies, func(i, j int) bool {
		if policies[i].PolicyCode == policies[j].PolicyCode {
			return policies[i].PolicyID < policies[j].PolicyID
		}
		return policies[i].PolicyCode < policies[j].PolicyCode
	})
	excs := append([]CompiledException(nil), pack.Exceptions...)
	sort.Slice(excs, func(i, j int) bool { return excs[i].ExceptionID < excs[j].ExceptionID })
	canonical := struct {
		TenantID    string              `json:"tenant_id"`
		Rules       []CompiledRule      `json:"rules"`
		Policies    []CompiledPolicy    `json:"policies"`
		Exceptions  []CompiledException `json:"exceptions"`
		FilePolicy  *FilePolicy         `json:"file_policy"`
		ReplyPolicy *ReplyPolicy        `json:"reply_policy"`
	}{
		TenantID:    pack.TenantID,
		Rules:       rules,
		Policies:    policies,
		Exceptions:  excs,
		FilePolicy:  pack.FilePolicy,
		ReplyPolicy: pack.ReplyPolicy,
	}
	blob, _ := json.Marshal(canonical)
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:8])
}
