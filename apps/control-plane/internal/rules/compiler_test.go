package rules

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// medicalRule 复用 P2-1 验收用例「病案号正则」，与引擎集成测试保持同一条规则。
func medicalRule() *repository.Rule {
	return &repository.Rule{
		ID:              "rule_med001",
		RuleSetID:       "ruleset_default",
		RuleType:        "regex",
		Name:            "病案号正则",
		Severity:        "high",
		Action:          "block",
		Enabled:         true,
		MatchConfigJSON: []byte("{\"regex\":\"病案号[:：]?\\\\s*([A-Za-z]{0,3}\\\\d{6,12})\",\"category\":\"custom_medical_record\"}"),
	}
}

// privateKeyRule 是一条命中保留类目 private_key 的规则。2.9.22 起这类规则的
// 例外照常下发（设计 5.4：例外一律生效）。
func privateKeyRule() *repository.Rule {
	return &repository.Rule{
		ID:              "rule_pk001",
		RuleSetID:       "ruleset_default",
		RuleType:        "regex",
		Name:            "私钥外发",
		Severity:        "critical",
		Action:          "block",
		Enabled:         true,
		MatchConfigJSON: []byte("{\"regex\":\"-----BEGIN [A-Z ]*PRIVATE KEY-----\",\"category\":\"private_key\"}"),
	}
}

// auditException 构造一条默认启用、tenant 作用域的内容安全例外。
func auditException(id, ruleID, decision string) *repository.ContentAuditException {
	return &repository.ContentAuditException{
		ID:        id,
		TenantID:  "tenant_default",
		ScopeType: "tenant",
		RuleID:    ruleID,
		Decision:  decision,
		Reason:    "复核确认误报",
		Enabled:   true,
	}
}

func TestCompile_RegexRuleMapsAllFields(t *testing.T) {
	pack := Compile("tenant_default", []*repository.Rule{medicalRule()}, nil)
	if len(pack.Rules) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d (skipped=%v)", len(pack.Rules), pack.Skipped)
	}
	r := pack.Rules[0]
	if r.RuleID != "rule_med001" || r.RuleName != "病案号正则" {
		t.Errorf("id/name mismatch: %+v", r)
	}
	// 客户自定义规则的 action 权威：必须原样透传，不被 severity 改写。
	if r.Action != "block" {
		t.Errorf("action must passthrough authoritatively, got %q", r.Action)
	}
	if r.Category != "custom_medical_record" {
		t.Errorf("category from match_config, got %q", r.Category)
	}
	if r.Severity != "high" {
		t.Errorf("severity passthrough, got %q", r.Severity)
	}
	if r.Regex == "" {
		t.Errorf("regex must be present")
	}
	if !r.Enabled {
		t.Errorf("compiled rule must be enabled")
	}
	if len(pack.Skipped) != 0 {
		t.Errorf("no skips expected, got %v", pack.Skipped)
	}
}

func TestCompile_RuntimeActionContract(t *testing.T) {
	for _, action := range []string{"allow", "audit", "mask", "block"} {
		t.Run("supported_"+action, func(t *testing.T) {
			rule := medicalRule()
			rule.Action = action
			pack := Compile("tenant_default", []*repository.Rule{rule}, nil)
			if len(pack.Rules) != 1 || pack.Rules[0].Action != action {
				t.Fatalf("action %q must compile unchanged: rules=%+v skipped=%+v", action, pack.Rules, pack.Skipped)
			}
		})
	}

	for _, action := range []string{"reply", "alert", "quarantine", "blok"} {
		t.Run("unsupported_"+action, func(t *testing.T) {
			rule := medicalRule()
			rule.Action = action
			pack := Compile("tenant_default", []*repository.Rule{rule}, nil)
			if len(pack.Rules) != 0 {
				t.Fatalf("unsupported action %q entered runtime pack: %+v", action, pack.Rules)
			}
			if len(pack.Skipped) != 1 || pack.Skipped[0].Reason != "unsupported_action" {
				t.Fatalf("unsupported action %q diagnostics=%+v", action, pack.Skipped)
			}
		})
	}
}

func TestCompile_JSONFieldsMatchEngineContract(t *testing.T) {
	// 序列化后的字段名必须与 security-engine CompiledRule(Pydantic) 严格对齐，
	// 否则引擎反序列化丢字段。
	pack := Compile("tenant_default", []*repository.Rule{medicalRule()}, nil)
	b, _ := json.Marshal(pack.Rules[0])
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("marshal/unmarshal: %v", err)
	}
	for _, k := range []string{"rule_id", "rule_name", "rule_type", "category", "severity", "action", "enabled", "regex"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing JSON key %q in %s", k, string(b))
		}
	}
}

func TestCompile_UnsafeRegexSkipped(t *testing.T) {
	// 嵌套量词 ReDoS：(a+)+ 必须在编译期被丢弃，永不下发（权威校验在编译期）。
	bad := &repository.Rule{
		ID:              "rule_bad",
		RuleType:        "regex",
		Name:            "恶意正则",
		Severity:        "high",
		Action:          "block",
		Enabled:         true,
		MatchConfigJSON: []byte("{\"regex\":\"(a+)+$\",\"category\":\"x\"}"),
	}
	pack := Compile("t1", []*repository.Rule{bad}, nil)
	if len(pack.Rules) != 0 {
		t.Fatalf("unsafe regex must not be served, got %d rules", len(pack.Rules))
	}
	if len(pack.Skipped) != 1 || pack.Skipped[0].Reason != "unsafe_regex" {
		t.Fatalf("expected unsafe_regex skip, got %v", pack.Skipped)
	}
}

func TestCompile_KeywordOnlyRuleCompiles(t *testing.T) {
	// 3.6：纯关键词规则现在必须真编译下发（不再 no_supported_matcher 静默跳过）。
	kw := &repository.Rule{
		ID:              "rule_kw",
		RuleType:        "keyword",
		Name:            "关键词规则",
		Severity:        "medium",
		Action:          "audit",
		Enabled:         true,
		MatchConfigJSON: []byte("{\"keywords\":[\"绝密\",\"机密\"],\"category\":\"kw\"}"),
	}
	pack := Compile("t1", []*repository.Rule{kw}, nil)
	if len(pack.Rules) != 1 {
		t.Fatalf("keyword-only rule must compile, got %d rules (skipped=%v)", len(pack.Rules), pack.Skipped)
	}
	if len(pack.Skipped) != 0 {
		t.Fatalf("no skip expected, got %v", pack.Skipped)
	}
	r := pack.Rules[0]
	if r.RuleType != "keyword" {
		t.Errorf("rule_type passthrough, got %q", r.RuleType)
	}
	if r.Category != "kw" {
		t.Errorf("category from match_config, got %q", r.Category)
	}
	if len(r.Keywords) != 2 {
		t.Errorf("expected 2 keywords carried, got %v", r.Keywords)
	}
	if r.Regex != "" {
		t.Errorf("keyword rule must not carry regex, got %q", r.Regex)
	}
	// keywords 必须随 JSON 下发给引擎（snake_case 对齐 Pydantic）。
	b, _ := json.Marshal(r)
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("marshal/unmarshal: %v", err)
	}
	if _, ok := m["keywords"]; !ok {
		t.Errorf("missing JSON key \"keywords\" in %s", string(b))
	}
}

func TestCompile_FieldNameOnlyRuleCompiles(t *testing.T) {
	// 3.6：纯字段名规则同样必须真编译下发。
	fn := &repository.Rule{
		ID:              "rule_fn",
		RuleType:        "field_name",
		Name:            "字段名规则",
		Severity:        "high",
		Action:          "block",
		Enabled:         true,
		MatchConfigJSON: []byte("{\"field_names\":[\"id_card\",\"password\"],\"category\":\"pii_field\"}"),
	}
	pack := Compile("t1", []*repository.Rule{fn}, nil)
	if len(pack.Rules) != 1 {
		t.Fatalf("field_name-only rule must compile, got %d rules (skipped=%v)", len(pack.Rules), pack.Skipped)
	}
	if len(pack.Skipped) != 0 {
		t.Fatalf("no skip expected, got %v", pack.Skipped)
	}
	r := pack.Rules[0]
	if r.RuleType != "field_name" {
		t.Errorf("rule_type passthrough, got %q", r.RuleType)
	}
	if r.Category != "pii_field" {
		t.Errorf("category from match_config, got %q", r.Category)
	}
	if len(r.FieldNames) != 2 {
		t.Errorf("expected 2 field_names carried, got %v", r.FieldNames)
	}
	if r.Regex != "" {
		t.Errorf("field_name rule must not carry regex, got %q", r.Regex)
	}
	b, _ := json.Marshal(r)
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("marshal/unmarshal: %v", err)
	}
	if _, ok := m["field_names"]; !ok {
		t.Errorf("missing JSON key \"field_names\" in %s", string(b))
	}
}

func TestCompile_NoMatcherAtAllSkipped(t *testing.T) {
	// 三种匹配器全空才记 no_supported_matcher（真缺匹配器，非静默截断）。
	bare := &repository.Rule{
		ID:              "rule_bare",
		RuleType:        "keyword",
		Name:            "无匹配器规则",
		Severity:        "low",
		Action:          "audit",
		Enabled:         true,
		MatchConfigJSON: []byte("{\"category\":\"x\"}"),
	}
	pack := Compile("t1", []*repository.Rule{bare}, nil)
	if len(pack.Rules) != 0 {
		t.Fatalf("rule with no matcher must not compile, got %d rules", len(pack.Rules))
	}
	if len(pack.Skipped) != 1 || pack.Skipped[0].Reason != "no_supported_matcher" {
		t.Fatalf("expected no_supported_matcher skip, got %v", pack.Skipped)
	}
}

func TestCompile_DisabledRuleSkipped(t *testing.T) {
	r := medicalRule()
	r.Enabled = false
	pack := Compile("t1", []*repository.Rule{r}, nil)
	if len(pack.Rules) != 0 {
		t.Fatalf("disabled rule must not compile")
	}
	if len(pack.Skipped) != 1 || pack.Skipped[0].Reason != "disabled" {
		t.Fatalf("expected disabled skip, got %v", pack.Skipped)
	}
}

func TestCompile_EmptyInputYieldsNonNilSlices(t *testing.T) {
	pack := Compile("t1", nil, nil)
	if len(pack.Rules) != 0 || len(pack.Skipped) != 0 {
		t.Fatalf("empty input -> empty pack")
	}
	if pack.TenantID != "t1" {
		t.Fatalf("tenant id must be set")
	}
	// rules / exceptions 必须序列化为 [] 而非 null，避免引擎侧解析歧义。
	b, _ := json.Marshal(pack)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	if m["rules"] == nil {
		t.Errorf("rules must marshal as [] not null: %s", string(b))
	}
	if m["exceptions"] == nil {
		t.Errorf("exceptions must marshal as [] not null: %s", string(b))
	}
}

// 2.9.22（设计 5.4）：编译期不再按规则类别丢例外。私钥、凭据路径等保留类目
// 规则的例外与普通例外一样下发，由引擎按命中套用。
func TestCompile_ExceptionOnReservedCategoryRuleIsCompiled(t *testing.T) {
	excs := []*repository.ContentAuditException{
		auditException("exc_pk", "rule_pk001", "audit"),
		auditException("exc_med", "rule_med001", "allow"),
	}
	pack := Compile("t1", []*repository.Rule{privateKeyRule(), medicalRule()}, excs)
	got := map[string]string{}
	for _, e := range pack.Exceptions {
		got[e.ExceptionID] = e.RuleID
	}
	if got["exc_pk"] != "rule_pk001" || got["exc_med"] != "rule_med001" || len(got) != 2 {
		t.Fatalf("保留类目规则的例外必须照常下发，实际 %v（skipped=%v）", got, pack.Skipped)
	}
}

func TestCompile_ExceptionDowngradesNormalRule(t *testing.T) {
	// 针对普通规则的有效例外（decision=audit）必须编译进规则包。
	exc := auditException("exc_1", "rule_med001", "audit")
	pack := Compile("t1", []*repository.Rule{medicalRule()}, []*repository.ContentAuditException{exc})
	if len(pack.Exceptions) != 1 {
		t.Fatalf("expected 1 compiled exception, got %d (skipped=%v)", len(pack.Exceptions), pack.Skipped)
	}
	e := pack.Exceptions[0]
	if e.ExceptionID != "exc_1" || e.RuleID != "rule_med001" || e.Decision != "audit" {
		t.Errorf("exception fields mismatch: %+v", e)
	}
	// JSON 契约：exception_id / decision 字段名必须与引擎对齐。
	b, _ := json.Marshal(e)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"exception_id", "scope_type", "rule_id", "decision"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing exception JSON key %q in %s", k, string(b))
		}
	}
}
func TestCompile_ExceptionInvalidDecisionDropped(t *testing.T) {
	// 例外只能降级（allow/audit），decision=block 非法，必须丢弃（不静默截断）。
	exc := auditException("exc_bad", "rule_med001", "block")
	pack := Compile("t1", []*repository.Rule{medicalRule()}, []*repository.ContentAuditException{exc})
	if len(pack.Exceptions) != 0 {
		t.Fatalf("invalid-decision exception must not be served, got %d", len(pack.Exceptions))
	}
	if len(pack.Skipped) != 1 || pack.Skipped[0].Reason != "exception_invalid_decision" {
		t.Fatalf("expected exception_invalid_decision skip, got %v", pack.Skipped)
	}
}

func TestCompile_DisabledExceptionRecordedSkipped(t *testing.T) {
	// 被停用的例外不进入下发列表，但记为 skipped（不静默截断，与停用规则一致）。
	exc := auditException("exc_off", "rule_med001", "audit")
	exc.Enabled = false
	pack := Compile("t1", []*repository.Rule{medicalRule()}, []*repository.ContentAuditException{exc})
	if len(pack.Exceptions) != 0 {
		t.Fatalf("disabled exception must not be served")
	}
	if len(pack.Skipped) != 1 || pack.Skipped[0].Reason != "exception_disabled" {
		t.Fatalf("expected exception_disabled skip, got %v", pack.Skipped)
	}
}

func TestCompile_ExceptionUsesRuleRefWhenRuleIDEmpty(t *testing.T) {
	// 契约 7：内置规则例外 rule_id 恒空、rule_ref 携带内置英文 ID；
	// 编译后下发字段名不变（rule_id），值取自 rule_ref。
	exc := &repository.ContentAuditException{
		ID:        "cex_b1",
		TenantID:  "tenant_default",
		ScopeType: "rule",
		RuleID:    "",
		RuleRef:   "content_safety_illegal_drugs",
		Decision:  "audit",
		Reason:    "复核确认误报",
		Enabled:   true,
	}
	pack := Compile("t1", []*repository.Rule{medicalRule()}, []*repository.ContentAuditException{exc})
	if len(pack.Exceptions) != 1 {
		t.Fatalf("expected 1 compiled exception, got %d (skipped=%v)", len(pack.Exceptions), pack.Skipped)
	}
	if got := pack.Exceptions[0].RuleID; got != "content_safety_illegal_drugs" {
		t.Fatalf("内置引用应经 rule_ref 下发到 RuleID，got %q", got)
	}
}

func TestCompile_ExceptionCarriesVersionedScopeAndIncludeChildren(t *testing.T) {
	exc := auditException("exc-dept", "", "audit")
	exc.ScopeType = "actor_department_v1"
	exc.ScopeRef = "dept-parent"
	exc.IncludeChildren = true
	pack := Compile("tenant_default", nil, []*repository.ContentAuditException{exc})

	if len(pack.Exceptions) != 1 {
		t.Fatalf("expected department exception, got %+v skipped=%+v", pack.Exceptions, pack.Skipped)
	}
	compiled := pack.Exceptions[0]
	if compiled.ScopeType != "actor_department_v1" || compiled.ScopeRef != "dept-parent" || !compiled.IncludeChildren {
		t.Fatalf("versioned scope fields lost during compile: %+v", compiled)
	}
	encoded, _ := json.Marshal(compiled)
	if !bytes.Contains(encoded, []byte(`"include_children":true`)) {
		t.Fatalf("wire contract lost include_children: %s", encoded)
	}
}

func TestCompile_UnknownExceptionScopeFailsClosed(t *testing.T) {
	exc := auditException("exc-future", "rule_med001", "audit")
	exc.ScopeType = "future_scope"
	pack := Compile("tenant_default", []*repository.Rule{medicalRule()}, []*repository.ContentAuditException{exc})

	if len(pack.Exceptions) != 0 {
		t.Fatalf("unknown exception scope must not enter runtime pack: %+v", pack.Exceptions)
	}
	if len(pack.Skipped) != 1 || pack.Skipped[0].Reason != "exception_unknown_scope" {
		t.Fatalf("unknown exception scope must be diagnosed: %+v", pack.Skipped)
	}
}
