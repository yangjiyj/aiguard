package repository

import (
	"strings"
	"testing"
)

// 多租户 + 行业隔离是安全敏感面（AGENTS.md 强制测试）。
// buildCompilableRulesQuery 必须保证：
//   - 本租户自有已发布规则恒纳入（含 disabled，交由编译器形成诊断）；
//   - 系统内置包仅当 source_type='builtin' 且 industry∈{generic, 本租户行业} 时纳入；
//   - 行业值只能经绑定参数进入，绝不拼进 SQL 文本（防注入）。
func TestBuildCompilableRulesQueryIsolatesTenantAndIndustry(t *testing.T) {
	query, args := buildCompilableRulesQuery("tenant_demo", "medical_imaging")

	// 参数顺序：$1=本租户, $2=系统租户, $3=行业
	if len(args) != 3 {
		t.Fatalf("args len = %d, want 3: %#v", len(args), args)
	}
	if args[0] != "tenant_demo" || args[1] != SystemTenantID || args[2] != "medical_imaging" {
		t.Fatalf("args = %#v, want [tenant_demo %s medical_imaging]", args, SystemTenantID)
	}

	// 系统内置规则必须合并当前租户动作覆盖；覆盖键同时绑定 tenant 与 rule，不能跨租户。
	for _, want := range []string{
		"LEFT JOIN builtin_rule_overrides bro",
		"bro.tenant_id = $1",
		"bro.rule_id = r.id",
		"COALESCE(bro.action, r.action)",
		"COALESCE(bro.enabled, r.enabled)",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("builtin override contract missing %q:\\n%s", want, query)
		}
	}

	// 本租户自有规则恒纳入
	if !strings.Contains(query, "rs.tenant_id = $1") {
		t.Fatalf("query must always include own tenant rules:\n%s", query)
	}
	// 系统预置包：必须同时满足 系统租户 + builtin + 行业∈{generic,本行业}
	for _, want := range []string{
		"rs.tenant_id = $2",
		"rs.source_type = 'builtin'",
		"rs.industry IN ('generic', $3)",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("builtin pack predicate missing %q:\n%s", want, query)
		}
	}
	// 规则集仍须发布；规则 enabled 状态必须交给编译器分类，不能在查询层静默丢弃。
	if !strings.Contains(query, "rs.published = TRUE") {
		t.Fatalf("must keep published gate:\n%s", query)
	}
	if strings.Contains(query, "r.enabled = TRUE") {
		t.Fatalf("disabled candidates must reach compiler diagnostics:\n%s", query)
	}
	if !strings.Contains(query, "LIMIT 10001") {
		t.Fatalf("candidate query must fetch at most one overflow sentinel row:\n%s", query)
	}
	// 安全：行业值只能经 $3 占位符进入，绝不拼接进 SQL 文本
	if strings.Contains(query, "medical_imaging") {
		t.Fatalf("industry must be a bound param, never inlined:\n%s", query)
	}
}

func TestBuildCompilableRulesQueryGenericTenantGetsOnlyGeneric(t *testing.T) {
	_, args := buildCompilableRulesQuery("tenant_demo", "generic")
	if args[2] != "generic" {
		t.Fatalf("generic tenant industry arg = %v, want generic", args[2])
	}
	// IN ('generic', 'generic') 语义上即只命中 generic，无需特判
}
