package repository

import (
	"strings"
	"testing"
)

// ListBuiltinDataSecurityRules 服务于「内容和数据安全」配置页的只读预置包展示，
// 它读取的是引擎实际编译下发的同一批内置规则——是给客户看的「当前生效数据安全规则」
// 单一事实源。它属多租户配置安全面（AGENTS.md 强制测试）：
//   - 只能读系统租户 tenant_system 名下的 builtin 规则，绝不能借此读到任意租户自有规则；
//   - 行业值只能经绑定参数进入，绝不拼进 SQL 文本（防注入）；
//   - 行业过滤口径必须与 buildCompilableRulesQuery 完全一致（generic ∪ 本行业），
//     否则配置页展示的预置包会与引擎真实下发漂移，对医疗政企客户即「所见非所防」。
func TestBuildBuiltinDataSecurityQueryIsolatesToSystemBuiltin(t *testing.T) {
	query, args := buildBuiltinDataSecurityQuery("medical_imaging")

	// 参数顺序：$1=系统租户, $2=行业
	if len(args) != 2 {
		t.Fatalf("args len = %d, want 2: %#v", len(args), args)
	}
	if args[0] != SystemTenantID || args[1] != "medical_imaging" {
		t.Fatalf("args = %#v, want [%s medical_imaging]", args, SystemTenantID)
	}

	// 必须收敛到 系统租户 + builtin（不能读任意租户自有规则）
	for _, want := range []string{
		"rs.tenant_id = $1",
		"rs.source_type = 'builtin'",
		"rs.industry IN ('generic', $2)",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("builtin pack predicate missing %q:\n%s", want, query)
		}
	}

	// 不得放开发布/启用门槛——展示口径须与引擎下发一致
	if !strings.Contains(query, "r.enabled = TRUE") || !strings.Contains(query, "rs.published = TRUE") {
		t.Fatalf("must keep enabled/published gates:\n%s", query)
	}

	// 安全：行业值只能经 $2 占位符进入，绝不拼接进 SQL 文本
	if strings.Contains(query, "medical_imaging") {
		t.Fatalf("industry must be a bound param, never inlined:\n%s", query)
	}
}

// 行业过滤口径必须与 buildCompilableRulesQuery 一致：内置预置包谓词
// （系统租户 + builtin + 行业∈{generic,本行业}）逐字对齐，杜绝展示与下发漂移。
func TestBuiltinDataSecurityMatchesCompilableIndustryPredicate(t *testing.T) {
	builtinQ, _ := buildBuiltinDataSecurityQuery("finance")
	compileQ, _ := buildCompilableRulesQuery("tenant_demo", "finance")
	for _, pred := range []string{
		"rs.source_type = 'builtin'",
		"rs.industry IN ('generic', $",
	} {
		if !strings.Contains(builtinQ, pred) {
			t.Fatalf("builtin query missing shared predicate %q:\n%s", pred, builtinQ)
		}
		if !strings.Contains(compileQ, pred) {
			t.Fatalf("compile query missing shared predicate %q:\n%s", pred, compileQ)
		}
	}
}
