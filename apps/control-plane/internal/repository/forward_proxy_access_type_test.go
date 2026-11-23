package repository

import (
	"strings"
	"testing"
)

// 查询期 access_type 过滤必须使用物化列，避免 CASE 表达式让
// access_type=llm 的内容留证 tab 退化成全表扫描。
func TestForwardProxyAccessTypeExprUsesResolvedColumn(t *testing.T) {
	expr := forwardProxyAccessTypeExpr()

	if !strings.Contains(expr, "rl.proxy_access_type_resolved") {
		t.Fatalf("access_type read expr should use resolved column:\n%s", expr)
	}
	if strings.Contains(expr, "CASE") || strings.Contains(expr, "rl.proxy_access_type,") || strings.Contains(expr, "rl.proxy_mode") || strings.Contains(expr, "rl.model_id") {
		t.Fatalf("access_type read expr must not re-evaluate legacy CASE branches:\n%s", expr)
	}
}

func TestBuildForwardProxyWhereAccessTypeUsesResolvedColumn(t *testing.T) {
	where, args := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{AccessType: "llm"})
	joined := strings.Join(where, "\n")

	if len(args) != 2 {
		t.Fatalf("args len = %d, want tenant and access_type args: %#v", len(args), args)
	}
	if !strings.Contains(joined, "rl.proxy_access_type_resolved = $2") {
		t.Fatalf("access_type filter should be directly sargable on resolved column:\n%s", joined)
	}
	if strings.Contains(joined, "CASE") {
		t.Fatalf("access_type filter must not include CASE expression:\n%s", joined)
	}
}

// 物化列回填仍要完全复用旧 CASE 语义：反向代理访问内部模型服务时，
// 即使历史 proxy_access_type 写成 normal_public，只要 proxy_mode<>'forward'
// 且带 model_id，就应解析成 llm。
func TestForwardProxyLegacyAccessTypeExprClassifiesReverseModelCallsAsLLM(t *testing.T) {
	expr := forwardProxyLegacyAccessTypeExpr()

	for _, want := range []string{"proxy_mode", "model_id", "'llm'"} {
		if !strings.Contains(expr, want) {
			t.Fatalf("legacy access_type expr should classify reverse model calls as llm, missing %q:\n%s", want, expr)
		}
	}

	modelBranch := strings.Index(expr, "model_id")
	passthrough := strings.Index(expr, "rl.proxy_access_type")
	if modelBranch < 0 || passthrough < 0 {
		t.Fatalf("legacy expr missing expected branches:\n%s", expr)
	}
	if modelBranch > passthrough {
		t.Fatalf("reverse+model_id llm branch must precede proxy_access_type passthrough:\n%s", expr)
	}
}

// 不显式指定 access_type 时，内容留证默认只看大模型流量(llm+ai_ide)，
// 排除 normal_public(CDN/对象存储/遥测噪声)。本地 Qwen 解析为 llm 不被误杀。
func TestBuildForwardProxyWhereDefaultsToAIOnly(t *testing.T) {
	where, args := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{})
	joined := strings.Join(where, "\n")
	if !strings.Contains(joined, "rl.proxy_access_type_resolved IN ('llm', 'ai_ide')") {
		t.Fatalf("empty access_type should default to llm+ai_ide:\n%s", joined)
	}
	if strings.Contains(joined, "proxy_access_type_resolved = $") {
		t.Fatalf("default branch must not emit an equality access_type predicate:\n%s", joined)
	}
	if len(args) != 1 {
		t.Fatalf("default access_type must not add args (got %d): %#v", len(args), args)
	}
}

// 显式传 normal_public 覆盖默认，可查看噪声(非破坏性出口)。
func TestBuildForwardProxyWhereExplicitNormalPublicOverridesDefault(t *testing.T) {
	where, _ := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{AccessType: "normal_public"})
	joined := strings.Join(where, "\n")
	if !strings.Contains(joined, "rl.proxy_access_type_resolved = $2") {
		t.Fatalf("explicit normal_public should use equality filter:\n%s", joined)
	}
	if strings.Contains(joined, "IN ('llm', 'ai_ide')") {
		t.Fatalf("explicit normal_public must not also apply AI-only default:\n%s", joined)
	}
}

func TestBuildForwardProxyWhereExplicitAllOverridesDefault(t *testing.T) {
	where, args := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{AccessType: "all"})
	joined := strings.Join(where, "\n")

	if strings.Contains(joined, "proxy_access_type_resolved") {
		t.Fatalf("explicit all must not filter access type:\n%s", joined)
	}
	if len(args) != 1 {
		t.Fatalf("explicit all must keep tenant as the only argument, got %#v", args)
	}
}

func TestBuildForwardProxyWhereFiltersAgentType(t *testing.T) {
	where, args := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{AgentType: " workbuddy "})
	joined := strings.Join(where, "\n")

	if len(args) != 2 || args[1] != "workbuddy" {
		t.Fatalf("agent type filter args = %#v, want normalized workbuddy as second arg", args)
	}
	if !strings.Contains(joined, "LOWER(COALESCE(rl.agent_type, '')) = $2") {
		t.Fatalf("agent type filter should constrain request_logs.agent_type:\n%s", joined)
	}
}

// rollup 旁路必须同口径默认 AI-only，否则默认态 summary(走rollup)与列表(走实时)漂移。
func TestAccessRollupFilterWhereDefaultsToAIOnly(t *testing.T) {
	where, _ := accessRollupFilterWhere("tenant_default", ForwardProxyAccessFilter{})
	if !strings.Contains(where, "access_type IN ('llm', 'ai_ide')") {
		t.Fatalf("rollup empty access_type should default to llm+ai_ide:\n%s", where)
	}
}

// 三态分流回归保护：filter.Direction=reverse 必须只匹配真正的反向代理，
// 不能再沿用历史上的「非 forward 即 reverse」二元假设，否则会把模型中转
// 流量(chat_completion)误并入 reverse 桶——这正是 UI 误标 Claude Code
// 请求为「反向代理」的根因。
func TestBuildForwardProxyWhereDirectionReverseDoesNotCaptureChatCompletion(t *testing.T) {
	where, _ := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{Direction: "reverse"})
	joined := strings.Join(where, "\n")
	if !strings.Contains(joined, "rl.proxy_mode = 'reverse'") {
		t.Fatalf("reverse direction should pin proxy_mode='reverse' explicitly:\n%s", joined)
	}
	if strings.Contains(joined, "<> 'forward'") || strings.Contains(joined, "IS NULL") {
		t.Fatalf("reverse direction must NOT use legacy 'non-forward' catch-all (would swallow chat_completion):\n%s", joined)
	}
}

func TestBuildForwardProxyWhereDirectionChatCompletionIsSargable(t *testing.T) {
	where, _ := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{Direction: "chat_completion"})
	joined := strings.Join(where, "\n")
	if !strings.Contains(joined, "rl.proxy_mode = 'chat_completion'") {
		t.Fatalf("chat_completion direction should be a direct equality filter:\n%s", joined)
	}
}
