package repository

import (
	"strings"
	"testing"
)

// 内容留证列表的 ContentOnly 过滤之前只查正向库 access_content_logs（按 rl.request_id
// 关联），把存放在 content_logs（按 rl.id 关联，content_logs.request_id 外键指向
// request_logs.id）的反向代理留证全部挡在列表外——1282 条反向大模型调用（含 LSE
// 攻击留证）在「全部 / 全部」标签下完全不可见。过滤必须同时识别反向内容。
func TestBuildForwardProxyWhereContentOnlyIncludesReverseContentLogs(t *testing.T) {
	where, _ := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{
		ContentOnly: true,
	})
	joined := strings.Join(where, "\n")

	if !strings.Contains(joined, "access_content_logs acl_content") {
		t.Fatalf("forward content store access_content_logs must be preserved:\n%s", joined)
	}
	if !strings.Contains(joined, "content_logs_legacy") {
		t.Fatalf("content-only filter must also recognize reverse content in content_logs:\n%s", joined)
	}
	// 反向内容按 rl.id 关联（content_logs.request_id -> request_logs.id），不能用 rl.request_id。
	if !strings.Contains(joined, "cl_content.request_id = rl.id") {
		t.Fatalf("reverse content branch must join content_logs on rl.id:\n%s", joined)
	}
	// 反向分支必须限定非 forward，保证正向行零回归，同时兼容历史 NULL。
	if !strings.Contains(joined, "rl.proxy_mode, '') <> 'forward'") {
		t.Fatalf("reverse content branch must be gated to reverse proxy rows:\n%s", joined)
	}
}

// 「大模型访问」标签会在内容过滤外再套 forwardProxyAuditableLLMContentExpr 的辅助
// 路径排除；反向行的 proxy_* 字段为空可穿过这些排除，反向内容分支也必须随之带入
// llm 分支（包装器套在 base 内容表达式之外）。
func TestBuildForwardProxyWhereLLMContentOnlyIncludesReverseContentLogs(t *testing.T) {
	where, _ := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{
		AccessType:  "llm",
		ContentOnly: true,
	})
	joined := strings.Join(where, "\n")

	if !strings.Contains(joined, "content_logs_legacy") {
		t.Fatalf("llm content-only filter must also recognize reverse content in content_logs:\n%s", joined)
	}
	if !strings.Contains(joined, "proxy_method") {
		t.Fatalf("llm wrapper auxiliary exclusions must be preserved:\n%s", joined)
	}
}

func TestBuildForwardProxyWhereContentOnlyExcludesInternalTitleCalls(t *testing.T) {
	where, _ := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{
		AccessType:  "llm",
		ContentOnly: true,
	})
	joined := strings.Join(where, "\n")

	for _, required := range []string{
		"LOWER(COALESCE(rl.agent_type, '')) = 'workbuddy'",
		"acl_internal.response_content_redacted",
		"LOWER(BTRIM(COALESCE(acl_internal.model, ''))) = 'deepseek-v4-flash'",
		"BTRIM(COALESCE(acl_internal.request_content_redacted, '')) LIKE '<session>%'",
		`"isNewTopic"`,
		`"title"`,
		"COALESCE(rl.proxy_mode, '') = 'chat_completion'",
		"LOWER(COALESCE(rl.endpoint_type, '')) = 'chat'",
		"COALESCE(rl.evidence_run_source, '') = ''",
		"content_log_entries",
		"cl_internal_user.request_id = rl.id",
		"cl_internal_user.role = 'user'",
		"BTRIM(COALESCE(cl_internal_user.content, '')) ~ '^<session>([[:space:]]|$)'",
		"content_logs_legacy",
		"cl_internal_assistant.request_id = rl.id",
		"cl_internal_assistant.role = 'assistant'",
		"LOWER(COALESCE(rl.agent_type, '')) = 'codebuddy'",
		"LOWER(COALESCE(rl.proxy_target_host, '')) = 'copilot.tencent.com'",
		"SPLIT_PART(LOWER(BTRIM(COALESCE(rl.proxy_target_path, ''))), '?', 1) = '/v2/chat/completions'",
		"COALESCE(rl.proxy_request_bytes, 0) BETWEEN 1 AND 4096",
		"LOWER(BTRIM(COALESCE(acl_internal.model, ''))) = 'deepseek-v4-pro'",
		"STRPOS(REPLACE(COALESCE(acl_internal.request_content_redacted, ''), E'\\r\\n', E'\\n'), E'\\nA:') > 0",
		"LOWER(COALESCE(rl.agent_type, '')) = 'openai-codex'",
		"SPLIT_PART(LOWER(BTRIM(COALESCE(rl.proxy_target_path, ''))), '?', 1) = '/v1/responses'",
		"LOWER(BTRIM(COALESCE(acl_internal.model, ''))) = 'gpt-5.6-luna'",
		`STRPOS(acl_internal.response_content_redacted, '"description"') > 0`,
		"You are a helpful assistant. You will be presented with a user prompt",
		"The title you generate will be shown in the UI to represent the prompt.",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("content-only filter must exclude client internal metadata; missing %q:\n%s", required, joined)
		}
	}
	for _, forbidden := range []string{"ILIKE '%title%'", "ILIKE '%summarize%'"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("internal metadata filter must use protocol fingerprints, not broad user keywords %q:\n%s", forbidden, joined)
		}
	}
	if got := strings.Count(joined, "OFFSET 0"); got < 15 {
		t.Fatalf("internal title probes must remain indexed correlated lookups, got %d OFFSET fences:\n%s", got, joined)
	}
}

func TestBuildForwardProxyWhereKeywordSearchStillExcludesInternalTitleCalls(t *testing.T) {
	where, _ := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{
		Keyword:     "title",
		ContentOnly: true,
	})
	joined := strings.Join(where, "\n")

	if !strings.Contains(joined, "keyword_match.request_content_redacted") {
		t.Fatalf("keyword filter unexpectedly lost its retained-content lookup:\n%s", joined)
	}
	if !strings.Contains(joined, "You are a helpful assistant. You will be presented with a user prompt") ||
		!strings.Contains(joined, `"isNewTopic"`) {
		t.Fatalf("keyword task projection must retain internal metadata exclusion:\n%s", joined)
	}
	if got := strings.Count(joined, "You are a helpful assistant. You will be presented with a user prompt"); got != 1 {
		t.Fatalf("keyword task projection must apply the internal metadata predicate exactly once, got %d:\n%s", got, joined)
	}
}
