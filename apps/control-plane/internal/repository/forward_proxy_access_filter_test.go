package repository

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestForwardProxyConversationGroupingExpressions(t *testing.T) {
	for name, expr := range map[string]string{
		"risk":           forwardProxyTurnRiskStateExpr(),
		"reasons":        forwardProxyTurnRiskReasonsExpr(),
		"events":         forwardProxyTurnSecurityEventCountExpr(),
		"members":        forwardProxyTurnMemberCountExpr(),
		"member_ids":     forwardProxyTurnMemberIDsExpr(),
		"representative": forwardProxyTurnAntiJoinPredicate([]string{"rl.tenant_id = $1"}),
	} {
		if !strings.Contains(expr, "conversation_id = macl.conversation_id") {
			t.Fatalf("%s expression must group by conversation_id: %s", name, expr)
		}
		if strings.Contains(expr, "section_id IS NOT DISTINCT FROM macl.section_id") {
			t.Fatalf("%s expression must not split the same conversation by section_id: %s", name, expr)
		}
	}
	turnExpr := forwardProxyConversationTurnCountExpr()
	if !strings.Contains(turnExpr, "COUNT(DISTINCT COALESCE(NULLIF(acl_tc.section_id, ''), acl_tc.request_id))") {
		t.Fatalf("turn count must count section_id and fall back to request_id: %s", turnExpr)
	}
}

func TestForwardProxyConversationRepresentativeUsesFilteredCandidateSet(t *testing.T) {
	predicate := forwardProxyTurnAntiJoinPredicate([]string{
		"rl.tenant_id = $1",
		"rl.created_at >= $2",
		"LOWER(COALESCE(NULLIF(rl.proxy_provider, ''), 'unknown')) = $3",
	})
	for _, want := range []string{"rln.tenant_id = $1", "rln.created_at >= $2", "rln.proxy_provider"} {
		if !strings.Contains(predicate, want) {
			t.Fatalf("representative anti-join must reuse candidate filter %q: %s", want, predicate)
		}
	}
}
func TestBuildForwardProxyWhereContentOnlyRequiresActualRetainedContent(t *testing.T) {
	where, args := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{
		AccessType:  "llm",
		ContentOnly: true,
	})
	joined := strings.Join(where, "\n")

	if len(args) != 2 {
		t.Fatalf("args len = %d, want tenant and access_type args: %#v", len(args), args)
	}
	for _, want := range []string{
		"access_content_logs acl_content",
		"request_content_redacted",
		"file_metadata_json",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("content-only filter missing %q in where clause:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "proxy_content_retained") {
		t.Fatalf("content-only filter should use actual retained content logs, not policy flag:\n%s", joined)
	}
	if !strings.Contains(joined, "proxy_endpoint_kind") || !strings.Contains(joined, "<> 'file'") {
		t.Fatalf("LLM content-only filter should exclude auxiliary file/upload/sign endpoints:\n%s", joined)
	}
	if !strings.Contains(joined, "proxy_method") || !strings.Contains(joined, "GET") || !strings.Contains(joined, "OPTIONS") {
		t.Fatalf("LLM content-only filter should exclude auxiliary GET/OPTIONS web requests:\n%s", joined)
	}
	for _, want := range []string{
		"client/settings",
		"telemetry",
		"create_pow_challenge",
		"chat_session",
		"/api/v1/chat/snap",
		"/backend-api/sentinel/",
		"/backend-api/beacons/",
		"/backend-api/accounts/",
		"/backend-api/canopy/",
		"/backend-api/lat/",
		"/experiences/",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("LLM content-only filter should exclude auxiliary path %q:\n%s", want, joined)
		}
	}

}

func TestBuildForwardProxyWhereKeywordSearchesRetainedContentLiterallyAndTenantScoped(t *testing.T) {
	where, args := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{
		Keyword: "  50%_计划\\路径  ", ContentOnly: true,
	})
	joined := strings.Join(where, "\n")

	for _, want := range []string{
		"access_content_logs keyword_match",
		"request_content_redacted",
		"response_content_redacted",
		"file_metadata_json",
		"keyword_match.tenant_id = $1",
		"SELECT keyword_current.request_id",
		"UNION",
		"conversation_id",
		"section_id IS NOT DISTINCT FROM",
		"FROM content_logs keyword_content",
		"JOIN request_logs keyword_canonical",
		"keyword_canonical.id = keyword_content.request_id",
		"keyword_content.role IN ('user', 'assistant')",
		"jjdguard_customer_content_text(keyword_content.content)",
		"ESCAPE E'\\\\'",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("keyword filter missing %q:\n%s", want, joined)
		}
	}
	for _, forbidden := range []string{"request_content_encrypted", "response_content_encrypted", "file_metadata_json::text"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("keyword filter must not inspect encrypted payload column %q:\n%s", forbidden, joined)
		}
	}
	if strings.Contains(joined, "content_logs cl_content") {
		t.Fatalf("keyword match already proves retained content and must not run the generic content-only scan:\n%s", joined)
	}
	if got := args[len(args)-1]; got != `%50\%\_计划\\路径%` {
		t.Fatalf("keyword pattern = %#v, want escaped literal pattern", got)
	}
}

func TestBuildForwardProxyKeywordMatchWhereBoundsRetainedRows(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	where, args := buildForwardProxyKeywordMatchWhere(
		ForwardProxyAccessFilter{StartTime: start, EndTime: end},
		[]interface{}{"tenant-a", "existing-filter-argument"},
	)
	joined := strings.Join(where, "\n")

	for _, want := range []string{
		"keyword_match.tenant_id = $1",
		"keyword_match.created_at >= $3",
		"keyword_match.created_at < $4",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("keyword match set missing %q:\n%s", want, joined)
		}
	}
	if len(args) != 4 || args[2] != start || args[3] != end {
		t.Fatalf("keyword match args = %#v, want existing args followed by start/end", args)
	}
}

func TestBuildForwardProxyWhereUsesScopedHalfOpenWindow(t *testing.T) {
	t.Setenv("RETENTION_INCLUDE_LEGACY_UNCLASSIFIED", "true")
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(30 * 24 * time.Hour)
	where, args := buildForwardProxyWhere("tenant_a", ForwardProxyAccessFilter{
		EnvironmentScope: "customer",
		StartTime:        start,
		EndTime:          end,
	})
	joined := strings.Join(where, " AND ")
	if !strings.Contains(joined, "rl.environment_scope = ANY($2)") {
		t.Fatalf("missing environment scope predicate: %s", joined)
	}
	if !strings.Contains(joined, "rl.created_at >= $3") || !strings.Contains(joined, "rl.created_at < $4") {
		t.Fatalf("expected half-open UTC window predicates: %s args=%#v", joined, args)
	}
	if strings.Contains(joined, "<=") {
		t.Fatalf("closed end boundary leaked into query: %s", joined)
	}
	if got, ok := args[1].([]string); !ok || len(got) != 2 || got[0] != "customer" || got[1] != LegacyEnvironmentScope {
		t.Fatalf("scope arg = %#v, want customer and legacy scopes", args[1])
	}
}

func TestEnvironmentScopesForReadKeepsNonCustomerScopesIsolated(t *testing.T) {
	t.Setenv("RETENTION_INCLUDE_LEGACY_UNCLASSIFIED", "true")
	for _, scope := range []string{"home", "codex"} {
		got := EnvironmentScopesForRead(scope)
		if len(got) != 1 || got[0] != scope {
			t.Fatalf("read scopes for %q = %#v, want only itself", scope, got)
		}
	}
}

func TestEnvironmentScopesForReadDefaultsToStrictCustomerScope(t *testing.T) {
	t.Setenv("RETENTION_INCLUDE_LEGACY_UNCLASSIFIED", "false")
	got := EnvironmentScopesForRead("customer")
	if len(got) != 1 || got[0] != "customer" {
		t.Fatalf("strict customer scope = %#v, want customer only", got)
	}
}

func TestBuildForwardProxyKeywordMatchWhereUsesCompatibleCustomerScopeOnly(t *testing.T) {
	t.Setenv("RETENTION_INCLUDE_LEGACY_UNCLASSIFIED", "true")
	where, args := buildForwardProxyKeywordMatchWhere(ForwardProxyAccessFilter{EnvironmentScope: "customer"}, []interface{}{"tenant-a"})
	joined := strings.Join(where, " AND ")
	if !strings.Contains(joined, "keyword_match.environment_scope = ANY($2)") {
		t.Fatalf("missing keyword scope predicate: %s", joined)
	}
	if got, ok := args[1].([]string); !ok || len(got) != 2 || got[0] != "customer" || got[1] != LegacyEnvironmentScope {
		t.Fatalf("keyword scope arg = %#v, want customer and legacy scopes", args[1])
	}
	for _, scope := range []string{"home", "codex"} {
		_, scopedArgs := buildForwardProxyKeywordMatchWhere(ForwardProxyAccessFilter{EnvironmentScope: scope}, []interface{}{"tenant-a"})
		got, ok := scopedArgs[1].([]string)
		if !ok || len(got) != 1 || got[0] != scope {
			t.Fatalf("keyword read scopes for %q = %#v, want only itself", scope, scopedArgs[1])
		}
	}
}

func TestScopedRetentionReadsUseEnvironmentScopesForRead(t *testing.T) {
	cases := []struct {
		file                string
		required, forbidden []string
	}{
		{file: "forward_proxy_access.go", required: []string{"EnvironmentScopesForRead(environmentScope)", "acl.environment_scope = ANY", "rl.environment_scope = ANY"}, forbidden: []string{"args = append(args, NormalizeEnvironmentScope(environmentScope))"}},
		{file: "retained_artifacts.go", required: []string{"EnvironmentScopesForRead(environmentScope)", "l.environment_scope = ANY", "a.environment_scope = ANY", "rl.environment_scope = ANY"}, forbidden: []string{"NormalizeEnvironmentScope(environmentScope)"}},
		{file: "evidence_timeline.go", required: []string{"EnvironmentScopesForRead(scope)", "environment_scope = ANY($3)"}, forbidden: []string{"scope = NormalizeEnvironmentScope(scope)"}},
	}
	for _, tc := range cases {
		body := readRepoFile(t, tc.file)
		for _, want := range tc.required {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing compatible scoped-read fragment %q", tc.file, want)
			}
		}
		for _, forbidden := range tc.forbidden {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s still contains single-scope read fragment %q", tc.file, forbidden)
			}
		}
	}
}

func TestNormalizeEnvironmentScopeRejectsUntrustedValue(t *testing.T) {
	if got := NormalizeEnvironmentScope("workspace-from-header"); got != LegacyEnvironmentScope {
		t.Fatalf("untrusted scope = %q, want %q", got, LegacyEnvironmentScope)
	}
}

func TestBuildForwardProxyWhereAIIdeContentOnlyRequiresActualContent(t *testing.T) {
	where, args := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{
		AccessType:  "ai_ide",
		ContentOnly: true,
	})
	joined := strings.Join(where, "\n")

	if len(args) != 2 {
		t.Fatalf("args len = %d, want tenant and access_type args: %#v", len(args), args)
	}
	if !strings.Contains(joined, "access_content_logs acl_content") {
		t.Fatalf("AI IDE content-only filter should require actual retained content logs:\n%s", joined)
	}
	if strings.Contains(joined, "proxy_method") || strings.Contains(joined, "create_pow_challenge") {
		t.Fatalf("AI IDE content-only filter should not inherit LLM web auxiliary path exclusions:\n%s", joined)
	}
}

func TestForwardProxyRiskExprIgnoresDoubaoProtocolBankCardFalsePositive(t *testing.T) {
	expr := forwardProxyRiskExpr()

	for _, want := range []string{
		"regex_bank_card_cn",
		"bank_card_cn",
		"www.doubao.com",
		"proxy_output_audit",
		"matched_location_preview",
		"redacted_evidence",
	} {
		if !strings.Contains(expr, want) {
			t.Fatalf("risk expression should filter known Doubao protocol bank-card false positives, missing %q:\n%s", want, expr)
		}
	}
	if strings.Contains(expr, "hasForwardProxyFindings") {
		t.Fatalf("risk expression should expand all finding checks:\n%s", expr)
	}
}

func TestForwardProxyRiskExprIgnoresWeakAuditOnlyProtocolAndFileSignals(t *testing.T) {
	expr := forwardProxyRiskExpr()
	reasonsExpr := forwardProxyRiskReasonsExpr()
	combined := expr + "\n" + reasonsExpr

	for _, want := range []string{
		"structured_html_comment",
		"structured_template_injection",
		"prompt_injection_template_injection",
		"file_unknown_type",
		"file_archive",
		"file_type_mismatch",
	} {
		if !strings.Contains(combined, want) {
			t.Fatalf("risk expressions should ignore weak audit-only signal %q, got:\n%s", want, combined)
		}
	}
	for _, strong := range []string{
		"file_disguised_executable",
		"file_zip_bomb",
		"private_key",
	} {
		if strings.Contains(combined, strong) {
			t.Fatalf("risk expressions must not classify strong signal %q as weak ignored finding:\n%s", strong, combined)
		}
	}
}

func TestForwardProxyRiskExprIgnoresAgentInventoryOnlySignals(t *testing.T) {
	expr := forwardProxyRiskExpr()
	reasonsExpr := forwardProxyRiskReasonsExpr()
	combined := expr + "\n" + reasonsExpr

	for _, want := range []string{
		"agent_github_copilot",
		"agent_cursor",
		"agent_claude_code",
	} {
		if !strings.Contains(combined, want) {
			t.Fatalf("risk expressions should ignore agent inventory-only signal %q, got:\n%s", want, combined)
		}
	}
	for _, strong := range []string{
		"agent_permission_governance",
		"agent_permission_policy",
	} {
		if strings.Contains(combined, strong) {
			t.Fatalf("risk expressions must not classify governance signal %q as inventory-only:\n%s", strong, combined)
		}
	}
}

func TestForwardProxyRiskReasonsExprUsesEffectiveFindings(t *testing.T) {
	expr := forwardProxyRiskReasonsExpr()

	for _, want := range []string{
		"jsonb_agg",
		"risk_reason",
		"regex_bank_card_cn",
		"matched_summary",
		"security_events",
	} {
		if !strings.Contains(expr, want) {
			t.Fatalf("risk reasons expression should collect concrete effective reasons, missing %q:\n%s", want, expr)
		}
	}
}

func TestForwardProxyAttentionTurnRiskReasonsKeepsLegacyEventCategory(t *testing.T) {
	expr := forwardProxyAttentionTurnRiskReasonsExpr()

	for _, want := range []string{
		"WHEN jsonb_array_length",
		"se_reason.matched_summary->>'category'",
		"jsonb_build_array(jsonb_build_object('category'",
	} {
		if !strings.Contains(expr, want) {
			t.Fatalf("attention risk reasons must retain legacy event category fallback, missing %q:\\n%s", want, expr)
		}
	}
}

func TestForwardProxyAccessCountsUsesSinglePrecomputedAggregate(t *testing.T) {
	source, err := os.ReadFile("forward_proxy_access.go")
	if err != nil {
		t.Fatalf("read forward_proxy_access.go: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "func (r *RequestLogRepository) GetForwardProxyAccessCounts")
	if start < 0 {
		t.Fatal("missing GetForwardProxyAccessCounts")
	}
	end := strings.Index(text[start:], "\nfunc ")
	if end < 0 {
		t.Fatal("could not isolate GetForwardProxyAccessCounts")
	}
	body := text[start : start+end]
	if strings.Contains(body, "r.GetForwardProxyAccessSummary(") {
		t.Fatal("counts endpoint must not call the full multi-query summary")
	}
	for _, want := range []string{
		"COUNT(*)::int",
		"rl.proxy_access_type_resolved = 'llm'",
		"rl.proxy_access_type_resolved = 'ai_ide'",
		"rl.proxy_access_type_resolved = 'normal_public'",
		"COALESCE(rl.has_retained_content, false)",
		"buildForwardProxyWhere(tenantID, filter)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("counts endpoint missing %q:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{"forwardProxyGroupedEvidenceQuality", "forwardProxyGroupedTimeline", "forwardProxyGroupedTopDimension"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("counts endpoint must not execute expensive facet %q", forbidden)
		}
	}
}

func TestForwardProxyAccessSummaryKeepsDirectionFilterAndUnboundedProviderFacet(t *testing.T) {
	source, err := os.ReadFile("forward_proxy_access.go")
	if err != nil {
		t.Fatalf("read forward_proxy_access.go: %v", err)
	}
	text := string(source)

	if strings.Contains(text, "filter.Direction = \"\"") {
		t.Fatalf("summary query must preserve direction in buildForwardProxyWhere")
	}
	if strings.Contains(text, "LIMIT 5") {
		t.Fatalf("provider facet must not be capped at 5 entries")
	}
}

func TestForwardProxyAccessProjectionJoinsAtMostOneContentRowPerRequest(t *testing.T) {
	source, err := os.ReadFile("forward_proxy_access.go")
	if err != nil {
		t.Fatalf("read forward_proxy_access.go: %v", err)
	}
	text := string(source)

	for _, want := range []string{
		"func forwardProxySingleContentLogJoinSQL",
		"LEFT JOIN LATERAL",
		"ORDER BY acl_selected.created_at DESC, acl_selected.id DESC",
		"LIMIT 1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("forward proxy projection must select one content row per request, missing %q", want)
		}
	}
	if got := strings.Count(text, "forwardProxySingleContentLogJoinSQL(\"macl\")"); got != 4 {
		t.Fatalf("list, count, keyword, and summary projections must share the one-row join; got %d call sites", got)
	}
}

func TestBuildForwardProxyWhereRequestIDResolvesTurnMember(t *testing.T) {
	where, args := buildForwardProxyWhere("t1", ForwardProxyAccessFilter{RequestID: "req_deep_1"})
	joined := strings.Join(where, " AND ")
	if !strings.Contains(joined, "rl.request_id = $") {
		t.Fatalf("应有 request_id 精确条件: %s", joined)
	}
	for _, want := range []string{
		"FROM access_content_logs acl_current",
		"JOIN access_content_logs acl_target",
		"acl_target.request_id = $",
		"acl_current.conversation_id = acl_target.conversation_id",
		"acl_current.section_id IS NOT DISTINCT FROM acl_target.section_id",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("request_id deep link should resolve a turn member to its representative, missing %q: %s", want, joined)
		}
	}

	found := false
	for _, a := range args {
		if a == "req_deep_1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("args 应含 request_id: %v", args)
	}
	// 深链定位时不应再强加 access_type IN ('llm','ai_ide') 默认限制（目标行可能是任意类型）
	if strings.Contains(joined, "IN ('llm', 'ai_ide')") {
		t.Fatalf("request_id 定位不应叠加默认 access_type 限制: %s", joined)
	}
}

func TestBuildForwardProxyWhereDefaultUnchangedWithoutRequestID(t *testing.T) {
	where, _ := buildForwardProxyWhere("t1", ForwardProxyAccessFilter{})
	if !strings.Contains(strings.Join(where, " AND "), "IN ('llm', 'ai_ide')") {
		t.Fatal("无 request_id 时默认大模型流量限制必须保持（零回归）")
	}
}

func TestBuildForwardProxyWhereTargetMatchesModelDisplayName(t *testing.T) {
	where, args := buildForwardProxyWhere("tenant_a", ForwardProxyAccessFilter{
		TargetHost: " GLM-5.2 ",
	})
	joined := strings.Join(where, "\n")

	for _, want := range []string{
		"rl.proxy_target_host",
		"rl.model_id",
		"FROM models model_filter",
		"JOIN providers provider_filter",
		"provider_filter.tenant_id = rl.tenant_id",
		"model_filter.model_name",
		"model_filter.model_label",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("target filter should match model display names, missing %q:\n%s", want, joined)
		}
	}
	if got := args[len(args)-1]; got != "%glm-5.2%" {
		t.Fatalf("target filter arg = %#v, want %%glm-5.2%%", got)
	}
}

func TestBuildForwardProxyWhereSourceUsesCustomerVisibleFields(t *testing.T) {
	where, args := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{SourceIP: "zhangsan"})
	joined := strings.Join(where, "\n")
	if len(args) != 2 || args[1] != "%zhangsan%" {
		t.Fatalf("responsibility args = %#v", args)
	}
	for _, want := range []string{
		"internal_keys responsibility_key",
		"responsibility_key.name",
		"proxy_source_ip",
		"proxy_mode",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("responsibility filter missing %q:\n%s", want, joined)
		}
	}
	for _, forbidden := range []string{
		"users responsibility_user",
		"responsibility_user.username",
		"LOWER(COALESCE(rl.client_id",
		"LOWER(COALESCE(rl.user_id",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("responsibility filter must not expose internal identifier matcher %q:\n%s", forbidden, joined)
		}
	}
}

func TestBuildForwardProxyWhereCombinesExactUserDispositionAndSourceFilters(t *testing.T) {
	where, args := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{
		UserID:      " user_42 ",
		Disposition: " resolved ",
		Provider:    "deepseek",
		SourceIP:    "研发入口",
	})
	joined := strings.Join(where, "\n")

	for _, want := range []string{
		"rl.user_id = $",
		"audit_dispositions disposition_filter",
		"SELECT disposition_filter.status",
		"LOWER(COALESCE(NULLIF(rl.proxy_provider",
		"internal_keys responsibility_key",
		"proxy_source_ip",
		"proxy_mode",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("combined filter missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "users responsibility_user") {
		t.Fatalf("source filter must not masquerade as a user selector:\n%s", joined)
	}
	for _, want := range []interface{}{"tenant_default", "deepseek", "user_42", "resolved", "%研发入口%"} {
		found := false
		for _, arg := range args {
			if arg == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("combined filter args %#v missing %#v", args, want)
		}
	}
}

func TestForwardProxyKeywordSourcesUseCanonicalRequestIDAndCustomerRoles(t *testing.T) {
	sql := forwardProxyKeywordMatchSourceSQL(
		[]string{"keyword_match.tenant_id = $1"},
		[]string{"keyword_content.tenant_id = $1"},
		2,
	)
	for _, want := range []string{
		"FROM access_content_logs keyword_match",
		"request_content_redacted",
		"response_content_redacted",
		"visible_file->>'file_name'",
		"visible_file->>'text_preview'",
		"UNION",
		// 正文：去重正文表按 trigram 找命中正文（写入时算好的客户正文判定），再找引用它们的条目；旧表照旧逐行判断。
		"FROM content_log_bodies keyword_body",
		"keyword_body.customer_text",
		"JOIN content_log_entries keyword_content",
		"FROM content_logs_legacy keyword_content",
		"JOIN request_logs keyword_canonical",
		"keyword_canonical.id = keyword_content.request_id",
		"keyword_canonical.request_id",
		"keyword_content.role IN ('user', 'assistant')",
		"jjdguard_customer_content_text(keyword_content.content)",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("keyword source SQL missing %q:\n%s", want, sql)
		}
	}
	for _, forbidden := range []string{"role = 'system'", "role = 'tool'", "role = 'memory'", "file_metadata_json::text"} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("keyword source SQL must not search %q:\n%s", forbidden, sql)
		}
	}
}

func TestBuildForwardProxyWhereAttentionUsesTurnRiskAndRepresentative(t *testing.T) {
	where, args := buildForwardProxyWhere("tenant_attention", ForwardProxyAccessFilter{RiskState: "attention"})
	joined := strings.Join(where, " AND ")

	if !strings.Contains(joined, "rl.tenant_id = $1") {
		t.Fatalf("attention filter must retain tenant scope: %s", joined)
	}
	if strings.Contains(joined, "rl.risk_state IN") {
		t.Fatalf("attention filter must not retain physical-row risk filtering: %s", joined)
	}
	if !strings.Contains(joined, "IN ($2, $3)") {
		t.Fatalf("attention filter must parameterize requested risk states: %s", joined)
	}
	for _, fragment := range []string{
		"acl_attention_current",
		"acl_attention_member",
		"acl_attention_newer",
		"bool_or(COALESCE(rlm.risk_state, 'normal') = 'blocked')",
		"NOT EXISTS (",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("attention filter must use turn aggregation fragment %q: %s", fragment, joined)
		}
	}
	if len(args) != 3 || args[0] != "tenant_attention" || args[1] != "risk" || args[2] != "blocked" {
		t.Fatalf("attention filter args = %#v, want tenant, risk, blocked", args)
	}
}

func TestAccessRollupFilterWhereAttentionIncludesRiskAndBlocked(t *testing.T) {
	where, args := accessRollupFilterWhere("tenant_attention", ForwardProxyAccessFilter{RiskState: "attention"})

	if !strings.Contains(where, "tenant_id = $1") {
		t.Fatalf("rollup attention filter must retain tenant scope: %s", where)
	}
	if !strings.Contains(where, "risk_state IN ($2, $3)") {
		t.Fatalf("rollup attention filter must use parameterized risk/blocked IN condition: %s", where)
	}
	if strings.Contains(where, "'risk'") || strings.Contains(where, "'blocked'") {
		t.Fatalf("rollup attention filter must not interpolate risk states into SQL: %s", where)
	}
	if len(args) != 3 || args[0] != "tenant_attention" || args[1] != "risk" || args[2] != "blocked" {
		t.Fatalf("rollup attention filter args = %#v, want tenant, risk, blocked", args)
	}
}

func TestRetentionKeywordScopeRestrictsBothSources(t *testing.T) {
	for _, scope := range []string{"request", "response"} {
		sql := forwardProxyKeywordMatchSourceSQL([]string{"keyword_match.tenant_id=$1"}, []string{"keyword_content.tenant_id=$1"}, 2, scope)
		role, excluded := "assistant", "request"
		if scope == "request" {
			role, excluded = "user", "response"
		}
		if !strings.Contains(sql, "keyword_content.role = '"+role+"'") || strings.Contains(sql, "jjdguard_customer_content_text(keyword_match."+excluded+"_content_redacted)") {
			t.Fatalf("scope=%s sql=%s", scope, sql)
		}
		if strings.Contains(sql, "visible_file") {
			t.Fatalf("scope must exclude file names: %s", sql)
		}
	}
}
