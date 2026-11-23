package repository

import (
	"strings"
	"testing"
)

// 总览聚合必须沿用会话列表那套「可处置告警」定义，否则页面数字会和告警页对不上。
func TestContentSecurityOverviewReusesActionableAlertDefinition(t *testing.T) {
	query := buildContentSecurityOverviewQuery()

	for _, fragment := range []string{
		"se.alert_group_id IS NOT NULL",                     // 只认已提升为告警的事件
		"agent_detect",                                      // 排除普通 agent 行为
		"agent_canary",                                      // 但保留金丝雀
		`finding->>'counts_as_security_finding'`,            // findings 是否计入安全发现
		"COUNT(DISTINCT (cs.user_id, cs.conversation_key))", // 维度按会话串去重
		"COALESCE(user_id, ''), conversation_key",           // 与会话列表相同的会话串归并键
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("overview query must contain %q", fragment)
		}
	}

	// 告警判定必须发生在计数之前：has_risk 过滤要在 ranked_sessions 里完成，
	// counted_sessions 只能从过滤后的结果里取，否则没有告警的会话也会进总数。
	rankedPos := strings.Index(query, "ranked_sessions AS MATERIALIZED")
	riskPos := strings.Index(query, "WHERE has_risk")
	countedPos := strings.Index(query, "counted_sessions AS MATERIALIZED")
	if rankedPos < 0 || riskPos < 0 || countedPos < 0 {
		t.Fatal("overview query must keep ranked_sessions / has_risk / counted_sessions")
	}
	if !(rankedPos < riskPos && riskPos < countedPos) {
		t.Fatal("overview must filter on has_risk before selecting counted sessions")
	}
}

// 会话串回退键（first_user）只对 client_session_id 为空的会话做索引点查，
// 不能再对整张 content_logs 做一次全表 DISTINCT ON（那是会话列表查询的主要开销）。
func TestContentSecurityOverviewKeepsFirstUserLookupLazy(t *testing.T) {
	query := buildContentSecurityOverviewQuery()

	if !strings.Contains(query, "WHERE client_session_id IS NULL") {
		t.Fatal("first_user lookup must be limited to sessions without a client session id")
	}
	if strings.Contains(query, "SELECT DISTINCT ON (cl.session_id)") {
		t.Fatal("first_user must not scan the whole content_logs table again")
	}
}

// 总览不返回明细行，因此不应携带为行渲染服务的重聚合。
func TestContentSecurityOverviewSkipsRowRenderingWork(t *testing.T) {
	query := buildContentSecurityOverviewQuery()
	for _, forbidden := range []string{
		"page_group_totals",
		"page_content",
		"session_total_tokens",
		"internal_keys",
		"LIMIT $4",
	} {
		if strings.Contains(query, forbidden) {
			t.Fatalf("overview query must not contain row-rendering fragment %q", forbidden)
		}
	}
}
