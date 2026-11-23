package repository

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestForwardProxyAccessTurnGrouping 验证内容留证读侧按 conversation 聚合：
//   - 同 conversation_id 的多轮、多物理请求收成 1 条逻辑记录（代表行=全会话最新）；
//   - member_count / member_request_ids 含全部物理请求，turn_count 统计不同 section_id；
//   - conversation_id 为 NULL 的行各自单条（回退）；
//   - risk_state 取会话成员 MAX 严重度（高风险老成员不被低风险代表行隐藏）；
//   - security_event_count 取会话成员求和。
func TestForwardProxyAccessTurnGrouping(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}

	suffix := time.Now().UnixNano()
	tenantID := fmt.Sprintf("tenant_turn_%d", suffix)
	projectID := fmt.Sprintf("project_turn_%d", suffix)
	// db.Close() 放 t.Cleanup 末尾：defer 会先于 t.Cleanup 执行，先关池会让 DELETE 静默失败。
	t.Cleanup(func() {
		type cleanupStmt struct {
			sql string
			arg string
		}
		for _, stmt := range []cleanupStmt{
			{"DELETE FROM security_events WHERE tenant_id = $1", tenantID},
			{"DELETE FROM access_content_logs WHERE tenant_id = $1", tenantID},
			{"DELETE FROM request_logs WHERE tenant_id = $1", tenantID},
			{"DELETE FROM projects WHERE id = $1", projectID},
			{"DELETE FROM tenants WHERE id = $1", tenantID},
		} {
			if _, err := db.Exec(ctx, stmt.sql, stmt.arg); err != nil {
				t.Logf("cleanup %s (%q): %v", stmt.arg, stmt.sql, err)
			}
		}
		db.Close()
	})

	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`, tenantID, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`, projectID, tenantID, projectID); err != nil {
		// projects 表可能有更多必填列；失败不致命（security_events 才需要 project_id），降级跳过依赖它的断言。
		t.Logf("insert project (non-fatal): %v", err)
		projectID = ""
	}

	base := time.Date(2026, 6, 27, 10, 0, 0, 0, time.UTC)

	insertReq := func(requestID string, createdAt time.Time, riskState string) {
		t.Helper()
		_, err := db.Exec(ctx, `
			INSERT INTO request_logs (
				id, request_id, tenant_id, endpoint_type, request_status,
				proxy_mode, proxy_target_host, proxy_target_path, proxy_method,
				proxy_access_type, proxy_access_type_resolved, proxy_provider, proxy_product, proxy_tls_inspected,
				proxy_content_retained, proxy_retention_level, proxy_endpoint_kind, agent_type,
				risk_state, has_retained_content, created_at
			) VALUES ($1, $1, $2, 'proxy', 'success', 'forward', 'www.doubao.com', '/api/v3/chat', 'POST',
				'llm', 'llm', 'bytedance', 'doubao', true, true, 'content', 'chat', 'agent-tool-call', $3, true, $4)
		`, requestID, tenantID, riskState, createdAt)
		if err != nil {
			t.Fatalf("insert request %s: %v", requestID, err)
		}
	}
	insertContent := func(requestID string, createdAt time.Time, conversationID, sectionID *string) {
		t.Helper()
		_, err := db.Exec(ctx, `
			INSERT INTO access_content_logs (
				id, request_id, tenant_id, request_content_redacted, response_content_redacted,
				file_metadata_json, conversation_id, section_id, provider, created_at
			) VALUES ($1, $1, $2, '问题', '回答', '[]'::jsonb, $3, $4, 'bytedance', $5)
		`, requestID, tenantID, conversationID, sectionID, createdAt)
		if err != nil {
			t.Fatalf("insert content %s: %v", requestID, err)
		}
	}
	insertEvent := func(idSuffix, requestID, matchedSummary string, createdAt time.Time) {
		t.Helper()
		if projectID == "" {
			t.Skip("projects insert failed; cannot exercise security_event rollup")
		}
		_, err := db.Exec(ctx, `
			INSERT INTO security_events (id, request_id, tenant_id, project_id, event_type, action_taken, severity, matched_summary, created_at)
			VALUES ($1, $2, $3, $4, 'proxy_output_audit', 'audit', 'high', $5::jsonb, $6)
		`, fmt.Sprintf("evt_%s_%d", idSuffix, suffix), requestID, tenantID, projectID, matchedSummary, createdAt)
		if err != nil {
			t.Fatalf("insert event %s: %v", idSuffix, err)
		}
	}

	conv := "conv_A"
	sec := "sec_A"
	sec2 := "sec_B"
	// 会话 A：第一轮三条同 section 的物理请求；再加入第二轮。最老的一条标 blocked、且挂安全事件；
	// 代表行=第二轮最新请求（normal）。验证会话级 MAX rollup 不被代表行掩盖。
	turnOld := fmt.Sprintf("turn_old_%d", suffix)
	turnMid := fmt.Sprintf("turn_mid_%d", suffix)
	turnNew := fmt.Sprintf("turn_new_%d", suffix)
	turnSecond := fmt.Sprintf("turn_second_%d", suffix)
	insertReq(turnOld, base.Add(1*time.Minute), "blocked")
	insertReq(turnMid, base.Add(2*time.Minute), "risk")
	insertReq(turnNew, base.Add(3*time.Minute), "normal")
	insertReq(turnSecond, base.Add(4*time.Minute), "normal")
	insertContent(turnOld, base.Add(1*time.Minute), &conv, &sec)
	insertContent(turnMid, base.Add(2*time.Minute), &conv, &sec)
	insertContent(turnNew, base.Add(3*time.Minute), &conv, &sec)
	insertContent(turnSecond, base.Add(4*time.Minute), &conv, &sec2)

	// 两条 NULL 键行：各自单条。
	null1 := fmt.Sprintf("null1_%d", suffix)
	null2 := fmt.Sprintf("null2_%d", suffix)
	insertReq(null1, base.Add(5*time.Minute), "normal")
	insertReq(null2, base.Add(6*time.Minute), "risk")
	insertContent(null1, base.Add(5*time.Minute), nil, nil)
	insertContent(null2, base.Add(6*time.Minute), nil, nil)

	// 安全事件挂在 turn 的旧成员上（代表行无事件）：最老成员为 findings 格式，
	// 中间成员为仅有顶层 category 的历史格式。
	eventOnOld := projectID != ""
	if eventOnOld {
		insertEvent("old", turnOld, `{"stage":"output","findings":[{"category":"id_card_cn","rule_id":"regex_id_card_cn"}]}`, base.Add(1*time.Minute))
		insertEvent("legacy", turnMid, `{"stage":"output","category":"legacy_attention_category"}`, base.Add(2*time.Minute))
	}

	repo := NewRequestLogRepository(db)
	filter := ForwardProxyAccessFilter{
		AccessType:  "llm",
		ContentOnly: true,
		Limit:       100,
	}
	records, total, err := repo.ListForwardProxyAccess(ctx, tenantID, filter)
	if err != nil {
		t.Fatalf("list forward access: %v", err)
	}

	// 期望 3 条逻辑记录：1 个会话（代表行=第二轮最新）+ 2 条 NULL 行。
	if total != 3 {
		t.Fatalf("total = %d, want 3 (1 turn + 2 null rows)", total)
	}
	if len(records) != 3 {
		t.Fatalf("len(records) = %d, want 3", len(records))
	}
	summary, err := repo.GetForwardProxyAccessSummary(ctx, tenantID, filter)
	if err != nil {
		t.Fatalf("summarize forward access: %v", err)
	}
	if summary.Total != 3 || summary.BlockedCount != 1 || summary.RiskCount != 1 || summary.NormalCount != 1 {
		t.Fatalf("conversation summary must match the three logical records, got %+v", summary)
	}
	if summary.RetainedContentCount != 3 || summary.LLMCount != 3 {
		t.Fatalf("conversation summary content/type counts must use logical records, got %+v", summary)
	}

	byID := map[string]ForwardProxyAccessRecord{}
	for _, rec := range records {
		byID[rec.RequestID] = rec
	}

	// 会话代表行必须是第二轮最新的 turnSecond；第一轮成员不应作为独立记录出现。
	rep, ok := byID[turnSecond]
	if !ok {
		t.Fatalf("representative turnSecond not found in records; got ids: %v", recordIDs(records))
	}
	for _, id := range []string{turnOld, turnMid, turnNew} {
		if _, leaked := byID[id]; leaked {
			t.Fatalf("non-representative member %s leaked as its own record", id)
		}
	}

	// member_count=4，成员含两轮全部四条 request_id；turn_count=2。
	if rep.MemberCount != 4 {
		t.Fatalf("conversation member_count = %d, want 4", rep.MemberCount)
	}
	if rep.TurnCount != 2 {
		t.Fatalf("conversation turn_count = %d, want 2", rep.TurnCount)
	}
	gotMembers := append([]string{}, rep.MemberRequestIDs...)
	sort.Strings(gotMembers)
	wantMembers := []string{turnMid, turnNew, turnOld, turnSecond}
	sort.Strings(wantMembers)
	if fmt.Sprint(gotMembers) != fmt.Sprint(wantMembers) {
		t.Fatalf("member_request_ids = %v, want %v", gotMembers, wantMembers)
	}

	// risk MAX rollup：代表行自身 normal，但 turn 含 blocked 老成员 → 必须 blocked。
	if rep.RiskState != "blocked" {
		t.Fatalf("turn risk_state = %q, want 'blocked' (MAX over members)", rep.RiskState)
	}
	if rep.ActionTaken != "block" {
		t.Fatalf("turn action_taken = %q, want 'block'", rep.ActionTaken)
	}

	// security_event_count SUM rollup：事件挂在旧成员上，代表行无事件 → turn 计数应=2。
	if eventOnOld {
		if rep.SecurityEventCount != 2 {
			t.Fatalf("turn security_event_count = %d, want 2 (summed over members)", rep.SecurityEventCount)
		}
		// risk_reasons UNION 应含老成员事件的原因。
		foundReason := false
		for _, r := range rep.RiskReasons {
			if r == "id_card_cn" {
				foundReason = true
			}
		}
		if !foundReason {
			t.Fatalf("turn risk_reasons = %v, want to include 'id_card_cn' (UNION over members)", rep.RiskReasons)
		}
	}

	// attention 按 turn 的最大风险筛选：中间/旧成员命中而最新代表行 normal 时，
	// 列表、总数、导出、直接 summary 与 summary_only counts 都必须返回同一个代表 turn。
	attentionFilter := ForwardProxyAccessFilter{
		RiskState:   "attention",
		AccessType:  "llm",
		ContentOnly: true,
		StartTime:   base,
		EndTime:     base.Add(4 * time.Minute),
		Limit:       100,
	}
	attentionRecords, attentionTotal, err := repo.ListForwardProxyAccess(ctx, tenantID, attentionFilter)
	if err != nil {
		t.Fatalf("list attention access: %v", err)
	}
	exportFilter := attentionFilter
	exportFilter.AllowLargeLimit = true
	exportFilter.Limit = 100000
	exportRecords, exportTotal, err := repo.ListForwardProxyAccess(ctx, tenantID, exportFilter)
	if err != nil {
		t.Fatalf("export attention access: %v", err)
	}
	attentionSummary, err := repo.GetForwardProxyAccessSummary(ctx, tenantID, attentionFilter)
	if err != nil {
		t.Fatalf("summarize attention access: %v", err)
	}
	attentionCounts, err := repo.GetForwardProxyAccessCounts(ctx, tenantID, attentionFilter)
	if err != nil {
		t.Fatalf("count attention access: %v", err)
	}
	assertAttentionTurn := func(path string, records []ForwardProxyAccessRecord, total int) {
		t.Helper()
		if total != 1 || len(records) != 1 {
			t.Fatalf("%s attention result total=%d len=%d, want one representative turn", path, total, len(records))
		}
		if records[0].RequestID != turnNew || records[0].RiskState != "blocked" {
			t.Fatalf("%s attention record=%+v, want latest representative %q with blocked turn risk", path, records[0], turnNew)
		}
	}
	assertAttentionTurn("list", attentionRecords, attentionTotal)
	assertAttentionTurn("export", exportRecords, exportTotal)
	if attentionSummary.Total != 1 || attentionSummary.NormalCount != 0 || attentionSummary.RiskCount != 0 || attentionSummary.BlockedCount != 1 {
		t.Fatalf("attention summary=%+v, want one blocked representative turn", attentionSummary)
	}
	if len(attentionSummary.TopProviders) != 1 || attentionSummary.TopProviders[0].Count != 1 || attentionSummary.TopProviders[0].RiskCount != 1 {
		t.Fatalf("attention provider facet=%+v, want one blocked representative turn", attentionSummary.TopProviders)
	}
	if len(attentionSummary.TopTargets) != 1 || attentionSummary.TopTargets[0].Count != 1 || attentionSummary.TopTargets[0].RiskCount != 1 {
		t.Fatalf("attention target facet=%+v, want one blocked representative turn", attentionSummary.TopTargets)
	}
	if len(attentionSummary.TopAgents) != 1 || attentionSummary.TopAgents[0].Count != 1 || attentionSummary.TopAgents[0].RiskCount != 1 {
		t.Fatalf("attention agent facet=%+v, want one blocked representative turn", attentionSummary.TopAgents)
	}
	if quality := attentionSummary.EvidenceQuality; quality.CompleteCount != 1 || quality.RequestOnlyCount != 0 || quality.ResponseOnlyCount != 0 || quality.MetadataOnlyCount != 0 {
		t.Fatalf("attention evidence quality=%+v, want one representative turn", quality)
	}
	if len(attentionSummary.Timeline) != 1 {
		t.Fatalf("attention timeline=%+v, want one bucket", attentionSummary.Timeline)
	}
	if point := attentionSummary.Timeline[0]; point.TotalCount != 1 || point.NormalCount != 0 || point.RiskCount != 0 || point.BlockedCount != 1 {
		t.Fatalf("attention timeline point=%+v, want one blocked representative turn", point)
	}
	if eventOnOld {
		categories := map[string]int{}
		for _, category := range attentionSummary.TopRiskCategories {
			categories[category.Name] = category.Count
		}
		if len(categories) != 2 || categories["id_card_cn"] != 1 || categories["legacy_attention_category"] != 1 {
			t.Fatalf("attention risk categories=%+v, want grouped findings and legacy category", attentionSummary.TopRiskCategories)
		}
	}
	if attentionCounts.Total != 1 || attentionCounts.LLMCount != 1 || attentionCounts.RetainedContentCount != 1 {
		t.Fatalf("attention counts=%+v, want one representative turn", attentionCounts)
	}

	attentionRuns, attentionRunTotal, err := repo.ListEvidenceRuns(ctx, tenantID, "agent_tasks", attentionFilter)
	if err != nil {
		t.Fatalf("list attention evidence runs: %v", err)
	}
	if attentionRunTotal != 1 || len(attentionRuns) != 1 {
		t.Fatalf("attention evidence runs total=%d records=%+v, want one blocked run", attentionRunTotal, attentionRuns)
	}
	if attentionRuns[0].RiskState != "blocked" {
		t.Fatalf("attention evidence run risk_state=%q, want blocked", attentionRuns[0].RiskState)
	}
	hasBlockedMember := false
	for _, requestID := range attentionRuns[0].MemberRequestIDs {
		if requestID == turnOld {
			hasBlockedMember = true
			break
		}
	}
	if !hasBlockedMember {
		t.Fatalf("attention evidence run members=%v, want blocked member %q", attentionRuns[0].MemberRequestIDs, turnOld)
	}

	// NULL conversation_id 沿用物理行语义：attention 不分组，风险行仍按自身命中。
	nullAttentionFilter := ForwardProxyAccessFilter{
		RiskState:   "attention",
		AccessType:  "llm",
		ContentOnly: true,
		StartTime:   base.Add(5 * time.Minute),
		EndTime:     base.Add(7 * time.Minute),
		Limit:       100,
	}
	nullAttentionRecords, nullAttentionTotal, err := repo.ListForwardProxyAccess(ctx, tenantID, nullAttentionFilter)
	if err != nil {
		t.Fatalf("list null-key attention access: %v", err)
	}
	nullAttentionSummary, err := repo.GetForwardProxyAccessSummary(ctx, tenantID, nullAttentionFilter)
	if err != nil {
		t.Fatalf("summarize null-key attention access: %v", err)
	}
	nullAttentionCounts, err := repo.GetForwardProxyAccessCounts(ctx, tenantID, nullAttentionFilter)
	if err != nil {
		t.Fatalf("count null-key attention access: %v", err)
	}
	if nullAttentionTotal != 1 || len(nullAttentionRecords) != 1 || nullAttentionRecords[0].RequestID != null2 || nullAttentionRecords[0].RiskState != "risk" {
		t.Fatalf("null-key attention records total=%d records=%+v, want own risk row %q", nullAttentionTotal, nullAttentionRecords, null2)
	}
	if nullAttentionSummary.Total != 1 || nullAttentionSummary.NormalCount != 0 || nullAttentionSummary.RiskCount != 1 || nullAttentionSummary.BlockedCount != 0 {
		t.Fatalf("null-key attention summary=%+v, want one own risk row", nullAttentionSummary)
	}
	if nullAttentionCounts.Total != 1 || nullAttentionCounts.LLMCount != 1 || nullAttentionCounts.RetainedContentCount != 1 {
		t.Fatalf("null-key attention counts=%+v, want one own risk row", nullAttentionCounts)
	}

	linkedRecords, linkedTotal, err := repo.ListForwardProxyAccess(ctx, tenantID, ForwardProxyAccessFilter{
		RequestID: turnOld,
		Limit:     100,
	})
	if err != nil {
		t.Fatalf("list forward access by turn member: %v", err)
	}
	if linkedTotal != 1 || len(linkedRecords) != 1 {
		t.Fatalf("member deep link returned total=%d len=%d, want one representative turn", linkedTotal, len(linkedRecords))
	}
	if linkedRecords[0].RequestID != turnNew {
		t.Fatalf("member deep link representative = %q, want %q", linkedRecords[0].RequestID, turnNew)
	}
	if linkedRecords[0].MemberCount != 4 {
		t.Fatalf("member deep link member_count = %d, want 4", linkedRecords[0].MemberCount)
	}

	// NULL 键行回退：各自单条，member_count=1，仅含自身。
	for _, id := range []string{null1, null2} {
		rec, ok := byID[id]
		if !ok {
			t.Fatalf("null-key row %s missing", id)
		}
		if rec.MemberCount != 1 {
			t.Fatalf("null-key %s member_count = %d, want 1", id, rec.MemberCount)
		}
		if len(rec.MemberRequestIDs) != 1 || rec.MemberRequestIDs[0] != id {
			t.Fatalf("null-key %s member_request_ids = %v, want [%s]", id, rec.MemberRequestIDs, id)
		}
	}
	// NULL 键行不串风险：null2 的 risk_state 取自身（risk），不受 turn 影响。
	if byID[null2].RiskState != "risk" {
		t.Fatalf("null2 risk_state = %q, want 'risk' (own state, no cross-turn bleed)", byID[null2].RiskState)
	}
}

func recordIDs(records []ForwardProxyAccessRecord) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.RequestID)
	}
	return out
}
