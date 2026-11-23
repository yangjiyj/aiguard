package repository

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// evidence_run_request_index 是证据留痕页面的读模型：由热表触发器维护，并把
// effective_agent_type / detection source / confidence 预先算好。但分组查询仍然保留了
// 一条直接从 request_logs 现场推导这些字段的旧路径（buildEvidenceRunsQueryWithTotal）。
//
// 本次钉住的"索引契约"就是：**两条路径必须逐字段给出同一批记录**。否则同一条留痕会
// 因为命中哪条查询而显示成不同的调用方身份或不同的识别来源——这类偏差在测试里表现为
// 记录数一致但字段不一致，肉眼很难发现，所以必须由实库用例守住。
//
// 需要 CONTENT_LOGS_TEST_DATABASE_URL 指向一个已应用迁移的空库；未设置则 skip。

func evidenceRunsContractDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		t.Fatalf("ping database: %v", err)
	}
	return db
}

// newEvidenceRunsContractTenant 建一个独占租户并登记清理，避免不同用例互相污染。
func newEvidenceRunsContractTenant(t *testing.T, db *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	tenantID := fmt.Sprintf("tenant_evidence_index_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $1, 'enterprise', 'active', TRUE)`,
		tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		for _, query := range []string{
			"DELETE FROM access_content_logs WHERE tenant_id = $1",
			"DELETE FROM content_logs WHERE tenant_id = $1",
			"DELETE FROM request_logs WHERE tenant_id = $1",
			"DELETE FROM tenants WHERE id = $1",
		} {
			if _, err := db.Exec(ctx, query, tenantID); err != nil {
				t.Logf("cleanup %q: %v", query, err)
			}
		}
		db.Close()
	})
	return tenantID
}

type evidenceRunFixture struct {
	id                string
	agentType         string
	agentRuntime      string
	detectionSource   string
	detectionConf     float64
	sessionID         string
	conversationID    string
	evidenceRunID     string
	evidenceRunSource string
	riskState         string
	requestText       string
	responseText      string
}

// insertEvidenceRunFixture 写入一条 request_logs 及其内容留痕。
// content_logs.request_id 指向 request_logs.id（与索引迁移的口径一致）。
func insertEvidenceRunFixture(
	t *testing.T, db *pgxpool.Pool, tenantID string, item evidenceRunFixture, createdAt time.Time,
) {
	t.Helper()
	ctx := context.Background()
	requestID := fmt.Sprintf("%s-%s", item.id, tenantID)
	riskState := item.riskState
	if riskState == "" {
		riskState = "normal"
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, endpoint_type, request_status,
			proxy_mode, proxy_target_host, proxy_target_path, proxy_method,
			proxy_access_type, proxy_access_type_resolved, proxy_provider, proxy_product,
			proxy_tls_inspected, proxy_content_retained, proxy_retention_level,
			proxy_endpoint_kind, agent_type, agent_runtime, agent_detection_source,
			agent_detection_confidence, session_id,
			evidence_run_id, evidence_run_source, risk_state, has_retained_content,
			environment_scope, created_at
		) VALUES (
			$1, $1, $2, 'proxy', 'success',
			'forward', 'api.example.test', '/v1/responses', 'POST',
			'ai_ide', 'ai_ide', 'test', 'test',
			TRUE, TRUE, 'content',
			'chat', $3, $4, $5,
			$6, $7,
			$8, $9, $10, TRUE,
			'customer', $11
		)
	`, requestID, tenantID, item.agentType, item.agentRuntime, item.detectionSource,
		item.detectionConf, item.sessionID,
		item.evidenceRunID, item.evidenceRunSource, riskState, createdAt); err != nil {
		t.Fatalf("insert request %s: %v", item.id, err)
	}
	if item.requestText == "" && item.responseText == "" {
		return
	}
	// conversation_id 只存在于 access_content_logs；索引的会话归属也由该表触发器写入。
	if _, err := db.Exec(ctx, `
		INSERT INTO access_content_logs (
			id, request_id, tenant_id, conversation_id, request_content_redacted,
			response_content_redacted, file_metadata_json, provider, model,
			environment_scope, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, '[]'::jsonb, 'test', NULLIF($7, ''), 'customer', $8)
	`, "acl-"+item.id, requestID, tenantID, item.conversationID, item.requestText,
		item.responseText, "gpt-5.6-luna", createdAt); err != nil {
		t.Fatalf("insert access content %s: %v", item.id, err)
	}
}

func evidenceRunContractFixtures() []evidenceRunFixture {
	return []evidenceRunFixture{
		// 一个 protocol_key 证据运行下的两轮请求。
		{id: "run-first", agentType: "openai-codex", evidenceRunID: "run-1", evidenceRunSource: "responses_prompt_cache_key",
			requestText: "请修复登录页的空指针", responseText: "已定位到空指针位置"},
		{id: "run-second", agentType: "openai-codex", evidenceRunID: "run-1", evidenceRunSource: "responses_prompt_cache_key",
			requestText: "继续修上面那个", responseText: "已提交修复"},
		// 一个 session_id 组，其中一轮风险态为 risk。
		{id: "session-first", agentType: "workbuddy", sessionID: "session-9",
			requestText: "帮我看下这个报错", responseText: "需要更多上下文", riskState: "risk"},
		{id: "session-second", agentType: "workbuddy", sessionID: "session-9",
			requestText: "报错在这", responseText: "已给出修复建议"},
		// 一个 conversation_id 组。
		{id: "conversation-first", agentType: "codebuddy", conversationID: "conversation-3",
			requestText: "写一个部署脚本", responseText: "脚本见下"},
		{id: "conversation-second", agentType: "codebuddy", conversationID: "conversation-3",
			requestText: "再加回滚", responseText: "已补充回滚"},
		// 只带 request 维度的一组，用来覆盖 'request:' 兜底键。
		{id: "unlinked-first", agentType: "cline", agentRuntime: "vscode",
			requestText: "解释一下这个函数", responseText: "它做了参数校验"},
		// vscode + Codex 内容特征：索引会把它投影成 openai-codex，
		// 这条正是「预计算路径」与「现场推导路径」最容易分叉的地方。
		{id: "codex-content", agentType: "vscode", detectionSource: "header", detectionConf: 0.4,
			requestText: "OpenAI Codex 桌面端发起的请求", responseText: "已处理"},
	}
}

func normalizeEvidenceRuns(records []EvidenceRunRecord) []string {
	normalized := make([]string, 0, len(records))
	for _, record := range records {
		members := append([]string(nil), record.MemberRequestIDs...)
		sort.Strings(members)
		models := append([]string(nil), record.Models...)
		sort.Strings(models)
		directions := append([]string(nil), record.AccessDirections...)
		sort.Strings(directions)
		normalized = append(normalized, strings.Join([]string{
			record.RunID,
			record.Kind,
			record.CorrelationSource,
			record.CorrelationConfidence,
			record.RepresentativeRequestID,
			strings.Join(members, ","),
			record.Title,
			record.StartedAt.UTC().Format(time.RFC3339Nano),
			record.EndedAt.UTC().Format(time.RFC3339Nano),
			record.AgentType,
			record.AgentRuntime,
			record.AgentDetectionSource,
			fmt.Sprintf("%.4f", record.AgentDetectionConfidence),
			record.Username,
			record.ClientName,
			record.SourceIP,
			strings.Join(models, ","),
			strings.Join(directions, ","),
			fmt.Sprintf("%d", record.RequestCount),
			record.EvidenceStatus,
			record.RiskState,
		}, "\x1f"))
	}
	sort.Strings(normalized)
	return normalized
}

func runEvidenceRunsWithBuilder(
	t *testing.T, ctx context.Context, repo *RequestLogRepository, tenantID string,
	filter ForwardProxyAccessFilter, buildQuery evidenceRunsQueryBuilder,
) ([]EvidenceRunRecord, int) {
	t.Helper()
	records, total, err := repo.listEvidenceRunsWithQueryBuilder(ctx, tenantID, "agent_tasks", filter, buildQuery)
	if err != nil {
		t.Fatalf("list evidence runs: %v", err)
	}
	return records, total
}

// TestIndexedEvidenceRunsQueryMatchesLegacyContract 是本次索引工作的核心不变量：
// 读模型路径与现场推导路径必须返回同一批记录、同一批字段、同一个总数。
func TestIndexedEvidenceRunsQueryMatchesLegacyContract(t *testing.T) {
	db := evidenceRunsContractDB(t)
	ctx := context.Background()
	tenantID := newEvidenceRunsContractTenant(t, db)

	base := time.Date(2026, 9, 8, 6, 0, 0, 0, time.UTC)
	for index, item := range evidenceRunContractFixtures() {
		insertEvidenceRunFixture(t, db, tenantID, item, base.Add(time.Duration(index)*time.Minute))
	}

	// 索引用例同时跑两遍筛选口径：不带内容约束（含 metadata_only）与只留证内容。
	filters := map[string]ForwardProxyAccessFilter{
		"all_records":  {EnvironmentScope: "customer", Limit: 100},
		"content_only": {EnvironmentScope: "customer", ContentOnly: true, Limit: 100},
	}

	for name, filter := range filters {
		t.Run(name, func(t *testing.T) {
			repo := NewRequestLogRepository(db)
			legacyRecords, legacyTotal := runEvidenceRunsWithBuilder(
				t, ctx, repo, tenantID, filter, buildEvidenceRunsQueryWithTotal)
			indexedRecords, indexedTotal := runEvidenceRunsWithBuilder(
				t, ctx, repo, tenantID, filter, buildIndexedEvidenceRunsQueryWithTotal)

			if len(legacyRecords) < 3 {
				t.Fatalf("fixture produced only %d visible runs; the comparison would be vacuous",
					len(legacyRecords))
			}
			if legacyTotal != indexedTotal {
				t.Fatalf("total mismatch: legacy=%d indexed=%d", legacyTotal, indexedTotal)
			}
			legacy := normalizeEvidenceRuns(legacyRecords)
			indexed := normalizeEvidenceRuns(indexedRecords)
			if len(legacy) != len(indexed) {
				t.Fatalf("record count mismatch: legacy=%d indexed=%d", len(legacy), len(indexed))
			}
			for position := range legacy {
				if legacy[position] != indexed[position] {
					t.Fatalf("run #%d diverged between query paths:\n legacy = %q\n indexed= %q",
						position, legacy[position], indexed[position])
				}
			}
		})
	}
}

// TestIndexedEvidenceRunsQueryPagesLikeTheLegacyContract 守住分页：读模型换了 CTE 结构，
// 但 limit/offset 语义（含 skip_total 时不带总数）必须与旧路径一致。
func TestIndexedEvidenceRunsQueryPagesLikeTheLegacyContract(t *testing.T) {
	db := evidenceRunsContractDB(t)
	ctx := context.Background()
	tenantID := newEvidenceRunsContractTenant(t, db)

	base := time.Date(2026, 9, 8, 6, 0, 0, 0, time.UTC)
	for index, item := range evidenceRunContractFixtures() {
		insertEvidenceRunFixture(t, db, tenantID, item, base.Add(time.Duration(index)*time.Minute))
	}

	repo := NewRequestLogRepository(db)
	fullFilter := ForwardProxyAccessFilter{EnvironmentScope: "customer", Limit: 100, AllowLargeLimit: true}
	fullLegacy, fullTotal := runEvidenceRunsWithBuilder(
		t, ctx, repo, tenantID, fullFilter, buildEvidenceRunsQueryWithTotal)
	if len(fullLegacy) < 3 {
		t.Fatalf("fixture produced only %d visible runs", len(fullLegacy))
	}

	pageFilter := fullFilter
	pageFilter.Limit = 2
	pageFilter.Offset = 1
	pageLegacy, _ := runEvidenceRunsWithBuilder(
		t, ctx, repo, tenantID, pageFilter, buildEvidenceRunsQueryWithTotal)
	pageIndexed, _ := runEvidenceRunsWithBuilder(
		t, ctx, repo, tenantID, pageFilter, buildIndexedEvidenceRunsQueryWithTotal)

	if len(pageLegacy) != len(pageIndexed) {
		t.Fatalf("page size mismatch: legacy=%d indexed=%d", len(pageLegacy), len(pageIndexed))
	}
	legacy := normalizeEvidenceRuns(pageLegacy)
	indexed := normalizeEvidenceRuns(pageIndexed)
	for position := range legacy {
		if legacy[position] != indexed[position] {
			t.Fatalf("paged run #%d diverged:\n legacy = %q\n indexed= %q",
				position, legacy[position], indexed[position])
		}
	}

	// skip_total 时不查真实总数，改为按"已取到的页 + 是否还有更多"合成一个下界，
	// 两条查询路径必须给出同样的下界与同样的一页。
	skipTotalFilter := pageFilter
	skipTotalFilter.SkipTotal = true
	skipLegacy, skipLegacyTotal := runEvidenceRunsWithBuilder(
		t, ctx, repo, tenantID, skipTotalFilter, buildEvidenceRunsQueryWithTotal)
	skipIndexed, skipIndexedTotal := runEvidenceRunsWithBuilder(
		t, ctx, repo, tenantID, skipTotalFilter, buildIndexedEvidenceRunsQueryWithTotal)

	if skipLegacyTotal != skipIndexedTotal {
		t.Fatalf("skip_total totals diverged: legacy=%d indexed=%d", skipLegacyTotal, skipIndexedTotal)
	}
	wantSkipTotal := skipTotalFilter.Offset + len(skipIndexed)
	if hasMore := len(skipLegacy) > skipTotalFilter.Limit; hasMore {
		wantSkipTotal++
	}
	if skipIndexedTotal != wantSkipTotal {
		t.Fatalf("skip_total total = %d, want offset+page(+1 if more) = %d",
			skipIndexedTotal, wantSkipTotal)
	}
	skipLegacyNormalized := normalizeEvidenceRuns(skipLegacy)
	skipIndexedNormalized := normalizeEvidenceRuns(skipIndexed)
	if len(skipLegacyNormalized) != len(skipIndexedNormalized) {
		t.Fatalf("skip_total page size diverged: legacy=%d indexed=%d",
			len(skipLegacyNormalized), len(skipIndexedNormalized))
	}
	for position := range skipLegacyNormalized {
		if skipLegacyNormalized[position] != skipIndexedNormalized[position] {
			t.Fatalf("skip_total run #%d diverged:\n legacy = %q\n indexed= %q",
				position, skipLegacyNormalized[position], skipIndexedNormalized[position])
		}
	}
	if fullTotal < len(fullLegacy) {
		t.Fatalf("total %d is smaller than the page of %d", fullTotal, len(fullLegacy))
	}
}

// TestEvidenceRunRequestIndexTracksRequestLogWrites 守住读模型的写入契约：
// 触发器必须为每条 request_logs 建索引行，并在关键列更新时跟着走，删主行时级联清掉。
func TestEvidenceRunRequestIndexTracksRequestLogWrites(t *testing.T) {
	db := evidenceRunsContractDB(t)
	ctx := context.Background()
	tenantID := newEvidenceRunsContractTenant(t, db)

	createdAt := time.Date(2026, 9, 8, 6, 0, 0, 0, time.UTC)
	insertEvidenceRunFixture(t, db, tenantID, evidenceRunFixture{
		id: "index-tracking", agentType: "openai-codex", sessionID: "session-index",
		requestText: "索引契约用例", responseText: "已记录",
	}, createdAt)
	requestID := fmt.Sprintf("%s-%s", "index-tracking", tenantID)

	var indexRequestID, indexedAgentType string
	var indexedCreatedAt time.Time
	if err := db.QueryRow(ctx, `
		SELECT request_id, effective_agent_type, created_at
		FROM evidence_run_request_index
		WHERE tenant_id = $1 AND request_log_id = $2
	`, tenantID, requestID).Scan(&indexRequestID, &indexedAgentType, &indexedCreatedAt); err != nil {
		t.Fatalf("index row is missing for a fresh request_logs row: %v", err)
	}
	if indexRequestID != requestID {
		t.Fatalf("index request_id = %q, want %q", indexRequestID, requestID)
	}
	if indexedAgentType != "openai-codex" {
		t.Fatalf("index effective_agent_type = %q, want openai-codex", indexedAgentType)
	}
	if !indexedCreatedAt.UTC().Equal(createdAt) {
		t.Fatalf("index created_at = %s, want %s", indexedCreatedAt.UTC(), createdAt)
	}

	// agent_type 是触发器监听的列，改完索引必须跟着改。
	if _, err := db.Exec(ctx,
		`UPDATE request_logs SET agent_type = 'workbuddy', agent_detection_source = 'header', agent_detection_confidence = 0.7
		 WHERE tenant_id = $1 AND id = $2`, tenantID, requestID); err != nil {
		t.Fatalf("update request_logs: %v", err)
	}
	var updatedAgentType string
	var updatedConfidence float64
	if err := db.QueryRow(ctx, `
		SELECT effective_agent_type, effective_detection_confidence
		FROM evidence_run_request_index
		WHERE tenant_id = $1 AND request_log_id = $2
	`, tenantID, requestID).Scan(&updatedAgentType, &updatedConfidence); err != nil {
		t.Fatalf("read updated index row: %v", err)
	}
	if updatedAgentType != "workbuddy" {
		t.Fatalf("index did not follow the agent_type update: %q", updatedAgentType)
	}

	// 删主行必须级联删索引行，否则留痕页面会列出已经不存在的请求。
	if _, err := db.Exec(ctx,
		`DELETE FROM request_logs WHERE tenant_id = $1 AND id = $2`, tenantID, requestID); err != nil {
		t.Fatalf("delete request_logs: %v", err)
	}
	var remaining int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM evidence_run_request_index WHERE tenant_id = $1 AND request_log_id = $2
	`, tenantID, requestID).Scan(&remaining); err != nil {
		t.Fatalf("count index rows: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("index row survived the request_logs delete: %d rows remain", remaining)
	}
}

// TestEvidenceRunRequestIndexHasARowForEveryRequestLog 守住回填契约：
// 146/148 的快照与补齐之后，读模型不得漏掉任何一条 request_logs。
func TestEvidenceRunRequestIndexHasARowForEveryRequestLog(t *testing.T) {
	db := evidenceRunsContractDB(t)
	ctx := context.Background()
	tenantID := newEvidenceRunsContractTenant(t, db)

	base := time.Date(2026, 9, 8, 6, 0, 0, 0, time.UTC)
	for index, item := range evidenceRunContractFixtures() {
		insertEvidenceRunFixture(t, db, tenantID, item, base.Add(time.Duration(index)*time.Minute))
	}

	var logged, indexed int
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM request_logs WHERE tenant_id = $1`, tenantID).Scan(&logged); err != nil {
		t.Fatalf("count request_logs: %v", err)
	}
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM evidence_run_request_index WHERE tenant_id = $1`, tenantID).Scan(&indexed); err != nil {
		t.Fatalf("count evidence_run_request_index: %v", err)
	}
	if logged == 0 {
		t.Fatal("fixture inserted no request_logs rows")
	}
	if logged != indexed {
		t.Fatalf("request_logs has %d rows but the index has %d", logged, indexed)
	}
}
