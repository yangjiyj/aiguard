package repository

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// usageRecordSeed 持有三类请求的标识与维度期望值，供断言使用。
type usageRecordSeed struct {
	costedReqID  string
	gapReqID     string
	failedReqID  string
	keyID        string
	keyPrefix    string
	providerName string
	modelLabel   string
}

// registerUsageRecordCleanup 在 harness 清理之前（LIFO）先删 request_logs 与 internal_keys，
// 避免 internal_keys.project_id FK→projects、request_logs.client_id→internal_keys 的删除顺序冲突。
func registerUsageRecordCleanup(t *testing.T, db *pgxpool.Pool, ctx context.Context, tenantID string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, "DELETE FROM request_logs WHERE tenant_id = $1", tenantID)
		_, _ = db.Exec(ctx, "DELETE FROM internal_keys WHERE tenant_id = $1", tenantID)
	})
}

// seedUsageDimensions 写入供应商、模型、内部 Key 三项维度数据，返回标识。
func seedUsageDimensions(t *testing.T, db *pgxpool.Pool, ctx context.Context, tenantID, userID, projectID string) (providerID, modelID, keyID, keyPrefix, providerName, modelLabel string) {
	t.Helper()
	suffix := time.Now().UnixNano()
	providerID = fmt.Sprintf("prov_usage_rec_%d", suffix)
	modelID = fmt.Sprintf("model_usage_rec_%d", suffix)
	keyID = fmt.Sprintf("ikey_usage_rec_%d", suffix)
	keyPrefix = fmt.Sprintf("sk-rec-%d", suffix%1000000)
	providerName = "测试供应商"
	modelLabel = "通义千问-Plus"

	if _, err := db.Exec(ctx, `
		INSERT INTO providers (id, tenant_id, name, provider_type, status)
		VALUES ($1, $2, $3, 'openai', 'active')
	`, providerID, tenantID, providerName); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO models (id, provider_id, model_name, model_label, status)
		VALUES ($1, $2, 'qwen3.6-plus', $3, 'active')
	`, modelID, providerID, modelLabel); err != nil {
		t.Fatalf("insert model: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, name, status)
		VALUES ($1, $2, $3, $4, $5, $6, '研发联调 Key', 'active')
	`, keyID, tenantID, projectID, userID, keyID+"_hash", keyPrefix); err != nil {
		t.Fatalf("insert internal key: %v", err)
	}
	return
}

// seedThreeUsageRecords 写入三类请求：已计费、未定价（费用缺口）、失败。
func seedThreeUsageRecords(t *testing.T, db *pgxpool.Pool, ctx context.Context, tenantID, userID, projectID string) usageRecordSeed {
	t.Helper()
	registerUsageRecordCleanup(t, db, ctx, tenantID)
	providerID, modelID, keyID, keyPrefix, providerName, modelLabel := seedUsageDimensions(t, db, ctx, tenantID, userID, projectID)

	now := time.Now().UTC()
	suffix := time.Now().UnixNano()
	seed := usageRecordSeed{
		costedReqID:  fmt.Sprintf("req_costed_%d", suffix),
		gapReqID:     fmt.Sprintf("req_gap_%d", suffix),
		failedReqID:  fmt.Sprintf("req_failed_%d", suffix),
		keyID:        keyID,
		keyPrefix:    keyPrefix,
		providerName: providerName,
		modelLabel:   modelLabel,
	}

	// 历史成本列刻意填充：调用明细不得读取它，而应只看账单表
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, project_id, user_id, client_id, provider_id, model_id,
			session_id, endpoint_type, request_status, upstream_status_code, latency_ms,
			input_tokens, output_tokens, total_cost, cost_meta_json, created_at
		) VALUES ($1, $1, $2, $3, $4, $5, $6, $7, 'sess-costed', 'anthropic_messages', 'success', 200, 350,
			100, 20, 0.012, '{"currency":"USD"}'::jsonb, $8)
	`, seed.costedReqID, tenantID, projectID, userID, keyID, providerID, modelID, now.Add(-3*time.Minute)); err != nil {
		t.Fatalf("insert costed request log: %v", err)
	}

	// 历史成本为空的成功调用同样应显示为 not_billed，不能再推导费用缺口
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, project_id, user_id, client_id,
			endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at
		) VALUES ($1, $1, $2, $3, $4, $5, 'chat', 'success', 1000, 100, NULL, $6)
	`, seed.gapReqID, tenantID, projectID, userID, keyID, now.Add(-2*time.Minute)); err != nil {
		t.Fatalf("insert gap request log: %v", err)
	}

	// 失败调用仍必须来自网关发放的 Key。
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, project_id, user_id, client_id,
			endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at
		) VALUES ($1, $1, $2, $3, $4, $5, 'chat', 'failed', 0, 0, NULL, $6)
	`, seed.failedReqID, tenantID, projectID, userID, keyID, now.Add(-1*time.Minute)); err != nil {
		t.Fatalf("insert failed request log: %v", err)
	}

	return seed
}

func usageRecordRange() (time.Time, time.Time) {
	now := time.Now().UTC()
	return now.Add(-time.Hour), now.Add(time.Hour)
}

func indexUsageRecordsByRequestID(records []UsageRecord) map[string]UsageRecord {
	m := make(map[string]UsageRecord, len(records))
	for _, rec := range records {
		m[rec.RequestID] = rec
	}
	return m
}

func TestListUsageRecordsUsesBillingStateAndBusinessNames(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	seed := seedThreeUsageRecords(t, db, ctx, tenantID, userID, projectID)

	start, end := usageRecordRange()
	scope := UsageScope{TenantID: tenantID, UserID: userID, ProjectIDs: []string{projectID}}
	records, total, err := NewUsageDailyRepository(db).ListUsageRecords(ctx, scope, UsageRecordFilter{StartDate: start, EndDate: end, Limit: 50})
	if err != nil {
		t.Fatalf("list usage records: %v", err)
	}
	if total != 3 || len(records) != 3 {
		t.Fatalf("expected 3 usage records, got total=%d len=%d", total, len(records))
	}

	byID := indexUsageRecordsByRequestID(records)
	record, ok := byID[seed.costedReqID]
	if !ok {
		t.Fatalf("record %s missing", seed.costedReqID)
	}
	if record.BillingState != "not_billed" || record.BillingAmountMicros != nil || record.BillingCurrency != "" {
		t.Fatalf("record must use billing tables rather than legacy cost, got %+v", record)
	}
	if record.KeyName != "研发联调 Key" || record.KeyPrefix != seed.keyPrefix {
		t.Fatalf("key display fields = name %q prefix %q", record.KeyName, record.KeyPrefix)
	}
	if record.ModelName != seed.modelLabel || record.ProviderName != seed.providerName {
		t.Fatalf("model/provider names = %q/%q", record.ModelName, record.ProviderName)
	}
	if record.ProjectName != projectID || record.UserName != userID {
		t.Fatalf("business dimensions = project %q user %q", record.ProjectName, record.UserName)
	}
	if record.TotalTokens != 120 || record.SessionID != "sess-costed" || record.LatencyMs != 350 || record.UpstreamStatusCode != 200 {
		t.Fatalf("request detail fields were not preserved: %+v", record)
	}
}

func TestListUsageRecordsUsesMeteringFactsForAmountAndState(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	seed := seedThreeUsageRecords(t, db, ctx, tenantID, userID, projectID)
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, "ALTER TABLE billing_usage_facts DISABLE TRIGGER trg_billing_usage_facts_append_only")
		_, _ = db.Exec(ctx, "DELETE FROM billing_usage_facts WHERE tenant_id = $1", tenantID)
		_, _ = db.Exec(ctx, "ALTER TABLE billing_usage_facts ENABLE TRIGGER trg_billing_usage_facts_append_only")
	})

	if _, err := db.Exec(ctx, `
		INSERT INTO billing_usage_facts (
			id, tenant_id, request_id, billing_mode, user_id, project_id, client_id,
			model_name, prompt_tokens, output_tokens, billable_amount_micros,
			currency, status, occurred_at
		) VALUES ($1, $2, $3, 'metering', $4, $5, $6, 'qwen3.6-plus', 100, 20, 1250000, 'CNY', 'settled', NOW())
	`, "fact_"+seed.costedReqID, tenantID, seed.costedReqID, userID, projectID, seed.keyID); err != nil {
		t.Fatalf("insert metering fact: %v", err)
	}

	start, end := usageRecordRange()
	scope := UsageScope{TenantID: tenantID, UserID: userID, ProjectIDs: []string{projectID}}
	records, _, err := NewUsageDailyRepository(db).ListUsageRecords(ctx, scope, UsageRecordFilter{StartDate: start, EndDate: end, Limit: 50})
	if err != nil {
		t.Fatalf("list usage records: %v", err)
	}
	record := indexUsageRecordsByRequestID(records)[seed.costedReqID]
	if record.BillingState != "settled" || record.BillingMode != "metering" || record.BillingAmountMicros == nil || *record.BillingAmountMicros != 1250000 || record.BillingCurrency != "CNY" {
		t.Fatalf("metering fact was not projected into usage record: %+v", record)
	}

	summary, err := NewUsageDailyRepository(db).SummarizeUsageRecords(ctx, scope, UsageRecordFilter{StartDate: start, EndDate: end})
	if err != nil {
		t.Fatalf("summarize usage records: %v", err)
	}
	if summary.SettledRequests != 1 || summary.BillingAmountMicros != 1250000 || summary.NotBilledRequests != 2 {
		t.Fatalf("metering fact missing from summary: %+v", summary)
	}
}

func TestSummarizeUsageRecordsCountsBillingStates(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	_ = seedThreeUsageRecords(t, db, ctx, tenantID, userID, projectID)

	start, end := usageRecordRange()
	scope := UsageScope{TenantID: tenantID, UserID: userID, ProjectIDs: []string{projectID}}
	summary, err := NewUsageDailyRepository(db).SummarizeUsageRecords(ctx, scope, UsageRecordFilter{StartDate: start, EndDate: end})
	if err != nil {
		t.Fatalf("summarize usage records: %v", err)
	}
	if summary.Requests != 3 || summary.Users != 1 || summary.Apps != 1 || summary.Keys != 1 {
		t.Fatalf("dimension counts = %+v", summary)
	}
	if summary.InputTokens != 1100 || summary.OutputTokens != 120 || summary.TotalTokens != 1220 {
		t.Fatalf("token counts = %+v", summary)
	}
	if summary.BillingAmountMicros != 0 || summary.NotBilledRequests != 3 || summary.SettledRequests != 0 || summary.ReservedRequests != 0 || summary.ReleasedRequests != 0 || summary.ExceptionRequests != 0 {
		t.Fatalf("billing summary must ignore legacy cost columns: %+v", summary)
	}
	if summary.SuccessRequests != 2 || summary.FailedRequests != 1 {
		t.Fatalf("request status counts = %+v", summary)
	}
}

func TestUsageRecordFilterWhereRestrictsToCostPipelineRows(t *testing.T) {
	where, _ := usageRecordFilterWhere(UsageRecordFilter{}, "rl.tenant_id = $1", []interface{}{"tenant_1"})

	if !strings.Contains(where, "COALESCE(rl.endpoint_type, '') <> 'proxy'") {
		t.Fatalf("usage records should exclude forward proxy audit rows, where=%s", where)
	}
	if !strings.Contains(where, "COALESCE(rl.request_status, '') NOT IN ('received', 'in_progress')") {
		t.Fatalf("usage records should exclude in-flight rows, where=%s", where)
	}
	if !strings.Contains(where, "k.id IS NOT NULL") {
		t.Fatalf("usage records should require a gateway-issued internal key, where=%s", where)
	}
	if strings.Contains(where, "total_cost = 0") {
		t.Fatalf("usage records must not infer cost eligibility from zero cost, where=%s", where)
	}
}

func TestListUsageRecordsScopeIsolation(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	registerUsageRecordCleanup(t, db, ctx, tenantID)

	otherUserID := fmt.Sprintf("%s_other", userID)
	otherProjectID := fmt.Sprintf("%s_other", projectID)
	if _, err := db.Exec(ctx, `INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, $3, 'developer', 'active')`, otherUserID, tenantID, otherUserID); err != nil {
		t.Fatalf("insert other user: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, owner_user_id, status) VALUES ($1, $2, $3, $4, 'active')`, otherProjectID, tenantID, otherProjectID, otherUserID); err != nil {
		t.Fatalf("insert other project: %v", err)
	}

	now := time.Now().UTC()
	suffix := time.Now().UnixNano()
	allowedReqID := fmt.Sprintf("req_allowed_%d", suffix)
	deniedReqID := fmt.Sprintf("req_denied_%d", suffix)
	allowedKeyID := fmt.Sprintf("key_allowed_%d", suffix)
	deniedKeyID := fmt.Sprintf("key_denied_%d", suffix)

	if _, err := db.Exec(ctx, `
		INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, status)
		VALUES ($1, $2, $3, $4, $5, 'sk-allowed', 'active')
	`, allowedKeyID, tenantID, projectID, userID, allowedKeyID+"_hash"); err != nil {
		t.Fatalf("insert allowed key: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, status)
		VALUES ($1, $2, $3, $4, $5, 'sk-denied', 'active')
	`, deniedKeyID, tenantID, otherProjectID, otherUserID, deniedKeyID+"_hash"); err != nil {
		t.Fatalf("insert denied key: %v", err)
	}

	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, client_id, endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at)
		VALUES ($1, $1, $2, $3, $4, $5, 'chat', 'success', 10, 5, 0.1, $6)
	`, allowedReqID, tenantID, projectID, userID, allowedKeyID, now.Add(-2*time.Minute)); err != nil {
		t.Fatalf("insert allowed request: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, client_id, endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at)
		VALUES ($1, $1, $2, $3, $4, $5, 'chat', 'success', 900, 100, 9, $6)
	`, deniedReqID, tenantID, otherProjectID, otherUserID, deniedKeyID, now.Add(-1*time.Minute)); err != nil {
		t.Fatalf("insert denied request: %v", err)
	}

	start, end := usageRecordRange()
	scope := UsageScope{TenantID: tenantID, UserID: userID, ProjectIDs: []string{projectID}}
	filter := UsageRecordFilter{StartDate: start, EndDate: end, Limit: 50}

	records, total, err := NewUsageDailyRepository(db).ListUsageRecords(ctx, scope, filter)
	if err != nil {
		t.Fatalf("list usage records: %v", err)
	}
	if total != 1 || len(records) != 1 {
		t.Fatalf("scope should only return allowed record, got total=%d len=%d", total, len(records))
	}
	if records[0].RequestID != allowedReqID {
		t.Fatalf("returned record = %q, want allowed %q", records[0].RequestID, allowedReqID)
	}
}

func TestUsageRecordsExcludeNonCostPipelineRows(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	seed := seedThreeUsageRecords(t, db, ctx, tenantID, userID, projectID)

	now := time.Now().UTC()
	proxyReqID := fmt.Sprintf("req_proxy_pending_%d", now.UnixNano())
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, endpoint_type, request_status,
			input_tokens, output_tokens, total_cost, created_at
		) VALUES ($1, $1, $2, 'proxy', 'in_progress', 0, 0, 0, $3)
	`, proxyReqID, tenantID, now.Add(-30*time.Second)); err != nil {
		t.Fatalf("insert proxy request log: %v", err)
	}

	noGatewayKeyReqID := fmt.Sprintf("req_no_gateway_key_%d", now.UnixNano())
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, project_id, user_id, client_id,
			endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at
		) VALUES ($1, $1, $2, $3, $4, 'proxy_key_not_internal', 'chat', 'success', 40, 10, 0.5, $5)
	`, noGatewayKeyReqID, tenantID, projectID, userID, now.Add(-25*time.Second)); err != nil {
		t.Fatalf("insert non-gateway-key request log: %v", err)
	}

	receivedReqID := fmt.Sprintf("req_received_pending_%d", now.UnixNano())
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, project_id, user_id, client_id,
			endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at
		) VALUES ($1, $1, $2, $3, $4, $5, 'chat', 'received', 0, 0, NULL, $6)
	`, receivedReqID, tenantID, projectID, userID, seed.keyID, now.Add(-20*time.Second)); err != nil {
		t.Fatalf("insert received request log: %v", err)
	}

	start, end := usageRecordRange()
	scope := UsageScope{TenantID: tenantID, FullTenant: true}
	filter := UsageRecordFilter{StartDate: start, EndDate: end, Limit: 50}

	records, total, err := NewUsageDailyRepository(db).ListUsageRecords(ctx, scope, filter)
	if err != nil {
		t.Fatalf("list usage records: %v", err)
	}
	if total != 3 || len(records) != 3 {
		t.Fatalf("cost records should exclude proxy/in-flight rows, got total=%d len=%d", total, len(records))
	}
	byID := indexUsageRecordsByRequestID(records)
	if _, ok := byID[proxyReqID]; ok {
		t.Fatalf("proxy request %s should not appear in cost records", proxyReqID)
	}
	if _, ok := byID[receivedReqID]; ok {
		t.Fatalf("received request %s should not appear in cost records", receivedReqID)
	}
	if _, ok := byID[noGatewayKeyReqID]; ok {
		t.Fatalf("request %s without a gateway-issued internal key should not appear in cost records", noGatewayKeyReqID)
	}

	summary, err := NewUsageDailyRepository(db).SummarizeUsageRecords(ctx, scope, filter)
	if err != nil {
		t.Fatalf("summarize usage records: %v", err)
	}
	if summary.Requests != 3 || summary.NotBilledRequests != 3 || summary.BillingAmountMicros != 0 {
		t.Fatalf("summary should count only cost pipeline rows, got %+v", summary)
	}
}

func TestListUsageRecordsBillingStateFilter(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	_ = seedThreeUsageRecords(t, db, ctx, tenantID, userID, projectID)

	start, end := usageRecordRange()
	scope := UsageScope{TenantID: tenantID, UserID: userID, ProjectIDs: []string{projectID}}
	records, total, err := NewUsageDailyRepository(db).ListUsageRecords(ctx, scope, UsageRecordFilter{StartDate: start, EndDate: end, Limit: 50, BillingState: "not_billed"})
	if err != nil {
		t.Fatalf("list not-billed records: %v", err)
	}
	if total != 3 || len(records) != 3 {
		t.Fatalf("billing_state=not_billed should return all records, got total=%d len=%d", total, len(records))
	}
	for _, record := range records {
		if record.BillingState != "not_billed" {
			t.Fatalf("filtered record has state %q", record.BillingState)
		}
	}
}

func TestBillingStateSQLUsesSpecifiedPriority(t *testing.T) {
	db, ctx, _, _, _ := setupAuditStatsRegressionFixture(t)
	query := fmt.Sprintf(`
		SELECT (%s)
		FROM (VALUES (1)) seed(n)
		LEFT JOIN LATERAL (SELECT $1::text AS status, $2::timestamptz AS created_at, 'reservation'::text AS id WHERE $1 <> '') br ON true
		LEFT JOIN LATERAL (SELECT $3::text AS status, 'charge'::text AS id WHERE $3 <> '') bc ON true
		LEFT JOIN LATERAL (SELECT $4::text AS status, $5::text AS billing_mode, 99::bigint AS billable_amount_micros, 'CNY'::text AS currency WHERE $4 <> '') buf ON true
	`, billingStateSQL)
	cases := []struct {
		name, reservation, charge, fact, mode, want string
		createdAt                                   time.Time
	}{
		{name: "failed prepaid charge wins", reservation: "settled", charge: "failed", fact: "settled", want: "exception", createdAt: time.Now().UTC()},
		{name: "settled metering reservation without charge", reservation: "settled", fact: "settled", want: "settled", createdAt: time.Now().UTC()},
		{name: "settled prepaid reservation without charge", reservation: "settled", fact: "settled", mode: "prepaid", want: "exception", createdAt: time.Now().UTC()},
		{name: "settled reservation without fact", reservation: "settled", want: "exception", createdAt: time.Now().UTC()},
		{name: "settled reservation with failed metering fact", reservation: "settled", fact: "failed", want: "exception", createdAt: time.Now().UTC()},
		{name: "inconsistent prepaid states", reservation: "released", charge: "settled", fact: "settled", want: "exception", createdAt: time.Now().UTC()},
		{name: "stale reservation", reservation: "reserved", fact: "settled", want: "exception", createdAt: time.Now().UTC().Add(-16 * time.Minute)},
		{name: "settled prepaid charge", reservation: "settled", charge: "settled", fact: "failed", want: "settled", createdAt: time.Now().UTC()},
		{name: "fresh reservation", reservation: "reserved", fact: "settled", want: "reserved", createdAt: time.Now().UTC()},
		{name: "released prepaid", reservation: "released", fact: "settled", want: "released", createdAt: time.Now().UTC()},
		{name: "settled metering fact", fact: "settled", want: "settled", createdAt: time.Now().UTC()},
		{name: "unpriced metering fact", fact: "unpriced", want: "unpriced", createdAt: time.Now().UTC()},
		{name: "failed metering fact", fact: "failed", want: "failed", createdAt: time.Now().UTC()},
		{name: "no billing row", want: "not_billed", createdAt: time.Now().UTC()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			mode := tc.mode
			if mode == "" {
				mode = "metering"
			}
			if err := db.QueryRow(ctx, query, tc.reservation, tc.createdAt, tc.charge, tc.fact, mode).Scan(&got); err != nil {
				t.Fatalf("evaluate state: %v", err)
			}
			if got != tc.want {
				t.Fatalf("billing state = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUsageRecordJoinsBillingByTenantAndRequest(t *testing.T) {
	for _, join := range []string{
		"LEFT JOIN billing_reservations br ON br.tenant_id = rl.tenant_id AND br.request_id = rl.request_id",
		"LEFT JOIN billing_charge_records bc ON bc.tenant_id = rl.tenant_id AND bc.request_id = rl.request_id",
		"LEFT JOIN billing_usage_facts buf ON buf.tenant_id = rl.tenant_id AND buf.request_id = rl.request_id",
	} {
		if !strings.Contains(usageRecordJoins, join) {
			t.Fatalf("usage records must join billing data by tenant and request: %s", join)
		}
	}
}

func TestUsageTroubleshootingFiltersAndStatusNormalization(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	seed := seedThreeUsageRecords(t, db, ctx, tenantID, userID, projectID)
	_, err := db.Exec(ctx, `UPDATE request_logs SET request_status='provider_timeout', upstream_status_code=504,
 source_ip='192.0.2.8', output_audit_result='{"response_metadata":{"error_message":"model capacity 50%_exhausted"}}'::jsonb
 WHERE tenant_id=$1 AND request_id=$2`, tenantID, seed.failedReqID)
	if err != nil {
		t.Fatal(err)
	}
	start, end := usageRecordRange()
	scope := UsageScope{TenantID: tenantID, UserID: userID, ProjectIDs: []string{projectID}}
	filter := UsageRecordFilter{StartDate: start, EndDate: end, RequestStatus: "failed", SourceIP: "192.0.2.8", FailureCategory: "timeout", HTTPStatus: 504, ErrorKeyword: "50%_exhausted"}
	repo := NewUsageDailyRepository(db)
	records, total, err := repo.ListUsageRecords(ctx, scope, filter)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(records) != 1 {
		t.Fatalf("records=%+v total=%d", records, total)
	}
	rec := records[0]
	if rec.RawStatus != "provider_timeout" || rec.RequestStatus != "failed" || rec.SourceIP != "192.0.2.8" || rec.FailureCategory != "timeout" || rec.ErrorMessage != "model capacity 50%_exhausted" {
		t.Fatalf("wrong diagnostic record: %+v", rec)
	}
	summary, err := repo.SummarizeUsageRecords(ctx, scope, filter)
	if err != nil || summary.Requests != 1 || summary.FailedRequests != 1 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	filter.ErrorKeyword = "50ANYexhausted"
	_, total, err = repo.ListUsageRecords(ctx, scope, filter)
	if err != nil || total != 0 {
		t.Fatalf("literal search total=%d err=%v", total, err)
	}
	filter.ErrorKeyword = ""
	filter.SourceIP = "192.0.2.9"
	_, total, err = repo.ListUsageRecords(ctx, scope, filter)
	if err != nil || total != 0 {
		t.Fatalf("IP filter total=%d err=%v", total, err)
	}
	filter.SourceIP = "192.0.2.8"
	scope.UserID = "another-user"
	scope.ProjectIDs = nil
	_, total, err = repo.ListUsageRecords(ctx, scope, filter)
	if err != nil || total != 0 {
		t.Fatalf("scope filter total=%d err=%v", total, err)
	}
}
