package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestListPortalCallRecordsUsesRealAuditShapeAndTenantUserIsolation(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	tenantA := "tenant_portal_calls_a_" + suffix
	tenantB := "tenant_portal_calls_b_" + suffix
	userA := "user_portal_calls_a_" + suffix
	userOther := "user_portal_calls_other_" + suffix
	userB := "user_portal_calls_b_" + suffix
	projectA := "project_portal_calls_a_" + suffix
	projectB := "project_portal_calls_b_" + suffix
	providerA := "provider_portal_calls_a_" + suffix
	knownModel := "model_portal_calls_known_" + suffix
	internalModel := "model_portal_calls_internal_" + suffix

	t.Cleanup(func() {
		if _, err := db.Exec(ctx, "ALTER TABLE billing_charge_records DISABLE TRIGGER trg_billing_charge_append_only"); err != nil {
			t.Logf("disable billing charge cleanup trigger: %v", err)
		} else {
			if _, err := db.Exec(ctx, "DELETE FROM billing_charge_records WHERE tenant_id = $1 OR tenant_id = $2", tenantA, tenantB); err != nil {
				t.Logf("cleanup billing charges: %v", err)
			}
			if _, err := db.Exec(ctx, "ALTER TABLE billing_charge_records ENABLE TRIGGER trg_billing_charge_append_only"); err != nil {
				t.Logf("re-enable billing charge cleanup trigger: %v", err)
			}
		}
		if _, err := db.Exec(ctx, "ALTER TABLE billing_usage_facts DISABLE TRIGGER trg_billing_usage_facts_append_only"); err != nil {
			t.Logf("停用用量事实清理触发器失败：%v", err)
		} else {
			if _, err := db.Exec(ctx, "DELETE FROM billing_usage_facts WHERE tenant_id = $1 OR tenant_id = $2", tenantA, tenantB); err != nil {
				t.Logf("清理缓存用量事实失败：%v", err)
			}
			if _, err := db.Exec(ctx, "ALTER TABLE billing_usage_facts ENABLE TRIGGER trg_billing_usage_facts_append_only"); err != nil {
				t.Logf("恢复用量事实触发器失败：%v", err)
			}
		}

		for _, stmt := range []string{
			"DELETE FROM security_events WHERE tenant_id = $1 OR tenant_id = $2",
			"DELETE FROM billing_reservations WHERE tenant_id = $1 OR tenant_id = $2",
			"DELETE FROM billing_wallets WHERE tenant_id = $1 OR tenant_id = $2",
			"DELETE FROM billing_customer_groups WHERE tenant_id = $1 OR tenant_id = $2",
			"DELETE FROM request_logs WHERE tenant_id = $1 OR tenant_id = $2",
			"DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = $1 OR tenant_id = $2)",
			"DELETE FROM providers WHERE tenant_id = $1 OR tenant_id = $2",
			"DELETE FROM projects WHERE tenant_id = $1 OR tenant_id = $2",
			"DELETE FROM users WHERE tenant_id = $1 OR tenant_id = $2",
			"DELETE FROM tenants WHERE id = $1 OR id = $2",
		} {
			if _, err := db.Exec(ctx, stmt, tenantA, tenantB); err != nil {
				t.Logf("cleanup fixture with %q: %v", stmt, err)
			}
		}
		db.Close()
	})

	if _, err := db.Exec(ctx, `
		INSERT INTO tenants (id, name, edition, status, is_test)
		VALUES ($1, $1, 'enterprise', 'active', TRUE),
		       ($2, $2, 'enterprise', 'active', TRUE)
	`, tenantA, tenantB); err != nil {
		t.Fatalf("insert tenants: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO users (id, tenant_id, username, role, status)
		VALUES ($1, $4, $1, 'developer', 'active'),
		       ($2, $4, $2, 'developer', 'active'),
		       ($3, $5, $3, 'developer', 'active')
	`, userA, userOther, userB, tenantA, tenantB); err != nil {
		t.Fatalf("insert users: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO projects (id, tenant_id, name, owner_user_id, status)
		VALUES ($1, $3, $1, $4, 'active'),
		       ($2, $5, $2, $6, 'active')
	`, projectA, projectB, tenantA, userA, tenantB, userB); err != nil {
		t.Fatalf("insert projects: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO providers (id, tenant_id, name, provider_type, status)
		VALUES ($1, $2, '测试供应商', 'openai', 'active')
	`, providerA, tenantA); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO models (id, provider_id, model_name, model_label, status)
		VALUES ($1, $3, 'upstream-known', '客户模型', 'active'),
		       ($2, $3, '', '', 'active')
	`, knownModel, internalModel, providerA); err != nil {
		t.Fatalf("insert models: %v", err)
	}
	walletA := "wallet_portal_calls_a_" + suffix
	walletB := "wallet_portal_calls_b_" + suffix
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_customer_groups (id, tenant_id, code, name, status, is_default)
		VALUES ($1, $3, 'default', '默认客户组', 'active', TRUE),
		       ($2, $4, 'default', '默认客户组', 'active', TRUE)
	`, "group-portal-a-"+suffix, "group-portal-b-"+suffix, tenantA, tenantB); err != nil {
		t.Fatalf("insert billing groups: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_wallets (id, tenant_id, user_id, currency, balance_micros)
		VALUES ($1, $3, $5, 'CNY', 1000000),
		       ($2, $4, $6, 'CNY', 1000000)
	`, walletA, walletB, tenantA, tenantB, userA, userB); err != nil {
		t.Fatalf("insert billing wallets: %v", err)
	}

	createdAt := time.Date(2026, 8, 16, 8, 0, 0, 0, time.UTC)
	insertRequest := func(
		requestID, tenantID, projectID, userID, modelID, endpoint, status string,
		upstreamStatus, inputTokens, outputTokens, latencyMs int,
		inputAudit, outputAudit string,
		at time.Time,
	) {
		t.Helper()
		var providerValue, modelValue interface{}
		if modelID != "" {
			providerValue = providerA
			modelValue = modelID
		}
		_, err := db.Exec(ctx, `
			INSERT INTO request_logs (
				id, request_id, tenant_id, project_id, user_id, provider_id, model_id,
				endpoint_type, request_status, upstream_status_code,
				input_tokens, output_tokens, latency_ms, agent_type,
				input_audit_result, output_audit_result, created_at
			)
			VALUES (
				$1, $1, $2, $3, $4, $5, $6,
				$7, $8, $9, $10, $11, $12, 'openai-codex',
				$13::jsonb, $14::jsonb, $15
			)
		`, requestID, tenantID, projectID, userID, providerValue, modelValue,
			endpoint, status, upstreamStatus, inputTokens, outputTokens, latencyMs,
			inputAudit, outputAudit, at)
		if err != nil {
			t.Fatalf("insert request %s: %v", requestID, err)
		}
	}

	requestZ := "req-portal-z-" + suffix
	requestA := "req-portal-a-" + suffix
	requestOld := "req-portal-old-" + suffix
	requestReserved := "req-portal-reserved-" + suffix
	requestReleased := "req-portal-released-" + suffix
	requestNotBilled := "req-portal-not-billed-" + suffix
	insertRequest(requestZ, tenantA, projectA, userA, knownModel, "responses", "success", 200, 120, 30, 450, `{"action":"block"}`, `{}`, createdAt)
	insertRequest(requestA, tenantA, projectA, userA, internalModel, "responses", "success", 200, 80, 20, 350, `{}`, `{"action":"redact"}`, createdAt)
	insertRequest(requestOld, tenantA, projectA, userA, knownModel, "responses", "billing_http_429", 429, 0, 0, 10, `{"action_taken":"audit"}`, `{}`, createdAt.Add(-time.Minute))
	insertRequest(requestReserved, tenantA, projectA, userA, knownModel, "responses", "success", 200, 1, 1, 1, `{}`, `{}`, createdAt.Add(-2*time.Minute))
	insertRequest(requestReleased, tenantA, projectA, userA, knownModel, "responses", "success", 200, 1, 1, 1, `{}`, `{}`, createdAt.Add(-3*time.Minute))
	insertRequest(requestNotBilled, tenantA, projectA, userA, knownModel, "responses", "success", 200, 1, 1, 1, `{}`, `{}`, createdAt.Add(-4*time.Minute))
	insertRequest("req-portal-other-user-"+suffix, tenantA, projectA, userOther, knownModel, "responses", "success", 200, 1, 1, 1, `{}`, `{}`, createdAt)
	insertRequest("req-portal-other-tenant-"+suffix, tenantB, projectB, userB, "", "responses", "success", 200, 1, 1, 1, `{}`, `{}`, createdAt)
	insertRequest("req-portal-proxy-"+suffix, tenantA, projectA, userA, knownModel, "proxy", "success", 200, 1, 1, 1, `{}`, `{}`, createdAt)
	insertRequest("req-portal-pending-"+suffix, tenantA, projectA, userA, knownModel, "responses", "in_progress", 0, 1, 0, 1, `{}`, `{}`, createdAt)

	if _, err := db.Exec(ctx, `
		INSERT INTO billing_reservations (
			id, tenant_id, wallet_id, request_id, reserved_micros,
			reserved_tokens, status, created_at
		)
		VALUES ($1, $2, $3, $4, 0, 2, 'reserved', NOW())
	`, "reservation-portal-"+suffix, tenantA, walletA, requestReserved); err != nil {
		t.Fatalf("insert billing reservation: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_charge_records (
			id, tenant_id, wallet_id, request_id, model_name,
			amount_micros, pricing_mode, currency, status, customer_group
		)
		VALUES
			($1, $6, $8, $10, 'upstream-known', 0,      'direct', 'CNY', 'settled', 'default'),
			($2, $6, $8, $11, 'upstream-known', 12345,  'direct', 'CNY', 'settled', 'default'),
			($3, $6, $8, $12, 'upstream-known', 0,      'direct', 'CNY', 'failed',   'default'),
			($4, $6, $8, $13, 'upstream-known', 0,      'direct', 'CNY', 'released', 'default'),
			($5, $7, $9, $10, 'upstream-known', 999999, 'direct', 'CNY', 'settled',  'default')
	`,
		"charge-portal-zero-"+suffix,
		"charge-portal-paid-"+suffix,
		"charge-portal-failed-"+suffix,
		"charge-portal-released-"+suffix,
		"charge-portal-cross-tenant-"+suffix,
		tenantA, tenantB, walletA, walletB,
		requestZ, requestA, requestOld, requestReleased,
	); err != nil {
		t.Fatalf("insert billing charges: %v", err)
	}

	if _, err := db.Exec(ctx, `
		INSERT INTO security_events (
			id, request_id, tenant_id, project_id, user_id,
			event_type, severity, action_taken, matched_summary, created_at
		)
		VALUES ($1, $2, $3, $4, $5, 'content_security', 'high', 'block', '{}'::jsonb, $6)
	`, "event-portal-"+suffix, requestZ, tenantA, projectA, userA, createdAt); err != nil {
		t.Fatalf("insert security event: %v", err)
	}

	if _, err := db.Exec(ctx, `
        INSERT INTO billing_usage_facts (
            id, tenant_id, request_id, user_id, model_name, prompt_tokens,
            cached_input_tokens, cache_write_input_tokens, output_tokens, occurred_at, admitted_at
        ) VALUES ($1, $2, $3, $4, 'upstream-known', 120, 90, 18, 30, $5, $5),
                 ($6, $7, $3, $8, 'upstream-known', 120, 99, 19, 30, $5, $5)
    `, "fact-portal-cache-"+suffix, tenantA, requestZ, userA, createdAt,
		"fact-portal-cross-"+suffix, tenantB, userB); err != nil {
		t.Fatalf("插入缓存用量事实失败：%v", err)
	}

	repo := NewRequestLogRepository(db)
	filter := PortalCallRecordFilter{
		TenantID:  tenantA,
		UserID:    userA,
		StartTime: createdAt.Add(-time.Hour),
		Limit:     2,
	}
	records, total, err := repo.ListPortalCallRecords(ctx, filter)
	if err != nil {
		t.Fatalf("list first cursor page: %v", err)
	}
	if total != 6 || len(records) != 2 {
		t.Fatalf("tenant/user/completion filters failed: total=%d records=%+v", total, records)
	}
	if records[0].RequestID != requestZ || records[1].RequestID != requestA {
		t.Fatalf("same-timestamp order is unstable: %+v", records)
	}
	if records[0].Model != "客户模型" || records[0].InputAction != "block" || records[0].SecurityEventCount != 1 {
		t.Fatalf("real action/model/security mapping failed: %+v", records[0])
	}
	if records[1].Model != "未识别模型" || strings.Contains(records[1].Model, internalModel) || records[1].OutputAction != "redact" {
		t.Fatalf("model privacy or output action mapping failed: %+v", records[1])
	}

	if records[0].CachedInputTokens != 90 || records[0].CacheWriteInputTokens != 18 || records[0].InputTokens != 120 {
		t.Fatalf("缓存字段扫描或租户隔离错误：%+v", records[0])
	}
	if records[1].CachedInputTokens != 0 || records[1].CacheWriteInputTokens != 0 {
		t.Fatalf("无计费事实的缓存应为零：%+v", records[1])
	}

	summary, summaryErr := repo.SummarizePortalCallRecords(ctx, filter)
	if summaryErr != nil || summary.Requests != total || summary.AverageLatencyMS == nil || summary.SuccessRate == nil {
		t.Fatalf("个人完整窗口汇总失败: %+v %v", summary, summaryErr)
	}
	filter.BeforeCreatedAt = records[1].CreatedAt
	filter.BeforeRequestID = records[1].RequestID
	next, nextTotal, err := repo.ListPortalCallRecords(ctx, filter)
	if err != nil {
		t.Fatalf("list second cursor page: %v", err)
	}
	if nextTotal != 6 || len(next) != 2 || next[0].RequestID != requestOld {
		t.Fatalf("cursor boundary repeated or skipped rows: total=%d records=%+v", nextTotal, next)
	}
	if next[0].Status != "billing_http_429" || next[0].InputAction != "audit" {
		t.Fatalf("failed calls or legacy action compatibility missing: %+v", next[0])
	}

	nextSummary, summaryErr := repo.SummarizePortalCallRecords(ctx, filter)
	if summaryErr != nil || nextSummary.Requests != summary.Requests || *nextSummary.AverageLatencyMS != *summary.AverageLatencyMS || *nextSummary.SuccessRate != *summary.SuccessRate {
		t.Fatalf("游标不能改变汇总: %+v %v", nextSummary, summaryErr)
	}
	filter.BeforeCreatedAt = time.Time{}
	filter.BeforeRequestID = ""
	filter.Limit = 10
	all, allTotal, err := repo.ListPortalCallRecords(ctx, filter)
	if err != nil {
		t.Fatalf("list billing states: %v", err)
	}
	if allTotal != 6 || len(all) != 6 {
		t.Fatalf("billing fixture filter failed: total=%d records=%+v", allTotal, all)
	}
	byRequest := make(map[string]PortalCallRecord, len(all))
	for _, record := range all {
		byRequest[record.RequestID] = record
	}
	if got := byRequest[requestZ]; got.BillingState != "settled" || got.BillingAmountMicros == nil || *got.BillingAmountMicros != 0 || got.BillingCurrency != "CNY" {
		t.Fatalf("zero-price settlement or cross-tenant isolation failed: %+v", got)
	}
	if got := byRequest[requestA]; got.BillingState != "settled" || got.BillingAmountMicros == nil || *got.BillingAmountMicros != 12345 {
		t.Fatalf("paid settlement failed: %+v", got)
	}
	for requestID, state := range map[string]string{
		requestReserved:  "reserved",
		requestReleased:  "released",
		requestOld:       "exception",
		requestNotBilled: "not_billed",
	} {
		got := byRequest[requestID]
		if got.BillingState != state || got.BillingAmountMicros != nil {
			t.Fatalf("billing state %s: want %s with nil amount, got %+v", requestID, state, got)
		}
	}
}
