package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Keyset pagination for customers and ledger must walk the full list in
// bounded pages, expose the reason recorded in the same transaction as the
// balance change, and the effective price projection must keep only the newest
// active version per (model, group).
func TestAdminKeysetPaginationCustomersLedgerAndReason(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()

	usernames := []string{"pag-a", "pag-b", "pag-c"}
	userIDs := []string{userID}
	for _, name := range usernames {
		uid := userID + "-" + name
		if _, err := db.Exec(ctx, `
			INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
			VALUES ($1, $2, $3, $4, 'x', 'developer', 'active')
		`, uid, tenantID, name, uid+"@test.invalid"); err != nil {
			t.Fatalf("insert pagination user %s: %v", name, err)
		}
		userIDs = append(userIDs, uid)
	}
	for _, uid := range userIDs {
		wallet, err := store.EnsureWallet(ctx, tenantID, uid, "CNY")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Credit(ctx, tenantID, wallet.ID, "pag-credit-"+uid, 5_000, "tester", "topup-audit-reason"); err != nil {
			t.Fatal(err)
		}
	}

	page1, cursor1, err := store.ListAdminCustomersPage(ctx, tenantID, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 2 || cursor1 == "" {
		t.Fatalf("page1 n=%d cursor=%q", len(page1), cursor1)
	}
	page2, cursor2, err := store.ListAdminCustomersPage(ctx, tenantID, 2, cursor1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 2 || cursor2 != "" {
		t.Fatalf("page2 n=%d cursor=%q", len(page2), cursor2)
	}
	if page1[0].UserID == page2[0].UserID || page1[0].UserID == page2[1].UserID {
		t.Fatalf("pages overlap: page1=%+v page2=%+v", page1[:1], page2)
	}
	if _, _, err := store.ListAdminCustomersPage(ctx, tenantID, 2, "!!!not-base64!!!"); err == nil {
		t.Fatal("malformed cursor accepted")
	}

	// Full-input idempotency on credit: an identical replay succeeds without
	// a second entry, while the same key with a different reason conflicts.
	mainWallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Credit(ctx, tenantID, mainWallet.ID, "pag-credit-"+userID, 5_000, "tester", "topup-audit-reason"); err != nil {
		t.Fatalf("identical credit replay: %v", err)
	}
	if _, err := store.Credit(ctx, tenantID, mainWallet.ID, "pag-credit-"+userID, 5_000, "tester", "different-reason"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("reason-changed credit replay err=%v want ErrIdempotencyConflict", err)
	}
	if _, err := store.Adjust(ctx, tenantID, mainWallet.ID, "pag-adjust-"+userID, -1_000, "tester", "adjust-reason"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Adjust(ctx, tenantID, mainWallet.ID, "pag-adjust-"+userID, -1_000, "tester", "other-reason"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("reason-changed adjust replay err=%v want ErrIdempotencyConflict", err)
	}

	// Walk the whole ledger in pages of 2 until the cursor is exhausted: 4
	// credit entries plus 1 adjustment must appear exactly once with their
	// reasons intact.
	seen := map[string]bool{}
	credited := 0
	adjusted := 0
	cursor := ""
	pages := 0
	for {
		entries, next, err := store.ListLedgerEntriesPage(ctx, tenantID, "", 2, cursor)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, entry := range entries {
			if seen[entry.ID] {
				t.Fatalf("ledger entry %s returned twice", entry.ID)
			}
			seen[entry.ID] = true
			switch entry.EventType {
			case "credit":
				credited++
				if entry.Reason != "topup-audit-reason" || entry.IdempotencyKey == "" {
					t.Fatalf("credit entry reason=%q idempotency=%q metadata=%s", entry.Reason, entry.IdempotencyKey, entry.MetadataJSON)
				}
			case "adjustment":
				adjusted++
				if entry.Reason != "adjust-reason" || entry.IdempotencyKey == "" {
					t.Fatalf("adjustment entry reason=%q idempotency=%q", entry.Reason, entry.IdempotencyKey)
				}
			}
		}
		if next == "" {
			break
		}
		if pages > 10 {
			t.Fatal("ledger pagination did not terminate")
		}
		cursor = next
	}
	if pages < 2 {
		t.Fatalf("ledger pagination produced %d page(s), want keyset walk", pages)
	}
	if len(seen) != 5 || credited != 4 || adjusted != 1 {
		t.Fatalf("ledger walk seen=%d credited=%d adjusted=%d", len(seen), credited, adjusted)
	}
}

func TestLedgerCurrencyComesFromWalletAcrossBothReadPaths(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	walletCurrencies := map[string]string{}
	for _, currency := range []string{"CNY", "USD"} {
		wallet, err := store.EnsureWallet(ctx, tenantID, userID, currency)
		if err != nil {
			t.Fatal(err)
		}
		walletCurrencies[wallet.ID] = currency
		for _, suffix := range []string{"a", "b"} {
			if _, err := db.Exec(ctx, `
				INSERT INTO billing_ledger_entries (id,tenant_id,wallet_id,event_type,
					balance_delta_micros,reserved_delta_micros,balance_after_micros,reserved_after_micros,
					idempotency_key,actor_type,metadata_json)
				VALUES ($1,$2,$3,'credit',5000,0,5000,0,$1,'system','{"currency":"EUR"}'::jsonb)
			`, "lc_"+wallet.ID+suffix, tenantID, wallet.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	legacy, err := store.ListLedgerEntries(ctx, tenantID, "", 100)
	if err != nil || len(legacy) != 4 {
		t.Fatalf("legacy rows=%+v err=%v", legacy, err)
	}
	for _, entry := range legacy {
		if entry.Currency != walletCurrencies[entry.WalletID] {
			t.Fatalf("legacy wallet currency mismatch: %+v", entry)
		}
	}
	seen := map[string]bool{}
	cursor := ""
	for {
		entries, next, err := store.ListLedgerEntriesPage(ctx, tenantID, "", 1, cursor)
		if err != nil || len(entries) != 1 {
			t.Fatalf("page rows=%+v err=%v", entries, err)
		}
		entry := entries[0]
		if entry.Currency != walletCurrencies[entry.WalletID] || seen[entry.ID] {
			t.Fatalf("page currency mismatch or duplicate: %+v", entry)
		}
		seen[entry.ID] = true
		if next == "" {
			break
		}
		if len(seen) > len(legacy) {
			t.Fatal("pagination did not terminate")
		}
		cursor = next
	}
	if len(seen) != len(legacy) {
		t.Fatalf("page rows=%d legacy=%d", len(seen), len(legacy))
	}
	for _, entry := range legacy {
		if !seen[entry.ID] {
			t.Fatalf("legacy entry absent from pages: %s", entry.ID)
		}
	}
	for walletID, currency := range walletCurrencies {
		entries, err := store.ListLedgerEntries(ctx, tenantID, walletID, 100)
		if err != nil || len(entries) != 2 {
			t.Fatalf("filtered legacy rows=%+v err=%v", entries, err)
		}
		paged, next, err := store.ListLedgerEntriesPage(ctx, tenantID, walletID, 100, "")
		if err != nil || len(paged) != 2 || next != "" {
			t.Fatalf("filtered page rows=%+v next=%q err=%v", paged, next, err)
		}
		for _, entry := range append(entries, paged...) {
			if entry.WalletID != walletID || entry.Currency != currency {
				t.Fatalf("wallet filter/currency mismatch: %+v", entry)
			}
		}
	}
}

func TestListEffectiveModelPricesKeepsNewestActivePerModel(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	mkPrice := func(model, currency string, amount Micros, status string, effective time.Time, expires *time.Time) *ModelPrice {
		created, err := store.CreateModelPrice(ctx, NewModelPrice{
			TenantID: tenantID, ModelName: model, CustomerGroup: DefaultCustomerGroup,
			PricingMode: PricingModeDirect, Currency: currency,
			DirectPrice: DirectPrice{InputPerMillionMicros: amount, OutputPerMillionMicros: amount},
			EffectiveAt: effective, ExpiresAt: expires, Status: status, CreatedBy: "test",
		})
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	mkPrice("eff-model", "CNY", 1_000_000, PriceStatusActive, past, nil)           // v1 superseded
	newest := mkPrice("eff-model", "CNY", 2_000_000, PriceStatusActive, past, nil) // v2 wins
	mkPrice("eff-model", "CNY", 3_000_000, PriceStatusActive, future, nil)         // not yet effective
	mkPrice("eff-model", "CNY", 4_000_000, PriceStatusDraft, past, nil)            // not active
	expiredEffective := past.Add(-2 * time.Hour)
	retiredExpires := past.Add(-time.Hour)
	mkPrice("eff-expired", "CNY", 5_000_000, PriceStatusActive, expiredEffective, &retiredExpires) // expired

	prices, err := store.ListEffectiveModelPrices(ctx, tenantID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(prices) != 1 || prices[0].ID != newest.ID || prices[0].DirectPrice.InputPerMillionMicros != 2_000_000 {
		t.Fatalf("effective prices=%+v want only %s", prices, newest.ID)
	}
}

// Exceptions must surface metering gaps (unpriced and failed facts) so
// operators can see revenue that was recorded without a price or without a
// billable outcome.
func TestBillingExceptionsIncludeMeteringGaps(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	base := MeteringInput{
		TenantID: tenantID, UserID: userID, AdmittedAt: time.Now().UTC(),
	}
	if _, err := store.RecordMeteringUsage(ctx, MeteringInput{
		TenantID: base.TenantID, UserID: base.UserID, RequestID: "gap-unpriced-1",
		ModelName: "no-such-priced-model", RequestStatus: "success",
		Usage: Usage{PromptTokens: 5, OutputTokens: 5}, AdmittedAt: base.AdmittedAt,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordMeteringUsage(ctx, MeteringInput{
		TenantID: base.TenantID, UserID: base.UserID, RequestID: "gap-failed-1",
		ModelName: "any-model", RequestStatus: "failed",
		AdmittedAt: base.AdmittedAt,
	}); err != nil {
		t.Fatal(err)
	}
	exceptions, err := store.ListBillingExceptions(ctx, tenantID, 100)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, item := range exceptions {
		kinds[item.Kind]++
	}
	if kinds["metering_unpriced"] != 1 || kinds["metering_failed"] != 1 {
		t.Fatalf("exception kinds=%v want metering_unpriced=1 metering_failed=1", kinds)
	}
}

// The analytics summary keeps the legacy priced definition and exposes the
// settled and failed outcomes as separate counters (settled_requests /
// failed_requests), all amounts in micros.
func TestAnalyticsSummarySettledAndFailedCounters(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	admittedAt := time.Now().UTC()
	if _, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "cny-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 1_000_000},
		EffectiveAt: admittedAt.Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordMeteringUsage(ctx, MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "sum-cny-1", ModelName: "cny-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 1_000_000, OutputTokens: 1_000_000},
		AdmittedAt: admittedAt,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordMeteringUsage(ctx, MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "sum-failed-1", ModelName: "cny-model",
		RequestStatus: "failed", AdmittedAt: admittedAt,
	}); err != nil {
		t.Fatal(err)
	}

	summary, err := store.GetAnalyticsSummary(ctx, AnalyticsFilter{
		TenantID: tenantID, Start: admittedAt.Add(-time.Hour), End: admittedAt.Add(time.Hour), FullTenant: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 1M input + 1M output tokens at 1 micro per token = 2_000_000 micros.
	if summary.Requests != 2 || summary.PricedRequests != 2 || summary.SettledRequests != 1 ||
		summary.FailedRequests != 1 || summary.BillableMicros != 2_000_000 || summary.Currency != "CNY" {
		t.Fatalf("summary counts=%+v", summary)
	}
}

// 多币种历史同时存在时，各聚合只统计系统币种。
func TestAnalyticsAggregatesSelectTenantCurrency(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	admittedAt := time.Now().UTC()
	if _, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "mix-cny-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 1_000_000},
		EffectiveAt: admittedAt.Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordMeteringUsage(ctx, MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "mix-cny-1", ModelName: "mix-cny-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 1_000_000, OutputTokens: 0},
		AdmittedAt: admittedAt,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_usage_facts (
			id,tenant_id,request_id,billing_mode,user_name,model_name,
			prompt_tokens,output_tokens,currency,status,occurred_at
		) VALUES ($1,$2,'mix-legacy-usd-1','metering','legacy','mix-usd-model',0,0,'USD','settled',NOW())
	`, "usage_fact_mixed_"+tenantID, tenantID); err != nil {
		t.Fatal(err)
	}
	filter := AnalyticsFilter{
		TenantID: tenantID, Start: admittedAt.Add(-time.Hour), End: admittedAt.Add(time.Hour), FullTenant: true,
	}

	if summary, err := store.GetAnalyticsSummary(ctx, filter); err != nil || summary.Currency != "CNY" || summary.BillableMicros != 1_000_000 || len(summary.OtherCurrencies) != 1 || summary.OtherCurrencies[0] != "USD" {
		t.Fatalf("默认币种摘要：%+v %v", summary, err)
	}
	if _, err := store.GetAnalyticsBreakdown(ctx, filter, "model", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAnalyticsSeries(ctx, filter, "day"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAnalyticsTimeProfile(ctx, filter, "UTC", 60); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAnalyticsDepartmentProviderMatrix(ctx, filter); err != nil {
		t.Fatal(err)
	}

	// The same selection scoped to a single currency must pass: the rejection
	// is about non-summable totals, not about the legacy row itself.
	singleTenant := tenantID + "S"
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, singleTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_usage_facts (
			id,tenant_id,request_id,billing_mode,user_name,model_name,
			prompt_tokens,output_tokens,currency,status,occurred_at
		) VALUES ($1,$2,'mix-single-cny-1','metering','legacy','mix-cny-model',0,0,'CNY','settled',NOW())
	`, "usage_fact_mixed_"+tenantID+"-s", singleTenant); err != nil {
		t.Fatal(err)
	}
	summary, err := store.GetAnalyticsSummary(ctx, AnalyticsFilter{
		TenantID: singleTenant, Start: admittedAt.Add(-time.Hour), End: admittedAt.Add(time.Hour), FullTenant: true,
	})
	if err != nil {
		t.Fatalf("single-currency summary must pass: %v", err)
	}
	if summary.Currency != "CNY" {
		t.Fatalf("single-currency summary currency=%s want CNY", summary.Currency)
	}
}

// 并发插入其它币种也绝不能改变当前币种的金额合计。
func TestAnalyticsSummaryConcurrentForeignCurrencyIsNeverSummed(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	admittedAt := time.Now().UTC()
	if _, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "race-cny-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 1_000_000},
		EffectiveAt: admittedAt.Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordMeteringUsage(ctx, MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "race-cny-1", ModelName: "race-cny-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 1_000_000, OutputTokens: 1_000_000},
		AdmittedAt: admittedAt,
	}); err != nil {
		t.Fatal(err)
	}
	filter := AnalyticsFilter{
		TenantID: tenantID, Start: admittedAt.Add(-time.Hour), End: admittedAt.Add(time.Hour), FullTenant: true,
	}
	stop := make(chan struct{})
	inserted := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		<-inserted
		if _, err := db.Exec(ctx, `
			INSERT INTO billing_usage_facts (
				id,tenant_id,request_id,billing_mode,user_name,model_name,
				prompt_tokens,output_tokens,currency,status,billable_amount_micros,occurred_at
			) VALUES ($1,$2,'race-usd-1','metering','legacy','race-usd-model',0,0,'USD','settled',999999,NOW())
		`, "usage_fact_race_"+tenantID, tenantID); err != nil {
			t.Errorf("concurrent insert: %v", err)
		}
		close(stop)
	}()
	close(inserted)
	iterations := 0
	for {
		select {
		case <-stop:
		default:
		}
		summary, err := store.GetAnalyticsSummary(ctx, filter)
		if err != nil {
			t.Fatalf("统计错误：%v", err)
		}
		if summary.BillableMicros != 2_000_000 {
			t.Fatalf("混加币种：%+v", summary)
		}

		iterations++
		select {
		case <-stop:
			for i := 0; i < 5; i++ {
				summary, err := store.GetAnalyticsSummary(ctx, filter)
				if err != nil || summary.BillableMicros != 2_000_000 {
					t.Fatalf("并发后混币统计：%+v %v", summary, err)
				}
			}
			<-writerDone
			return
		default:
			if iterations > 500 {
				t.Fatal("reader loop did not observe the concurrent insert")
			}
		}
	}
}
