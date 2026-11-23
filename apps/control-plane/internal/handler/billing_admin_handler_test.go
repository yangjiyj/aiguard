package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// Handler-level tests for the billing admin endpoints: pagination is opt-in
// via the cursor parameter (no cursor keeps the legacy response shape without
// meta), the effective price projection supports a model_name query, and a
// mixed-currency analytics selection is refused with the stable 409 code
// billing_currency_mixed instead of summing across currencies.

func openBillingHandlerTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set CONTENT_LOGS_TEST_DATABASE_URL to run billing handler integration tests")
	}
	db, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// billingHandlerTestTenant returns a fresh tenant id per run: the integration
// database persists between runs, so fixed ids would collide with durable
// metering idempotency state from a previous execution.
func billingHandlerTestTenant(t *testing.T, prefix string) string {
	t.Helper()
	return fmt.Sprintf("%s-%09x", prefix, time.Now().UnixNano()%0xfffffffff)
}

func billingHandlerAdminRequest(r *http.Request, userID, tenantID, role string) *http.Request {
	user := &repository.User{ID: userID, TenantID: tenantID, Role: role, Username: "billing-handler-test"}
	return r.WithContext(context.WithValue(r.Context(), auth.UserKey, user))
}

func billingHandlerGet(t *testing.T, handlerFunc http.HandlerFunc, deps *Dependencies, userID, tenantID, role, query string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	target := "/test"
	if query != "" {
		target += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req = billingHandlerAdminRequest(req, userID, tenantID, role)
	rec := httptest.NewRecorder()
	handlerFunc(rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return rec, body
}

func TestBillingAdminHandlersPaginationOptIn(t *testing.T) {
	db := openBillingHandlerTestDB(t)
	store := billing.NewStore(db)
	deps := &Dependencies{BillingStore: store}
	ctx := context.Background()
	tenantID := billingHandlerTestTenant(t, "hpag1")
	adminID := "user-hpag-admin"
	if _, err := db.Exec(ctx, `
		INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')
		ON CONFLICT (id) DO NOTHING
	`, tenantID); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"a", "b", "c"} {
		uid := tenantID + "-u" + suffix
		if _, err := db.Exec(ctx, `
			INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
			VALUES ($1, $2, $1, $3, 'x', 'developer', 'active')
			ON CONFLICT (id) DO NOTHING
		`, uid, tenantID, uid+"@test.invalid"); err != nil {
			t.Fatal(err)
		}
		wallet, err := store.EnsureWallet(ctx, tenantID, uid, "CNY")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Credit(ctx, tenantID, wallet.ID, "hpag-credit-"+uid, 5_000, "tester", "handler-reason"); err != nil {
			t.Fatal(err)
		}
	}

	// Legacy shape: no cursor parameter means no meta key at all.
	rec, body := billingHandlerGet(t, ListBillingCustomers(deps), deps, adminID, tenantID, "platform_admin", "tenant_id="+tenantID)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy customers status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, hasMeta := body["meta"]; hasMeta {
		t.Fatalf("legacy customer response must not carry meta: %s", rec.Body.String())
	}
	data, _ := body["data"].([]any)
	if len(data) != 3 {
		t.Fatalf("legacy customers rows=%d want 3", len(data))
	}

	// Opt-in: ?cursor= switches to the paginated shape with meta.
	rec, body = billingHandlerGet(t, ListBillingCustomers(deps), deps, adminID, tenantID, "platform_admin", "tenant_id="+tenantID+"&limit=2&cursor=")
	if rec.Code != http.StatusOK {
		t.Fatalf("paginated customers status=%d body=%s", rec.Code, rec.Body.String())
	}
	meta, ok := body["meta"].(map[string]any)
	if !ok {
		t.Fatalf("opt-in customer response must carry meta: %s", rec.Body.String())
	}
	nextCursor, _ := meta["next_cursor"].(string)
	if nextCursor == "" || meta["has_more"] != true {
		t.Fatalf("first page meta=%v want next_cursor+has_more", meta)
	}
	_, body = billingHandlerGet(t, ListBillingCustomers(deps), deps, adminID, tenantID, "platform_admin",
		"tenant_id="+tenantID+"&limit=2&cursor="+nextCursor)
	meta, ok = body["meta"].(map[string]any)
	if !ok {
		t.Fatalf("second page must carry meta: %s", rec.Body.String())
	}
	if meta["next_cursor"] != "" {
		t.Fatalf("second page meta=%v want exhausted cursor", meta)
	}
	if data, _ = body["data"].([]any); len(data) != 1 {
		t.Fatalf("second page rows=%d want 1", len(data))
	}

	// Ledger: same opt-in contract, walkable keyset pages.
	rec, body = billingHandlerGet(t, ListBillingLedger(deps), deps, adminID, tenantID, "platform_admin", "tenant_id="+tenantID)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy ledger status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, hasMeta := body["meta"]; hasMeta {
		t.Fatalf("legacy ledger response must not carry meta: %s", rec.Body.String())
	}
	seen := 0
	cursor := ""
	pages := 0
	for {
		query := "tenant_id=" + tenantID + "&limit=2&cursor=" + cursor
		rec, body = billingHandlerGet(t, ListBillingLedger(deps), deps, adminID, tenantID, "platform_admin", query)
		if rec.Code != http.StatusOK {
			t.Fatalf("ledger page status=%d body=%s", rec.Code, rec.Body.String())
		}
		meta, ok := body["meta"].(map[string]any)
		if !ok {
			t.Fatalf("opt-in ledger page must carry meta: %s", rec.Body.String())
		}
		if data, _ = body["data"].([]any); len(data) == 0 {
			t.Fatal("ledger page returned no rows")
		}
		seen += len(data)
		pages++
		cursor, _ = meta["next_cursor"].(string)
		if cursor == "" {
			break
		}
		if pages > 10 {
			t.Fatal("ledger pagination did not terminate")
		}
	}
	if pages < 2 || seen < 3 {
		t.Fatalf("ledger walk pages=%d seen=%d, want keyset pages covering all entries", pages, seen)
	}
}

func TestBillingLedgerHTTPWalletCurrencyBothReadPaths(t *testing.T) {
	db := openBillingHandlerTestDB(t)
	store := billing.NewStore(db)
	deps := &Dependencies{BillingStore: store}
	ctx := context.Background()
	tenantID := billingHandlerTestTenant(t, "hcur")
	userID := tenantID + "-u"
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,role,status) VALUES ($1,$2,$1,'developer','active')`, userID, tenantID); err != nil {
		t.Fatal(err)
	}
	departmentID := tenantID + "-department"
	if _, err := db.Exec(ctx, `INSERT INTO teams(id,tenant_id,name,path) VALUES ($1,$2,'Existing ledger department',$1)`, departmentID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE users SET department_id=$1 WHERE id=$2`, departmentID, userID); err != nil {
		t.Fatal(err)
	}
	walletCurrencies := map[string]string{}
	usdWalletID := ""
	for _, currency := range []string{"CNY", "USD"} {
		wallet, err := store.EnsureWallet(ctx, tenantID, userID, currency)
		if err != nil {
			t.Fatal(err)
		}
		walletCurrencies[wallet.ID] = currency
		if currency == "USD" {
			usdWalletID = wallet.ID
		}
		if _, err := db.Exec(ctx, `
			INSERT INTO billing_ledger_entries (id,tenant_id,wallet_id,event_type,
				balance_delta_micros,reserved_delta_micros,balance_after_micros,reserved_after_micros,
				idempotency_key,actor_type,metadata_json)
			VALUES ($1,$2,$3,'credit',5000,0,5000,0,$1,'system','{"currency":"EUR"}'::jsonb)
		`, "lh_"+wallet.ID, tenantID, wallet.ID); err != nil {
			t.Fatal(err)
		}
	}
	for _, walletFilter := range []string{"", "&wallet_id=" + usdWalletID} {
		for _, paginated := range []bool{false, true} {
			seen := map[string]bool{}
			cursor := ""
			for {
				query := "tenant_id=" + tenantID + walletFilter
				if paginated {
					query += "&limit=1&cursor=" + cursor
				}
				rec, body := billingHandlerGet(t, ListBillingLedger(deps), deps, userID, tenantID, "platform_admin", query)
				if rec.Code != http.StatusOK {
					t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
				}
				rows, ok := body["data"].([]any)
				if !ok || len(rows) == 0 {
					t.Fatalf("missing ledger rows: %s", rec.Body.String())
				}
				for _, raw := range rows {
					row, ok := raw.(map[string]any)
					if !ok {
						t.Fatalf("invalid row: %v", raw)
					}
					if row["department_id"] != departmentID || row["department_name"] != "Existing ledger department" || row["username"] != userID {
						t.Fatalf("ledger identity metadata mismatch: %v", row)
					}
					walletID, _ := row["wallet_id"].(string)
					entryID, _ := row["id"].(string)
					if row["currency"] != walletCurrencies[walletID] || row["currency"] == "" || seen[entryID] {
						t.Fatalf("non-authoritative currency or duplicate: %v", row)
					}
					if walletFilter != "" && row["currency"] != "USD" {
						t.Fatalf("USD wallet filter returned: %v", row)
					}
					seen[entryID] = true
				}
				meta, hasMeta := body["meta"].(map[string]any)
				if !paginated {
					if _, present := body["meta"]; present {
						t.Fatalf("legacy response has meta: %s", rec.Body.String())
					}
					break
				}
				if !hasMeta {
					t.Fatalf("page has no meta: %s", rec.Body.String())
				}
				cursor, _ = meta["next_cursor"].(string)
				if meta["has_more"] != (cursor != "") {
					t.Fatalf("incorrect meta: %v", meta)
				}
				if cursor == "" {
					break
				}
				if len(seen) > 2 {
					t.Fatal("pagination did not terminate")
				}
			}
			wantRows := 2
			if walletFilter != "" {
				wantRows = 1
			}
			if len(seen) != wantRows {
				t.Fatalf("paginated=%v filter=%q rows=%d want=%d", paginated, walletFilter, len(seen), wantRows)
			}
		}
	}
}

func TestBillingAdminPricesHandlerEffectiveModelFilter(t *testing.T) {
	db := openBillingHandlerTestDB(t)
	store := billing.NewStore(db)
	deps := &Dependencies{BillingStore: store}
	ctx := context.Background()
	tenantID := billingHandlerTestTenant(t, "hprc1")
	adminID := "user-hprc-admin"
	if _, err := db.Exec(ctx, `
		INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')
		ON CONFLICT (id) DO NOTHING
	`, tenantID); err != nil {
		t.Fatal(err)
	}
	for _, model := range []string{"hprc-model-a", "hprc-model-b"} {
		if _, err := store.CreateModelPrice(ctx, billing.NewModelPrice{
			TenantID: tenantID, ModelName: model, CustomerGroup: billing.DefaultCustomerGroup,
			PricingMode: billing.PricingModeDirect, Currency: "CNY",
			DirectPrice: billing.DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 1_000_000},
			EffectiveAt: time.Now().Add(-time.Minute), Status: billing.PriceStatusActive, CreatedBy: "test",
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Legacy scope without model filter: full list, untouched.
	rec, body := billingHandlerGet(t, ListBillingPrices(deps), deps, adminID, tenantID, "platform_admin", "tenant_id="+tenantID)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy prices status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rows, _ := body["data"].([]any); len(rows) < 2 {
		t.Fatalf("legacy price rows=%d want >= 2", len(rows))
	}

	// Effective scope: only currently active prices, one per model.
	rec, body = billingHandlerGet(t, ListBillingPrices(deps), deps, adminID, tenantID, "platform_admin", "tenant_id="+tenantID+"&scope=effective")
	if rec.Code != http.StatusOK {
		t.Fatalf("effective prices status=%d body=%s", rec.Code, rec.Body.String())
	}
	rows, _ := body["data"].([]any)
	if len(rows) != 2 {
		t.Fatalf("effective price rows=%d want 2", len(rows))
	}

	// Effective scope with model_name query: exactly the requested model.
	rec, body = billingHandlerGet(t, ListBillingPrices(deps), deps, adminID, tenantID, "platform_admin",
		"tenant_id="+tenantID+"&scope=effective&model=hprc-model-a")
	if rec.Code != http.StatusOK {
		t.Fatalf("effective model prices status=%d body=%s", rec.Code, rec.Body.String())
	}
	rows, _ = body["data"].([]any)
	if len(rows) != 1 {
		t.Fatalf("effective model filter rows=%d want 1", len(rows))
	}
	row, _ := rows[0].(map[string]any)
	if row["model_name"] != "hprc-model-a" {
		t.Fatalf("filtered price model=%v want hprc-model-a", row["model_name"])
	}

	// model_name is the approved authoritative parameter and works on its own.
	rec, body = billingHandlerGet(t, ListBillingPrices(deps), deps, adminID, tenantID, "platform_admin",
		"tenant_id="+tenantID+"&scope=effective&model_name=hprc-model-b")
	if rec.Code != http.StatusOK {
		t.Fatalf("model_name prices status=%d body=%s", rec.Code, rec.Body.String())
	}
	rows, _ = body["data"].([]any)
	if len(rows) != 1 {
		t.Fatalf("model_name filter rows=%d want 1", len(rows))
	}
	row, _ = rows[0].(map[string]any)
	if row["model_name"] != "hprc-model-b" {
		t.Fatalf("model_name filtered price model=%v want hprc-model-b", row["model_name"])
	}

	// Both parameters with the same value: accepted.
	rec, body = billingHandlerGet(t, ListBillingPrices(deps), deps, adminID, tenantID, "platform_admin",
		"tenant_id="+tenantID+"&scope=effective&model_name=hprc-model-a&model=hprc-model-a")
	if rec.Code != http.StatusOK {
		t.Fatalf("matching params status=%d body=%s", rec.Code, rec.Body.String())
	}
	// Both parameters with conflicting values: explicit client error, no
	// silent priority pick.
	rec, body = billingHandlerGet(t, ListBillingPrices(deps), deps, adminID, tenantID, "platform_admin",
		"tenant_id="+tenantID+"&scope=effective&model_name=hprc-model-a&model=hprc-model-b")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("conflicting params status=%d body=%s want 400", rec.Code, rec.Body.String())
	}
	errBody, _ := body["error"].(map[string]any)
	if code, _ := errBody["code"].(string); code != "invalid_request" {
		t.Fatalf("conflicting params code=%q want invalid_request", code)
	}
}

// The persisted presence bit must reflect what the CALLER actually sent, and the
// HTTP measurement handler carries only AdmittedAt — it has no extra flag to
// set. So a real HTTP request with a non-zero admitted_at must persist
// admitted_at_supplied = TRUE, and one without must persist FALSE.
//
// This is the dynamic end-to-end check of that: it drives the real HTTP handler
// against a real store and a real database, then reads the boolean back out of
// PostgreSQL. An exported bool that the handler forgot to populate would show up
// here as false on a request that plainly carried a timestamp.
func TestGatewayMeasurementPersistsAdmittedAtPresenceFromHTTP(t *testing.T) {
	db := openBillingHandlerTestDB(t)
	store := billing.NewStore(db)
	deps := &Dependencies{BillingStore: store}
	ctx := context.Background()

	cases := []struct {
		name        string
		admittedAt  time.Time
		wantPersist bool
	}{
		// A real admission timestamp: the caller supplied it.
		{"non-zero admitted_at", time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond), true},
		// No timestamp at all: the store defaults one, which is not caller intent.
		{"omitted admitted_at", time.Time{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenantID := billingHandlerTestTenant(t, "hpres")
			adminID := "user-hpres-admin"
			if _, err := db.Exec(ctx,
				`INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active') ON CONFLICT DO NOTHING`,
				tenantID); err != nil {
				t.Fatal(err)
			}
			requestID := "hpres-" + tenantID

			body := map[string]any{
				"tenant_id": tenantID, "user_id": adminID, "request_id": requestID,
				"model_name": "presence-model", "request_status": "success",
				"usage":     map[string]any{"prompt_tokens": 3, "output_tokens": 2},
				"raw_usage": map[string]any{"usage_source": "upstream"},
			}
			if !tc.admittedAt.IsZero() {
				body["admitted_at"] = tc.admittedAt.Format(time.RFC3339Nano)
			}
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/internal/v1/billing/measurements", strings.NewReader(string(encoded)))
			rec := httptest.NewRecorder()
			RecordGatewayMeasurement(deps)(rec, req)
			if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
				t.Fatalf("measurement status=%d body=%s", rec.Code, rec.Body.String())
			}

			// Read the boolean straight out of PostgreSQL.
			var persisted *bool
			if err := db.QueryRow(ctx,
				`SELECT admitted_at_supplied FROM billing_usage_facts WHERE tenant_id=$1 AND request_id=$2`,
				tenantID, requestID).Scan(&persisted); err != nil {
				t.Fatalf("read presence bit: %v", err)
			}
			if persisted == nil {
				t.Fatal("presence bit is NULL; a row written now must record it")
			}
			if *persisted != tc.wantPersist {
				t.Fatalf("persisted admitted_at_supplied=%v want %v (non-zero=%v)",
					*persisted, tc.wantPersist, !tc.admittedAt.IsZero())
			}

			// A replay of the same HTTP request must stay idempotent, and a
			// replay that changes only the timestamp presence must conflict.
			replay := httptest.NewRequest(http.MethodPost, "/internal/v1/billing/measurements", strings.NewReader(string(encoded)))
			rec2 := httptest.NewRecorder()
			RecordGatewayMeasurement(deps)(rec2, replay)
			if rec2.Code != http.StatusOK && rec2.Code != http.StatusAccepted {
				t.Fatalf("replay status=%d body=%s", rec2.Code, rec2.Body.String())
			}
			if tc.admittedAt.IsZero() {
				// Supplying a timestamp the first write lacked is a different
				// input, and the persisted bit is what makes it decidable.
				changed := map[string]any{}
				for k, v := range body {
					changed[k] = v
				}
				changed["admitted_at"] = time.Now().UTC().Format(time.RFC3339Nano)
				encodedChanged, err := json.Marshal(changed)
				if err != nil {
					t.Fatal(err)
				}
				conflictReq := httptest.NewRequest(http.MethodPost, "/internal/v1/billing/measurements", strings.NewReader(string(encodedChanged)))
				rec3 := httptest.NewRecorder()
				RecordGatewayMeasurement(deps)(rec3, conflictReq)
				if rec3.Code < 400 {
					t.Fatalf("presence change must conflict, got status=%d body=%s", rec3.Code, rec3.Body.String())
				}
			}
		})
	}
}

func TestBillingAnalyticsSummaryMixedHistoryUsesTenantCurrency(t *testing.T) {
	db := openBillingHandlerTestDB(t)
	store := billing.NewStore(db)
	deps := &Dependencies{BillingStore: store}
	ctx := context.Background()
	tenantID := billingHandlerTestTenant(t, "hmix1")
	// tenant_admin resolves as tenant-wide reader, so FullTenant=true and the
	// summary sees the whole tenant selection.
	adminID := "user-hmix-admin"
	if _, err := db.Exec(ctx, `
		INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')
		ON CONFLICT (id) DO NOTHING
	`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateModelPrice(ctx, billing.NewModelPrice{
		TenantID: tenantID, ModelName: "hmix-cny-model", CustomerGroup: billing.DefaultCustomerGroup,
		PricingMode: billing.PricingModeDirect, Currency: "CNY",
		DirectPrice: billing.DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 1_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: billing.PriceStatusActive, CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordMeteringUsage(ctx, billing.MeteringInput{
		TenantID: tenantID, UserID: adminID, RequestID: "hmix-cny-1", ModelName: "hmix-cny-model",
		RequestStatus: "success", Usage: billing.Usage{PromptTokens: 1_000_000},
		AdmittedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_usage_facts (
			id,tenant_id,request_id,billing_mode,user_name,model_name,
			prompt_tokens,output_tokens,currency,status,occurred_at
		) VALUES ($1,$2,'hmix-usd-1','metering','legacy','hmix-usd-model',0,0,'USD','settled',NOW())
	`, "usage_fact_hmix_"+tenantID, tenantID); err != nil {
		t.Fatal(err)
	}
	from := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	to := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	rec, body := billingHandlerGet(t, GetBillingAnalyticsSummary(deps), deps, adminID, tenantID, "tenant_admin",
		fmt.Sprintf("tenant_id=%s&from=%s&to=%s", tenantID, from, to))
	if rec.Code != http.StatusOK || body["currency"] != "CNY" || body["billable_micros"] != float64(1_000_000) {
		t.Fatalf("默认币种摘要：%d %s", rec.Code, rec.Body.String())
	}
	others, _ := body["other_currencies"].([]any)
	if len(others) != 1 || others[0] != "USD" {
		t.Fatalf("历史提示：%v", body)
	}
	rec, body = billingHandlerGet(t, GetBillingAnalyticsSummary(deps), deps, adminID, tenantID, "tenant_admin",
		fmt.Sprintf("currency=USD&from=%s&to=%s", from, to))
	if rec.Code != http.StatusOK || body["currency"] != "USD" || body["billable_micros"] != float64(0) {
		t.Fatalf("显式币种：%d %s", rec.Code, rec.Body.String())
	}
	for _, listHandler := range []http.HandlerFunc{GetBillingAnalyticsBreakdown(deps), GetBillingAnalyticsSeries(deps), GetBillingAnalyticsTimeProfile(deps), GetBillingAnalyticsDepartmentProviderMatrix(deps)} {
		rec, body = billingHandlerGet(t, listHandler, deps, adminID, tenantID, "tenant_admin", fmt.Sprintf("currency=USD&dimension=model&from=%s&to=%s", from, to))
		if rec.Code != http.StatusOK || body["currency"] != "USD" {
			t.Fatalf("币种明细元数据：%d %s", rec.Code, rec.Body.String())
		}
		if _, ok := body["data"].([]any); !ok {
			t.Fatalf("明细应为数组：%v", body)
		}
		others, _ := body["other_currencies"].([]any)
		if len(others) != 1 || others[0] != "CNY" {
			t.Fatalf("遗漏历史币种：%v", body)
		}
	}

}
