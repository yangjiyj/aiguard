package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/jackc/pgx/v5/pgxpool"
)

func billingEndToEndFixture(t *testing.T) (*pgxpool.Pool, *billing.Store, string, string, string) {
	t.Helper()
	db := openBillingHandlerTestDB(t)
	ctx := context.Background()
	tenant := billingHandlerTestTenant(t, "be2e")
	user, project := tenant+"-u", tenant+"-p"
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, []any{tenant}},
		{`INSERT INTO users(id,tenant_id,username,email,password_hash,role,status) VALUES ($1,$2,$1,$3,'x','developer','active')`, []any{user, tenant, user + "@test.invalid"}},
		{`INSERT INTO projects(id,tenant_id,name,status) VALUES ($1,$2,$1,'active')`, []any{project, tenant}},
	} {
		if _, err := db.Exec(ctx, seed.sql, seed.args...); err != nil {
			t.Fatal(err)
		}
	}
	store := billing.NewStore(db)
	wallet, err := store.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Credit(ctx, tenant, wallet.ID, tenant+"-credit", 1000000, "tester"); err != nil {
		t.Fatal(err)
	}
	return db, store, tenant, user, project
}

func TestGatewayMeasurementHTTPPresenceAndJSONBReplay(t *testing.T) {
	db, store, tenant, user, _ := billingEndToEndFixture(t)
	server := httptest.NewServer(RecordGatewayMeasurement(&Dependencies{BillingStore: store}))
	defer server.Close()
	send := func(payload map[string]any, want int) map[string]any {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.Post(server.URL, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("HTTP=%d want=%d body=%v input=%s", resp.StatusCode, want, out, raw)
		}
		return out
	}
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond).Add(123 * time.Nanosecond)
	base := func(id string) map[string]any {
		return map[string]any{"tenant_id": tenant, "user_id": user, "request_id": id, "model_name": "unpriced-e2e", "request_status": "success", "usage": billing.Usage{PromptTokens: 10, CachedInputTokens: 2, CacheWriteInputTokens: 1, OutputTokens: 4, ReasoningTokens: 1}, "raw_usage": json.RawMessage(`{"n":1e2,"ratio":1.0,"large":9007199254740993}`)}
	}
	supplied := base("http-supplied")
	supplied["admitted_at"] = at
	first := send(supplied, 200)
	send(supplied, 200)
	supplied["raw_usage"] = json.RawMessage(`{"large":9007199254740993,"ratio":1,"n":100}`)
	if got := send(supplied, 200); got["usage_fact_id"] != first["usage_fact_id"] {
		t.Fatal("numeric replay changed fact")
	}
	supplied["raw_usage"] = json.RawMessage(`{"n":100,"ratio":1,"large":9007199254740992}`)
	send(supplied, 409)
	supplied["raw_usage"] = base("x")["raw_usage"]
	delete(supplied, "admitted_at")
	send(supplied, 409)
	omitted := base("http-omitted")
	bareFirst := send(omitted, 200)
	send(omitted, 200)
	omitted["admitted_at"] = at
	send(omitted, 409)
	for _, id := range []string{"http-supplied", "http-omitted"} {
		var bit *bool
		if err := db.QueryRow(context.Background(), `SELECT admitted_at_supplied FROM billing_usage_facts WHERE tenant_id=$1 AND request_id=$2`, tenant, id).Scan(&bit); err != nil {
			t.Fatal(err)
		}
		if bit == nil || *bit != (id == "http-supplied") {
			t.Fatalf("presence %s=%v", id, bit)
		}
	}
	bare := base("http-sql-null")
	delete(bare, "raw_usage")
	send(bare, 200)
	send(bare, 200)
	bare["raw_usage"] = json.RawMessage(`null`)
	send(bare, 409)
	blank := base("http-blank-status")
	blank["request_status"] = ""
	send(blank, 200)
	send(blank, 200)
	blank["request_status"] = "provider_error"
	send(blank, 409)
	omitted = base("http-omitted")
	if got := send(omitted, 200); got["usage_fact_id"] != bareFirst["usage_fact_id"] {
		t.Fatal("omitted replay changed fact")
	}
	full := base("http-full")
	full["admitted_at"] = at
	send(full, 200)
	for _, change := range []func(map[string]any){
		func(p map[string]any) { p["request_status"] = "incomplete" },
		func(p map[string]any) { p["admitted_at"] = at.Add(time.Microsecond) },
		func(p map[string]any) {
			p["usage"] = billing.Usage{PromptTokens: 10, CachedInputTokens: 3, CacheWriteInputTokens: 1, OutputTokens: 4, ReasoningTokens: 1}
		},
		func(p map[string]any) {
			p["usage"] = billing.Usage{PromptTokens: 10, CachedInputTokens: 2, CacheWriteInputTokens: 2, OutputTokens: 4, ReasoningTokens: 1}
		},
		func(p map[string]any) {
			p["usage"] = billing.Usage{PromptTokens: 10, CachedInputTokens: 2, CacheWriteInputTokens: 1, OutputTokens: 4, ReasoningTokens: 2}
		},
	} {
		p := base("http-full")
		p["admitted_at"] = at
		change(p)
		send(p, 409)
	}
}

func TestGatewayDurableEvidenceFeedsRealCompensationWorker(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-module real-PostgreSQL integration")
	}
	db, store, tenant, user, project := billingEndToEndFixture(t)
	ctx := context.Background()
	defer func() {
		_, _ = db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW() WHERE tenant_id=$1`, tenant)
	}()
	for _, model := range []string{"paid-e2e", "free-e2e"} {
		rate := int64(1000000)
		if model == "free-e2e" {
			rate = 0
		}
		if _, err := store.CreateModelPrice(ctx, billing.NewModelPrice{TenantID: tenant, ModelName: model, CustomerGroup: "default", PricingMode: billing.PricingModeDirect, Currency: "CNY", DirectPrice: billing.DirectPrice{InputPerMillionMicros: billing.Micros(rate), OutputPerMillionMicros: billing.Micros(rate)}, EffectiveAt: time.Now().UTC().Add(-time.Hour), Status: billing.PriceStatusActive, CreatedBy: "tester"}); err != nil {
			t.Fatal(err)
		}
	}
	deps := &Dependencies{BillingStore: store}
	var settlePosts, releasePosts atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/v1/billing/reservations", ReserveGatewayBilling(deps))
	mux.HandleFunc("/internal/v1/billing/settlements", func(w http.ResponseWriter, r *http.Request) {
		settlePosts.Add(1)
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"error":"injected_accounting_outage"}`))
	})
	mux.HandleFunc("/internal/v1/billing/releases", func(w http.ResponseWriter, r *http.Request) { releasePosts.Add(1); ReleaseGatewayBilling(deps)(w, r) })
	server := httptest.NewServer(mux)
	defer server.Close()
	gatewayDir, err := filepath.Abs("../../../gateway-core")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "gateway-billing-bridge.test")
	goBin := filepath.Join(os.Getenv("GOROOT"), "bin", "go")
	if os.Getenv("GOROOT") == "" {
		goBin = "/usr/local/go/bin/go"
	}
	build := exec.Command(goBin, "test", "-buildvcs=false", "-c", "-o", binary, "./internal/handler")
	build.Dir = gatewayDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile gateway bridge: %v\n%s", err, out)
	}
	cases := []struct {
		id, model, kind, body, status, source, outcome string
		settled                                        bool
		amount                                         int64
	}{
		{"verified", "paid-e2e", "", `{"usage":{"prompt_tokens":2,"completion_tokens":3}}`, "success", "upstream", "failed", true, 5},
		{"adjusted", "paid-e2e", "", `{"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":9}}`, "success", "upstream_total_adjusted", "failed", true, 9},
		{"estimate", "paid-e2e", "", `{"id":"no-usage"}`, "success", "estimated_reservation", "failed", true, 16},
		{"cancel", "paid-e2e", "", `{"id":"no-usage"}`, "client_canceled", "estimated_incomplete", "failed", true, 16},
		{"invalid", "paid-e2e", "", `{"usage":{"prompt_tokens":-1}}`, "success", "estimated_reservation_invalid_usage", "failed", true, 16},
		{"free", "free-e2e", "", `{"id":"no-usage"}`, "success", "estimated_reservation", "failed", true, 0},
		{"unknown", "paid-e2e", "lost_tracking", `{"id":"no-usage"}`, "success", "unknown_no_admission_evidence", "", false, 0},
		{"missing", "paid-e2e", "no_log", "", "", "", "", false, 0},
		{"provider_error", "paid-e2e", "", `{"usage":{"prompt_tokens":2,"completion_tokens":3}}`, "provider_error", "upstream", "released", false, 0},
		{"release", "paid-e2e", "", `{"usage":{"prompt_tokens":2,"completion_tokens":3}}`, "provider_unavailable", "upstream", "released", false, 0},
	}
	var wantAmount int64
	for _, tc := range cases {
		request := tenant + "-" + tc.id
		cmd := exec.Command(binary, "-test.run=^TestBillingCompensationGatewayBridge$", "-test.v")
		cmd.Env = append(os.Environ(), "BILLING_BRIDGE_ENDPOINT="+server.URL, "BILLING_BRIDGE_TENANT="+tenant, "BILLING_BRIDGE_USER="+user, "BILLING_BRIDGE_PROJECT="+project, "BILLING_BRIDGE_REQUEST="+request, "BILLING_BRIDGE_MODEL="+tc.model, "BILLING_BRIDGE_KIND="+tc.kind, "BILLING_BRIDGE_BODY="+tc.body, "BILLING_BRIDGE_STATUS="+tc.status, "BILLING_BRIDGE_SOURCE="+tc.source, "BILLING_BRIDGE_OUTCOME="+tc.outcome)
		out, err := cmd.CombinedOutput()
		t.Logf("gateway %s:\n%s", tc.id, out)
		if err != nil {
			t.Fatal(err)
		}
		wantAmount += tc.amount
	}
	if settlePosts.Load() != 18 || releasePosts.Load() != 2 {
		t.Fatalf("realtime paths settlements=%d releases=%d", settlePosts.Load(), releasePosts.Load())
	}
	if _, err = db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '11 years' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	// This is the exact Store method invoked by cmd/server/main.go's compensation worker.
	result, err := store.ReconcileStaleReservations(ctx, 10*365*24*time.Hour, 500)
	if err != nil {
		t.Fatal(err)
	}
	if result.Settled != 6 || result.Pending != 2 || result.Released != 0 {
		t.Fatalf("worker result=%+v", result)
	}
	for _, tc := range cases {
		r, err := store.GetReservation(ctx, tenant, tenant+"-"+tc.id)
		if err != nil {
			t.Fatal(err)
		}
		want := "reserved"
		if tc.settled {
			want = "settled"
		}
		if tc.id == "release" || tc.id == "provider_error" {
			want = "released"
		}
		if r.Status != want {
			t.Fatalf("%s reservation=%s want=%s", tc.id, r.Status, want)
		}
	}
	var balance, reserved int64
	if err = db.QueryRow(ctx, `SELECT balance_micros,reserved_micros FROM billing_wallets WHERE tenant_id=$1 AND user_id=$2`, tenant, user).Scan(&balance, &reserved); err != nil {
		t.Fatal(err)
	}
	if balance != 1000000-wantAmount || reserved != 32 {
		t.Fatalf("wallet balance=%d reserved=%d want balance=%d reserved=32", balance, reserved, 1000000-wantAmount)
	}
	again, err := store.ReconcileStaleReservations(ctx, 10*365*24*time.Hour, 500)
	if err != nil || again.Settled != 0 || again.Pending != 2 {
		t.Fatalf("repeat result=%+v err=%v", again, err)
	}
	var secondBalance int64
	if err = db.QueryRow(ctx, `SELECT balance_micros FROM billing_wallets WHERE tenant_id=$1 AND user_id=$2`, tenant, user).Scan(&secondBalance); err != nil || secondBalance != balance {
		t.Fatalf("repeat double debit=%d before=%d err=%v", secondBalance, balance, err)
	}
	var count int
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_charge_records WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 6 {
		t.Fatalf("charges=%d err=%v", count, err)
	}
	t.Logf("real HTTP admission, gateway SQL writer, compensation twice: charges=%d debit=%d reserved=%d", count, wantAmount, reserved)
}
