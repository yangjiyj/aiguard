package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
	"time"
)

func TestMeteringReservationBindsPriceOwnerTariffAndOriginalDepartment(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	at := time.Now().UTC().Truncate(time.Microsecond)
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	deptA := tenant + "-a"
	deptB := tenant + "-b"
	if _, e := db.Exec(ctx, `INSERT INTO teams(id,tenant_id,name,path) VALUES($1,$3,'A',$1),($2,$3,'B',$2)`, deptA, deptB, tenant); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(ctx, `UPDATE users SET department_id=$2 WHERE id=$1`, user, deptA); e != nil {
		t.Fatal(e)
	}
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "bound-model", Currency: "CNY", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000}, EffectiveAt: at.Add(-time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	tariff := DefaultTariffQuote(at, "UTC")
	tariff.MultiplierPPM = 2 * ratioScale
	attr, e := s.ResolveBillingAttribution(ctx, tenant, user)
	if e != nil {
		t.Fatal(e)
	}
	r, _, e := s.ReservePricedWithUsageForGroupAndTariff(ctx, tenant, w.ID, "bound", 20, 5, p, DefaultCustomerGroup, ratioScale, attr, tariff)
	if e != nil {
		t.Fatal(e)
	}
	newer, e := s.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: p.ModelName, Currency: "CNY", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 10_000_000, OutputPerMillionMicros: 20_000_000}, EffectiveAt: at.Add(-time.Minute)})
	if e != nil {
		t.Fatal(e)
	}
	ratio := r.CustomerGroupRatioPPM
	frozenTariff := reservationTariff(r)
	good := MeteringInput{TenantID: tenant, UserID: user, RequestID: "bound", ModelName: p.ModelName, RequestStatus: "success", Usage: Usage{PromptTokens: 2, OutputTokens: 3}, AdmittedAt: r.AdmittedAt, QuotePriceID: p.ID, QuoteGroupRatioPPM: &ratio, QuoteTariff: &frozenTariff}
	for _, kind := range []string{"owner", "model", "price", "group", "tariff", "time", "unpriced"} {
		t.Run(kind, func(t *testing.T) {
			bad := good
			switch kind {
			case "owner":
				bad.UserID = user + "-other"
			case "model":
				bad.ModelName = "another"
			case "price":
				bad.QuotePriceID = newer.ID
			case "group":
				v := int64(2 * ratioScale)
				bad.QuoteGroupRatioPPM = &v
			case "tariff":
				v := frozenTariff
				v.MultiplierPPM = ratioScale
				bad.QuoteTariff = &v
			case "time":
				bad.AdmittedAt = bad.AdmittedAt.Add(time.Second)
			case "unpriced":
				bad.Unpriced = true
			}
			if _, e := s.RecordMeteringUsage(ctx, bad); !errors.Is(e, ErrIdempotencyConflict) {
				t.Fatalf("false snapshot accepted: %v", e)
			}
			current, e := s.GetWallet(ctx, tenant, w.ID)
			if e != nil || current.BalanceMicros != 1000 || current.ReservedMicros != 20 {
				t.Fatalf("rejected snapshot moved funds: %+v %v", current, e)
			}
			var count int
			if e = db.QueryRow(ctx, `SELECT count(*) FROM billing_usage_facts WHERE tenant_id=$1 AND request_id='bound'`, tenant).Scan(&count); e != nil || count != 0 {
				t.Fatalf("false snapshot wrote fact: %d %v", count, e)
			}
		})
	}
	if _, e = db.Exec(ctx, `UPDATE users SET department_id=$2 WHERE id=$1`, user, deptB); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RecordMeteringUsage(ctx, good); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RecordMeteringUsage(ctx, good); e != nil {
		t.Fatalf("legitimate replay=%v", e)
	}
	var dept string
	var charged int64
	if e = db.QueryRow(ctx, `SELECT department_id,billable_amount_micros FROM billing_usage_facts WHERE tenant_id=$1 AND request_id='bound'`, tenant).Scan(&dept, &charged); e != nil || dept != deptA || charged != 16 {
		t.Fatalf("stream was reassigned or repriced: dept=%s charge=%d %v", dept, charged, e)
	}
	current, e := s.GetWallet(ctx, tenant, w.ID)
	if e != nil || current.BalanceMicros != 984 || current.ReservedMicros != 0 {
		t.Fatalf("bound settlement=%+v %v", current, e)
	}
}

func TestMeteringReconciliationUsesMeteringModeAndFrozenGiftQuote(t *testing.T) {
	for _, estimated := range []bool{false, true} {
		t.Run(fmt.Sprint(estimated), func(t *testing.T) {
			s, db, tenant, user := setupBillingStoreTest(t)
			ctx := context.Background()
			amount := int64(1000)
			at := time.Now().UTC().Truncate(time.Microsecond)
			if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
				t.Fatal(e)
			}
			w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
			if e != nil {
				t.Fatal(e)
			}
			p, e := s.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "meter-recover", Currency: "CNY", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000}, EffectiveAt: at.Add(-time.Hour)})
			if e != nil {
				t.Fatal(e)
			}
			request := tenant + "-recover"
			tariff := DefaultTariffQuote(at, "UTC")
			tariff.MultiplierPPM = 2 * ratioScale
			attr, e := s.ResolveBillingAttribution(ctx, tenant, user)
			if e != nil {
				t.Fatal(e)
			}
			r, _, e := s.ReservePricedWithUsageForGroupAndTariff(ctx, tenant, w.ID, request, 20, 5, p, DefaultCustomerGroup, ratioScale, attr, tariff)
			if e != nil {
				t.Fatal(e)
			}
			project := tenant + "-project"
			if _, e = db.Exec(ctx, `INSERT INTO projects(id,tenant_id,name,owner_user_id,status) VALUES($1,$2,$1,$3,'active')`, project, tenant, user); e != nil {
				t.Fatal(e)
			}
			usage := Usage{PromptTokens: 2, OutputTokens: 3}
			source := "upstream"
			status := "success"
			if estimated {
				source = "estimated_incomplete"
				status = "stream_aborted"
			}
			audit, _ := json.Marshal(map[string]any{"response_metadata": map[string]any{"usage_source": source, "billing_usage": usage}})
			if _, e = db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,created_at,output_audit_result) VALUES($1,$7,$2,$3,$4,'chat_completion',$5,2,3,NOW()-INTERVAL '1 hour',$6)`, tenant+"-log", tenant, project, user, status, audit, request); e != nil {
				t.Fatal(e)
			}
			if _, e = db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '1 hour' WHERE tenant_id=$1 AND request_id=$2`, tenant, request); e != nil {
				t.Fatal(e)
			}
			result, e := s.ReconcileStaleMeteringReservations(ctx, time.Minute, 500)
			if e != nil || result.Settled < 1 {
				t.Fatalf("meter recovery=%+v %v", result, e)
			}
			var mode string
			var factEstimated bool
			var charged int64
			var raw []byte
			if e = db.QueryRow(ctx, `SELECT billing_mode,billable_amount_micros,estimated,raw_usage_json FROM billing_usage_facts WHERE tenant_id=$1 AND request_id=$2`, tenant, request).Scan(&mode, &charged, &factEstimated, &raw); e != nil || mode != "metering" || charged != 16 || factEstimated != estimated {
				t.Fatalf("recovery mode=%s charged=%d estimated=%v %v", mode, charged, factEstimated, e)
			}
			ratio := r.CustomerGroupRatioPPM
			frozen := reservationTariff(r)
			requestStatus := "success"
			if estimated {
				requestStatus = "incomplete"
			}
			// The stored raw quote is re-inserted canonically on an identical replay.
			var evidence map[string]json.RawMessage
			if e = json.Unmarshal(raw, &evidence); e != nil {
				t.Fatal(e)
			}
			delete(evidence, "billing_quote")
			replayRaw, _ := json.Marshal(evidence)
			if _, e = s.RecordMeteringUsage(ctx, MeteringInput{TenantID: tenant, UserID: user, RequestID: request, ModelName: p.ModelName, RequestStatus: requestStatus, Usage: usage, AdmittedAt: r.AdmittedAt, QuotePriceID: p.ID, QuoteGroupRatioPPM: &ratio, QuoteTariff: &frozen, Estimated: estimated, RawUsage: replayRaw}); e != nil {
				t.Fatalf("meter recovery replay conflicts: %v", e)
			}
			current, e := s.GetWallet(ctx, tenant, w.ID)
			if e != nil || current.BalanceMicros != 984 || current.ReservedMicros != 0 {
				t.Fatalf("recovery wallet=%+v %v", current, e)
			}
			var gift int64
			if e = db.QueryRow(ctx, `SELECT remaining_micros FROM billing_wallet_monthly_grants WHERE tenant_id=$1`, tenant).Scan(&gift); e != nil || gift != 984 {
				t.Fatalf("recovery did not debit gift exactly once: %d %v", gift, e)
			}
		})
	}
}

func TestMeteringFrozenWalletCompletesWithSingleConnectionPool(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	at := time.Now().UTC()
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "single-pool", Currency: "CNY", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000}})
	if e != nil {
		t.Fatal(e)
	}
	r, _, e := s.ReservePricedWithUsage(ctx, tenant, w.ID, "single-pool", 10, 2, p)
	if e != nil {
		t.Fatal(e)
	}
	config, e := pgxpool.ParseConfig(os.Getenv("BILLING_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	config.MaxConns = 1
	single, e := pgxpool.NewWithConfig(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer single.Close()
	limited := NewStore(single)
	timeout, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, e = limited.RecordMeteringUsage(timeout, MeteringInput{TenantID: tenant, UserID: user, RequestID: "single-pool", ModelName: p.ModelName, RequestStatus: "success", Usage: Usage{PromptTokens: 2}, AdmittedAt: r.AdmittedAt, QuotePriceID: p.ID}); e != nil {
		t.Fatalf("one-connection finalization blocked itself: %v", e)
	}
	current, e := s.GetWallet(ctx, tenant, w.ID)
	if e != nil || current.BalanceMicros != 998 || current.ReservedMicros != 0 {
		t.Fatalf("single connection financial state=%+v %v", current, e)
	}
	_ = db
}
