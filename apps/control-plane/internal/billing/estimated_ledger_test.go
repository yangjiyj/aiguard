package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestEstimatedSettlementsMarkWalletLedgerAndFactsIdempotently(t *testing.T) {
	for _, mode := range []string{"metering", "prepaid"} {
		for _, estimated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-estimated-%t", mode, estimated), func(t *testing.T) {
				store, db, tenant, user := setupBillingStoreTest(t)
				ctx := context.Background()
				wallet, err := store.EnsureWallet(ctx, tenant, user, "CNY")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = store.Credit(ctx, tenant, wallet.ID, "estimated-credit", 10_000, "test"); err != nil {
					t.Fatal(err)
				}
				price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "estimated-model", PricingMode: PricingModeDirect, Currency: "CNY", DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000}, EffectiveAt: time.Now().Add(-time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				request := tenant + "-estimated"
				reservation, _, err := store.ReservePricedWithUsageForGroup(ctx, tenant, wallet.ID, request, 10, 5, price, DefaultCustomerGroup, ratioScale)
				if err != nil {
					t.Fatal(err)
				}
				source := "provider_verified"
				status := "success"
				if estimated {
					source = "estimated_incomplete"
					status = "incomplete"
				}
				raw, _ := json.Marshal(map[string]any{"usage_source": source, "usage": map[string]int64{"prompt_tokens": 2, "completion_tokens": 3}})
				usage := Usage{PromptTokens: 2, OutputTokens: 3}
				settle := func() error {
					if mode == "prepaid" {
						_, _, err := store.SettleCharge(ctx, tenant, request, price, usage, raw, nil)
						return err
					}
					_, err := store.RecordMeteringUsage(ctx, MeteringInput{TenantID: tenant, UserID: user, RequestID: request, ModelName: price.ModelName, RequestStatus: status, Usage: usage, AdmittedAt: reservation.AdmittedAt, QuotePriceID: price.ID, Estimated: estimated, RawUsage: raw})
					return err
				}
				if err = settle(); err != nil {
					t.Fatal(err)
				}
				if err = settle(); err != nil {
					t.Fatalf("replay=%v", err)
				}
				var metadata []byte
				var factEstimated bool
				var delta int64
				if err = db.QueryRow(ctx, `SELECT l.metadata_json,f.estimated,l.balance_delta_micros FROM billing_ledger_entries l JOIN billing_usage_facts f ON f.tenant_id=l.tenant_id AND f.request_id=l.request_id WHERE l.tenant_id=$1 AND l.request_id=$2 AND l.event_type='settle'`, tenant, request).Scan(&metadata, &factEstimated, &delta); err != nil {
					t.Fatal(err)
				}
				var evidence struct {
					Estimated bool `json:"estimated"`
				}
				if err = json.Unmarshal(metadata, &evidence); err != nil {
					t.Fatal(err)
				}
				if evidence.Estimated != estimated || factEstimated != estimated || delta != -8 {
					t.Fatalf("ledger=%s fact=%t delta=%d expected estimated=%t", metadata, factEstimated, delta, estimated)
				}
				var count int
				if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_ledger_entries WHERE tenant_id=$1 AND request_id=$2 AND event_type='settle'`, tenant, request).Scan(&count); err != nil || count != 1 {
					t.Fatalf("count=%d err=%v", count, err)
				}
			})
		}
	}
}
