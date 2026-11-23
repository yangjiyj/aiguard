package billing

import (
	"context"
	"testing"
	"time"
)

func TestUpstreamCostPublicAliasUsesRoutedModelForPrepaidAndMetering(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	provider, modelID := "alias-provider-"+user, "alias-model-"+user
	if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,'alias channel','openai')`, provider, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name,model_label) VALUES($1,$2,'actual-cost-model','A display label')`, modelID, provider); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveUpstreamRate(ctx, tenant, UpstreamRate{ProviderID: provider, ModelName: "actual-cost-model", Currency: "CNY", InputMicros: 2_000_000}); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "public-alias", PricingMode: PricingModeDirect, Currency: "CNY", DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000}, EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Credit(ctx, tenant, wallet.ID, "alias-credit", 100_000_000, "admin"); err != nil {
		t.Fatal(err)
	}
	initialProvider, initialModel := "alias-initial-provider-"+user, "alias-initial-model-"+user
	if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,'initial channel','openai')`, initialProvider, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name) VALUES($1,$2,'initial-cost-model')`, initialModel, initialProvider); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveUpstreamRate(ctx, tenant, UpstreamRate{ProviderID: initialProvider, ModelName: "initial-cost-model", Currency: "CNY", InputMicros: 9_000_000}); err != nil {
		t.Fatal(err)
	}
	usage := Usage{PromptTokens: 1_000_000}
	for _, mode := range []string{"prepaid", "metering"} {
		requestID := "cost-alias-" + mode
		if _, err := db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,user_id,provider_id,model_id,endpoint_type,request_status,created_at) VALUES($1,$2,$3,$4,$5,$6,'chat_completion','success',NOW())`, requestID+"-"+user, requestID, tenant, user, initialProvider, initialModel); err != nil {
			t.Fatal(err)
		}
		// Gateway persists the final fallback route before accounting finalizes.
		// Both channels have prices so selecting the stale initial route would
		// produce a wrong non-null cost, not merely an unknown cost.
		if _, err := db.Exec(ctx, `UPDATE request_logs SET provider_id=$3::varchar,model_id=$4::varchar WHERE tenant_id=$1::varchar AND request_id=$2::varchar`, tenant, requestID, provider, modelID); err != nil {
			t.Fatal(err)
		}
		if mode == "prepaid" {
			if _, _, err := store.ReservePricedWithUsageForGroup(ctx, tenant, wallet.ID, requestID, 1_000_000, 1_000_000, price, DefaultCustomerGroup, ratioScale); err != nil {
				t.Fatal(err)
			}
			charge, _, err := store.SettleCharge(ctx, tenant, requestID, price, usage, []byte(`{}`), nil)
			if err != nil || charge.ModelName != "public-alias" || charge.AmountMicros != 1_000_000 || charge.UpstreamCostMicros == nil || *charge.UpstreamCostMicros != 2_000_000 {
				t.Fatalf("alias prepaid price/cost=%#v, err=%v", charge, err)
			}
		} else {
			if _, err := store.RecordMeteringUsage(ctx, MeteringInput{TenantID: tenant, UserID: user, RequestID: requestID, ModelName: "public-alias", RequestStatus: "success", Usage: usage}); err != nil {
				t.Fatal(err)
			}
		}
		var cost *int64
		var factPriceID string
		if err := db.QueryRow(ctx, `SELECT upstream_cost_micros,price_id FROM billing_usage_facts WHERE tenant_id=$1 AND request_id=$2`, tenant, requestID).Scan(&cost, &factPriceID); err != nil || cost == nil || *cost != 2_000_000 || factPriceID != price.ID {
			t.Fatalf("%s alias fact price/cost=%s/%v, err=%v", mode, factPriceID, cost, err)
		}
	}
	_, _, otherTenant, otherUser := setupBillingStoreTest(t)
	otherProvider, otherModel := "foreign-cost-provider-"+otherUser, "foreign-cost-model-"+otherUser
	if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,'foreign channel','openai')`, otherProvider, otherTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name) VALUES($1,$2,'actual-cost-model')`, otherModel, otherProvider); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveUpstreamRate(ctx, otherTenant, UpstreamRate{ProviderID: otherProvider, ModelName: "actual-cost-model", Currency: "CNY", InputMicros: 9_000_000}); err != nil {
		t.Fatal(err)
	}
	for _, identity := range [][2]string{{provider, otherModel}, {otherProvider, otherModel}, {otherProvider, modelID}} {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cost, costErr := ComputeUpstreamCost(ctx, tx, tenant, identity[0], identity[1], "actual-cost-model", "CNY", usage)
		_ = tx.Rollback(ctx)
		if costErr != nil || cost != nil {
			t.Fatalf("foreign/mismatched model identity inherited a cost: %v, err=%v", cost, costErr)
		}
	}
}
