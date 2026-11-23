package billing

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/billingmedia"
)

func TestImageReconciliationUsesDetailedActualUsageAndHistoricalPrice(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "recover-image", Currency: "CNY", PricingMode: PricingModeDirect, Extensions: PriceExtensions{ImagePricing: imageMatrix()}})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Credit(ctx, tenant, wallet.ID, "recover-credit", 1_000_000, "test"); err != nil {
		t.Fatal(err)
	}
	usage := Usage{PromptTokens: 100, OutputTokens: 200, UsageExtensions: UsageExtensions{ImageRequest: true, ImageCount: 2, ImageVariants: []billingmedia.ImageVariantUsage{{Size: "1024x1024", Quality: "hd", Count: 1}, {Size: "1792x1024", Quality: "hd", Count: 1}}}}
	audit, _ := json.Marshal(map[string]any{"response_metadata": map[string]any{"usage_source": "upstream", "billing_usage": usage}})
	for _, request := range []string{"detailed-image", "missing-image", "mismatched-image"} {
		if _, _, err := store.ReservePricedWithUsageForGroup(ctx, tenant, wallet.ID, request, 200_010, 300, price, DefaultCustomerGroup, ratioScale); err != nil {
			t.Fatal(err)
		}
		evidence := audit
		if request == "missing-image" {
			evidence = []byte(`{"response_metadata":{"usage_source":"upstream"}}`)
		}
		if request == "mismatched-image" {
			bad := usage
			bad.OutputTokens = 201
			evidence, _ = json.Marshal(map[string]any{"response_metadata": map[string]any{"usage_source": "upstream", "billing_usage": bad}})
		}
		if _, err := db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,output_audit_result,created_at) VALUES($1,$2,$3,$4,'images','success',100,200,$5::jsonb,NOW())`, request+user, request, tenant, user, string(evidence)); err != nil {
			t.Fatal(err)
		}
	}
	changed := imageMatrix()
	changed.Variants[1].PricePerImageMicros = 999_999
	if _, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "recover-image", Currency: "CNY", PricingMode: PricingModeDirect, Extensions: PriceExtensions{ImagePricing: changed}}); err != nil {
		t.Fatal(err)
	}
	item := reconcileTarget{tenantID: tenant, requestID: "detailed-image", status: "success", usageSource: "upstream"}
	if err := store.reconcileSettleFromRequestLog(ctx, item, 100, 200); err != nil {
		t.Fatal(err)
	}
	var amount int64
	var source string
	var count int64
	if err := db.QueryRow(ctx, `SELECT amount_micros,raw_usage_json->>'usage_source',(usage_extras->>'image_count')::bigint FROM billing_charge_records WHERE tenant_id=$1 AND request_id='detailed-image'`, tenant).Scan(&amount, &source, &count); err != nil || amount != 200_010 || source != "recovered_request_log_detailed" || count != 2 {
		t.Fatalf("recovered image guessed Token/quantity/rate: %d/%s/%d %v", amount, source, count, err)
	}
	if err := store.reconcileSettleFromRequestLog(ctx, item, 100, 200); err != nil {
		t.Fatalf("detailed recovery replay: %v", err)
	}
	for _, request := range []string{"missing-image", "mismatched-image"} {
		item.requestID = request
		if err := store.reconcileSettleFromRequestLog(ctx, item, 100, 200); !errors.Is(err, ErrInvalidUsage) {
			t.Fatalf("missing/conflicting image evidence settled: %s %v", request, err)
		}
		reservation, err := store.GetReservation(ctx, tenant, request)
		if err != nil || reservation.Status != ReservationReserved {
			t.Fatalf("evidence gap released/debited freeze: %+v %v", reservation, err)
		}
	}
}
