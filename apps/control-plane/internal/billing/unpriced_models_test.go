package billing

import (
	"context"
	"testing"
	"time"
)

// 近 N 天被调用过但没有生效价格的模型，必须全部列出；已有生效价格、失败请求、窗口外的不算。
func TestListUnpricedModelsReturnsCalledModelsWithoutActivePrice(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	insert := func(id, model, status string, at time.Time) {
		t.Helper()
		if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,billing_mode,user_id,model_name,currency,status,occurred_at,admitted_at)
			VALUES($1,$2,$1,'metering',$3,$4,'CNY',$5,$6,$6)`, id+"-"+tenant, tenant, user, model, status, at); err != nil {
			t.Fatalf("insert fact %s: %v", id, err)
		}
	}
	insert("a1", "gpt-unpriced", "unpriced", now.Add(-time.Hour))
	insert("a2", "gpt-unpriced", "unpriced", now.Add(-2*time.Hour))
	insert("b1", "claude-unpriced", "unpriced", now.Add(-48*time.Hour))
	insert("c1", "gpt-priced", "unpriced", now.Add(-time.Hour)) // 事后补了价格
	insert("d1", "gpt-failed", "failed", now.Add(-time.Hour))   // 失败请求不代表未定价
	insert("e1", "gpt-old", "unpriced", now.Add(-40*24*time.Hour))
	if _, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "gpt-priced", Currency: "CNY", PricingMode: PricingModeDirect,
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000}, EffectiveAt: now.Add(-24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, err := store.ListUnpricedModels(ctx, tenant, now.Add(-30*24*time.Hour+time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ModelName != "gpt-unpriced" || got[0].RequestCount != 2 || got[1].ModelName != "claude-unpriced" || got[1].RequestCount != 1 {
		t.Fatalf("unpriced models = %+v", got)
	}
	// 其他租户不可见。
	other, err := store.ListUnpricedModels(ctx, tenant+"-other", now.Add(-30*24*time.Hour), now)
	if err != nil || len(other) != 0 {
		t.Fatalf("other tenant leak: %+v %v", other, err)
	}
}
