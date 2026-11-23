package billing

import (
	"context"
	"testing"
	"time"
)

func TestBuildChannelMarginsComparesChannelsAndFlagsNegativeMargin(t *testing.T) {
	rates := []UpstreamRate{
		{ProviderID: "p1", ProviderName: "渠道甲", ModelName: "m", Currency: "CNY", InputMicros: 2_000_000, OutputMicros: 8_000_000},
		{ProviderID: "p2", ProviderName: "渠道乙", ModelName: "m", Currency: "CNY", InputMicros: 5_000_000, OutputMicros: 20_000_000},
		{ProviderID: "p3", ProviderName: "渠道丙", ModelName: "solo", Currency: "CNY"},
	}
	usage := []ChannelUsage{
		{ProviderID: "p1", ProviderName: "渠道甲", ModelName: "m", Currency: "CNY", Requests: 10, CostKnownRequests: 10, BilledMicros: 1_000_000, BilledCostKnownMicros: 1_000_000, CostMicros: 400_000},
		{ProviderID: "p2", ProviderName: "渠道乙", ModelName: "m", Currency: "CNY", Requests: 4, CostKnownRequests: 3, BilledMicros: 500_000, BilledCostKnownMicros: 400_000, CostMicros: 700_000},
		{ProviderID: "p4", ProviderName: "渠道丁", ModelName: "m", Currency: "CNY", Requests: 2, CostKnownRequests: 0, BilledMicros: 100_000},
	}
	groups := BuildChannelMargins(rates, usage)
	if len(groups) != 2 || groups[0].ModelName != "m" || len(groups[0].Channels) != 3 {
		t.Fatalf("groups = %#v", groups)
	}
	byID := map[string]ChannelMargin{}
	for _, c := range groups[0].Channels {
		byID[c.ProviderID] = c
	}
	if c := byID["p1"]; c.MarginMicros == nil || *c.MarginMicros != 600_000 || c.Negative || !c.HasRate {
		t.Fatalf("p1 = %#v", c)
	}
	// 毛利只用“成本已知”的那部分计费金额，避免把成本未知请求的收入算成利润。
	if c := byID["p2"]; c.MarginMicros == nil || *c.MarginMicros != -300_000 || !c.Negative || c.Suggestion == "" {
		t.Fatalf("p2 = %#v", c)
	}
	if c := byID["p4"]; c.MarginMicros != nil || c.HasRate || c.Negative {
		t.Fatalf("p4 成本未知不能算毛利: %#v", c)
	}
	if !groups[0].HasNegative || groups[1].HasNegative {
		t.Fatalf("negative flags = %v %v", groups[0].HasNegative, groups[1].HasNegative)
	}
	if solo := groups[1].Channels[0]; solo.Requests != 0 || solo.MarginMicros != nil {
		t.Fatalf("无用量渠道 = %#v", solo)
	}
}

func TestChannelMarginsReadsSevenDayFactsPerChannel(t *testing.T) {
	store, db, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	p1, p2 := "prov_cm1_"+tenantID, "prov_cm2_"+tenantID
	for _, p := range []string{p1, p2} {
		if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,$1,'openai')`, p, tenantID); err != nil {
			t.Fatalf("provider: %v", err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name) VALUES($1,$2,'cm-model')`, "model_"+p, p); err != nil {
			t.Fatalf("model: %v", err)
		}
		if err := store.SaveUpstreamRate(ctx, tenantID, UpstreamRate{ProviderID: p, ModelName: "cm-model", Currency: "CNY", InputMicros: 1, OutputMicros: 1}); err != nil {
			t.Fatalf("rate: %v", err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	insert := func(id, provider string, billed, cost any, at time.Time, status string) {
		t.Helper()
		if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts (id,tenant_id,request_id,provider_id,provider_name,model_name,billable_amount_micros,upstream_cost_micros,currency,status,occurred_at)
			VALUES ($1,$2,$1,$3,$3,'cm-model',$4,$5,'CNY',$6,$7)`, id+tenantID, tenantID, provider, billed, cost, status, at); err != nil {
			t.Fatalf("fact: %v", err)
		}
	}
	insert("a1", p1, 1000, 300, now.Add(-time.Hour), "settled")
	insert("a2", p1, 1000, nil, now.Add(-time.Hour), "settled")
	insert("a3", p1, 9000, 1, now.Add(-8*24*time.Hour), "settled") // 窗口外
	insert("b1", p2, 500, 900, now.Add(-2*time.Hour), "settled")
	insert("b2", p2, nil, nil, now.Add(-2*time.Hour), "unpriced") // 未定价不计入
	groups, err := store.ChannelMargins(ctx, tenantID, now.Add(-7*24*time.Hour), now)
	if err != nil {
		t.Fatalf("margins: %v", err)
	}
	if len(groups) != 1 || len(groups[0].Channels) != 2 {
		t.Fatalf("groups = %#v", groups)
	}
	for _, c := range groups[0].Channels {
		switch c.ProviderID {
		case p1:
			if c.Requests != 2 || c.CostKnownRequests != 1 || c.MarginMicros == nil || *c.MarginMicros != 700 {
				t.Fatalf("p1 = %#v", c)
			}
		case p2:
			if c.Requests != 1 || !c.Negative || *c.MarginMicros != -400 {
				t.Fatalf("p2 = %#v", c)
			}
		}
	}
}
