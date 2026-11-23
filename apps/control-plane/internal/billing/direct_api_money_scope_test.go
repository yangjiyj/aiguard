package billing

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
	"time"
)

func TestHistoricalProxyFactsDoNotConsumeAllowanceOrChannelRevenue(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	// Clone just the fact table in an isolated schema. The current table accepts
	// only gateway/forward_proxy; historical reverse facts must be exercised
	// without changing public constraints shared with other real-PG tests.
	publicDB := db
	schema := pgx.Identifier{"legacy_facts_" + tenant}.Sanitize()
	if _, err := db.Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.billing_usage_facts (LIKE public.billing_usage_facts INCLUDING DEFAULTS)`); err != nil {
		t.Fatal(err)
	}
	config := db.Config()
	config.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	legacyDB, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		legacyDB.Close()
		if _, err := publicDB.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Error(err)
		}
	})
	store = NewStore(legacyDB)
	db = legacyDB
	now := time.Now().UTC()
	cap := int64(1000)
	if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai", DefaultMonthlyMicros: &cap}); err != nil {
		t.Fatal(err)
	}
	provider := "api_scope_" + tenant
	if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,$1,'openai')`, provider, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name) VALUES($1,$2,'api-scope-model')`, provider+"_model", provider); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveUpstreamRate(ctx, tenant, UpstreamRate{ProviderID: provider, ModelName: "api-scope-model", Currency: "CNY", InputMicros: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name) VALUES($1,$2,'proxy-only-model')`, provider+"_proxy_model", provider); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveUpstreamRate(ctx, tenant, UpstreamRate{ProviderID: provider, ModelName: "proxy-only-model", Currency: "CNY", InputMicros: 1}); err != nil {
		t.Fatal(err)
	}
	for _, fact := range []struct {
		source       string
		amount, cost int64
	}{{UsageSourceGateway, 100, 10}, {UsageSourceForwardProxy, 10000, 1000}, {"reverse_proxy", 20000, 2000}} {
		id := tenant + "-" + fact.source
		if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,user_id,provider_id,provider_name,model_name,billable_amount_micros,upstream_cost_micros,currency,status,usage_source,occurred_at,admitted_at) VALUES($1,$2,$1,$3,$4,$4,'api-scope-model',$5,$6,'CNY','settled',$7,$8,$8)`, id, tenant, user, provider, fact.amount, fact.cost, fact.source, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, source := range []string{UsageSourceForwardProxy, "reverse_proxy"} {
		if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,user_id,provider_id,model_name,billable_amount_micros,upstream_cost_micros,currency,status,usage_source,occurred_at,admitted_at) VALUES($1,$2,$1,$3,$4,'proxy-only-model',10000,1000,'CNY','settled',$5,$6,$6)`, tenant+"-proxy-only-"+source, tenant, user, provider, source, now); err != nil {
			t.Fatal(err)
		}
	}
	fixed, err := store.SaveChannelFixedCost(ctx, tenant, ChannelFixedCost{ProviderID: provider, Currency: "CNY", AmountMicros: 31_000_000, Period: "month", EffectiveFrom: "2026-01-01"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReserveEmployeeAllowance(ctx, tenant, user, tenant+"-api-only-hold", "CNY", 800, now); err != nil {
		t.Fatalf("proxy history consumed allowance: %v", err)
	}
	employees, err := store.ListEmployeeAllowances(ctx, tenant, now)
	if err != nil || len(employees) != 1 || employees[0].UsedMicros != 100 || employees[0].ReservedMicros != 0 {
		t.Fatalf("allowance=%+v err=%v", employees, err)
	}
	status, err := store.EmployeeAllowanceForUser(ctx, tenant, user, now)
	if err != nil || status == nil || status.UsedMicros != 100 || status.ReservedMicros != 0 {
		t.Fatalf("employee status=%+v err=%v", status, err)
	}
	if err := store.ReserveEmployeeAllowance(ctx, tenant, user, tenant+"-over-limit", "CNY", 1001, now); !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("amount limit failed: %v", err)
	}
	start, end := now.Add(-time.Hour), now.Add(time.Second)
	groups, err := store.ChannelMargins(ctx, tenant, start, end)
	if err != nil || len(groups) != 2 {
		t.Fatalf("margins=%+v err=%v", groups, err)
	}
	loc, _ := time.LoadLocation("Asia/Shanghai")
	expectedFixed, err := ProrateChannelFixedCost(*fixed, start, end, loc)
	if err != nil {
		t.Fatal(err)
	}
	var allocated int64
	for _, group := range groups {
		if len(group.Channels) != 1 {
			t.Fatalf("channels=%+v", group)
		}
		channel := group.Channels[0]
		allocated += channel.FixedCostMicros
		if group.ModelName == "api-scope-model" {
			if channel.Requests != 1 || channel.BilledMicros != 100 || channel.VariableCostMicros != 10 || channel.FixedCostMicros != expectedFixed || channel.MarginMicros == nil || *channel.MarginMicros != 90-expectedFixed {
				t.Fatalf("proxy history leaked into channel finance: %+v", channel)
			}
		} else if group.ModelName == "proxy-only-model" {
			if channel.Requests != 0 || channel.BilledMicros != 0 || channel.FixedCostMicros != 0 {
				t.Fatalf("proxy usage affected fixed cost allocation: %+v", channel)
			}
		}
	}
	if allocated != expectedFixed {
		t.Fatalf("fixed allocation=%d expected=%d", allocated, expectedFixed)
	}
}
