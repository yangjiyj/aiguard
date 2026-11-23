package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEmployeeSettingsDormantHoldsDoNotFreezeDenomination(t *testing.T) {
	for _, scenario := range []struct {
		name                      string
		expired, settled, blocked bool
	}{
		{name: "expired crash hold", expired: true},
		{name: "settled residual hold", settled: true},
		{name: "current live hold", blocked: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			store, db, tenant, user := setupBillingStoreTest(t)
			ctx := context.Background()
			if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC"}); err != nil {
				t.Fatal(err)
			}
			start, end, err := allowanceMonth(time.Now().UTC(), "UTC")
			if err != nil {
				t.Fatal(err)
			}
			if scenario.expired {
				end = start
				start = start.AddDate(0, -1, 0)
			}
			request := "settings-hold-" + user
			if _, err := db.Exec(ctx, `INSERT INTO billing_employee_reservations(tenant_id,request_id,user_id,month_start,month_end,amount_micros,currency) VALUES($1,$2,$3,$4,$5,10,'CNY')`, tenant, request, user, start, end); err != nil {
				t.Fatal(err)
			}
			if scenario.settled {
				if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,billing_mode,user_id,model_name,billable_amount_micros,currency,status,occurred_at,admitted_at) VALUES($1,$2,$3,'metering',$4,'fixture',10,'CNY','settled',$5,$5)`, "settled-hold-"+user, tenant, request, user, start.Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
			err = store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "America/New_York"})
			if scenario.blocked {
				if !errors.Is(err, ErrAllowanceCurrency) {
					t.Fatalf("live hold must freeze denomination: %v", err)
				}
			} else if err != nil {
				t.Fatalf("dormant hold blocked reconfiguration: %v", err)
			}
			cfg, err := store.GetEmployeeSettings(ctx, tenant)
			if err != nil {
				t.Fatal(err)
			}
			wantCurrency := "USD"
			if scenario.blocked {
				wantCurrency = "CNY"
			}
			if cfg.Currency != wantCurrency {
				t.Fatalf("currency=%s want %s", cfg.Currency, wantCurrency)
			}
			var remaining int
			if err := db.QueryRow(ctx, `SELECT count(*) FROM billing_employee_reservations WHERE tenant_id=$1 AND request_id=$2`, tenant, request).Scan(&remaining); err != nil || remaining != 1 {
				t.Fatalf("hold history deleted: count=%d err=%v", remaining, err)
			}
		})
	}
}
