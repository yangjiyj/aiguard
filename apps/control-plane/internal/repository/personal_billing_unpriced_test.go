package repository

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"testing"
	"time"
)

func TestPersonalBillingSeparatesUnpricedWithoutChangingSettledAmount(t *testing.T) {
	db, tenant, user, _, _, _ := employeeKeyFixture(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,user_id,model_name,prompt_tokens,cached_input_tokens,cache_write_input_tokens,output_tokens,billable_amount_micros,status,occurred_at,admitted_at)
 VALUES($1,$3,$1,$4,'priced',20,4,2,5,12345,'settled',now(),now()),($2,$3,$2,$4,'unpriced',10,2,1,2,NULL,'unpriced',now(),now())`, tenant+"_priced", tenant+"_unpriced", tenant, user); err != nil {
		t.Fatal(err)
	}
	summary, err := billing.NewStore(db).CustomerSummary(ctx, tenant, user, time.Now().Add(-time.Hour), 50)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(summary.Usage)
	var usage map[string]int64
	if err = json.Unmarshal(raw, &usage); err != nil {
		t.Fatal(err)
	}
	if usage["amount_micros"] != 12345 || usage["requests"] != 1 || usage["unpriced_requests"] != 1 || usage["unpriced_tokens"] != 12 || usage["unpriced_cached_input_tokens"] != 2 || usage["unpriced_cache_write_input_tokens"] != 1 {
		t.Fatalf("personal usage reconciliation failed: requests=%d unpriced=%d", usage["requests"], usage["unpriced_requests"])
	}
}
