package billing

import (
	"context"
	"testing"
	"time"
)

// 费用趋势按北京时间切日：UTC 15:00 与 17:00 跨过北京时间零点，必须落在两个日桶里，桶起点是北京时间零点。
func TestAnalyticsSeriesBucketsDaysInBeijingTime(t *testing.T) {
	store, db, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	for i, at := range []time.Time{time.Date(2026, 10, 10, 15, 0, 0, 0, time.UTC), time.Date(2026, 10, 10, 17, 0, 0, 0, time.UTC)} {
		if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts (id,tenant_id,request_id,model_name,billable_amount_micros,currency,status,occurred_at)
			VALUES ($1,$2,$1,'m',1000,'CNY','settled',$3)`, tenantID+"-tz-"+string(rune('a'+i)), tenantID, at); err != nil {
			t.Fatal(err)
		}
	}
	filter := AnalyticsFilter{TenantID: tenantID, Start: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), FullTenant: true}
	rows, err := store.GetAnalyticsSeries(ctx, filter, "day")
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	if !rows[0].Bucket.Equal(time.Date(2026, 10, 9, 16, 0, 0, 0, time.UTC)) || !rows[1].Bucket.Equal(time.Date(2026, 10, 10, 16, 0, 0, 0, time.UTC)) {
		t.Fatalf("buckets = %v / %v，应为北京时间 10-10 与 10-11 零点", rows[0].Bucket, rows[1].Bucket)
	}
}
