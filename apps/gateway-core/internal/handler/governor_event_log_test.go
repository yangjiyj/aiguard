package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 库不可用时 alert_inbox 写入失败：日志要有错误类别、不含连接串，且洪峰下限频。
func TestRecordGovernorEventInsertFailureLogsClassAndIsThrottled(t *testing.T) {
	buf := captureGatewayLog(t)

	pool, err := pgxpool.New(context.Background(), "postgres://leaky_user:leaky_pw@127.0.0.1:1/leaky_db?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	decision := governor.Decision{Action: governor.ActionRateLimit, TriggeredScope: "tenant", TriggeredMetric: "month_cost_micros"}
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-1", ProjectID: "p", UserID: "u"}
	for i := 0; i < 25; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		recordGovernorEvent(ctx, pool, decision, envelope, "quota.admission.month_cost_micros")
		cancel()
	}
	out := buf.String()
	failures := strings.Count(out, "[recordGovernorEvent] alert_inbox insert failed")
	if failures == 0 || failures > 3 {
		t.Fatalf("failure lines=%d, want 1..3 for 25 failures\n%s", failures, out)
	}
	if !strings.Contains(out, "class=connect_failed") && !strings.Contains(out, "class=timeout") {
		t.Fatalf("no error class in log:\n%s", out)
	}
	for _, leaked := range []string{"leaky_user", "leaky_pw", "leaky_db", "127.0.0.1"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("log leaks %q:\n%s", leaked, out)
		}
	}
}
