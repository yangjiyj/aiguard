package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 不解密 CONNECT 隧道结束时回写的上/下行字节数与时长，必须能从访问记录读接口带出。
func TestForwardProxyAccessReturnsTunnelBytesAndDuration(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	suffix := time.Now().UnixNano()
	tenantID := fmt.Sprintf("tenant_tunnel_bytes_%d", suffix)
	t.Cleanup(func() {
		for _, stmt := range []string{
			"DELETE FROM request_logs WHERE tenant_id = $1",
			"DELETE FROM tenants WHERE id = $1",
		} {
			if _, err := db.Exec(ctx, stmt, tenantID); err != nil {
				t.Logf("cleanup %s (%q): %v", tenantID, stmt, err)
			}
		}
		db.Close()
	})
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`, tenantID, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	insert := func(requestID string, up, down int64, durationMS *int64) {
		t.Helper()
		_, err := db.Exec(ctx, `
			INSERT INTO request_logs (
				id, request_id, tenant_id, endpoint_type, request_status,
				proxy_mode, proxy_target_host, proxy_target_path, proxy_method,
				proxy_access_type, proxy_access_type_resolved, proxy_tls_inspected,
				proxy_content_retained, proxy_retention_level, risk_state,
				proxy_request_bytes, proxy_response_bytes, proxy_tunnel_duration_ms, created_at
			) VALUES ($1, $1, $2, 'proxy', 'success', 'forward', 'files.example.test:443', '', 'CONNECT',
				'normal_public', 'normal_public', false, false, 'summary', 'normal', $3, $4, $5, $6)
		`, requestID, tenantID, up, down, durationMS, time.Now().UTC())
		if err != nil {
			t.Fatalf("insert request %s: %v", requestID, err)
		}
	}
	ms := int64(2345)
	insert(fmt.Sprintf("req_tunnel_done_%d", suffix), 7000, 12345, &ms)
	insert(fmt.Sprintf("req_tunnel_legacy_%d", suffix), 0, 0, nil)

	// 不解密隧道多为普通公网访问，默认列表只看大模型流量，需显式查看全部类型。
	repo := NewRequestLogRepository(db)
	records, _, err := repo.ListForwardProxyAccess(ctx, tenantID, ForwardProxyAccessFilter{Direction: "forward", AccessType: "all", Limit: 100})
	if err != nil {
		t.Fatalf("list forward access: %v", err)
	}
	got := map[string]ForwardProxyAccessRecord{}
	for _, item := range records {
		got[item.RequestID] = item
	}
	done := got[fmt.Sprintf("req_tunnel_done_%d", suffix)]
	if done.RequestBytes != 7000 || done.ResponseBytes != 12345 || done.TunnelDurationMS != 2345 {
		t.Fatalf("tunnel traffic not returned: %+v", done)
	}
	legacy, ok := got[fmt.Sprintf("req_tunnel_legacy_%d", suffix)]
	if !ok || legacy.TunnelDurationMS != 0 {
		t.Fatalf("legacy row without duration must read as 0: ok=%v %+v", ok, legacy)
	}
}
