package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 平台出站被拒事件挂靠在一条 platform_egress 请求日志上：/admin/v1/audit/events 正常返回并含该事件。
func TestPlatformEgressDeniedEventListedOnRealPostgres(t *testing.T) {
	dsn := os.Getenv("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL is required; use disposable PostgreSQL")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id, err := repository.RecordPlatformEgressDenied(ctx, db, PlatformTenantID, "", "notify_channel:webhook", "127.0.0.1")
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	var requestID, endpointType, status string
	if err := db.QueryRow(ctx, `SELECT se.request_id, rl.endpoint_type, rl.request_status FROM security_events se JOIN request_logs rl ON rl.request_id = se.request_id WHERE se.id=$1`, id).Scan(&requestID, &endpointType, &status); err != nil {
		t.Fatalf("event must reference a request log: %v", err)
	}
	if endpointType != "platform_egress" || status == "success" || status == "failed" {
		t.Fatalf("request log endpoint=%s status=%s", endpointType, status)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM security_events WHERE id=$1`, id)
		_, _ = db.Exec(ctx, `DELETE FROM request_logs WHERE request_id=$1`, requestID)
	})
	deps := &Dependencies{SecurityEventRepo: repository.NewSecurityEventRepository(db)}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/events?limit=200", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u_admin", TenantID: PlatformTenantID, Role: "platform_admin"}))
	w := httptest.NewRecorder()
	ListSecurityEvents(deps).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range payload.Data {
		if event["id"] == id {
			found = true
		}
	}
	if !found {
		t.Fatalf("platform egress event %s missing from %d listed events", id, len(payload.Data))
	}
}
