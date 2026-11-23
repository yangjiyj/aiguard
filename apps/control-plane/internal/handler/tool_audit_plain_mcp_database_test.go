package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// D5（Postgres）：网关给普通 MCP tools/call 的载荷带 operation_id 却没有 event_type。
// 真实库有 tool_call_logs_destructive_operation_tuple_check（二者同有同无），修复前该请求 500 并丢行。
func TestD5_PlainMCPToolLogWithOperationIDOnlyIsStoredOnPostgres(t *testing.T) {
	dsn := os.Getenv("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL is required; use disposable PostgreSQL")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	tenant := fmt.Sprintf("f_d5_%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, "DELETE FROM tool_call_logs WHERE tenant_id=$1", tenant)
		_, _ = db.Exec(ctx, "DELETE FROM tenants WHERE id=$1", tenant)
		db.Close()
	})
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true)`, tenant); err != nil {
		t.Fatal(err)
	}
	deps := &Dependencies{ToolCallLogRepo: repository.NewToolCallLogRepository(db)}

	for i, c := range []struct{ name, op, evt string }{
		{"普通调用只带 operation_id（修复前 500）", "op-plain-1", ""},
		{"普通调用两者皆无", "", ""},
	} {
		body, _ := json.Marshal(map[string]any{
			"request_id": fmt.Sprintf("req_d5_%d", i), "tool_name": "demo__echo", "tool_type": "mcp",
			"status": "audited", "event_kind": "invocation_proposed", "provenance": "mcp_gateway",
			"attribution_mode": "explicit", "attribution_confidence": 1,
			"operation_id": c.op, "event_type": c.evt, "tool_call_id": fmt.Sprintf("number:%d", i),
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/tools/logs", strings.NewReader(string(body)))
		req.Header.Set("X-Tenant-ID", tenant)
		w := httptest.NewRecorder()
		CreateToolCallLogInternal(deps)(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("%s: status=%d body=%s", c.name, w.Code, w.Body.String())
		}
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM tool_call_logs WHERE tenant_id=$1`, tenant).Scan(&n); err != nil || n != 2 {
		t.Fatalf("两条普通 MCP 调用都应落 tool_call_logs，实际 %d (err=%v)", n, err)
	}
}
