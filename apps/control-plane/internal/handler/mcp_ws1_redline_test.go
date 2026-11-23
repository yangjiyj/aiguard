package handler

// W1 1.11：红线处置配置端点（默认 alert；管理员可逐条改为 block；修改留痕）。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestWS1RedlineUpdatesValidation(t *testing.T) {
	if _, err := repository.NormalizeMCPRedlineUpdates(nil); err == nil {
		t.Fatalf("empty must be rejected")
	}
	if _, err := repository.NormalizeMCPRedlineUpdates(map[string]string{"nope": "block"}); err == nil {
		t.Fatalf("unknown rule must be rejected")
	}
	if _, err := repository.NormalizeMCPRedlineUpdates(map[string]string{"cloud_metadata": "deny"}); err == nil {
		t.Fatalf("invalid action must be rejected")
	}
	got, err := repository.NormalizeMCPRedlineUpdates(map[string]string{" cloud_metadata ": " BLOCK "})
	if err != nil || got["cloud_metadata"] != "block" {
		t.Fatalf("normalize: %v %v", got, err)
	}
}

func TestWS1RedlineContractListsConfigurableRules(t *testing.T) {
	listed := map[string]bool{}
	for _, name := range mcpContractRuntimeRedlines {
		listed[name] = true
	}
	for _, name := range repository.MCPConfigurableRedlines {
		if !listed[name] {
			t.Fatalf("policy contract runtime_redlines must include configurable redline %s", name)
		}
	}
}

func ws1RedlineRequest(method, path, tenant, role string, body interface{}) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u-" + role, TenantID: tenant, Role: role})
	return req.WithContext(ctx)
}

func TestWS1RedlineSettingsOnRealPostgres(t *testing.T) {
	dsn := os.Getenv("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tenant := fmt.Sprintf("ws1rl%d", time.Now().UnixNano()%1_000_000_000)
	other := tenant + "o"
	for _, id := range []string{tenant, other} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, id); err != nil {
			t.Fatalf("tenant: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM mcp_redline_settings WHERE tenant_id IN ($1,$2)`, tenant, other)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenant, other)
	})
	store := repository.NewMCPRedlineSettingsRepository(pool)
	deps := &Dependencies{}

	internal := func(tid string) map[string]string {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/mcp/redline-settings", nil)
		req.Header.Set("X-Tenant-ID", tid)
		rec := httptest.NewRecorder()
		GetInternalMCPRedlineSettings(store)(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("internal status %d %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Actions map[string]string `json:"actions"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Actions
	}
	for _, name := range repository.MCPConfigurableRedlines {
		if got := internal(tenant)[name]; got != "alert" {
			t.Fatalf("default for %s must be alert, got %q", name, got)
		}
	}

	rec := httptest.NewRecorder()
	UpdateMCPRedlineSettings(deps, store)(rec, ws1RedlineRequest(http.MethodPut, "/admin/v1/mcp-redline-settings", tenant, "viewer",
		map[string]interface{}{"actions": map[string]string{"cloud_metadata": "block"}}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin must be 403, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	UpdateMCPRedlineSettings(deps, store)(rec, ws1RedlineRequest(http.MethodPut, "/admin/v1/mcp-redline-settings", tenant, "tenant_admin",
		map[string]interface{}{"actions": map[string]string{"bogus": "block"}}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown rule must be 400, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	UpdateMCPRedlineSettings(deps, store)(rec, ws1RedlineRequest(http.MethodPut, "/admin/v1/mcp-redline-settings", tenant, "tenant_admin",
		map[string]interface{}{"actions": map[string]string{"cloud_metadata": "block", "reverse_shell": "block"}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin update: %d %s", rec.Code, rec.Body.String())
	}
	got := internal(tenant)
	if got["cloud_metadata"] != "block" || got["reverse_shell"] != "block" || got["private_key_egress"] != "alert" {
		t.Fatalf("after update: %v", got)
	}
	if internal(other)["cloud_metadata"] != "alert" {
		t.Fatalf("settings must not leak across tenants")
	}
	before, err := store.Upsert(ctx, tenant, "u2", map[string]string{"cloud_metadata": "alert"})
	if err != nil || before["cloud_metadata"] != "block" {
		t.Fatalf("upsert must report previous action: %v %v", before, err)
	}
	rec = httptest.NewRecorder()
	GetMCPRedlineSettings(deps, store)(rec, ws1RedlineRequest(http.MethodGet, "/admin/v1/mcp-redline-settings", tenant, "viewer", nil))
	var view struct {
		Items []repository.MCPRedlineSetting `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if rec.Code != http.StatusOK || len(view.Items) != len(repository.MCPConfigurableRedlines) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_redline_settings(tenant_id,rule_name,action) VALUES ($1,'x','deny')`, tenant); err == nil {
		t.Fatalf("db check constraint must reject invalid action")
	}
}
