package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// 真实 Postgres：URL 内明文密钥保存时自动拆出，密钥加密落库、URL 干净、列表与审计里无明文；
// 编辑表单回传脱敏占位 *** 不会覆盖库内真实参数；存量 streamable_http 行的 capabilities 不被改动。
func TestMCPServerUpstreamConfigDatabaseSplitsURLSecretAndKeepsLegacyRows(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-upstream-config-db-key")
	db, deps, tenant, user, server := mcpHardeningDatabaseFixture(t)
	ctx := context.Background()

	// 1) 新建：URL 带 ?key=明文
	body, _ := json.Marshal(map[string]interface{}{
		"name": "amap", "server_url": "https://mcp.amap.com/mcp?key=PLAINKEY-98765&lang=zh", "transport": "auto",
	})
	w := httptest.NewRecorder()
	CreateMCPServer(deps)(w, mcpHardeningAdminRequest(http.MethodPost, tenant, user, "", body))
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "PLAINKEY-98765") {
		t.Fatalf("create response leaks URL secret: %s", w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	stored, err := deps.MCPServerRepo.Get(ctx, tenant, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored.ServerURL, "PLAINKEY") || stored.ServerURL != "https://mcp.amap.com/mcp?lang=zh" {
		t.Fatalf("stored URL must be clean: %q", stored.ServerURL)
	}
	if got, derr := secrets.DecryptProviderSecret(stored.AuthCiphertext); derr != nil || got != "PLAINKEY-98765" || strings.Contains(stored.AuthCiphertext, "PLAINKEY") {
		t.Fatalf("secret must be stored encrypted: ciphertext=%q plain=%q err=%v", stored.AuthCiphertext, got, derr)
	}
	if stored.Transport != "auto" || stored.Capabilities["upstream_auth_location"] != "query" || stored.Capabilities["upstream_auth_query_param"] != "key" {
		t.Fatalf("not converted to query auth: transport=%s caps=%v", stored.Transport, stored.Capabilities)
	}
	var audited int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE target_id=$1 AND action_detail::text LIKE '%PLAINKEY%'`, created.ID).Scan(&audited); err != nil || audited != 0 {
		t.Fatalf("audit leaks URL secret: count=%d err=%v", audited, err)
	}

	// 2) 列表：server_url 脱敏
	lw := httptest.NewRecorder()
	ListMCPServers(deps)(lw, mcpHardeningAdminRequest(http.MethodGet, tenant, user, "", nil))
	if lw.Code != 200 || strings.Contains(lw.Body.String(), "PLAINKEY") {
		t.Fatalf("list=%d leaks secret? %s", lw.Code, lw.Body.String())
	}

	// 3) 编辑：表单回传脱敏占位 → 以库内值还原，不会把真实参数覆盖成 ***
	legacyURL := "https://legacy.example/mcp?token=LEGACYTOKEN-1234&region=cn"
	if _, err := db.Exec(ctx, `UPDATE mcp_servers SET server_url=$3 WHERE tenant_id=$1 AND id=$2`, tenant, server, legacyURL); err != nil {
		t.Fatal(err)
	}
	edit, _ := json.Marshal(map[string]interface{}{"name": "safe", "server_url": "https://legacy.example/mcp?token=***&region=***", "transport": "streamable_http"})
	ew := httptest.NewRecorder()
	UpdateMCPServer(deps)(ew, mcpHardeningAdminRequest(http.MethodPut, tenant, user, server, edit))
	if ew.Code != 200 {
		t.Fatalf("edit=%d %s", ew.Code, ew.Body.String())
	}
	after, _ := deps.MCPServerRepo.Get(ctx, tenant, server)
	if strings.Contains(after.ServerURL, "***") || strings.Contains(after.ServerURL, "LEGACYTOKEN") || !strings.Contains(after.ServerURL, "region=cn") {
		t.Fatalf("redacted placeholder must be restored then split: %q", after.ServerURL)
	}
	if got, _ := secrets.DecryptProviderSecret(after.AuthCiphertext); got != "LEGACYTOKEN-1234" {
		t.Fatalf("legacy URL secret must be moved into encrypted auth, got %q", got)
	}

	// 4) 无法还原的占位被拒绝
	bad, _ := json.Marshal(map[string]interface{}{"name": "safe", "server_url": "https://x.example/mcp?key=***", "transport": "streamable_http"})
	bw := httptest.NewRecorder()
	UpdateMCPServer(deps)(bw, mcpHardeningAdminRequest(http.MethodPut, tenant, user, server, bad))
	if bw.Code != 400 || !strings.Contains(bw.Body.String(), "脱敏占位符") {
		t.Fatalf("unrestorable placeholder must be 400: %d %s", bw.Code, bw.Body.String())
	}

	// 5) 非法 transport / 禁用额外头一律 400
	for _, c := range []map[string]interface{}{
		{"name": "x", "server_url": "https://x.example/mcp", "transport": "websocket"},
		{"name": "x", "server_url": "https://x.example/mcp", "transport": "auto", "capabilities": map[string]interface{}{"upstream_extra_headers": map[string]interface{}{"Host": "evil"}}},
	} {
		b, _ := json.Marshal(c)
		cw := httptest.NewRecorder()
		CreateMCPServer(deps)(cw, mcpHardeningAdminRequest(http.MethodPost, tenant, user, "", b))
		if cw.Code != 400 {
			t.Fatalf("expected 400 for %v: %d %s", c, cw.Code, cw.Body.String())
		}
	}
}

// 同步事务把协商产物（auto 探测到的 transport、前向兼容的原始版本）合并进 capabilities，
// 且不会丢失管理员配置的上游连接键；再次以非前向版本同步时清除过期的 raw/forward 标记。
func TestMCPSyncPersistsNegotiationIntoCapabilities(t *testing.T) {
	db, deps, tenant, _, server := mcpHardeningDatabaseFixture(t)
	ctx := context.Background()
	cur, err := deps.MCPServerRepo.Get(ctx, tenant, server)
	if err != nil {
		t.Fatal(err)
	}
	cur.Transport = "auto"
	cur.Capabilities = map[string]interface{}{"upstream_auth_location": "query", "upstream_auth_query_param": "key"}
	upd := repositoryUpdateFrom(cur)
	if err := deps.MCPServerRepo.Update(ctx, tenant, server, upd); err != nil {
		t.Fatal(err)
	}
	deps.MCPToolRepo = repository.NewMCPToolsRepository(db)
	deps.MCPSupplyChainRepo = deps.MCPToolRepo

	srv, _ := deps.MCPServerRepo.Get(ctx, tenant, server)
	fetch := func(_ context.Context, s *repository.MCPServer) ([]mcpManifestTool, error) {
		s.Capabilities["protocol_version"] = "2025-11-25"
		s.Capabilities["detected_transport"] = "sse"
		s.Capabilities["protocol_version_raw"] = "2099-01-01"
		s.Capabilities["protocol_version_forward_compat"] = true
		return []mcpManifestTool{{Name: "read", Description: "d"}}, nil
	}
	scan := func(context.Context, string, string, string) ([]string, error) { return []string{}, nil }
	if _, err := runMCPServerSync(ctx, deps, tenant, srv, fetch, scan); err != nil {
		t.Fatal(err)
	}
	got, _ := deps.MCPServerRepo.Get(ctx, tenant, server)
	if got.Capabilities["detected_transport"] != "sse" || got.Capabilities["protocol_version_raw"] != "2099-01-01" ||
		got.Capabilities["protocol_version"] != "2025-11-25" || got.Capabilities["upstream_auth_query_param"] != "key" {
		t.Fatalf("negotiation not persisted or config lost: %v", got.Capabilities)
	}

	// 第二次：上游回到已知版本 → raw/forward 标记被清除，探测结果与配置保留。
	srv2, _ := deps.MCPServerRepo.Get(ctx, tenant, server)
	fetch2 := func(_ context.Context, s *repository.MCPServer) ([]mcpManifestTool, error) {
		s.Capabilities["protocol_version"] = "2025-06-18"
		s.Capabilities["detected_transport"] = "sse"
		delete(s.Capabilities, "protocol_version_raw")
		delete(s.Capabilities, "protocol_version_forward_compat")
		return []mcpManifestTool{{Name: "read", Description: "d"}}, nil
	}
	if _, err := runMCPServerSync(ctx, deps, tenant, srv2, fetch2, scan); err != nil {
		t.Fatal(err)
	}
	got2, _ := deps.MCPServerRepo.Get(ctx, tenant, server)
	if _, has := got2.Capabilities["protocol_version_raw"]; has || got2.Capabilities["protocol_version"] != "2025-06-18" || got2.Capabilities["upstream_auth_location"] != "query" {
		t.Fatalf("stale forward-compat markers must be cleared: %v", got2.Capabilities)
	}

}

func repositoryUpdateFrom(s *repository.MCPServer) repository.MCPServerUpdateParams {
	return repository.MCPServerUpdateParams{
		Name: s.Name, ServerURL: s.ServerURL, Owner: s.Owner, TrustLevel: s.TrustLevel,
		Capabilities: s.Capabilities, Status: s.Status, Transport: s.Transport, AllowPrivateEgress: s.AllowPrivateEgress,
	}
}
