package handler

// 对抗式审查 E：路由指纹覆盖 capabilities 里的上游连接配置键（需要新迁移 982）。
// 需要真实 Postgres（MCP_SUPPLY_CHAIN_TEST_DATABASE_URL，按 initdb 001 + migration-runner 建库）。

import (
	"context"
	"testing"
)

type pgxRow interface{ Scan(dest ...any) error }

func fetchRouteHash(t *testing.T, ctx context.Context, q func(sql string, args ...any) pgxRow, tenant, server string) string {
	t.Helper()
	var h string
	if err := q(`SELECT observed_route_hash FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestAdvReviewE_RouteHashCoversUpstreamConnectionCapabilities(t *testing.T) {
	db, _, tenant, _, server := mcpHardeningDatabaseFixture(t)
	ctx := context.Background()
	q := func(sql string, args ...any) pgxRow { return db.QueryRow(ctx, sql, args...) }
	set := func(caps string) {
		if _, err := db.Exec(ctx, `UPDATE mcp_servers SET capabilities_json=$3::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, server, caps); err != nil {
			t.Fatal(err)
		}
	}
	// 基线：没有任何新字段 → 指纹必须等于旧公式（迁移不得让存量服务瞬间失配）。
	set(`{}`)
	var legacy, now string
	if err := db.QueryRow(ctx, `SELECT compute_mcp_route_hash(server_url,transport,allow_private_egress,auth_key_ref,auth_ciphertext), observed_route_hash FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&legacy, &now); err != nil {
		t.Fatal(err)
	}
	// 旧公式的独立重算（与 117 迁移逐字一致），证明“空配置”不改变指纹。
	var oldFormula string
	if err := db.QueryRow(ctx, `SELECT encode(sha256(convert_to(COALESCE(server_url,'')||chr(31)||COALESCE(transport,'streamable_http')||chr(31)||COALESCE(allow_private_egress,FALSE)::text||chr(31)||COALESCE(auth_key_ref,'')||chr(31)||encode(sha256(convert_to(COALESCE(auth_ciphertext,''),'UTF8')),'hex'),'UTF8')),'hex') FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&oldFormula); err != nil {
		t.Fatal(err)
	}
	if now != oldFormula {
		t.Fatalf("legacy rows (no upstream capabilities) must keep the exact pre-migration fingerprint:\n now=%s\n old=%s", now, oldFormula)
	}
	// 与路由无关的 capabilities（协议版本、同步写入的探测结果）不得改变指纹。
	base := fetchRouteHash(t, ctx, q, tenant, server)
	for _, caps := range []string{
		`{"protocol_version":"2025-11-25"}`,
		`{"protocol_version":"2025-11-25","detected_transport":"sse"}`,
		`{"protocol_version_raw":"2099-01-01","protocol_version_forward_compat":true}`,
		`{"tools":["x"]}`,
	} {
		set(caps)
		if got := fetchRouteHash(t, ctx, q, tenant, server); got != base {
			t.Fatalf("non-route capabilities must not change the fingerprint (would self-quarantine on every sync): %s -> %s", caps, got)
		}
	}
	// 存量字段 auth_header_name 不纳入摘要：现网已批准且自定义了头名的服务，迁移后指纹必须逐字节不变，
	// 否则它们会在迁移后的任意一次 UPDATE 后与已批准指纹失配，被网关当作“路由未批准”硬阻断。
	set(`{"auth_header_name":"X-MCP-Token","protocol_version":"2025-03-26"}`)
	if got := fetchRouteHash(t, ctx, q, tenant, server); got != base {
		t.Fatalf("legacy auth_header_name rows must keep the pre-migration fingerprint: %s vs %s", got, base)
	}
	// 路由相关的新增 capabilities 变化必须改变指纹，且不同配置得到不同指纹。
	seen := map[string]string{base: "{}"}
	for _, caps := range []string{
		`{"upstream_auth_location":"query","upstream_auth_query_param":"key"}`,
		`{"upstream_auth_location":"query","upstream_auth_query_param":"ak"}`,
		`{"upstream_auth_template":"Bearer {secret}"}`,
		`{"upstream_auth_template":"{secret}"}`,
		`{"upstream_extra_headers":{"Stripe-Account":"acct_1"}}`,
		`{"upstream_extra_headers":{"Stripe-Account":"acct_2"}}`,
	} {
		set(caps)
		got := fetchRouteHash(t, ctx, q, tenant, server)
		if prev, dup := seen[got]; dup {
			t.Fatalf("fingerprint collision between %s and %s", prev, caps)
		}
		seen[got] = caps
	}
	// 键顺序不影响指纹（jsonb 规范化）；同一配置重复写入指纹稳定（幂等）。
	set(`{"upstream_extra_headers":{"B":"2","A":"1"},"upstream_auth_location":"query","upstream_auth_query_param":"key"}`)
	h1 := fetchRouteHash(t, ctx, q, tenant, server)
	set(`{"upstream_auth_query_param":"key","upstream_auth_location":"query","upstream_extra_headers":{"A":"1","B":"2"}}`)
	if h2 := fetchRouteHash(t, ctx, q, tenant, server); h1 != h2 {
		t.Fatalf("key order must not matter: %s vs %s", h1, h2)
	}
}

// 已批准服务改动上游连接配置（不改 URL / 密钥）：必须像改地址一样被自动隔离，等待复核。
func TestAdvReviewE_ApprovedServerIsQuarantinedWhenUpstreamConfigChanges(t *testing.T) {
	db, _, tenant, _, server := mcpHardeningDatabaseFixture(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `UPDATE mcp_servers SET capabilities_json='{}'::jsonb, admission_status='approved', approved_route_hash=observed_route_hash, manifest_hash='m1', approved_manifest_hash='m1' WHERE tenant_id=$1 AND id=$2`, tenant, server); err != nil {
		t.Fatal(err)
	}
	var status string
	_ = db.QueryRow(ctx, `SELECT admission_status FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&status)
	if status != "approved" {
		t.Fatalf("precondition: expected approved, got %s", status)
	}
	// 同步写入的非路由字段：不得触发隔离。
	if _, err := db.Exec(ctx, `UPDATE mcp_servers SET capabilities_json=jsonb_build_object('protocol_version','2025-11-25','detected_transport','sse') WHERE tenant_id=$1 AND id=$2`, tenant, server); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(ctx, `SELECT admission_status FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&status)
	if status != "approved" {
		t.Fatalf("sync-written capabilities must not quarantine an approved server, got %s", status)
	}
	// 改鉴权位置：路由指纹失配（2.9.22 起不再由触发器隔离，原期望 quarantined/route_binding_changed；
	// 网关按 route_binding_mismatch 走 mcp.drift 防护项处置）。
	if _, err := db.Exec(ctx, `UPDATE mcp_servers SET capabilities_json=jsonb_build_object('upstream_auth_location','query','upstream_auth_query_param','key') WHERE tenant_id=$1 AND id=$2`, tenant, server); err != nil {
		t.Fatal(err)
	}
	var mismatch bool
	_ = db.QueryRow(ctx, `SELECT admission_status, observed_route_hash<>approved_route_hash FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&status, &mismatch)
	if status != "approved" || !mismatch {
		t.Fatalf("changing upstream auth config must break the route binding: status=%s mismatch=%v", status, mismatch)
	}
}

// 存量带 auth_header_name 的已批准服务：迁移后经任意 UPDATE（如改负责人）仍保持 approved 且路由指纹不失配。
func TestAdvReviewE_LegacyAuthHeaderNameApprovedServerStaysMatched(t *testing.T) {
	db, _, tenant, _, server := mcpHardeningDatabaseFixture(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `UPDATE mcp_servers SET capabilities_json='{"auth_header_name":"X-MCP-Token"}'::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, server); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE mcp_servers SET admission_status='approved', approved_route_hash=observed_route_hash, manifest_hash='m', approved_manifest_hash='m' WHERE tenant_id=$1 AND id=$2`, tenant, server); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE mcp_servers SET owner='ops' WHERE tenant_id=$1 AND id=$2`, tenant, server); err != nil {
		t.Fatal(err)
	}
	var status string
	var match bool
	if err := db.QueryRow(ctx, `SELECT admission_status, observed_route_hash = approved_route_hash FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&status, &match); err != nil {
		t.Fatal(err)
	}
	if status != "approved" || !match {
		t.Fatalf("legacy custom-header server must stay approved with a matching fingerprint: status=%s match=%v", status, match)
	}
}
