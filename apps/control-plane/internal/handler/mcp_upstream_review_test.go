package handler

// 对抗式审查（2026-10-19）C / K / D 回归测试：先写、确认失败，再修复。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/jackc/pgx/v5"
)

func putJSON(t *testing.T, deps *Dependencies, tenant, user, server string, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	UpdateMCPServer(deps)(w, mcpHardeningAdminRequest(http.MethodPut, tenant, user, server, b))
	return w
}

// C. 只改 host、不重填 token：必须拒绝保存，旧密钥不得被带去新 host。
func TestAdvReviewC_ChangingHostWithoutNewTokenIsRejected(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "review-c-key")
	db, deps, tenant, user, server := mcpHardeningDatabaseFixture(t)
	ctx := context.Background()
	ct, ref, _ := secrets.EncryptProviderSecret("OLD-SECRET-424242")
	if _, err := db.Exec(ctx, `UPDATE mcp_servers SET server_url='https://old.example/mcp', auth_ciphertext=$3, auth_key_ref=$4 WHERE tenant_id=$1 AND id=$2`, tenant, server, ct, ref); err != nil {
		t.Fatal(err)
	}
	w := putJSON(t, deps, tenant, user, server, map[string]interface{}{"name": "safe", "server_url": "https://evil.example/mcp", "transport": "streamable_http"})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "上游地址或鉴权方式已变更，请重新填写密钥") {
		t.Fatalf("host change without token must be rejected with the Chinese hint: %d %s", w.Code, w.Body.String())
	}
	after, _ := deps.MCPServerRepo.Get(ctx, tenant, server)
	if after.ServerURL != "https://old.example/mcp" {
		t.Fatalf("rejected save must not persist the new URL: %q", after.ServerURL)
	}
	// 重新提交 token 则允许。
	ok := putJSON(t, deps, tenant, user, server, map[string]interface{}{"name": "safe", "server_url": "https://new.example/mcp", "transport": "streamable_http", "auth_token": "NEW-SECRET-777777"})
	if ok.Code != http.StatusOK {
		t.Fatalf("host change WITH a fresh token must be accepted: %d %s", ok.Code, ok.Body.String())
	}
}

// C. scheme / port / path 任一变化同样要求重填；鉴权位置 / 头名 / 参数名 / 值模板变化也要求重填。
func TestAdvReviewC_AnyRouteOrAuthShapeChangeRequiresNewToken(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "review-c-key2")
	db, deps, tenant, user, server := mcpHardeningDatabaseFixture(t)
	ctx := context.Background()
	reset := func() {
		ct, ref, _ := secrets.EncryptProviderSecret("OLD-SECRET-424242")
		if _, err := db.Exec(ctx, `UPDATE mcp_servers SET server_url='https://old.example/mcp', auth_ciphertext=$3, auth_key_ref=$4, transport='streamable_http', capabilities_json='{}'::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, server, ct, ref); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		body map[string]interface{}
	}{
		{"scheme", map[string]interface{}{"server_url": "http://old.example/mcp"}},
		{"port", map[string]interface{}{"server_url": "https://old.example:8443/mcp"}},
		{"path", map[string]interface{}{"server_url": "https://old.example/other"}},
		{"auth location", map[string]interface{}{"server_url": "https://old.example/mcp", "capabilities": map[string]interface{}{"upstream_auth_location": "query", "upstream_auth_query_param": "key"}}},
		{"header name", map[string]interface{}{"server_url": "https://old.example/mcp", "capabilities": map[string]interface{}{"auth_header_name": "X-Token"}}},
		{"template", map[string]interface{}{"server_url": "https://old.example/mcp", "capabilities": map[string]interface{}{"upstream_auth_template": "{secret}"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reset()
			c.body["name"], c.body["transport"] = "safe", "streamable_http"
			w := putJSON(t, deps, tenant, user, server, c.body)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "请重新填写密钥") {
				t.Fatalf("%s change without token must be rejected: %d %s", c.name, w.Code, w.Body.String())
			}
		})
	}
	// 未变化的保存（只改名称/负责人）仍可不重填 token。
	reset()
	ok := putJSON(t, deps, tenant, user, server, map[string]interface{}{"name": "renamed", "owner": "ops", "server_url": "https://old.example/mcp", "transport": "streamable_http"})
	if ok.Code != http.StatusOK {
		t.Fatalf("saving without touching URL/auth must keep working without a token: %d %s", ok.Code, ok.Body.String())
	}
}

// C. 带 *** 且换了 host 的 URL：不还原旧明文（旧值不得流向任意新 host）。
func TestAdvReviewC_RedactedPlaceholderNotRestoredAcrossOrigins(t *testing.T) {
	for _, tc := range []struct{ name, submitted, stored string }{
		{"other host", "https://evil.example/mcp?key=***", "https://good.example/mcp?key=REALSECRET1"},
		{"other scheme", "http://good.example/mcp?key=***", "https://good.example/mcp?key=REALSECRET1"},
		{"other port", "https://good.example:8443/mcp?key=***", "https://good.example/mcp?key=REALSECRET1"},
		{"other path", "https://good.example/other?key=***", "https://good.example/mcp?key=REALSECRET1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := restoreRedactedQueryValues(tc.submitted, tc.stored)
			if err == nil && strings.Contains(got, "REALSECRET1") {
				t.Fatalf("old plaintext must not be restored into a different origin/path: %q", got)
			}
			if err == nil {
				t.Fatalf("an unrestorable placeholder must be rejected, got %q", got)
			}
		})
	}
	// 同源同路径仍还原（回归保护）。
	got, err := restoreRedactedQueryValues("https://good.example/mcp?key=***&lang=***", "https://good.example/mcp?key=REALSECRET1&lang=zh")
	if err != nil || !strings.Contains(got, "REALSECRET1") {
		t.Fatalf("same origin+path must still restore: %q err=%v", got, err)
	}
}

// C. 对 quarantined / revoked 的服务，测试连接与同步不得用库中密钥外呼（不能借此把密钥发往未审批地址）。
func TestAdvReviewC_QuarantinedServerDoesNotSendStoredSecret(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "review-c-key3")
	var hits int
	useLoopbackUpstreamClients(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	ct, ref, _ := secrets.EncryptProviderSecret("STORED-SECRET-999999")
	for _, status := range []string{"quarantined", "revoked"} {
		server := &repository.MCPServer{ID: "s", TenantID: "t", ServerURL: srv.URL + "/mcp", Transport: "streamable_http",
			AuthCiphertext: ct, AuthKeyRef: ref, AdmissionStatus: status, QuarantineReason: "route_binding_changed",
			AllowPrivateEgress: true, Capabilities: map[string]interface{}{}}
		if _, kind, err := testMCPServerConnection(context.Background(), server); err == nil || kind != "quarantined" ||
			!strings.Contains(err.Error(), "复核") {
			t.Fatalf("[%s] test-connection must refuse with a review hint: kind=%q err=%v", status, kind, err)
		}
		if _, err := fetchMCPManifestForServer(context.Background(), server); err == nil || !strings.Contains(err.Error(), "复核") {
			t.Fatalf("[%s] sync must refuse with a review hint: %v", status, err)
		}
	}
	if hits != 0 {
		t.Fatalf("no request (and no stored secret) may leave for a quarantined/revoked server, hits=%d", hits)
	}

	// 反例：因清单漂移被隔离、路由未变的服务，仍要继续同步供管理员复核新清单（外呼照常）。
	drift := &repository.MCPServer{ID: "s2", TenantID: "t", ServerURL: srv.URL + "/mcp", Transport: "streamable_http",
		AuthCiphertext: ct, AuthKeyRef: ref, AdmissionStatus: "quarantined", QuarantineReason: "rug_pull_manifest_changed",
		AllowPrivateEgress: true, Capabilities: map[string]interface{}{}}
	_, _, _ = testMCPServerConnection(context.Background(), drift)
	if hits == 0 {
		t.Fatal("a quarantine that is not about the route (e.g. manifest drift) must still allow syncing for review")
	}
}

// K. Get 返回非 ErrNoRows 错误时直接 500，不能吞掉后继续写库。
// 构造“Get 失败而随后的 Update 会成功”：把 trust_level 置 NULL，scanMCPServer 把它扫进非指针 string
// 会失败（非 ErrNoRows）；而 Update 会直接覆盖该列，因此若处理器吞掉 Get 错误，写库会成功并返回 200。
func TestAdvReviewK_UpdateFailsClosedOnGetError(t *testing.T) {
	db, deps, tenant, user, server := mcpHardeningDatabaseFixture(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `UPDATE mcp_servers SET trust_level=NULL WHERE tenant_id=$1 AND id=$2`, tenant, server); err != nil {
		t.Fatal(err)
	}
	if _, gerr := deps.MCPServerRepo.Get(ctx, tenant, server); gerr == nil || errors.Is(gerr, pgx.ErrNoRows) {
		t.Fatalf("precondition: Get must fail with a non-ErrNoRows error, got %v", gerr)
	}
	w := putJSON(t, deps, tenant, user, server, map[string]interface{}{"name": "mutated-by-bug", "server_url": "https://mcp.example/rpc", "transport": "streamable_http"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("a non-ErrNoRows Get failure must yield 500 and stop before writing: %d %s", w.Code, w.Body.String())
	}
	var name string
	_ = db.QueryRow(ctx, `SELECT name FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&name)
	if name == "mutated-by-bug" {
		t.Fatal("the update must not have been written after Get failed")
	}
}

// D. 脱敏默认全敏感：任意 query 值都脱敏，仅白名单参数保留；密钥名单补全且大小写不敏感。
func TestAdvReviewD_RedactURLDefaultsToRedactAndAllowlistKeepsKnownSafeParams(t *testing.T) {
	got := mcpupstream.RedactURL("https://x.example/sse?x-amz-signature=SIG123&sessionId=abc&version=1&foo=BARSECRET&Region=cn&lang=zh")
	for _, leak := range []string{"SIG123", "BARSECRET", "abc"} {
		if strings.Contains(got, leak) {
			t.Fatalf("unknown params and session ids must be redacted by default, leaked %q in %q", leak, got)
		}
	}
	// 复审 L-2：会话 id 可能被当作凭据重放，不在白名单里；白名单只留真正非敏感的参数。
	for _, keep := range []string{"version=1", "lang=zh", "Region=cn"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("allowlisted param %q must be kept: %q", keep, got)
		}
	}
}

func TestAdvReviewD_SplitRecognizesExpandedSecretNamesCaseInsensitively(t *testing.T) {
	for _, name := range []string{"access_key", "SECRET_KEY", "secretkey", "auth_token", "API_TOKEN", "apitoken", "refresh_token", "Access_Token", "signature", "sign", "jwt", "X-Api-Key"} {
		_, ex, err := mcpupstream.SplitURLSecrets("https://x.example/mcp?" + name + "=VALUE12345")
		if err != nil || ex == nil || ex.Secret != "VALUE12345" {
			t.Fatalf("%q must be treated as a secret name: ex=%+v err=%v", name, ex, err)
		}
	}
	// 普通参数不能被误当密钥拆走。
	for _, name := range []string{"lang", "region", "sessionId", "version", "format", "page", "limit"} {
		clean, ex, _ := mcpupstream.SplitURLSecrets("https://x.example/mcp?" + name + "=v1")
		if ex != nil || !strings.Contains(clean, name+"=v1") {
			t.Fatalf("%q is not a secret and must stay in the URL: %q ex=%+v", name, clean, ex)
		}
	}
	// 未知参数名：脱敏时默认遮蔽，但自动拆分不拆（只拆明确的密钥名）。
	clean, ex, _ := mcpupstream.SplitURLSecrets("https://x.example/mcp?customthing=ZZZ")
	if ex != nil || !strings.Contains(clean, "customthing=ZZZ") {
		t.Fatalf("unknown names must not be auto-split: %q", clean)
	}
	if strings.Contains(mcpupstream.RedactURL("https://x.example/mcp?customthing=ZZZ"), "ZZZ") {
		t.Fatal("but unknown names must still be redacted for display/logging")
	}
}

// G. 控制面拉取：存量行保持原有请求头（不带统一 UA）；新能力行才带；存量已存的“被新黑名单拦住的头名”继续可用，
// 新建/修改保存时才校验。
func TestAdvReviewG_ControlPlaneLegacyRowKeepsPreRefactorRequestHeaders(t *testing.T) {
	useLoopbackUpstreamClients(t)
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "cp-legacy-bytes")
	var seen []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Clone())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","tools":[]}}`))
	}))
	defer srv.Close()
	ct, ref, _ := secrets.EncryptProviderSecret("cp-secret")
	legacy := &repository.MCPServer{ID: "s", TenantID: "t", ServerURL: srv.URL + "/mcp", Transport: "streamable_http",
		AuthCiphertext: ct, AuthKeyRef: ref, AllowPrivateEgress: true, Capabilities: map[string]interface{}{"protocol_version": "2025-11-25"}}
	if _, _, err := testMCPServerConnection(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	for _, h := range seen {
		if ua := h.Get("User-Agent"); strings.Contains(ua, "JJDGuard-MCP") {
			t.Fatalf("legacy control-plane request must keep the pre-refactor UA (Go default), got %q", ua)
		}
	}
	seen = nil
	fresh := *legacy
	fresh.Capabilities = map[string]interface{}{"upstream_extra_headers": map[string]interface{}{"X-Tenant": "a"}}
	if _, _, err := testMCPServerConnection(context.Background(), &fresh); err != nil {
		t.Fatal(err)
	}
	for _, h := range seen {
		if !strings.HasPrefix(h.Get("User-Agent"), "JJDGuard-MCP/") || h.Get("X-Tenant") != "a" {
			t.Fatalf("rows with new fields use the product UA and extra headers: %v", h)
		}
	}
}

func TestAdvReviewG_StoredBlacklistedHeaderNameStillSyncsButCannotBeSavedNew(t *testing.T) {
	useLoopbackUpstreamClients(t)
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "cp-legacy-bytes2")
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Te")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}`))
	}))
	defer srv.Close()
	ct, ref, _ := secrets.EncryptProviderSecret("stored-te-secret")
	stored := &repository.MCPServer{ID: "s", TenantID: "t", ServerURL: srv.URL + "/mcp", Transport: "streamable_http",
		AuthCiphertext: ct, AuthKeyRef: ref, AllowPrivateEgress: true, Capabilities: map[string]interface{}{"auth_header_name": "Te"}}
	if _, _, err := testMCPServerConnection(context.Background(), stored); err != nil {
		t.Fatalf("a stored header name that only the new blacklist rejects must keep working: %v", err)
	}
	if got != "stored-te-secret" {
		t.Fatalf("stored header must carry the secret, got %q", got)
	}
	// 新建 / 修改保存时按新黑名单校验。
	if _, err := prepareMCPServerInput("https://x.example/mcp", "streamable_http", map[string]interface{}{"auth_header_name": "Te"}, "tok", nil); err == nil {
		t.Fatal("saving a new/changed config with a blacklisted auth header must be rejected")
	}
	// 保存时未改动鉴权头名（只是回传存量值）则放行。
	if _, err := prepareMCPServerInput("https://x.example/mcp", "streamable_http", map[string]interface{}{"auth_header_name": "Te"}, "tok", map[string]interface{}{"auth_header_name": "Te"}); err != nil {
		t.Fatalf("an unchanged stored header name must not block unrelated edits: %v", err)
	}
}
