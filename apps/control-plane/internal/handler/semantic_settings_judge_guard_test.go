package handler

// High-3：安全员通过 PUT /security/semantic/settings 设置 judge_backend=custom、judge_url=任意公网 HTTPS，
// 返回 200 并落库，等于可以把受检内容外发；同一接口还能改 judge_api_key。改动前只有 platform_admin 能配研判地址。
//
// 约束（本文件逐条钉住）：
//  1. 安全员只能在 judge_backend=bundled 与 judge_backend=provider 之间切换，provider 必须是系统管理员已登记的 provider_id；
//     custom、judge_url、judge_api_key 一律只允许系统管理员修改，安全员提交即整体拒绝（403），中文提示，不得部分落库。
//  2. 审计记录变更前后的值：judge_url / judge_backend / judge_provider_id 记原值与新值；judge_api_key 只记「已变更/未变更」。
//  3. 并发控制：读取返回版本号，保存必须带回，不一致 409，避免后保存的覆盖先保存的。
//  4. 语义配置存放在全局 system_settings（全平台共享，不分租户）：租户级安全员不能改，只有平台级安全员（与平台管理员、
//     语义配置的 provider 解析同属平台默认租户 semanticConfigTenant）可以。

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// versionedRepo 在 capturingSystemRepo 之上实现带版本的原子写入，供 handler 单测使用。
type versionedRepo struct {
	capturingSystemRepo
	versions map[string]int64 // key -> 最近一次写入的版本（毫秒）
	clock    int64
}

func newVersionedRepo(initial map[string]string) *versionedRepo {
	r := &versionedRepo{versions: map[string]int64{}, clock: 1_000}
	r.settings = map[string]string{}
	for k, v := range initial {
		r.settings[k] = v
		r.versions[k] = r.clock
	}
	return r
}

func (r *versionedRepo) SetMultiple(_ context.Context, m map[string]string) error {
	r.clock++
	for k, v := range m {
		r.settings[k] = v
		r.versions[k] = r.clock
	}
	return nil
}

func (r *versionedRepo) GetUpdatedAt(_ context.Context, keys []string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	for _, k := range keys {
		if v, ok := r.versions[k]; ok {
			out[k] = time.UnixMilli(v).UTC()
		}
	}
	return out, nil
}

func (r *versionedRepo) SetMultipleIfVersion(ctx context.Context, guardKeys []string, expected string,
	versionOf func(map[string]time.Time) string, settings map[string]string) error {
	current, _ := r.GetUpdatedAt(ctx, guardKeys)
	if versionOf(current) != expected {
		return repository.ErrSystemSettingsVersionConflict
	}
	return r.SetMultiple(ctx, settings)
}

func (r *versionedRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	r.auditOps = append(r.auditOps, op)
	return nil
}

// providerStub 实现 ProviderRepo 中语义配置会用到的 GetByID；其余方法不会被调用。
type providerStub struct {
	ProviderRepo
	ids map[string]bool
}

func (p providerStub) GetByID(_ context.Context, _ string, id string) (*repository.Provider, error) {
	if p.ids[id] {
		return &repository.Provider{ID: id, BaseURL: "https://provider.example.test/v1"}, nil
	}
	return nil, nil
}

func providerRepoWith(ids map[string]bool) ProviderRepo { return providerStub{ids: ids} }

func semanticReq(role, tenant string, body map[string]any) *http.Request {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/security/semantic/settings", strings.NewReader(string(raw)))
	user := &repository.User{ID: "u-" + role, TenantID: tenant, Role: role, Status: "active"}
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	return req.WithContext(permission.WithSoDAllowed(ctx))
}

func putSemantic(t *testing.T, repo *versionedRepo, providers map[string]bool, role, tenant string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	deps := &Dependencies{SystemRepo: repo, ProviderRepo: providerRepoWith(providers)}
	rec := httptest.NewRecorder()
	UpdateSemanticSettings(deps).ServeHTTP(rec, semanticReq(role, tenant, body))
	return rec
}

func currentVersion(t *testing.T, repo *versionedRepo) string {
	t.Helper()
	deps := &Dependencies{SystemRepo: repo}
	v, err := semanticConfigVersion(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// ---- 1. 安全员不能改研判地址、custom 后端与密钥 ----

func TestSecurityOfficerCannotPointTheJudgeAtAnArbitraryURLOrKey(t *testing.T) {
	cases := map[string]map[string]any{
		"custom 后端":      {"judge_backend": "custom"},
		"任意公网 judge_url": {"judge_url": "https://203.0.113.50/v1/judge"},
		"custom 加地址":     {"judge_backend": "custom", "judge_url": "https://203.0.113.50/v1/judge", "judge_model": "x"},
		"改密钥":            {"judge_api_key": "sk-attacker"},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			repo := newVersionedRepo(map[string]string{"judge_backend": "bundled", "semantic_enabled": "true"})
			body["semantic_enabled"] = true // 夹带一个合法键：必须整体拒绝，合法键也不得落库
			body["expected_version"] = currentVersion(t, repo)
			rec := putSemantic(t, repo, nil, "security_officer", semanticConfigTenant, body)
			if rec.Code != http.StatusForbidden && rec.Code != http.StatusBadRequest {
				t.Fatalf("安全员改研判地址/密钥必须被拒（403/400），实际 %d %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "研判服务地址与密钥由系统管理员配置") {
				t.Fatalf("提示应为「研判服务地址与密钥由系统管理员配置」：%s", rec.Body.String())
			}
			if repo.settings["judge_url"] != "" || repo.settings["judge_api_key"] != "" || repo.settings["judge_backend"] != "bundled" {
				t.Fatalf("不得落库：%v", repo.settings)
			}
		})
	}
}

func TestSecurityOfficerMaySwitchBetweenBundledAndARegisteredProvider(t *testing.T) {
	repo := newVersionedRepo(map[string]string{"judge_backend": "bundled"})
	providers := map[string]bool{"prov-registered": true}

	rec := putSemantic(t, repo, providers, "security_officer", semanticConfigTenant, map[string]any{
		"judge_backend": "provider", "judge_provider_id": "prov-registered", "judge_model": "m1", "expected_version": currentVersion(t, repo)})
	if rec.Code != http.StatusOK || repo.settings["judge_provider_id"] != "prov-registered" {
		t.Fatalf("切到已登记 provider 应成功：%d %s %v", rec.Code, rec.Body.String(), repo.settings)
	}
	rec = putSemantic(t, repo, providers, "security_officer", semanticConfigTenant, map[string]any{
		"judge_backend": "bundled", "expected_version": currentVersion(t, repo)})
	if rec.Code != http.StatusOK || repo.settings["judge_backend"] != "bundled" {
		t.Fatalf("切回 bundled 应成功：%d %s", rec.Code, rec.Body.String())
	}
}

func TestSecurityOfficerCannotUseAnUnregisteredProvider(t *testing.T) {
	repo := newVersionedRepo(map[string]string{"judge_backend": "bundled"})
	rec := putSemantic(t, repo, map[string]bool{"prov-registered": true}, "security_officer", semanticConfigTenant, map[string]any{
		"judge_backend": "provider", "judge_provider_id": "prov-not-registered", "expected_version": currentVersion(t, repo)})
	if rec.Code == http.StatusOK || repo.settings["judge_provider_id"] != "" {
		t.Fatalf("未登记的 provider 不得保存：%d %s %v", rec.Code, rec.Body.String(), repo.settings)
	}
	// provider 模式不带 provider_id 同样不行。
	rec = putSemantic(t, repo, map[string]bool{"prov-registered": true}, "security_officer", semanticConfigTenant, map[string]any{
		"judge_backend": "provider", "expected_version": currentVersion(t, repo)})
	if rec.Code == http.StatusOK {
		t.Fatalf("provider 模式必须指定已登记的 provider_id：%d", rec.Code)
	}
}

func TestSystemAdministratorKeepsFullControlOfTheJudgeEndpointAndKey(t *testing.T) {
	repo := newVersionedRepo(map[string]string{"judge_backend": "bundled"})
	rec := putSemantic(t, repo, nil, "platform_admin", semanticConfigTenant, map[string]any{
		"judge_backend": "custom", "judge_url": "https://judge.example.test/v1/chat/completions", "judge_model": "m",
		"judge_api_key": "sk-admin-key", "expected_version": currentVersion(t, repo)})
	// 域名解析由校验网络层处理；这里只关心角色闸门：系统管理员不得被 403 拒绝。
	if rec.Code == http.StatusForbidden {
		t.Fatalf("系统管理员不应被角色闸门拒绝：%s", rec.Body.String())
	}
}

// ---- 2. 审计记录变更前后的值 ----

func TestSemanticSettingsAuditRecordsBeforeAndAfterWithoutTheKey(t *testing.T) {
	repo := newVersionedRepo(map[string]string{"judge_backend": "bundled", "judge_url": "https://old.example.test/v1", "judge_provider_id": "prov-old", "judge_api_key": "enc:v1:old"})
	rec := putSemantic(t, repo, map[string]bool{"prov-new": true}, "security_officer", semanticConfigTenant, map[string]any{
		"judge_backend": "provider", "judge_provider_id": "prov-new", "judge_model": "m2", "expected_version": currentVersion(t, repo)})
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var op *repository.AuditOperation
	for _, o := range repo.auditOps {
		if o.ActionType == "update_semantic_settings" {
			op = o
		}
	}
	if op == nil {
		t.Fatalf("没有语义配置审计：%v", repo.auditOps)
	}
	d := op.ActionDetail
	changes, _ := d["changes"].(map[string]interface{})
	if changes == nil {
		t.Fatalf("审计应含 changes（前后值）：%v", d)
	}
	assertChange := func(key, before, after string) {
		c, _ := changes[key].(map[string]interface{})
		if c == nil || c["before"] != before || c["after"] != after {
			t.Fatalf("%s 的前后值应为 %q -> %q：%v", key, before, after, changes[key])
		}
	}
	assertChange("judge_backend", "bundled", "provider")
	assertChange("judge_provider_id", "prov-old", "prov-new")
	if strings.Contains(strings.ToLower(jsonOf(d)), "enc:v1:old") || strings.Contains(jsonOf(d), "sk-") {
		t.Fatalf("审计不得含密钥密文/明文：%s", jsonOf(d))
	}
}

func TestSemanticSettingsAuditMarksTheKeyOnlyAsChangedOrUnchanged(t *testing.T) {
	repo := newVersionedRepo(map[string]string{"judge_backend": "bundled", "judge_api_key": "enc:v1:old"})
	rec := putSemantic(t, repo, nil, "platform_admin", semanticConfigTenant, map[string]any{
		"semantic_enabled": true, "expected_version": currentVersion(t, repo)})
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	d := lastSemanticAudit(t, repo).ActionDetail
	if d["judge_api_key"] != "unchanged" {
		t.Fatalf("未改密钥应记 unchanged：%v", d["judge_api_key"])
	}
}

// 系统管理员改了密钥：审计只能记「已变更」，不得出现密钥明文、密文或其任何片段。
func TestSemanticSettingsAuditNeverContainsTheKeyWhenItIsChanged(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "semantic-audit-test-key-not-production")
	repo := newVersionedRepo(map[string]string{"judge_backend": "custom", "judge_url": "https://old.example.test/v1", "judge_api_key": "enc:v1:OLDCIPHER"})
	// 桩解析器：让 judge_url 校验走完整路径而不依赖外网 DNS。
	resolver := &staticSemanticJudgeResolver{records: map[string][]net.IPAddr{"old.example.test": {{IP: net.ParseIP("93.184.216.34")}}}}
	deps := &Dependencies{SystemRepo: repo, ProviderRepo: providerRepoWith(nil)}
	rec := httptest.NewRecorder()
	updateSemanticSettingsWithNetwork(deps, semanticJudgeTestNetwork(resolver, nil)).ServeHTTP(rec, semanticReq("platform_admin", semanticConfigTenant, map[string]any{
		"judge_backend": "custom", "judge_url": "https://old.example.test/v1", "judge_model": "m",
		"judge_api_key": "sk-PLAINTEXT-SECRET", "expected_version": currentVersion(t, repo)}))
	if rec.Code != http.StatusOK {
		t.Fatalf("系统管理员配置 custom 研判应成功：%d %s", rec.Code, rec.Body.String())
	}
	d := lastSemanticAudit(t, repo).ActionDetail
	if d["judge_api_key"] != "changed" {
		t.Fatalf("改了密钥应记 changed：%v", d["judge_api_key"])
	}
	blob := jsonOf(d)
	stored := repo.settings["judge_api_key"]
	for _, leak := range []string{"sk-PLAINTEXT-SECRET", "OLDCIPHER", stored} {
		if leak != "" && strings.Contains(blob, leak) {
			t.Fatalf("审计泄露了密钥内容 %q：%s", leak, blob)
		}
	}
	for k := range d {
		if strings.Contains(k, "api_key") && k != "judge_api_key" {
			t.Fatalf("审计里不应有额外的密钥字段 %q：%v", k, d)
		}
	}
}

func jsonOf(v any) string { b, _ := json.Marshal(v); return string(b) }

func lastSemanticAudit(t *testing.T, repo *versionedRepo) *repository.AuditOperation {
	t.Helper()
	for i := len(repo.auditOps) - 1; i >= 0; i-- {
		if repo.auditOps[i].ActionType == "update_semantic_settings" {
			return repo.auditOps[i]
		}
	}
	t.Fatalf("没有语义配置审计：%v", repo.auditOps)
	return nil
}

// ---- 3. 并发控制：版本号 / 409 ----

func TestSemanticSettingsRejectsAStaleVersionWith409(t *testing.T) {
	repo := newVersionedRepo(map[string]string{"judge_backend": "bundled", "semantic_enabled": "false"})
	v0 := currentVersion(t, repo)

	// A、B 同时读到 v0；A 先保存成功，B 带着旧版本保存必须 409，且不覆盖 A 的修改。
	a := putSemantic(t, repo, nil, "security_officer", semanticConfigTenant, map[string]any{"semantic_enabled": true, "expected_version": v0})
	if a.Code != http.StatusOK {
		t.Fatalf("A 应成功：%d %s", a.Code, a.Body.String())
	}
	b := putSemantic(t, repo, nil, "security_officer", semanticConfigTenant, map[string]any{"semantic_enabled": false, "expected_version": v0})
	if b.Code != http.StatusConflict {
		t.Fatalf("B 带旧版本必须 409，实际 %d %s", b.Code, b.Body.String())
	}
	if !strings.Contains(b.Body.String(), "version_conflict") || !containsChinese(b.Body.String()) {
		t.Fatalf("409 应带 version_conflict 与中文提示：%s", b.Body.String())
	}
	if repo.settings["semantic_enabled"] != "true" {
		t.Fatalf("B 不得覆盖 A 的修改：%v", repo.settings)
	}
}

func TestSemanticSettingsRequiresTheVersionToBeSent(t *testing.T) {
	repo := newVersionedRepo(map[string]string{"judge_backend": "bundled"})
	rec := putSemantic(t, repo, nil, "security_officer", semanticConfigTenant, map[string]any{"semantic_enabled": true})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "expected_version") {
		t.Fatalf("不带 expected_version 必须 400：%d %s", rec.Code, rec.Body.String())
	}
	if repo.settings["semantic_enabled"] != "" {
		t.Fatalf("不得落库：%v", repo.settings)
	}
}

func TestSemanticSettingsVersionIsReturnedOnRead(t *testing.T) {
	repo := newVersionedRepo(map[string]string{"judge_backend": "bundled", "semantic_enabled": "true"})
	deps := &Dependencies{SystemRepo: repo}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/security/semantic/settings", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u", TenantID: semanticConfigTenant, Role: "security_officer"}))
	GetSemanticSettings(deps).ServeHTTP(rec, req)
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got["config_version"] != currentVersion(t, repo) || got["config_version"] == "" {
		t.Fatalf("读取应返回 config_version：%d %v", rec.Code, got)
	}
	if got["judge_backend"] != "bundled" {
		t.Fatalf("读取应返回语义配置键：%v", got)
	}
	if _, leaked := got["judge_api_key"]; leaked && got["judge_api_key"] != maskedSecretValue {
		t.Fatalf("读取不得返回密钥原文：%v", got["judge_api_key"])
	}
}

// ---- 4. 租户级安全员不能改全局语义配置 ----

func TestTenantScopedSecurityOfficerCannotChangeTheGlobalSemanticConfig(t *testing.T) {
	repo := newVersionedRepo(map[string]string{"semantic_enabled": "false"})
	rec := putSemantic(t, repo, nil, "security_officer", "tenant-a", map[string]any{"semantic_enabled": true, "expected_version": currentVersion(t, repo)})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("租户级安全员改全局语义配置必须 403：%d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "全平台") {
		t.Fatalf("提示应说明这是全平台共享配置：%s", rec.Body.String())
	}
	if repo.settings["semantic_enabled"] != "false" {
		t.Fatalf("不得落库：%v", repo.settings)
	}
	// 平台级安全员（平台默认租户）可以。
	rec = putSemantic(t, repo, nil, "security_officer", semanticConfigTenant, map[string]any{"semantic_enabled": true, "expected_version": currentVersion(t, repo)})
	if rec.Code != http.StatusOK {
		t.Fatalf("平台级安全员应可保存：%d %s", rec.Code, rec.Body.String())
	}
}
