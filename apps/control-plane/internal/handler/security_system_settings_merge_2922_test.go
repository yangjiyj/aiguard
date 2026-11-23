package handler

// 合流（2B + 批次 4 + 批次 5）：PUT /admin/v1/security/system-settings 的白名单扩到批次 4 的平台级
// 防护键。控制台（批次 5）对这些键只发这一个接口，请求体与 /system/settings 相同的键值形式
// （布尔、数字原样，semantic_block_stages 是 JSON 字符串），不带 expected_version。
// 校验复用 updateSettingsWithScope 的通用链（runtimeoptions、布尔、置信度范围），写入推进语义
// 配置版本（updated_at），签名投影的修订号按内容计算随之变化；写操作审计带前后值。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 控制台 SecuritySettingsSections.tsx、FilePolicySettings.tsx、ClassifiedOutputDisposition.tsx 实际发出的形态。
var consoleSecuritySystemSettingsBody = map[string]any{
	"guardrail_fail_closed_enabled":       true,
	"security_capacity_fail_mode":         "closed",
	"mcp_policy_fail_mode":                "closed",
	"retention_failure_mode":              "closed",
	"output_security_mode":                "strict_buffered",
	"output_strict_max_bytes":             2097152,
	"confidence_gating_enabled":           false,
	"confidence_threshold":                0.7,
	"semantic_block_stages":               `["agent","input"]`,
	"agent_security_monitor_disposition":  "follow_policy",
	"model_output_classified_disposition": "follow_policy",
	"upload_inspection_failure_action":    "block",
	"agentguard_allow_self_approval":      true,
}

var consoleSecuritySystemSettingsStored = map[string]string{
	"guardrail_fail_closed_enabled": "true", "security_capacity_fail_mode": "closed", "mcp_policy_fail_mode": "closed",
	"retention_failure_mode": "closed", "output_security_mode": "strict_buffered", "output_strict_max_bytes": "2097152",
	"confidence_gating_enabled": "false", "confidence_threshold": "0.7", "semantic_block_stages": `["input","agent"]`,
	"agent_security_monitor_disposition": "follow_policy", "model_output_classified_disposition": "follow_policy",
	"upload_inspection_failure_action": "block", "agentguard_allow_self_approval": "true",
}

func putSecuritySystemSettings(repo SystemRepo, role, tenant string, body map[string]any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/security/system-settings", strings.NewReader(string(raw)))
	user := &repository.User{ID: "u-" + role, TenantID: tenant, Role: role, Status: "active"}
	req = req.WithContext(permission.WithSoDAllowed(context.WithValue(req.Context(), auth.UserKey, user)))
	rec := httptest.NewRecorder()
	UpdateSecuritySystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(rec, req)
	return rec
}

func TestSecuritySystemSettingsWritesPlatformRuntimeKeysInConsoleShape(t *testing.T) {
	for _, tc := range []struct {
		name, role, tenant string
		want               int
	}{
		{"platform security officer", "security_officer", semanticConfigTenant, http.StatusOK},
		{"platform admin", "platform_admin", semanticConfigTenant, http.StatusOK},
		{"tenant security officer", "security_officer", "tenant-a", http.StatusForbidden},
		{"auditor", "auditor", semanticConfigTenant, http.StatusForbidden},
		{"tenant admin", "tenant_admin", semanticConfigTenant, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newVersionedRepo(nil)
			rec := putSecuritySystemSettings(repo, tc.role, tc.tenant, consoleSecuritySystemSettingsBody)
			if rec.Code != tc.want {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if tc.want != http.StatusOK {
				if len(repo.settings) != 0 || len(repo.auditOps) != 0 {
					t.Fatalf("refused write must not persist or audit: %v %v", repo.settings, repo.auditOps)
				}
				return
			}
			for key, want := range consoleSecuritySystemSettingsStored {
				if repo.settings[key] != want {
					t.Errorf("%s stored %q want %q", key, repo.settings[key], want)
				}
			}
			if len(repo.settings) != len(consoleSecuritySystemSettingsStored) {
				t.Fatalf("only the submitted keys may be written: %v", repo.settings)
			}
		})
	}
}

// 每个可写键都能单独提交（控制台只提交改动过的键）。
func TestSecuritySystemSettingsAcceptsEachWritableKeyAlone(t *testing.T) {
	for key, value := range consoleSecuritySystemSettingsBody {
		repo := newVersionedRepo(nil)
		rec := putSecuritySystemSettings(repo, "security_officer", semanticConfigTenant, map[string]any{key: value})
		if rec.Code != http.StatusOK || repo.settings[key] != consoleSecuritySystemSettingsStored[key] || len(repo.settings) != 1 {
			t.Fatalf("%s: status=%d body=%s stored=%v", key, rec.Code, rec.Body.String(), repo.settings)
		}
	}
}

// 校验与语义设置入口是同一套：非法值 400，不落库、不审计。
func TestSecuritySystemSettingsReusesRuntimeValidation(t *testing.T) {
	for key, bad := range map[string]any{
		"security_capacity_fail_mode":         "block",
		"mcp_policy_fail_mode":                "deny",
		"retention_failure_mode":              "close",
		"output_security_mode":                "buffered",
		"output_strict_max_bytes":             1023,
		"semantic_block_stages":               `[]`,
		"agent_security_monitor_disposition":  "block",
		"model_output_classified_disposition": "alert",
		"upload_inspection_failure_action":    "allow",
		"confidence_threshold":                1.5,
		"guardrail_fail_closed_enabled":       "maybe",
		"confidence_gating_enabled":           "yes",
		"agentguard_allow_self_approval":      "yes",
	} {
		repo := newVersionedRepo(nil)
		rec := putSecuritySystemSettings(repo, "platform_admin", semanticConfigTenant, map[string]any{key: bad})
		if rec.Code != http.StatusBadRequest || len(repo.settings) != 0 || len(repo.auditOps) != 0 {
			t.Fatalf("%s=%v must be rejected: status=%d saved=%v", key, bad, rec.Code, repo.settings)
		}
	}
}

// 白名单外仍 400：全局执行模式、语义检测与研判、系统类键、身份源出站键只走各自入口。
func TestSecuritySystemSettingsStillRejectsKeysOutsideTheList(t *testing.T) {
	for _, key := range []string{"security_execution_mode", "security_audit_only", "semantic_enabled", "judge_url",
		"judge_api_key", "log_retention_days", "outbound_proxy_url", "content_file_policy_json", "rule_pack_missing_action",
		"idp_block_private", "ldap_allowed_targets", "expected_version"} {
		repo := newVersionedRepo(nil)
		rec := putSecuritySystemSettings(repo, "platform_admin", semanticConfigTenant, map[string]any{key: "x", "mcp_policy_fail_mode": "open"})
		if rec.Code != http.StatusBadRequest || len(repo.settings) != 0 {
			t.Fatalf("%s must be rejected by the security endpoint: status=%d saved=%v", key, rec.Code, repo.settings)
		}
	}
}

// 审计只记本次改动的键的前后值。
func TestSecuritySystemSettingsAuditsBeforeAndAfter(t *testing.T) {
	repo := newVersionedRepo(map[string]string{"mcp_policy_fail_mode": "open", "retention_failure_mode": "open"})
	rec := putSecuritySystemSettings(repo, "security_officer", semanticConfigTenant, map[string]any{"mcp_policy_fail_mode": "closed"})
	if rec.Code != http.StatusOK || len(repo.auditOps) != 1 {
		t.Fatalf("status=%d audit=%v", rec.Code, repo.auditOps)
	}
	op := repo.auditOps[0]
	if op.ActionType != "update_security_system_settings" {
		t.Fatalf("action=%s", op.ActionType)
	}
	raw, _ := json.Marshal(op.ActionDetail)
	var detail struct {
		Before map[string]string `json:"before"`
		After  map[string]string `json:"after"`
	}
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatalf("detail=%s err=%v", raw, err)
	}
	if detail.Before["mcp_policy_fail_mode"] != "open" || detail.After["mcp_policy_fail_mode"] != "closed" {
		t.Fatalf("detail=%s", raw)
	}
	if _, untouched := detail.Before["retention_failure_mode"]; untouched || len(detail.After) != 1 {
		t.Fatalf("only touched keys belong in the audit: %s", raw)
	}
}

// 写入推进语义配置版本：语义检测控制台拿着旧 config_version 保存会 409；签名投影修订号按内容变化。
func TestSecuritySystemSettingsAdvancesSemanticVersionAndRevision(t *testing.T) {
	repo := newVersionedRepo(map[string]string{"mcp_policy_fail_mode": "open"})
	before, err := semanticConfigVersion(context.Background(), &Dependencies{SystemRepo: repo})
	if err != nil {
		t.Fatal(err)
	}
	beforeConfigs, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(map[string]string{"mcp_policy_fail_mode": "open"}))
	if err != nil {
		t.Fatal(err)
	}
	if rec := putSecuritySystemSettings(repo, "security_officer", semanticConfigTenant, map[string]any{"mcp_policy_fail_mode": "closed"}); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	after, err := semanticConfigVersion(context.Background(), &Dependencies{SystemRepo: repo})
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatal("a write through the security endpoint must advance the semantic config version")
	}
	stale := putSemantic(t, repo, nil, "security_officer", semanticConfigTenant, map[string]any{"expected_version": before, "retention_failure_mode": "closed"})
	if stale.Code != http.StatusConflict {
		t.Fatalf("the semantic console with a stale version must get 409: %d %s", stale.Code, stale.Body.String())
	}
	afterConfigs, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(map[string]string{"mcp_policy_fail_mode": repo.settings["mcp_policy_fail_mode"]}))
	if err != nil {
		t.Fatal(err)
	}
	if afterConfigs.Gateway["mcp_policy_fail_mode"] != "closed" || afterConfigs.GatewayRevision == beforeConfigs.GatewayRevision {
		t.Fatalf("signed gateway projection must carry the new value with a new revision: %v %s -> %s",
			afterConfigs.Gateway["mcp_policy_fail_mode"], beforeConfigs.GatewayRevision, afterConfigs.GatewayRevision)
	}
}

// 安全员 GET /system/settings 读回每个可写键（控制台的安全员页面只读这里）。
func TestSecurityOfficerReadsBackEveryWritableKey(t *testing.T) {
	for _, key := range securityWritableSettingKeyList {
		if !securityOfficerSettingKeys[key] {
			t.Errorf("%s is writable by security officers but missing from their settings view", key)
		}
	}
	repo := newVersionedRepo(consoleSecuritySystemSettingsStored)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/system/settings", nil)
	user := &repository.User{ID: "officer", TenantID: semanticConfigTenant, Role: "security_officer", Status: "active"}
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
	rec := httptest.NewRecorder()
	GetSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for key, want := range consoleSecuritySystemSettingsStored {
		if got[key] != want {
			t.Errorf("officer view %s=%v want %q", key, got[key], want)
		}
	}
}

// 白名单与共享包对齐：批次 4 的运行时选项全部可经安全员接口写。
func TestSecurityWritableListCoversRuntimeOptions(t *testing.T) {
	for _, key := range runtimeSecurityWritableKeys {
		if !securityWritableSettingKeys[key] {
			t.Errorf("%s missing from the security officer writable list", key)
		}
	}
	if len(securityWritableSettingKeys) != len(securityWritableSettingKeyList) {
		t.Fatal("writable list has duplicates")
	}
}

// 合流（批次 3）：正向代理 7 个键也由安全员接口写；校验、出站放宽审计（egress_override.enable，改前值取
// 环境变量折算的生效值）与 PUT /system/settings 同一条链。身份源与 LDAP 键仍只归平台管理员。
func TestSecuritySystemSettingsWritesForwardProxyEgressKeys(t *testing.T) {
	t.Setenv("GATEWAY_FORWARD_PROXY_MODE", "deny_unlisted")
	body := map[string]any{
		"forward_proxy_egress_allow_private":  false,
		"forward_proxy_egress_allow_loopback": true,
		"forward_proxy_egress_allow_metadata": false,
		"forward_proxy_egress_allowed_cidrs":  `["10.20.0.0/16"]`,
		"forward_proxy_egress_allowed_hosts":  `["api.internal.example"]`,
		"forward_proxy_unlisted_action":       "allow_audit",
		"proxy_whitelist_fail_mode":           "closed",
	}
	repo := newVersionedRepo(nil)
	if rec := putSecuritySystemSettings(repo, "security_officer", semanticConfigTenant, body); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	for key := range body {
		if _, ok := repo.settings[key]; !ok {
			t.Errorf("%s not stored: %v", key, repo.settings)
		}
	}
	if repo.settings["forward_proxy_egress_allow_loopback"] != "true" || repo.settings["forward_proxy_unlisted_action"] != "allow_audit" {
		t.Fatalf("stored=%v", repo.settings)
	}
	loosened := false
	for _, op := range repo.auditOps {
		if op.ActionType == egressOverrideEnableAuditAction {
			loosened = true
		}
	}
	if !loosened {
		t.Fatalf("opening egress through the security endpoint must write %s: %+v", egressOverrideEnableAuditAction, repo.auditOps)
	}
	if rec := putSecuritySystemSettings(newVersionedRepo(nil), "security_officer", "tenant-a", map[string]any{"forward_proxy_unlisted_action": "allow_audit"}); rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-level officers cannot loosen platform egress: %d", rec.Code)
	}
	if rec := putSecuritySystemSettings(newVersionedRepo(nil), "security_officer", semanticConfigTenant, map[string]any{"forward_proxy_unlisted_action": "open_everything"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid egress values are rejected by the shared validation: %d", rec.Code)
	}
	for _, key := range identityEgressSettingKeys {
		if rec := putSecuritySystemSettings(newVersionedRepo(nil), "security_officer", semanticConfigTenant, map[string]any{key: "true"}); rec.Code != http.StatusBadRequest {
			t.Fatalf("identity egress key %s stays platform-admin only: %d", key, rec.Code)
		}
	}
}

// 安全员 GET /system/settings 读回正向代理键的生效值和来源（fillPlatformEgressEffectiveValues），
// 来源表只含安全员可见的键，不带身份源、LDAP 键。
func TestSecurityOfficerReadsForwardProxyEffectiveValuesWithSources(t *testing.T) {
	t.Setenv("GATEWAY_FORWARD_PROXY_MODE", "tunnel_audit")
	repo := newVersionedRepo(map[string]string{"forward_proxy_egress_allow_loopback": "true"})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/system/settings", nil)
	user := &repository.User{ID: "officer", TenantID: semanticConfigTenant, Role: "security_officer", Status: "active"}
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
	rec := httptest.NewRecorder()
	GetSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(rec, req)
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	sources, _ := got["egress_setting_sources"].(map[string]any)
	if got["forward_proxy_egress_allow_loopback"] != "true" || sources["forward_proxy_egress_allow_loopback"] != "db" {
		t.Fatalf("stored value with source db: %v %v", got["forward_proxy_egress_allow_loopback"], sources)
	}
	if got["forward_proxy_unlisted_action"] == nil || sources["forward_proxy_unlisted_action"] != "env" {
		t.Fatalf("deployment value with source env: %v %v", got["forward_proxy_unlisted_action"], sources)
	}
	if sources["forward_proxy_egress_allowed_cidrs"] != "default" {
		t.Fatalf("default source: %v", sources)
	}
	for _, key := range identityEgressSettingKeys {
		if _, leaked := got[key]; leaked {
			t.Errorf("identity egress key %s must not reach security officers", key)
		}
		if _, leaked := sources[key]; leaked {
			t.Errorf("identity egress source %s must not reach security officers", key)
		}
	}
}
