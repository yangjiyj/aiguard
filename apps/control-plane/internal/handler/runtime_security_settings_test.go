package handler

// 2.9.22 任务 4.4、4.5：故障处理与检测执行设置（system_settings）可在控制台改，
// 平台管理员和安全员可写（语义设置专用入口），写操作审计，经签名投影下发。

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

var runtimeSecurityTestValues = map[string]any{
	"security_capacity_fail_mode":         "closed",
	"mcp_policy_fail_mode":                "closed",
	"retention_failure_mode":              "closed",
	"output_security_mode":                "strict_buffered",
	"output_strict_max_bytes":             "2097152",
	"semantic_block_stages":               `["agent","input"]`,
	"agent_security_monitor_disposition":  "follow_policy",
	"model_output_classified_disposition": "follow_policy",
	"upload_inspection_failure_action":    "block",
	"guardrail_fail_closed_enabled":       true,
	"confidence_gating_enabled":           false,
	"confidence_threshold":                "0.7",
}

func TestRuntimeSecuritySettingsWritableBySecurityOfficerAndAdminWithAudit(t *testing.T) {
	for _, role := range []string{"security_officer", "platform_admin"} {
		rec, repo := putSemanticSettingsAs(t, role, runtimeSecurityTestValues)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s 保存故障处理与检测执行设置应成功：status=%d body=%s", role, rec.Code, rec.Body.String())
		}
		want := map[string]string{
			"security_capacity_fail_mode": "closed", "mcp_policy_fail_mode": "closed", "retention_failure_mode": "closed",
			"output_security_mode": "strict_buffered", "output_strict_max_bytes": "2097152",
			// 阶段按固定顺序规范化，便于签名与比对。
			"semantic_block_stages":              `["input","agent"]`,
			"agent_security_monitor_disposition": "follow_policy", "model_output_classified_disposition": "follow_policy",
			"upload_inspection_failure_action": "block",
			"guardrail_fail_closed_enabled":    "true", "confidence_gating_enabled": "false", "confidence_threshold": "0.7",
		}
		for key, value := range want {
			if repo.settings[key] != value {
				t.Fatalf("%s：%s 落库为 %q，期望 %q", role, key, repo.settings[key], value)
			}
		}
		if len(repo.auditOps) != 1 || repo.auditOps[0].ActionType != "update_semantic_settings" {
			t.Fatalf("%s：写操作必须审计：%+v", role, repo.auditOps)
		}
	}
	for _, role := range []string{"auditor", "viewer"} {
		rec, repo := putSemanticSettingsAs(t, role, map[string]any{"security_capacity_fail_mode": "closed"})
		if rec.Code != http.StatusForbidden || len(repo.settings) != 0 {
			t.Fatalf("%s 不能改故障处理设置：status=%d saved=%v", role, rec.Code, repo.settings)
		}
	}
}

func TestRuntimeSecuritySettingsRejectInvalidValues(t *testing.T) {
	for key, bad := range map[string]any{
		"security_capacity_fail_mode":         "block",
		"mcp_policy_fail_mode":                "",
		"retention_failure_mode":              "close",
		"output_security_mode":                "buffered",
		"output_strict_max_bytes":             "1023",
		"semantic_block_stages":               `["input","bogus"]`,
		"agent_security_monitor_disposition":  "block",
		"model_output_classified_disposition": "alert",
		"upload_inspection_failure_action":    "allow",
		"confidence_threshold":                "1.5",
	} {
		rec, repo := putSemanticSettingsAs(t, "platform_admin", map[string]any{key: bad})
		if rec.Code != http.StatusBadRequest || len(repo.settings) != 0 {
			t.Fatalf("%s=%v 应被拒：status=%d saved=%v", key, bad, rec.Code, repo.settings)
		}
	}
	for _, bad := range []string{`[]`, `"input"`, `["input","input"]`, `not-json`, `67108865`} {
		key := "semantic_block_stages"
		if bad == `67108865` {
			key = "output_strict_max_bytes"
		}
		rec, _ := putSemanticSettingsAs(t, "platform_admin", map[string]any{key: bad})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s=%s 应被拒：status=%d", key, bad, rec.Code)
		}
	}
}

func TestRuntimeSecuritySettingsProjectedOnlyWhenStored(t *testing.T) {
	// 未存的键不下发：网关、引擎各自取缺省（网关侧原环境变量只在此时作初值）。
	empty, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	for key := range runtimeSecurityTestValues {
		if key == guardrailFailClosedSettingKey || key == "confidence_gating_enabled" || key == "confidence_threshold" {
			continue
		}
		if _, ok := empty.Gateway[key]; ok {
			t.Fatalf("未配置的 %s 不应下发给网关：%#v", key, empty.Gateway)
		}
		if _, ok := empty.Engine[key]; ok {
			t.Fatalf("未配置的 %s 不应下发给引擎：%#v", key, empty.Engine)
		}
	}

	stored := map[string]string{}
	for key, value := range runtimeSecurityTestValues {
		switch v := value.(type) {
		case string:
			stored[key] = v
		case bool:
			if v {
				stored[key] = "true"
			} else {
				stored[key] = "false"
			}
		}
	}
	stored["semantic_block_stages"] = `["input","agent"]`
	configs, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(stored))
	if err != nil {
		t.Fatal(err)
	}
	gatewayWant := map[string]any{
		"security_capacity_fail_mode": "closed", "mcp_policy_fail_mode": "closed", "retention_failure_mode": "closed",
		"output_security_mode": "strict_buffered", "output_strict_max_bytes": "2097152",
		"upload_inspection_failure_action": "block", guardrailFailClosedSettingKey: true,
	}
	for key, value := range gatewayWant {
		if configs.Gateway[key] != value {
			t.Fatalf("网关投影 %s=%#v，期望 %#v", key, configs.Gateway[key], value)
		}
		if key != guardrailFailClosedSettingKey {
			if _, leaked := configs.Engine[key]; leaked {
				t.Fatalf("网关专用键 %s 不应进引擎投影", key)
			}
		}
	}
	engineWant := map[string]any{
		"semantic_block_stages":              `["input","agent"]`,
		"agent_security_monitor_disposition": "follow_policy", "model_output_classified_disposition": "follow_policy",
		"confidence_gating_enabled": false, "confidence_threshold": "0.7",
	}
	for key, value := range engineWant {
		if configs.Engine[key] != value {
			t.Fatalf("引擎投影 %s=%#v，期望 %#v", key, configs.Engine[key], value)
		}
		if _, leaked := configs.Gateway[key]; leaked {
			t.Fatalf("引擎专用键 %s 不应进网关投影", key)
		}
	}
	// 投影签名覆盖新键：改任一值，修订号都变。
	stored["output_security_mode"] = "stream_audit"
	changed, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(stored))
	if err != nil || changed.GatewayRevision == configs.GatewayRevision {
		t.Fatalf("网关修订号必须随新键变化：%v", err)
	}
	stored["model_output_classified_disposition"] = "observe"
	changed2, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(stored))
	if err != nil || changed2.EngineRevision == changed.EngineRevision {
		t.Fatalf("引擎修订号必须随新键变化：%v", err)
	}
}

func TestStoredInvalidRuntimeSecuritySettingIsNotProjected(t *testing.T) {
	// 绕过接口写进库的非法值不下发（组件取缺省），不让整份配置校验失败。
	configs, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(map[string]string{
		"security_capacity_fail_mode": "maybe", "semantic_block_stages": `["bogus"]`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := configs.Gateway["security_capacity_fail_mode"]; ok {
		t.Fatalf("非法值不应下发：%#v", configs.Gateway)
	}
	if _, ok := configs.Engine["semantic_block_stages"]; ok {
		t.Fatalf("非法值不应下发：%#v", configs.Engine)
	}
}

func TestSecurityOfficerViewIncludesRuntimeSecuritySettings(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{"security_capacity_fail_mode": "closed", "semantic_block_stages": `["input"]`}}
	view := securityOfficerSettingsView(context.Background(), &Dependencies{SystemRepo: repo}, mustSettings(t, repo), securityExecutionModeView{})
	if view["security_capacity_fail_mode"] != "closed" || view["semantic_block_stages"] != `["input"]` {
		raw, _ := json.Marshal(view)
		t.Fatalf("安全员视图缺少故障处理设置：%s", raw)
	}
}

func mustSettings(t *testing.T, repo *capturingSystemRepo) []*repository.SystemSetting {
	t.Helper()
	all, err := repo.GetAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return all
}

// 端到端夹具（控制面 Go 半）：按库里的故障处理与检测执行设置，用真网关端点产出签名投影，
// 写到 gateway-core 的 testdata，网关测试 TestGatewayReadsControlPlaneRuntimeFixture 读回验证。
// 部署变量为 true、库里是 protect：投影必须是防护模式（设计 D7）。
func TestGetInternalSemanticGatewayConfigWritesRuntimeFixture(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	deps := semanticTestDeps(map[string]string{
		"security_execution_mode": "protect", "security_audit_only": "false",
		"security_capacity_fail_mode": "closed", "mcp_policy_fail_mode": "closed", "retention_failure_mode": "closed",
		"output_security_mode": "strict_buffered", "output_strict_max_bytes": "2097152",
		"upload_inspection_failure_action": "block", "agent_security_monitor_disposition": "follow_policy",
	})
	// 与 gateway-core 测试里的 gatewaySemanticTestKey 一致。
	deps.SemanticGatewayAttestationKey = "semantic-gateway-test-key-32-bytes"
	w := httptest.NewRecorder()
	GetInternalSemanticGatewayConfig(deps).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/v1/internal/security/semantic-config/gateway", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["security_audit_only"] != false || got["security_capacity_fail_mode"] != "closed" || got["output_strict_max_bytes"] != "2097152" {
		t.Fatalf("网关投影不对：%#v", got)
	}
	if _, leaked := got["agent_security_monitor_disposition"]; leaked {
		t.Fatalf("引擎专用键泄进网关投影：%#v", got)
	}
	path, err := filepath.Abs("../../../gateway-core/internal/handler/testdata/semantic_gateway_runtime_config.json")
	if err != nil {
		t.Fatal(err)
	}
	if *updateRuntimeFixture {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, w.Body.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	// 缺省只比对：夹具与真端点产出不一致时失败，加 -update 才重写。
	stored, err := os.ReadFile(path)
	if err != nil || string(bytes.TrimSpace(stored)) != string(bytes.TrimSpace(w.Body.Bytes())) {
		t.Fatalf("网关端到端夹具与控制面产出不一致，确认后用 go test -run TestGetInternalSemanticGatewayConfigWritesRuntimeFixture -update 重写：%v\n夹具：%s\n产出：%s", err, stored, w.Body.Bytes())
	}
}

// updateRuntimeFixture 让 TestGetInternalSemanticGatewayConfigWritesRuntimeFixture 重写网关夹具。
var updateRuntimeFixture = flag.Bool("update", false, "rewrite the gateway runtime fixture from the real control-plane endpoint")

// 运行时选项的键直接列在写入白名单与安全员视图的声明里，与共享包对齐（不在 init 里补）。
func TestRuntimeOptionKeysListedInWritableAndOfficerViews(t *testing.T) {
	for _, key := range runtimeSecurityWritableKeys {
		if !semanticSettingsWritableKeys[key] {
			t.Errorf("%s 不在语义设置写入白名单", key)
		}
		if !securityOfficerSettingKeys[key] {
			t.Errorf("%s 不在安全员视图", key)
		}
	}
	if semanticSettingsWritableKeys["rule_pack_missing_action"] {
		t.Error("rule_pack_missing_action 只有一个取值，不写库")
	}
}
