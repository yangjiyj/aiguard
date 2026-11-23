package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// e2eFixtureRelPath 是本仓内 security-engine 端到端测试消费的共享夹具（由真 Go 端点产出）。
// 相对 control-plane 包目录（internal/handler）回到仓根再进 security-engine tests/fixtures。
const e2eFixtureRelPath = "../../../security-engine/tests/fixtures/internal_semantic_config.json"

// TestGetInternalSemanticConfigWritesE2EFixture 是 SFIX-1(d) 端到端断言的 Go 半：
// 用 DB 配置态（Tier-1 开、FP 关、阈值 0.15/0.85）驱动**真** GetInternalSemanticConfig 端点，
// 断言响应确实 emit 了四键，并把响应体原样落到共享夹具。security-engine 的 test_semantic_config_e2e.py
// 再把此夹具喂进真 loader（httpx→map_config_to_overrides→apply_overrides）验证四键流到 feature_flags。
//
// 单一事实源：夹具由真 Go handler 产出，不是 Python 侧手写镜像——(a) 断链回归会让此处的四键断言先失败，
// 且夹具内容随之变化，下游 Python 断言也随之失败。
func TestGetInternalSemanticConfigWritesE2EFixture(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{
		"tier1_enabled":          "true",
		"fp_suppression_enabled": "false",
		"tier1_low_threshold":    "0.15",
		"tier1_high_threshold":   "0.85",
		// 2.9.22：引擎专用的处置与拦截阶段键（存了才下发），供引擎端到端测试读回。
		"semantic_block_stages":               `["agent","input"]`,
		"agent_security_monitor_disposition":  "follow_policy",
		"model_output_classified_disposition": "follow_policy",
		// 网关专用键不得出现在引擎夹具里。
		"output_security_mode": "strict_buffered",
	}}
	deps := semanticTestDeps(repo.settings)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/security/semantic-config", nil)
	w := httptest.NewRecorder()
	GetInternalSemanticConfig(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	// 断言真端点确实 emit 四键（SFIX-1(a) 修的断链——回归会在此先炸）。
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal endpoint body: %v; body=%s", err, w.Body.String())
	}
	if v, ok := got["tier1_enabled"].(bool); !ok || v != true {
		t.Fatalf("端点未 emit tier1_enabled=true（断链回归）: %#v", got["tier1_enabled"])
	}
	if v, ok := got["fp_suppression_enabled"].(bool); !ok || v != false {
		t.Fatalf("端点未 emit fp_suppression_enabled=false: %#v", got["fp_suppression_enabled"])
	}
	if got["tier1_low_threshold"] != "0.15" || got["tier1_high_threshold"] != "0.85" {
		t.Fatalf("端点未 emit 阈值: low=%#v high=%#v", got["tier1_low_threshold"], got["tier1_high_threshold"])
	}
	if got["semantic_block_stages"] != `["input","agent"]` || got["agent_security_monitor_disposition"] != "follow_policy" || got["model_output_classified_disposition"] != "follow_policy" {
		t.Fatalf("端点未 emit 2.9.22 引擎键: %#v", got)
	}
	if _, leaked := got["output_security_mode"]; leaked {
		t.Fatalf("网关专用键泄进引擎投影: %#v", got)
	}

	// 把真端点响应体落到共享夹具，供 security-engine 端到端测试消费。
	fixturePath, err := filepath.Abs(e2eFixtureRelPath)
	if err != nil {
		t.Fatalf("resolve fixture path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		t.Fatalf("mkdir fixture dir: %v", err)
	}
	if err := os.WriteFile(fixturePath, w.Body.Bytes(), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
