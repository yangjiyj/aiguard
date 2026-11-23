package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 审查意见 7：GET /admin/v1/protection-settings 显示实际生效值。旧 behavior_json 的突发阈值折算出的
// agent.burst=确认、旧 dlp_json 折算出的 agent.secret_egress 都要体现（configured=true，source=legacy），
// 不能显示“告警放行”而网关实际按确认/阻断执行；PUT 写入后以表里的行为准。
func legacyProtectionDeps(t *testing.T) (*Dependencies, *fakeProtectionStore) {
	t.Helper()
	agentRepo := newFakeAgentGuardPolicyRepo()
	agentRepo.policies["legacy"] = &repository.AgentGuardPolicy{
		ID: "legacy", TenantID: "tenant-a", ScopeType: "tenant", Enabled: true, Mode: "strict",
		BehaviorJSON: map[string]any{"file_read_burst_10s": float64(20)},
		DLPJSON:      map[string]any{"high_confidence_secret_egress": "block"},
		CreatedAt:    time.Now(), UpdatedAt: time.Now(),
	}
	store := &fakeProtectionStore{}
	return &Dependencies{ProtectionSettingsStore: store, AgentGuardPolicyRepo: agentRepo, SystemRepo: &captureAuditSystemRepo{}}, store
}

func protectionViews(t *testing.T, rec *httptest.ResponseRecorder) map[string]map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, item := range response.Items {
		out[item["key"].(string)] = item
	}
	return out
}

func TestProtectionSettings2922ShowLegacyEffectiveValues(t *testing.T) {
	deps, _ := legacyProtectionDeps(t)
	rec := httptest.NewRecorder()
	GetProtectionSettings(deps)(rec, protectionReq(http.MethodGet, "security_officer", nil))
	views := protectionViews(t, rec)
	if v := views["agent.burst"]; v["action"] != "confirm" || v["configured"] != true || v["source"] != "legacy" {
		t.Fatalf("legacy burst thresholds act as confirm and must show so: %v", v)
	}
	if v := views["agent.secret_egress"]; v["action"] != "block" || v["configured"] != true || v["source"] != "legacy" {
		t.Fatalf("legacy dlp_json acts as block and must show so: %v", v)
	}
	if v := views["agent.ssh_private_key"]; v["action"] != "alert_allow" || v["configured"] != false || v["source"] != nil {
		t.Fatalf("items without legacy configuration show the default: %v", v)
	}

	put := httptest.NewRecorder()
	UpdateProtectionSettings(deps)(put, protectionReq(http.MethodPut, "security_officer",
		map[string]any{"items": map[string]any{"agent.burst": map[string]any{"action": "alert_allow"}}}))
	views = protectionViews(t, put)
	if v := views["agent.burst"]; v["action"] != "alert_allow" || v["configured"] != true || v["source"] != nil {
		t.Fatalf("after a write the stored row wins: %v", v)
	}
	if v := views["agent.secret_egress"]; v["action"] != "block" || v["source"] != "legacy" {
		t.Fatalf("other legacy values stay visible: %v", v)
	}
	if got, _ := protectionsForEffectivePolicy(t.Context(), deps, "tenant-a", map[string]any{"high_confidence_secret_egress": "block"}, map[string]any{"file_read_burst_10s": 20}); got["agent.burst"].Action != protection.ActionAlertAllow {
		t.Fatalf("the gateway gets the same values the page shows: %+v", got)
	}
}
