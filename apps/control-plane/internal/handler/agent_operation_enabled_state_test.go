package handler

// Low-1：GetPolicy 的 SQL 带 enabled=true，被停用的策略被读成「未配置」。现在响应要带 enabled 字段，
// 三种状态互相区分：
//   enabled=true  + configured=true  ：已配置且启用；
//   enabled=false + configured=true  ：已配置但已停用（页面显示「已停用」，不显示默认值）；
//   enabled=true  + configured=false ：未配置（系统默认值）。

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func getProtection(t *testing.T, repo AgentOperationRepo, path string) map[string]any {
	t.Helper()
	deps := &Dependencies{AgentOperationRepo: repo}
	rec, req := agentOperationRequest(t, http.MethodGet, path, "", officerIn("tenant-a", "platform_admin"))
	GetAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestGetAgentOperationProtectionReportsEnabledStateForAllThreeCases(t *testing.T) {
	enabled := getProtection(t, &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "strict", Action: "block", Version: 4}},
		"/admin/v1/agent-operation-protection?tenant_scope=all")
	if enabled["enabled"] != true || enabled["configured"] != true || enabled["mode"] != "strict" {
		t.Fatalf("启用的策略：enabled=true configured=true：%v", enabled)
	}

	disabled := getProtection(t, &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "strict", Action: "block", Version: 4, Disabled: true}},
		"/admin/v1/agent-operation-protection?tenant_scope=all")
	if disabled["enabled"] != false || disabled["configured"] != true {
		t.Fatalf("已停用的策略必须是 enabled=false 且 configured=true（不是未配置）：%v", disabled)
	}
	if disabled["mode"] != "strict" || disabled["action"] != "block" {
		t.Fatalf("已停用的策略应原样返回它保存的内容，不能换成默认值：%v", disabled)
	}
	// 重新保存会新建启用行，版本从 1 开始；所以已停用策略读出的 version 必须是 1，页面照原样带回才能保存成功
	//（不是停用行自己的版本号，否则「已停用 -> 重新启用」会无条件 409）。
	if disabled["version"] != float64(1) {
		t.Fatalf("已停用的策略读出的 version 必须是 1（保存会新建启用行）：%v", disabled["version"])
	}

	unconfigured := getProtection(t, &notConfiguredAgentOperationRepo{err: repository.ErrAgentOperationNotFound}, "/admin/v1/agent-operation-protection?tenant_scope=all")
	if unconfigured["enabled"] != true || unconfigured["configured"] != false || unconfigured["config_source"] != "new_scope" {
		t.Fatalf("未配置：configured=false，默认值本身视为启用：%v", unconfigured)
	}
}
