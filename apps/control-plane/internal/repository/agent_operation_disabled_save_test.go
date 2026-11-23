package repository

// 停用的策略再保存：SavePolicy 的查找与更新条件都带 enabled=true，所以会把停用行当作不存在、新建一条启用行，
// 版本从 1 开始（读取停用策略时页面带的是停用行的版本号，需要用 1 保存）。这条测试把这个行为钉住，
// 也保证保存之后 GetPolicy 读到的是新的启用行，而不是继续显示「已停用」。

import (
	"context"
	"testing"
)

func TestSavingOverADisabledPolicyCreatesAFreshEnabledRowAndGetPolicyThenReportsIt(t *testing.T) {
	repo, db, tenantID := setupOperationPolicyDB(t)
	ctx := context.Background()
	insertPolicyRow(t, db, tenantID, "adp_stale_"+tenantID[len(tenantID)-8:], "strict", "block", false)

	before, err := repo.GetPolicy(ctx, tenantID, "tenant", "")
	if err != nil || !before.Disabled {
		t.Fatalf("前提：读到的应是已停用的策略：%+v err=%v", before, err)
	}

	stored, err := repo.SavePolicy(ctx, AgentOperationPolicyMutation{
		TenantID: tenantID, ScopeType: "tenant", ScopeRef: "", Mode: "light", Action: "alert_allow",
		ExpectedVersion: 1, ActorID: "tester", Source: "test",
	})
	if err != nil {
		t.Fatalf("在已停用的范围上以版本 1 保存应成功（新建启用行）：%v", err)
	}
	if stored.Version != 1 {
		t.Fatalf("新建的启用行版本应从 1 开始：%d", stored.Version)
	}
	after, err := repo.GetPolicy(ctx, tenantID, "tenant", "")
	if err != nil || after.Disabled || after.Mode != "light" {
		t.Fatalf("保存后应读到新的启用行：%+v err=%v", after, err)
	}
}
