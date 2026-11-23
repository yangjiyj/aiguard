package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor/providers"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
)

// 任务 2.7：team/key 级预算计量写入（P0-3b，支柱③）。
// 规格：team/key 维度请求 → 计量累加（fan-out 覆盖 team/key）→ 超额被拒。
//
// 现状根因：数据面计量只写 tenant/project/user（interfaces.go），team/key 维度
// 永远 0，故团队/单 key 配额形同虚设。本测试锁定计量 fan-out 必须覆盖全部 5 个维度，
// team/key 两维显式守护，防止再次回归到 0。
func TestBuildMeteringScopes_IncludesAllFiveScopes(t *testing.T) {
	env := &modelrouter.RequestEnvelope{
		TenantID:  "tenant-1",
		TeamID:    "team-1",
		ProjectID: "proj-1",
		UserID:    "user-1",
		ClientID:  "key-id-1",
		KeyPrefix: "sk-abc",
		Principal: &principal.Context{SchemaVersion: 1, TenantID: "tenant-1", ActorUserID: "user-1", ProjectID: "proj-1", ApplicationID: "proj-1", IdentitySource: principal.SourceSession, TrustLevel: principal.TrustAuthenticated},
	}

	scopes := buildMeteringScopes(env)

	got := map[string]string{}
	for _, s := range scopes {
		if _, dup := got[s.Scope]; dup {
			t.Fatalf("计量 fan-out 出现重复维度 %q", s.Scope)
		}
		got[s.Scope] = s.ID
	}

	want := map[string]string{
		"tenant":  "tenant-1",
		"team":    "team-1",
		"project": "proj-1",
		"user":    "user-1",
		"key":     "key-id-1",
	}
	for scope, id := range want {
		if got[scope] != id {
			t.Fatalf("计量维度 %q：期望 ID %q，实际 %q（scopes=%+v）", scope, id, got[scope], scopes)
		}
	}

	if got["team"] == "" {
		t.Fatalf("team 维度缺失：团队预算将永远计 0、配额形同虚设")
	}
	if got["key"] == "" {
		t.Fatalf("key 维度缺失：单 key 预算将永远计 0、配额形同虚设")
	}
	if _, ok := got["key_legacy"]; ok {
		t.Fatal("prefix compatibility bucket must not be written")
	}
}

func TestBuildMeteringScopesDoesNotTreatKeyOwnerAsActor(t *testing.T) {
	env := &modelrouter.RequestEnvelope{
		TenantID: "tenant-1", ProjectID: "project-1", UserID: "key-owner", ClientID: "key-1",
		Principal: &principal.Context{SchemaVersion: 1, TenantID: "tenant-1", KeyOwnerUserID: "key-owner", ProjectID: "project-1", ApplicationID: "project-1", KeyID: "key-1", IdentitySource: principal.SourceAPIKey, TrustLevel: principal.TrustKeyBound},
	}
	for _, scope := range buildMeteringScopes(env) {
		if scope.Scope == "user" && scope.ID != "" {
			t.Fatalf("key owner leaked into actor user quota: %+v", scope)
		}
	}
}

func TestBuildMeteringScopesIncludesApplicationTeamAncestorsWithoutDuplicates(t *testing.T) {
	env := &modelrouter.RequestEnvelope{
		TenantID: "tenant-1", TeamID: "team-child", ProjectID: "project-1",
		QuotaAccountingScopes: []modelrouter.QuotaAccountingScope{
			{Scope: "team", ID: "team-root"},
			{Scope: "team", ID: "team-child"},
		},
	}
	counts := make(map[string]int)
	for _, scope := range buildMeteringScopes(env) {
		counts[scope.Scope+":"+scope.ID]++
	}
	if counts["team:team-root"] != 1 || counts["team:team-child"] != 1 {
		t.Fatalf("ancestor/direct team scopes=%v", counts)
	}
}

// buildMeteringScopes 应无条件返回全部 5 维（含空 ID）——空 ID 交由
// aggregator.IncrementAllScopes 跳过，与既有 tenant/project/user 的无条件写入语义一致。
func TestBuildMeteringScopes_KeepsEmptyIDsForAggregatorToSkip(t *testing.T) {
	env := &modelrouter.RequestEnvelope{
		TenantID:  "tenant-1",
		ProjectID: "proj-1",
		// TeamID / UserID / KeyPrefix 留空：未分配团队、匿名等场景。
	}

	scopes := buildMeteringScopes(env)

	if len(scopes) != 5 {
		t.Fatalf("期望 5 个稳定维度，实际 %d 个：%+v", len(scopes), scopes)
	}
	var hasTeam, hasKey bool
	for _, s := range scopes {
		switch s.Scope {
		case "team":
			hasTeam = true
		case "key":
			hasKey = true
		}
	}
	if !hasTeam || !hasKey {
		t.Fatalf("即使 ID 为空，team/key 维度也应保留交给 aggregator 跳过；hasTeam=%v hasKey=%v", hasTeam, hasKey)
	}
	_ = providers.ScopeKey{} // 确保 providers 包被引用
}
