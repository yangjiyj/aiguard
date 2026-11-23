package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 任务 3.8（P1-19）规格：ruleset/sync 占位落地。
//
// SyncRuleSet 必须把「权威规则集版本」与「各节点收敛情况」做成真实回答，
// 而不是返回占位串。权威版本沿用 3.7 的 rules.ContentVersion（引擎实际拉到的
// 同一指纹）；收敛情况从 3.7 的进程内台账（recordRulePackPull 记录）推导。
//
// 核心防坑点（本任务真正的 bug 风险）：收敛与否必须用「节点当前持有的
// HeldVersion」对比「当前权威版本」。ServedVersion 仅表示本次响应下发了什么；
// 节点必须在下一次拉取时回报已经持有该版本，才能算真正收敛。

// 节点 sync-cv-lagging 本次已被下发权威版本，但回报仍持有旧版本；
// 必须判为未收敛。这正是不能用 ServedVersion 冒充实际持有版本的反例。
func TestEvaluateRulePackConvergenceUsesAuthoritativeVersion(t *testing.T) {
	resetRulePackPullLedger(t)
	at := time.Date(2026, 6, 9, 10, 0, 0, 0, time.UTC)
	setRulePackStatusNow(t, at)
	tenant := "tenant_sync_cv"
	authoritative := "ruleset-version-current"
	old := "ruleset-version-old"

	// 节点持有权威版本 → 收敛
	recordRulePackPull("sync-cv-current", tenant, authoritative, authoritative, at)
	// 本次已经下发权威版本，但节点回报仍持有旧版本 → 必须等下次回报后才收敛。
	recordRulePackPull("sync-cv-lagging", tenant, old, authoritative, at)
	// 别的租户的节点不得计入本租户统计
	recordRulePackPull("sync-cv-other", "tenant_other_cv", authoritative, authoritative, at)

	conv := evaluateRulePackConvergence(tenant, authoritative)

	if conv.NodeCount != 2 {
		t.Fatalf("应只统计本租户 2 个节点，实际 NodeCount=%d", conv.NodeCount)
	}
	if conv.FreshCount != 2 || conv.FreshConvergedCount != 1 || conv.StaleCount != 0 {
		t.Fatalf("fresh convergence counters drifted: %+v", conv)
	}
	if conv.ConvergedCount != 1 {
		t.Fatalf("仅 1 个节点持有权威版本，实际 ConvergedCount=%d", conv.ConvergedCount)
	}
	if conv.AllConverged {
		t.Fatalf("有节点落后时 AllConverged 必须为 false")
	}
	if len(conv.StaleNodes) != 1 {
		t.Fatalf("应有 1 个落后节点，实际 %d", len(conv.StaleNodes))
	}
	if conv.StaleNodes[0].NodeID != "sync-cv-lagging" {
		t.Fatalf("落后节点应为 sync-cv-lagging，实际 %s", conv.StaleNodes[0].NodeID)
	}
	if conv.StaleNodes[0].CurrentVersion != old {
		t.Fatalf("落后节点应如实回显其旧版本 %s，实际 %s", old, conv.StaleNodes[0].CurrentVersion)
	}
	if conv.StaleNodes[0].Status != rulePackNodeStatusLagging {
		t.Fatalf("新鲜但持有版本落后时状态应为 lagging，实际 %s", conv.StaleNodes[0].Status)
	}
}

// 全部节点都在权威版本上 → 全收敛。
func TestEvaluateRulePackConvergenceAllConverged(t *testing.T) {
	resetRulePackPullLedger(t)
	at := time.Date(2026, 6, 9, 11, 0, 0, 0, time.UTC)
	setRulePackStatusNow(t, at)
	tenant := "tenant_sync_all"
	authoritative := "ffffffffffffffff"

	recordRulePackPull("sync-all-a", tenant, authoritative, authoritative, at)
	recordRulePackPull("sync-all-b", tenant, authoritative, authoritative, at)

	conv := evaluateRulePackConvergence(tenant, authoritative)

	if conv.NodeCount != 2 || conv.ConvergedCount != 2 {
		t.Fatalf("应 2/2 收敛，实际 %d/%d", conv.ConvergedCount, conv.NodeCount)
	}
	if conv.FreshCount != 2 || conv.FreshConvergedCount != 2 || conv.StaleCount != 0 {
		t.Fatalf("all-fresh counters drifted: %+v", conv)
	}
	if !conv.AllConverged {
		t.Fatalf("全部在权威版本上时 AllConverged 必须为 true")
	}
	if len(conv.StaleNodes) != 0 {
		t.Fatalf("不应有落后节点，实际 %d", len(conv.StaleNodes))
	}
}

// 保守不编造：该租户没有任何节点上报过 → AllConverged 必须为 false（而非空集即真）。
func TestEvaluateRulePackConvergenceNoNodesIsNotConverged(t *testing.T) {
	resetRulePackPullLedger(t)
	setRulePackStatusNow(t, time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC))
	conv := evaluateRulePackConvergence("tenant_sync_nobody_zzz", "deadbeefdeadbeef")

	if conv.NodeCount != 0 {
		t.Fatalf("该租户应无节点，实际 NodeCount=%d", conv.NodeCount)
	}
	if conv.AllConverged {
		t.Fatalf("零节点时 AllConverged 必须为 false（不编造全网收敛）")
	}
}

func TestEvaluateRulePackConvergenceClassifiesFreshnessAndHeldVersion(t *testing.T) {
	resetRulePackPullLedger(t)
	now := time.Date(2026, 6, 9, 13, 0, 0, 0, time.UTC)
	setRulePackStatusNow(t, now)
	tenant := "tenant_sync_status"
	authoritative := "ruleset-current"

	recordRulePackPull("node-stale", tenant, authoritative, authoritative, now.Add(-rulePackFreshnessWindow-time.Second))
	recordRulePackPull("node-lagging", tenant, "ruleset-old", authoritative, now)
	recordRulePackPull("node-converged", tenant, authoritative, authoritative, now)

	conv := evaluateRulePackConvergence(tenant, authoritative)
	if conv.NodeCount != 3 || conv.ConvergedCount != 1 || conv.AllConverged {
		t.Fatalf("状态汇总应为 1/3 收敛且非全收敛，实际 %+v", conv)
	}
	if conv.FreshCount != 2 || conv.FreshConvergedCount != 1 || conv.StaleCount != 1 {
		t.Fatalf("stale node must be excluded from fresh denominator: %+v", conv)
	}
	got := make(map[string]rulePackNodeConvergence, len(conv.StaleNodes))
	for _, node := range conv.StaleNodes {
		got[node.NodeID] = node
	}
	if got["node-stale"].Status != rulePackNodeStatusStale {
		t.Fatalf("超过三个刷新周期应为 stale，实际 %+v", got["node-stale"])
	}
	if got["node-stale"].Converged {
		t.Fatalf("过期节点即使持有权威版本也不能算收敛")
	}
	if got["node-lagging"].Status != rulePackNodeStatusLagging {
		t.Fatalf("新鲜但持有旧版本应为 lagging，实际 %+v", got["node-lagging"])
	}
}

// SyncRuleSet 鉴权门：无登录用户 → 403（不触达 DB/编译路径）。
func TestSyncRuleSetForbidsAnonymous(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/system/ruleset/sync", nil)
	rec := httptest.NewRecorder()

	SyncRuleSet(&Dependencies{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("匿名访问应 403，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
}

// SyncRuleSet 鉴权门：非 platform_admin 角色 → 403。
func TestSyncRuleSetForbidsNonAdmin(t *testing.T) {
	user := &repository.User{ID: "u-viewer", TenantID: "tenant_sync_cv", Role: "viewer", Status: "active"}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/system/ruleset/sync", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
	rec := httptest.NewRecorder()

	SyncRuleSet(&Dependencies{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("非 platform_admin 应 403，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	// 确认走的是鉴权拒绝，没有误吐占位 JSON
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if _, isPlaceholder := body["message"]; isPlaceholder {
		t.Fatalf("不应再返回占位 message 字段，body=%s", rec.Body.String())
	}
}
