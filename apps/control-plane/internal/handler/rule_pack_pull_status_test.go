package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 按节点拉取可见性：引擎每次拉规则包时带 X-Node-ID 与它当前持有的
// X-RulePack-Version；control-plane 登记「该节点持有版本 vs 本次下发版本」，
// 暴露 GET /admin/v1/rules/pull-status 供运维查看各节点是否已收敛到最新版本。

func TestRecordAndExposeRulePackPull(t *testing.T) {
	resetRulePackPullLedger(t)
	now := time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC)
	setRulePackStatusNow(t, now)
	// 节点 A 已收敛（持有版本 == 下发版本）
	recordRulePackPull("node-conv-A", "tenant_default", "ver-aaaaaaaaaaaa", "ver-aaaaaaaaaaaa", now)
	// 节点 B 落后（持有旧版本，本次下发新版本）→ 未收敛
	recordRulePackPull("node-lag-B", "tenant_default", "ver-old000000000", "ver-new000000000", now)

	rec := httptest.NewRecorder()
	writeRulePackPullStatusResponse(rec, "tenant_default", "ver-aaaaaaaaaaaa", now)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码应为 200，实际 %d", rec.Code)
	}
	var body struct {
		Nodes []struct {
			NodeID        string `json:"node_id"`
			TenantID      string `json:"tenant_id"`
			HeldVersion   string `json:"held_version"`
			ServedVersion string `json:"served_version"`
			Converged     bool   `json:"converged"`
			Status        string `json:"status"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应应为 JSON：%v；原文=%s", err, rec.Body.String())
	}
	type view struct {
		held, served string
		converged    bool
		status       string
	}
	got := map[string]view{}
	for _, n := range body.Nodes {
		got[n.NodeID] = view{n.HeldVersion, n.ServedVersion, n.Converged, n.Status}
	}
	a, ok := got["node-conv-A"]
	if !ok {
		t.Fatalf("应登记 node-conv-A；实得 %+v", body.Nodes)
	}
	if !a.converged {
		t.Fatalf("持有版本==下发版本时 converged 应为 true：%+v", a)
	}
	if a.status != rulePackNodeStatusConverged {
		t.Fatalf("持有版本==下发版本时 status 应为 converged：%+v", a)
	}
	b, ok := got["node-lag-B"]
	if !ok {
		t.Fatalf("应登记 node-lag-B；实得 %+v", body.Nodes)
	}
	if b.converged {
		t.Fatalf("持有版本!=下发版本时 converged 应为 false：%+v", b)
	}
	if b.status != rulePackNodeStatusLagging {
		t.Fatalf("新鲜但持有版本落后时 status 应为 lagging：%+v", b)
	}
	if b.held != "ver-old000000000" || b.served != "ver-new000000000" {
		t.Fatalf("应如实回显持有/下发版本：%+v", b)
	}
}

func TestRulePackPullNeedsNextHeldVersionReportBeforeConverged(t *testing.T) {
	resetRulePackPullLedger(t)
	now := time.Date(2026, 6, 10, 11, 0, 0, 0, time.UTC)
	setRulePackStatusNow(t, now)
	tenant := "tenant_handshake"

	recordRulePackPull("node-handshake", tenant, "version-old", "version-new", now)
	first := getRulePackPullStatusBody(t, tenant, "version-new")
	if len(first.Nodes) != 1 || first.Nodes[0].Status != rulePackNodeStatusLagging || first.Nodes[0].Converged {
		t.Fatalf("第一次下发新版本后仍应等待节点确认持有，实际 %+v", first.Nodes)
	}

	recordRulePackPull("node-handshake", tenant, "version-new", "version-new", now.Add(time.Second))
	second := getRulePackPullStatusBody(t, tenant, "version-new")
	if len(second.Nodes) != 1 || second.Nodes[0].Status != rulePackNodeStatusConverged || !second.Nodes[0].Converged {
		t.Fatalf("下一次回报已持有新版本后才应收敛，实际 %+v", second.Nodes)
	}
}

func TestRulePackPullStatusMarksOldNodeStale(t *testing.T) {
	resetRulePackPullLedger(t)
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	setRulePackStatusNow(t, now)
	tenant := "tenant_stale"
	recordRulePackPull("node-old", tenant, "version-current", "version-current", now.Add(-rulePackFreshnessWindow-time.Second))

	body := getRulePackPullStatusBody(t, tenant, "version-current")
	if len(body.Nodes) != 1 || body.Nodes[0].Status != rulePackNodeStatusStale {
		t.Fatalf("超过三个刷新周期未上报的节点应为 stale，实际 %+v", body.Nodes)
	}
	if body.Nodes[0].Converged {
		t.Fatalf("stale 节点不得通过兼容 converged 字段冒充已收敛")
	}
}

func TestRecordRulePackPullRejectsAnonymousNode(t *testing.T) {
	resetRulePackPullLedger(t)
	now := time.Date(2026, 6, 10, 13, 0, 0, 0, time.UTC)
	setRulePackStatusNow(t, now)
	if recordRulePackPullWithTelemetry("", "tenant_default", "", "ver-zzzzzzzzzzzz", nil, nil, 60, now) {
		t.Fatal("anonymous node must be rejected, not silently served without a receipt")
	}

	rec := httptest.NewRecorder()
	writeRulePackPullStatusResponse(rec, "tenant_default", "ver-zzzzzzzzzzzz", now)

	var body struct {
		Nodes []struct {
			NodeID string `json:"node_id"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应应为 JSON：%v", err)
	}
	for _, n := range body.Nodes {
		if n.NodeID == "" {
			t.Fatalf("空 NodeID 不应被登记：%+v", body.Nodes)
		}
	}
}

type rulePackPullStatusTestBody struct {
	Nodes []struct {
		NodeID        string `json:"node_id"`
		HeldVersion   string `json:"held_version"`
		ServedVersion string `json:"served_version"`
		Converged     bool   `json:"converged"`
		Status        string `json:"status"`
	} `json:"nodes"`
	Count int `json:"count"`
}

func resetRulePackPullLedger(t *testing.T) {
	t.Helper()
	rulePackPullStatus.Lock()
	rulePackPullStatus.nodes = nil
	rulePackPullStatus.Unlock()
	t.Cleanup(func() {
		rulePackPullStatus.Lock()
		rulePackPullStatus.nodes = nil
		rulePackPullStatus.Unlock()
	})
}

func setRulePackStatusNow(t *testing.T, now time.Time) {
	t.Helper()
	previous := rulePackStatusNow
	rulePackStatusNow = func() time.Time { return now }
	t.Cleanup(func() { rulePackStatusNow = previous })
}

func newRulePackAdminRequest(method, target, tenantID string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	user := &repository.User{
		ID:       "admin-" + tenantID,
		TenantID: tenantID,
		Role:     "platform_admin",
		Status:   "active",
	}
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
}

func getRulePackPullStatusBody(t *testing.T, tenantID, desiredVersion string) rulePackPullStatusTestBody {
	t.Helper()
	rec := httptest.NewRecorder()
	writeRulePackPullStatusResponse(rec, tenantID, desiredVersion, rulePackStatusNow())
	if rec.Code != http.StatusOK {
		t.Fatalf("拉取状态接口应返回 200，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	var body rulePackPullStatusTestBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("拉取状态响应应为 JSON：%v；原文=%s", err, rec.Body.String())
	}
	return body
}

func TestPullStatusUsesCurrentAuthoritativeVersionNotLastServedVersion(t *testing.T) {
	resetRulePackPullLedger(t)
	now := time.Date(2026, 6, 10, 15, 0, 0, 0, time.UTC)
	setRulePackStatusNow(t, now)
	tenant := "tenant-authoritative"
	recordRulePackPull("node-old", tenant, "version-old", "version-old", now)

	body := getRulePackPullStatusBody(t, tenant, "version-new")
	if len(body.Nodes) != 1 || body.Nodes[0].Status != rulePackNodeStatusLagging || body.Nodes[0].Converged {
		t.Fatalf("old held==served must still lag current authoritative version: %+v", body.Nodes)
	}
}

func TestPullStatusFreshnessUsesReportedRefreshInterval(t *testing.T) {
	resetRulePackPullLedger(t)
	now := time.Date(2026, 6, 10, 16, 0, 0, 0, time.UTC)
	setRulePackStatusNow(t, now)
	tenant := "tenant-refresh-window"
	recordRulePackPullWithTelemetry("node-slow", tenant, "desired", "desired", nil, nil, 120, now.Add(-5*time.Minute))
	recordRulePackPull("node-default", tenant, "desired", "desired", now.Add(-4*time.Minute))

	body := getRulePackPullStatusBody(t, tenant, "desired")
	got := map[string]string{}
	for _, node := range body.Nodes {
		got[node.NodeID] = node.Status
	}
	if got["node-slow"] != rulePackNodeStatusConverged || got["node-default"] != rulePackNodeStatusStale {
		t.Fatalf("dynamic/default freshness windows misclassified: %+v", got)
	}
}

func TestRulePackLedgerNormalizesNodeIDAndPrunesOldOrExcessNodes(t *testing.T) {
	resetRulePackPullLedger(t)
	now := time.Date(2026, 6, 10, 17, 0, 0, 0, time.UTC)
	tenant := "tenant-ledger-bounds"
	recordRulePackPull("old-node", tenant, "desired", "desired", now.Add(-rulePackLedgerRetention-time.Second))
	recordRulePackPull("  current-node  ", tenant, "desired", "desired", now)
	recordRulePackPull(strings.Repeat("x", rulePackNodeIDMaxLength+1), tenant, "desired", "desired", now)
	recordRulePackPull("bad-node", "../invalid-tenant", "desired", "desired", now)

	nodes := listRulePackPullStatus(tenant, "desired", now)
	if len(nodes) != 1 || nodes[0].NodeID != "current-node" {
		t.Fatalf("node ID normalization/retention cleanup failed: %+v", nodes)
	}

	resetRulePackPullLedger(t)
	for i := 0; i <= rulePackMaxNodesPerTenant; i++ {
		recordRulePackPull(fmt.Sprintf("node-%04d", i), tenant, "desired", "desired", now.Add(time.Duration(i)*time.Millisecond))
	}
	nodes = listRulePackPullStatus(tenant, "desired", now.Add(time.Second))
	if len(nodes) != rulePackMaxNodesPerTenant {
		t.Fatalf("tenant ledger size=%d want=%d", len(nodes), rulePackMaxNodesPerTenant)
	}
	for _, node := range nodes {
		if node.NodeID == "node-0000" {
			t.Fatal("oldest node must be evicted at tenant cap")
		}
	}
}

func TestRulePackLedgerEnforcesGlobalCapAndRefreshMaximum(t *testing.T) {
	resetRulePackPullLedger(t)
	now := time.Date(2026, 6, 10, 18, 0, 0, 0, time.UTC)
	for i := 0; i <= rulePackMaxNodesGlobal; i++ {
		tenantID := fmt.Sprintf("tenant-global-%02d", i%20)
		recordRulePackPull(fmt.Sprintf("global-node-%05d", i), tenantID, "desired", "desired", now.Add(time.Duration(i)*time.Microsecond))
	}
	rulePackPullStatus.RLock()
	count := len(rulePackPullStatus.nodes)
	_, oldestPresent := rulePackPullStatus.nodes[rulePackNodeKey{TenantID: "tenant-global-00", NodeID: "global-node-00000"}]
	rulePackPullStatus.RUnlock()
	if count != rulePackMaxNodesGlobal || oldestPresent {
		t.Fatalf("global ledger cap failed: count=%d oldest_present=%v", count, oldestPresent)
	}
	if parseRulePackRefreshSeconds("3600") != maxRulePackRefreshSeconds || parseRulePackRefreshSeconds("3601") != 0 {
		t.Fatalf("refresh seconds must clamp/reject outside 1..%d", maxRulePackRefreshSeconds)
	}
}
