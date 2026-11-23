package diagnostics

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// t7AddProxy 写一条没有上游状态码的代理请求（endpoint_type=proxy）。
func t7AddProxy(t *testing.T, f *t4Fix, rid, status, upOutcome, delOutcome string, latencyMS, agoMin int) {
	t.Helper()
	t4Exec(t, context.Background(), f.conn, `
INSERT INTO request_logs (id, request_id, tenant_id, user_id, client_id, endpoint_type, request_status,
  latency_ms, created_at, proxy_mode, proxy_target_host, agent_type, upstream_outcome, delivery_outcome)
VALUES ($1,$2,$3,$4,$5,'proxy',$6,$7, now() - make_interval(mins => $8),'reverse','api.example.com','openai-codex',$9,$10)`,
		"id_"+rid, rid, f.tenant, f.userA, f.keyA, status, latencyMS, agoMin, upOutcome, delOutcome)
}

// t7SnapRegistry 返回带宿主机快照（容器 started_at 由调用方给定）的注册表。
func t7SnapRegistry(t *testing.T, containers []map[string]any) *Registry {
	t.Helper()
	d := filepath.Join(t.TempDir(), "diag")
	if err := os.MkdirAll(filepath.Join(d, "snapshot"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"at": time.Now().UTC().Format(time.RFC3339), "agent_version": "1.0.0",
		"containers": containers, "drift": []any{}, "disk": []any{}, "certs": []any{}, "errors": []string{}})
	if err := os.WriteFile(filepath.Join(d, "snapshot", "latest.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	c := &AgentClient{Dir: d, Key: []byte("k")}
	return NewRegistry(append(append(append(RequestTools(), ConfigTools()...), ChangeTools()...), HostTools(c)...)...)
}

func t7ProxyTree(t *testing.T, f *t4Fix, reg *Registry, s Scope, rid string) *Report {
	t.Helper()
	rep, err := RunTree(context.Background(), f.x, reg, s, Input{Kind: "request", Ref: rid}, &HostView{Err: ErrAgentMissing})
	if err != nil {
		t.Fatalf("RunTree: %v", err)
	}
	if err := FactCheck(rep); err != nil {
		t.Fatalf("FactCheck: %v", err)
	}
	return rep
}

func t7Text(rep *Report) string { b, _ := json.Marshal(rep.Findings); return string(b) }

func TestT7ProxyFailureForms(t *testing.T) {
	f := t4NewFixture(t)
	reg := t7SnapRegistry(t, []map[string]any{})
	cases := []struct {
		name, status, up, del, wantID, wantLv string
		latency                               int
	}{
		{"客户端中断", "client_canceled", "canceled", "client_canceled", "proxy_client_canceled", "confirmed", 3000},
		{"目标站点超时", "failed", "timeout", "unknown", "proxy_timeout", "confirmed", 60000},
		{"连不上目标站点", "failed", "network_error", "not_started", "proxy_upstream_unreachable", "confirmed", 200},
		{"传输中断", "stream_aborted", "success", "aborted", "proxy_stream_aborted", "confirmed", 9000},
		{"原因不明", "failed", "unknown", "unknown", "proxy_interrupted", "suspected", 5000},
	}
	for i, c := range cases {
		rid := t7RID(f, 200+i)
		t7AddProxy(t, f, rid, c.status, c.up, c.del, c.latency, 10)
		rep := t7ProxyTree(t, f, reg, f.admin(), rid)
		got := t7Find1(rep, c.wantID)
		if got == nil || string(got.Level) != c.wantLv {
			t.Errorf("%s：应有 %s(%s)\n%s", c.name, c.wantID, c.wantLv, t7Dump(rep))
		}
		if t7Find1(rep, "request_unknown") != nil || strings.Contains(t7Text(rep), "无法判断这条请求") {
			t.Errorf("%s：不应落入“无法判断”", c.name)
		}
	}
}

func TestT7ProxyRestartConfirmedByContainer(t *testing.T) {
	f := t4NewFixture(t)
	rid := t7RID(f, 210)
	t7AddProxy(t, f, rid, "failed", "unknown", "unknown", 61276, 10)
	start := time.Now().Add(-10 * time.Minute)
	reg := t7SnapRegistry(t, []map[string]any{
		{"name": "x-proxy-server-1", "service": "proxy-server", "state": "running", "health": "healthy", "restart_count": 0,
			"started_at": start.Add(50 * time.Second).UTC().Format(time.RFC3339)},
	})
	rep := t7ProxyTree(t, f, reg, f.admin(), rid)
	g := t7Find1(rep, "gw_restart_interrupt")
	if g == nil || g.Level != LevelConfirmed || !strings.Contains(g.Title, "重启时被中断") {
		t.Fatalf("容器 started_at 落在区间内应为确定结论:\n%s", t7Dump(rep))
	}
	if !strings.Contains(t7Text(rep), "避开业务高峰做升级") {
		t.Errorf("建议应包含避开高峰升级")
	}
	// 容器在请求之前就已启动：不是重启中断
	reg2 := t7SnapRegistry(t, []map[string]any{
		{"name": "x-proxy-server-1", "service": "proxy-server", "started_at": start.Add(-time.Hour).UTC().Format(time.RFC3339)},
	})
	if rep2 := t7ProxyTree(t, f, reg2, f.admin(), rid); t7Find1(rep2, "gw_restart_interrupt") != nil {
		t.Errorf("容器未在区间内重启，不应判为重启中断")
	}
}

func TestT7ProxyRestartSuspectedByUpgradeRecord(t *testing.T) {
	f := t4NewFixture(t)
	rid := t7RID(f, 211)
	t7AddProxy(t, f, rid, "failed", "unknown", "unknown", 61276, 10)
	t4Exec(t, context.Background(), f.conn, `INSERT INTO upgrade_history (id, version_from, version_to, status, created_at)
VALUES ($1,'2.9.6','2.9.7','completed', now() - interval '9 minutes 30 seconds')`, "t4up_"+f.sfx+"_px")
	reg := t7SnapRegistry(t, []map[string]any{}) // 快照里没有重启
	rep := t7ProxyTree(t, f, reg, f.admin(), rid)
	g := t7Find1(rep, "gw_restart_interrupt")
	if g == nil || g.Level != LevelSuspected || !strings.Contains(g.Title, "疑似") {
		t.Fatalf("只有升级记录应为疑似:\n%s", t7Dump(rep))
	}
}

func TestT7ProxyRestartStaffNoHostDetail(t *testing.T) {
	f := t4NewFixture(t)
	rid := t7RID(f, 212)
	t7AddProxy(t, f, rid, "failed", "unknown", "unknown", 61276, 10)
	reg := t7SnapRegistry(t, []map[string]any{
		{"name": "x-proxy-server-1", "service": "proxy-server", "started_at": time.Now().Add(-9 * time.Minute).UTC().Format(time.RFC3339)},
	})
	rep := t7ProxyTree(t, f, reg, f.staff(f.userA), rid)
	if t7Find1(rep, "gw_restart_interrupt") != nil {
		t.Fatalf("员工不应得到宿主机重启结论:\n%s", t7Dump(rep))
	}
	g := t7Find1(rep, "proxy_interrupted")
	if g == nil || g.Level != LevelSuspected {
		t.Fatalf("员工只给疑似:\n%s", t7Dump(rep))
	}
	txt := t7Text(rep)
	for _, bad := range []string{"proxy-server", "容器", "宿主机"} {
		if strings.Contains(txt, bad) {
			t.Errorf("员工结论不应出现宿主机细节 %q", bad)
		}
	}
}
