package diagnostics

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/diagsign"
)

func t12Registry(c *AgentClient) *Registry { return NewRegistry(HostTools(c)...) }

func TestT12HostToolsAdminOnly(t *testing.T) {
	ts := HostTools(t12Client(t12Dir(t), t12Key))
	names := map[string]bool{}
	for _, tl := range ts {
		names[tl.Name()] = true
		if !tl.AdminOnly() {
			t.Errorf("%s 必须仅管理员", tl.Name())
		}
		if tl.Description() == "" || !json.Valid(tl.Schema()) {
			t.Errorf("%s 缺描述或 schema 非法", tl.Name())
		}
	}
	for _, n := range []string{"host_snapshot", "host_container_logs", "host_drift"} {
		if !names[n] {
			t.Errorf("缺少工具 %s", n)
		}
	}
	r := t12Registry(t12Client(t12Dir(t), t12Key))
	st := r.Call(context.Background(), nil, Scope{TenantID: "t", UserID: "u"}, "host_snapshot", nil)
	if st.Err != ErrForbidden.Error() {
		t.Fatalf("员工应被拒绝: %q", st.Err)
	}
}

func TestT12HostSnapshotTool(t *testing.T) {
	d := t12Dir(t)
	t12WriteSnap(t, d, time.Now(), []any{})
	st := t12Registry(t12Client(d, t12Key)).Call(context.Background(), nil, Scope{TenantID: "t", IsAdmin: true}, "host_snapshot", nil)
	if st.Err != "" {
		t.Fatal(st.Err)
	}
	var out struct {
		Fresh      bool `json:"fresh"`
		Containers []struct {
			Service string `json:"service"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(st.Output, &out); err != nil || !out.Fresh || out.Containers[0].Service != "control-plane" {
		t.Fatalf("输出不对: %s err=%v", st.Output, err)
	}
}

func TestT12HostSnapshotToolMissing(t *testing.T) {
	c := t12Client(t.TempDir()+"/nope", t12Key)
	st := t12Registry(c).Call(context.Background(), nil, Scope{TenantID: "t", IsAdmin: true}, "host_snapshot", nil)
	if !strings.Contains(st.Err, "未安装") {
		t.Fatalf("应提示未安装采集器: %q", st.Err)
	}
}

func TestT12HostLogsTool(t *testing.T) {
	d := t12Dir(t)
	var got diagsign.Task
	t12Fake(t, d, t12Key, func(task diagsign.Task) diagsign.Result {
		got = task
		return diagsign.Result{OK: true, Output: "line1 token=abc12345secret\nline2 req_abc failed"}
	})
	args := json.RawMessage(`{"service":"gateway-core","grep":"req_abc","since_minutes":15}`)
	st := t12Registry(t12Client(d, t12Key)).Call(context.Background(), nil, Scope{TenantID: "t", IsAdmin: true}, "host_container_logs", args)
	if st.Err != "" {
		t.Fatal(st.Err)
	}
	if got.Action != "container_logs" || got.Params["service"] != "gateway-core" ||
		got.Params["grep"] != "req_abc" || got.Params["since_minutes"] != float64(15) {
		t.Fatalf("下发的任务不对: %+v", got)
	}
	if strings.Contains(string(st.Output), "abc12345secret") {
		t.Fatalf("控制面这边应再次脱敏: %s", st.Output)
	}
	if !strings.Contains(string(st.Output), "req_abc failed") {
		t.Fatalf("输出丢失: %s", st.Output)
	}
}

func TestT12HostLogsToolBadArgs(t *testing.T) {
	d := t12Dir(t)
	r := t12Registry(t12Client(d, t12Key))
	for _, a := range []string{`{}`, `{"service":""}`, `{"service":"a","since_minutes":0}`, `{"service":"a","since_minutes":61}`, `not json`} {
		st := r.Call(context.Background(), nil, Scope{TenantID: "t", IsAdmin: true}, "host_container_logs", json.RawMessage(a))
		if st.Err == "" {
			t.Errorf("参数 %s 应报错", a)
		}
	}
}

func TestT12HostLogsToolAgentError(t *testing.T) {
	d := t12Dir(t)
	t12Fake(t, d, t12Key, func(diagsign.Task) diagsign.Result {
		return diagsign.Result{OK: false, Error: "unknown_service"}
	})
	st := t12Registry(t12Client(d, t12Key)).Call(context.Background(), nil, Scope{TenantID: "t", IsAdmin: true},
		"host_container_logs", json.RawMessage(`{"service":"nope"}`))
	if !strings.Contains(st.Err, "unknown_service") {
		t.Fatalf("应带采集器错误码: %q", st.Err)
	}
}

func TestT12HostLogsToolTimeoutAndNoKey(t *testing.T) {
	d := t12Dir(t)
	c := t12Client(d, t12Key)
	c.timeout = 100 * time.Millisecond
	st := t12Registry(c).Call(context.Background(), nil, Scope{TenantID: "t", IsAdmin: true},
		"host_container_logs", json.RawMessage(`{"service":"a"}`))
	if !strings.Contains(st.Err, "超时") {
		t.Fatalf("应提示超时: %q", st.Err)
	}
	st = t12Registry(t12Client(d, nil)).Call(context.Background(), nil, Scope{TenantID: "t", IsAdmin: true},
		"host_container_logs", json.RawMessage(`{"service":"a"}`))
	if !strings.Contains(st.Err, "密钥") {
		t.Fatalf("应提示缺密钥: %q", st.Err)
	}
}

func TestT12HostDriftTool(t *testing.T) {
	d := t12Dir(t)
	r := t12Registry(t12Client(d, t12Key))
	admin := Scope{TenantID: "t", IsAdmin: true}

	t12WriteSnap(t, d, time.Now(), []any{
		map[string]any{"service": "chat-portal-ui", "image_match": true, "env_diff": []any{
			map[string]any{"key": "PORTAL_PUBLIC_URL", "sensitive": false, "chain": "https://a", "running": "http://b"}}},
		map[string]any{"service": "worker", "not_running": true, "env_diff": []any{}},
	})
	st := r.Call(context.Background(), nil, admin, "host_drift", nil)
	if st.Err != "" {
		t.Fatal(st.Err)
	}
	var out struct {
		Fresh      bool             `json:"fresh"`
		DriftError string           `json:"drift_error"`
		Drift      []map[string]any `json:"drift"`
	}
	if err := json.Unmarshal(st.Output, &out); err != nil || !out.Fresh || len(out.Drift) != 2 || out.DriftError != "" {
		t.Fatalf("数组形态输出不对: %s err=%v", st.Output, err)
	}

	t12WriteSnap(t, d, time.Now(), map[string]any{"error": "开机链渲染失败"})
	st = r.Call(context.Background(), nil, admin, "host_drift", nil)
	if st.Err != "" {
		t.Fatal(st.Err)
	}
	out.Drift, out.DriftError = nil, ""
	if err := json.Unmarshal(st.Output, &out); err != nil || out.DriftError != "开机链渲染失败" || len(out.Drift) != 0 {
		t.Fatalf("错误形态输出不对: %s err=%v", st.Output, err)
	}
}
