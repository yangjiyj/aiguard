package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/diagsign"
)

var t12Key = []byte("t12-test-key")

func t12Dir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for _, s := range []string{"inbox", "outbox", "snapshot"} {
		if err := os.MkdirAll(filepath.Join(d, s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func t12Client(d string, key []byte) *AgentClient {
	c := &AgentClient{Dir: d, Key: key, Now: time.Now}
	c.pollEvery = 10 * time.Millisecond
	c.timeout = 2 * time.Second
	return c
}

// t12Fake 模拟采集器：轮询 inbox，验签后按 handler 写 outbox，并删除任务文件。
func t12Fake(t *testing.T, d string, key []byte, handler func(diagsign.Task) diagsign.Result) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			ents, _ := os.ReadDir(filepath.Join(d, "inbox"))
			for _, e := range ents {
				if !strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".") {
					continue
				}
				p := filepath.Join(d, "inbox", e.Name())
				b, err := os.ReadFile(p)
				if err != nil {
					continue
				}
				var task diagsign.Task
				if json.Unmarshal(b, &task) != nil {
					continue
				}
				_ = os.Remove(p)
				var res diagsign.Result
				if err := diagsign.Verify(key, task); err != nil {
					res = diagsign.Result{ID: task.ID, OK: false, Error: err.Error()}
				} else {
					res = handler(task)
					res.ID = task.ID
				}
				rb, _ := json.Marshal(res)
				tmp := filepath.Join(d, "outbox", "."+task.ID+".tmp")
				_ = os.WriteFile(tmp, rb, 0o644)
				_ = os.Rename(tmp, filepath.Join(d, "outbox", task.ID+".json"))
			}
		}
	}()
}

func t12WriteSnap(t *testing.T, d string, at time.Time, drift any) {
	t.Helper()
	snap := map[string]any{
		"at": at.UTC().Format(time.RFC3339), "agent_version": "1.0.0",
		"containers": []map[string]any{{"name": "x-control-plane-1", "service": "control-plane", "state": "running",
			"health": "healthy", "restart_count": 2, "image": "img:1", "image_id": "sha256:aa", "started_at": "2026-10-24T01:00:00Z"}},
		"drift":  drift,
		"disk":   []map[string]any{{"mount": "/", "used_pct": 91, "avail_bytes": 1000}},
		"certs":  []map[string]any{{"path": "/etc/jjdguard/a.crt", "not_after": "2027-01-01T00:00:00Z", "days_left": 69}},
		"errors": []string{},
	}
	b, _ := json.Marshal(snap)
	if err := os.WriteFile(filepath.Join(d, "snapshot", "latest.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestT12DoEndToEnd(t *testing.T) {
	d := t12Dir(t)
	var got diagsign.Task
	t12Fake(t, d, t12Key, func(task diagsign.Task) diagsign.Result {
		got = task
		return diagsign.Result{OK: true, Output: "pong", FinishedAt: time.Now().UTC().Format(time.RFC3339)}
	})
	res, err := t12Client(d, t12Key).Do(context.Background(), "container_logs",
		map[string]any{"service": "gateway-core", "since_minutes": 5})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Output != "pong" {
		t.Fatalf("结果不对: %+v", res)
	}
	if got.Action != "container_logs" || got.Params["service"] != "gateway-core" {
		t.Fatalf("采集器收到的任务不对: %+v", got)
	}
	// outbox 文件在读取后删除
	if ents, _ := os.ReadDir(filepath.Join(d, "outbox")); len(ents) != 0 {
		t.Fatalf("outbox 应被清理: %v", ents)
	}
}

func TestT12DoWrongKeyRejectedByAgent(t *testing.T) {
	d := t12Dir(t)
	t12Fake(t, d, []byte("other-key"), func(diagsign.Task) diagsign.Result { return diagsign.Result{OK: true} })
	res, err := t12Client(d, t12Key).Do(context.Background(), "ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Error != "bad_signature" {
		t.Fatalf("应被采集器拒绝: %+v", res)
	}
}

func TestT12DoTimeout(t *testing.T) {
	d := t12Dir(t)
	c := t12Client(d, t12Key)
	c.timeout = 150 * time.Millisecond
	_, err := c.Do(context.Background(), "ping", nil)
	if !errors.Is(err, ErrAgentTimeout) {
		t.Fatalf("应超时, got %v", err)
	}
	// 超时后清理自己写的任务文件，避免采集器迟到执行
	if ents, _ := os.ReadDir(filepath.Join(d, "inbox")); len(ents) != 0 {
		t.Fatalf("超时后 inbox 应清理: %v", ents)
	}
}

func TestT12DoContextCancel(t *testing.T) {
	d := t12Dir(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := t12Client(d, t12Key).Do(ctx, "ping", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestT12DoNoKey(t *testing.T) {
	d := t12Dir(t)
	if _, err := t12Client(d, nil).Do(context.Background(), "ping", nil); !errors.Is(err, ErrAgentNoKey) {
		t.Fatalf("got %v", err)
	}
}

func TestT12DoAgentMissing(t *testing.T) {
	c := t12Client(filepath.Join(t.TempDir(), "nope"), t12Key)
	if _, err := c.Do(context.Background(), "ping", nil); !errors.Is(err, ErrAgentMissing) {
		t.Fatalf("got %v", err)
	}
}

func TestT12SnapshotMissing(t *testing.T) {
	d := t12Dir(t)
	if _, err := t12Client(d, t12Key).Snapshot(); !errors.Is(err, ErrAgentMissing) {
		t.Fatalf("got %v", err)
	}
}

func TestT12SnapshotFreshAndStale(t *testing.T) {
	d := t12Dir(t)
	now := time.Now()
	t12WriteSnap(t, d, now.Add(-30*time.Second), []any{})
	s, err := t12Client(d, t12Key).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !s.Fresh || s.Age < 29*time.Second || s.Age > 40*time.Second {
		t.Fatalf("应新鲜: fresh=%v age=%v", s.Fresh, s.Age)
	}
	if len(s.Containers) != 1 || s.Containers[0].RestartCount != 2 || s.Disk[0].UsedPct != 91 || s.Certs[0].DaysLeft != 69 {
		t.Fatalf("字段解析不对: %+v", s)
	}
	t12WriteSnap(t, d, now.Add(-4*time.Minute), []any{})
	s, err = t12Client(d, t12Key).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if s.Fresh {
		t.Fatalf("4 分钟前的快照应过期, age=%v", s.Age)
	}
}

func TestT12SnapshotDriftArray(t *testing.T) {
	d := t12Dir(t)
	t12WriteSnap(t, d, time.Now(), []any{
		map[string]any{"service": "chat-portal-ui", "image_match": true, "env_diff": []any{
			map[string]any{"key": "PORTAL_PUBLIC_URL", "sensitive": false, "chain": "https://a", "running": "http://10.0.0.1"}}},
		map[string]any{"service": "worker", "image_match": false, "not_running": true, "env_diff": []any{}},
	})
	s, err := t12Client(d, t12Key).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if s.DriftError != "" || len(s.Drift) != 2 {
		t.Fatalf("drift 解析不对: %+v err=%q", s.Drift, s.DriftError)
	}
	if s.Drift[0].EnvDiff[0].Key != "PORTAL_PUBLIC_URL" || !s.Drift[1].NotRunning {
		t.Fatalf("drift 内容不对: %+v", s.Drift)
	}
}

func TestT12SnapshotDriftErrorObject(t *testing.T) {
	d := t12Dir(t)
	t12WriteSnap(t, d, time.Now(), map[string]any{"error": ".upgrade 目录不存在"})
	s, err := t12Client(d, t12Key).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if s.DriftError != ".upgrade 目录不存在" || len(s.Drift) != 0 {
		t.Fatalf("got %+v %q", s.Drift, s.DriftError)
	}
}

func TestT12SnapshotCorrupt(t *testing.T) {
	d := t12Dir(t)
	_ = os.WriteFile(filepath.Join(d, "snapshot", "latest.json"), []byte("{bad"), 0o644)
	if _, err := t12Client(d, t12Key).Snapshot(); err == nil || errors.Is(err, ErrAgentMissing) {
		t.Fatalf("损坏的快照应报解析错误, got %v", err)
	}
}

func TestT12NewFromEnv(t *testing.T) {
	t.Setenv("DIAG_AGENT_DIR", "")
	t.Setenv("DIAG_AGENT_HMAC_KEY", "")
	c := NewAgentClientFromEnv()
	if c.Dir != "/var/lib/jjdguard/diag" || c.Key != nil || c.Now == nil {
		t.Fatalf("默认值不对: %+v", c)
	}
	t.Setenv("DIAG_AGENT_DIR", "/x")
	t.Setenv("DIAG_AGENT_HMAC_KEY", "abc")
	c = NewAgentClientFromEnv()
	if c.Dir != "/x" || string(c.Key) != "abc" {
		t.Fatalf("环境变量未生效: %+v", c)
	}
}
