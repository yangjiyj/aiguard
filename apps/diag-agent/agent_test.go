package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/diagsign"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

// 假 docker：模拟 ps / logs / inspect / image inspect。
const fakeDocker = `#!/bin/sh
echo "$@" >> "$FAKE_DOCKER_LOG"
case "$1" in
ps)
  echo '{"ID":"c1","Names":"docker-compose-gateway-core-1","State":"running","Image":"gw:1","Labels":"com.docker.compose.project=docker-compose,com.docker.compose.service=gateway-core,com.docker.compose.project.working_dir=/srv/x"}'
  echo '{"ID":"c2","Names":"docker-compose-control-plane-1","State":"running","Image":"cp:1","Labels":"com.docker.compose.project=docker-compose,com.docker.compose.service=control-plane"}'
  echo '{"ID":"c9","Names":"other-svc-1","State":"running","Image":"o:1","Labels":"com.docker.compose.project=other,com.docker.compose.service=intruder"}'
  ;;
logs)
  echo "2026-10-24 INFO start"
  echo "2026-10-24 ERROR req_abc failed Authorization: Bearer abc.def.ghi"
  echo "2026-10-24 INFO req_xyz ok"
  echo "DB_PASSWORD=hunter2"
  echo "url postgres://user:pw@db:5432/x?token=zzz"
  ;;
inspect)
  shift
  out=""
  for id in "$@"; do
    [ -n "$out" ] && out="$out,"
    out="$out{\"Id\":\"$id-full\",\"Image\":\"sha256:img-$id\",\"Name\":\"/n-$id\",\"RestartCount\":3,\"State\":{\"Status\":\"running\",\"StartedAt\":\"2026-10-24T01:00:00Z\",\"Health\":{\"Status\":\"healthy\"}},\"Config\":{\"Image\":\"img:tag\",\"Env\":[\"FOO=bar\",\"SECRET_KEY=old\",\"MODE=run\"]}}"
  done
  echo "[$out]"
  ;;
image)
  echo "sha256:img-c1"
  ;;
esac
`

func setupFake(t *testing.T) (logFile string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	logFile = filepath.Join(t.TempDir(), "docker.log")
	t.Setenv("FAKE_DOCKER_LOG", logFile)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	return logFile
}

func newTestAgent(t *testing.T) *agent {
	t.Helper()
	deploy := t.TempDir()
	a, err := newAgent(t.TempDir(), deploy, testKey)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func submit(t *testing.T, a *agent, id, action string, params map[string]any, issued time.Time, key []byte) {
	t.Helper()
	ts := issued.UTC().Format(time.RFC3339)
	task := diagsign.Task{ID: id, Action: action, Params: params, IssuedAt: ts,
		Sig: diagsign.Sign(key, id, action, ts, params)}
	b, _ := json.Marshal(task)
	if err := os.WriteFile(filepath.Join(a.dir, "inbox", id+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func result(t *testing.T, a *agent, id string) diagsign.Result {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(a.dir, "outbox", id+".json"))
	if err != nil {
		t.Fatalf("没有结果 %s: %v", id, err)
	}
	var r diagsign.Result
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPingAndInboxDeleted(t *testing.T) {
	setupFake(t)
	a := newTestAgent(t)
	submit(t, a, "t_ping", "ping", map[string]any{}, time.Now(), testKey)
	a.scanInbox(context.Background())
	r := result(t, a, "t_ping")
	if !r.OK || !strings.HasPrefix(r.Output, "pong") {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(filepath.Join(a.dir, "inbox", "t_ping.json")); !os.IsNotExist(err) {
		t.Fatal("任务文件应被删除")
	}
}

func TestSignatureFailures(t *testing.T) {
	setupFake(t)
	a := newTestAgent(t)
	submit(t, a, "t_bad", "ping", map[string]any{}, time.Now(), []byte("wrong-key-wrong-key-wrong-key-xx"))
	submit(t, a, "t_old", "ping", map[string]any{}, time.Now().Add(-3*time.Minute), testKey)
	a.scanInbox(context.Background())
	if r := result(t, a, "t_bad"); r.OK || r.Error != "bad_signature" {
		t.Fatalf("%+v", r)
	}
	if r := result(t, a, "t_old"); r.OK || r.Error != "expired" {
		t.Fatalf("%+v", r)
	}
}

func TestReplayRejected(t *testing.T) {
	setupFake(t)
	a := newTestAgent(t)
	issued := time.Now()
	submit(t, a, "t_r", "ping", map[string]any{}, issued, testKey)
	a.scanInbox(context.Background())
	if r := result(t, a, "t_r"); !r.OK {
		t.Fatalf("%+v", r)
	}
	os.Remove(filepath.Join(a.dir, "outbox", "t_r.json"))
	submit(t, a, "t_r", "ping", map[string]any{}, issued, testKey)
	a.scanInbox(context.Background())
	if r := result(t, a, "t_r"); r.OK || r.Error != "replay" {
		t.Fatalf("%+v", r)
	}
	// 重启后（重新加载 seen.log）仍然拒绝
	a2, err := newAgent(a.dir, a.deployDir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(a.dir, "outbox", "t_r.json"))
	submit(t, a2, "t_r", "ping", map[string]any{}, issued, testKey)
	a2.scanInbox(context.Background())
	if r := result(t, a2, "t_r"); r.OK || r.Error != "replay" {
		t.Fatalf("重启后 %+v", r)
	}
}

func TestInjectionRejected(t *testing.T) {
	logFile := setupFake(t)
	a := newTestAgent(t)
	cases := []struct {
		id, action string
		params     map[string]any
		wantErr    string
	}{
		{"i1", "container_logs", map[string]any{"service": "gateway-core", "grep": "a;rm -rf /"}, "bad_params"},
		{"i2", "container_logs", map[string]any{"service": "../etc", "grep": "x"}, "bad_params"},
		{"i3", "container_logs", map[string]any{"service": "gateway-core", "since_minutes": 9999}, "bad_params"},
		{"i4", "rm_rf", map[string]any{}, "unknown_action"},
		{"i5", "container_logs", map[string]any{"service": "gateway-core", "grep": "$(id)"}, "bad_params"},
		{"i6", "container_logs", map[string]any{"service": "gateway-core", "grep": "a b"}, "bad_params"},
		{"i7", "container_logs", map[string]any{"service": "gateway-core", "since_minutes": 0}, "bad_params"},
		{"i8", "container_logs", map[string]any{"service": "gateway-core", "since_minutes": 1.5}, "bad_params"},
		{"i9", "container_logs", map[string]any{"service": "gateway-core", "since_minutes": "5"}, "bad_params"},
		{"i10", "container_logs", map[string]any{"service": "gateway-core", "extra": "x"}, "bad_params"},
		{"i11", "container_logs", map[string]any{"grep": "x"}, "bad_params"},
		{"i12", "container_logs", map[string]any{"service": "gateway-core", "grep": strings.Repeat("a", 129)}, "bad_params"},
		{"i13", "container_inspect", map[string]any{"service": "-rf"}, "bad_params"},
		{"i14", "container_inspect", map[string]any{"service": "gateway-core;id"}, "bad_params"},
		{"i15", "ping", map[string]any{"x": 1}, "bad_params"},
		{"i16", "container_logs", map[string]any{"service": "intruder"}, "unknown_service"},
		{"i17", "container_inspect", map[string]any{"service": "nonexistent"}, "unknown_service"},
		{"i18", "container_logs", map[string]any{"service": "gateway-core", "grep": 5}, "bad_params"},
	}
	for _, c := range cases {
		submit(t, a, c.id, c.action, c.params, time.Now(), testKey)
	}
	a.scanInbox(context.Background())
	for _, c := range cases {
		r := result(t, a, c.id)
		if r.OK || r.Error != c.wantErr {
			t.Errorf("%s: %+v 期望 %s", c.id, r, c.wantErr)
		}
	}
	// 注入类用例不应触发任何 docker logs
	b, _ := os.ReadFile(logFile)
	if strings.Contains(string(b), "logs") && !strings.Contains(string(b), "ps") {
		t.Fatalf("不应执行 logs: %s", b)
	}
}

func TestContainerLogsFilterRedactAndArgs(t *testing.T) {
	logFile := setupFake(t)
	a := newTestAgent(t)
	submit(t, a, "l1", "container_logs", map[string]any{"service": "gateway-core", "grep": "req_abc", "since_minutes": 7}, time.Now(), testKey)
	submit(t, a, "l2", "container_logs", map[string]any{"service": "gateway-core"}, time.Now(), testKey)
	a.scanInbox(context.Background())
	r := result(t, a, "l1")
	if !r.OK || !strings.Contains(r.Output, "req_abc") || strings.Contains(r.Output, "req_xyz") {
		t.Fatalf("grep 过滤失败: %+v", r)
	}
	if strings.Contains(r.Output, "abc.def.ghi") {
		t.Fatalf("Bearer 未脱敏: %s", r.Output)
	}
	r2 := result(t, a, "l2")
	if strings.Contains(r2.Output, "hunter2") || strings.Contains(r2.Output, "user:pw") || strings.Contains(r2.Output, "zzz") {
		t.Fatalf("未脱敏: %s", r2.Output)
	}
	b, _ := os.ReadFile(logFile)
	if !strings.Contains(string(b), "logs --since 7m c1") {
		t.Fatalf("docker logs 参数不对: %s", b)
	}
	if strings.Contains(string(b), "req_abc") {
		t.Fatal("grep 不应传给 docker")
	}
}

func TestContainerInspectNoEnv(t *testing.T) {
	setupFake(t)
	a := newTestAgent(t)
	submit(t, a, "n1", "container_inspect", map[string]any{"service": "control-plane"}, time.Now(), testKey)
	a.scanInbox(context.Background())
	r := result(t, a, "n1")
	if !r.OK || !strings.Contains(r.Output, "restart_count=3") || !strings.Contains(r.Output, "health=healthy") {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(r.Output, "SECRET_KEY") || strings.Contains(r.Output, "FOO") {
		t.Fatalf("不应输出 env: %s", r.Output)
	}
}

func TestOutputCap(t *testing.T) {
	s := strings.Repeat("x", diagsign.MaxOutputBytes+100)
	o, tr := capOutput(s)
	if len(o) != diagsign.MaxOutputBytes || !tr {
		t.Fatal("上限未生效")
	}
	if _, tr := capOutput("ok"); tr {
		t.Fatal()
	}
}

func TestPEMRedaction(t *testing.T) {
	in := "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIsecret\nmore\n-----END RSA PRIVATE KEY-----\nb"
	out := redactText(in)
	if strings.Contains(out, "MIIsecret") || !strings.Contains(out, "a") || !strings.HasSuffix(out, "b") {
		t.Fatalf("%q", out)
	}
	if got := redactText(`{"password":"p@ss","name":"n"}`); strings.Contains(got, "p@ss") || !strings.Contains(got, `"name":"n"`) {
		t.Fatal(got)
	}
}

func TestSnapshotAtomicAndContent(t *testing.T) {
	setupFake(t)
	a := newTestAgent(t)
	ctx := context.Background()
	if err := a.writeSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	snapPath := filepath.Join(a.dir, "snapshot", "latest.json")
	b, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		AgentVersion string         `json:"agent_version"`
		Containers   []containerRow `json:"containers"`
		Drift        map[string]any `json:"drift"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if s.AgentVersion != agentVersion || len(s.Containers) != 2 {
		t.Fatalf("%+v", s)
	}
	if s.Drift["error"] == nil {
		t.Fatalf("没有 .upgrade 时 drift.error 应存在: %+v", s.Drift)
	}
	for _, c := range s.Containers {
		if c.Service == "intruder" {
			t.Fatal("不应包含其它项目的容器")
		}
	}
	// 并发读写：读到的永远是完整 JSON，目录里不残留临时文件。
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				bb, err := os.ReadFile(snapPath)
				if err != nil || !json.Valid(bb) {
					t.Errorf("读到不完整快照: %v len=%d", err, len(bb))
					return
				}
			}
		}
	}()
	for i := 0; i < 30; i++ {
		if err := a.writeSnapshot(ctx); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	ents, _ := os.ReadDir(filepath.Join(a.dir, "snapshot"))
	if len(ents) != 1 {
		t.Fatalf("残留临时文件: %v", ents)
	}
}

func TestDriftDetectsDifferences(t *testing.T) {
	setupFake(t)
	a := newTestAgent(t)
	up := filepath.Join(a.deployDir, ".upgrade")
	os.MkdirAll(up, 0o755)
	os.WriteFile(filepath.Join(up, "project-directory"), []byte("/srv/x\n"), 0o644)
	os.WriteFile(filepath.Join(up, "compose-files"), []byte("/srv/x/a.yml\n\n/srv/x/b.yml\n"), 0o644)
	cfg := `{"services":{"gateway-core":{"image":"gw:1","environment":{"FOO":"bar","MODE":"new","SECRET_KEY":"changed"}},"control-plane":{"image":"cp:1","environment":{"FOO":"bar"}},"ghost":{"image":"g:1"}}}`
	script := "#!/bin/sh\necho \"$@\" > " + filepath.Join(a.deployDir, "args.txt") + "\ncat <<'EOF'\n" + cfg + "\nEOF\n"
	os.WriteFile(filepath.Join(a.deployDir, "compose-wrapper.sh"), []byte(script), 0o755)

	rows, e := a.collectDrift(context.Background())
	if e != "" {
		t.Fatal(e)
	}
	by := map[string]driftRow{}
	for _, r := range rows {
		by[r.Service] = r
	}
	gw := by["gateway-core"]
	if !gw.ImageMatch {
		t.Errorf("gateway-core 镜像应一致: %+v", gw)
	}
	if len(gw.EnvDiff) != 2 {
		t.Fatalf("env_diff: %+v", gw.EnvDiff)
	}
	for _, d := range gw.EnvDiff {
		if d.Key == "MODE" && (d.Sensitive || d.Chain != "new" || d.Running != "run") {
			t.Errorf("%+v", d)
		}
		if d.Key == "SECRET_KEY" && (!d.Sensitive || d.Chain != "" || d.Running != "") {
			t.Errorf("敏感值不应出现: %+v", d)
		}
	}
	if cp := by["control-plane"]; cp.ImageMatch { // fake 的 image inspect 恒返回 img-c1，c2 不同
		t.Errorf("control-plane 镜像应不一致: %+v", cp)
	}
	if !by["ghost"].NotRunning {
		t.Error("ghost 应为 not_running")
	}
	args, _ := os.ReadFile(filepath.Join(a.deployDir, "args.txt"))
	want := "--project-name docker-compose --project-directory /srv/x --env-file .env -f docker-compose.offline.yml -f /srv/x/a.yml -f /srv/x/b.yml config --format json"
	if strings.TrimSpace(string(args)) != want {
		t.Errorf("渲染参数:\n got %s\nwant %s", args, want)
	}
}

func TestDriftProjectDirectoryNotShellInterpreted(t *testing.T) {
	setupFake(t)
	a := newTestAgent(t)
	up := filepath.Join(a.deployDir, ".upgrade")
	os.MkdirAll(up, 0o755)
	marker := filepath.Join(t.TempDir(), "pwned")
	os.WriteFile(filepath.Join(up, "project-directory"), []byte("/srv/x;touch "+marker+"\n"), 0o644)
	os.WriteFile(filepath.Join(up, "compose-files"), []byte(""), 0o644)
	os.WriteFile(filepath.Join(a.deployDir, "compose-wrapper.sh"), []byte("#!/bin/sh\necho '{\"services\":{}}'\n"), 0o755)
	if _, e := a.collectDrift(context.Background()); e != "" {
		t.Fatal(e)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("project-directory 被当作 shell 执行")
	}
}

func TestDriftRenderFailure(t *testing.T) {
	setupFake(t)
	a := newTestAgent(t)
	up := filepath.Join(a.deployDir, ".upgrade")
	os.MkdirAll(up, 0o755)
	os.WriteFile(filepath.Join(up, "project-directory"), []byte("/srv/x\n"), 0o644)
	os.WriteFile(filepath.Join(up, "compose-files"), []byte(""), 0o644)
	os.WriteFile(filepath.Join(a.deployDir, "compose-wrapper.sh"), []byte("#!/bin/sh\necho boom >&2\nexit 1\n"), 0o755)
	_, e := a.collectDrift(context.Background())
	if !strings.Contains(e, "开机链渲染失败") {
		t.Fatalf("%q", e)
	}
}

func TestReadKeyPerms(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "k")
	os.WriteFile(p, []byte("0123456789abcdef0123\n"), 0o644)
	if _, err := readKey(p); err == nil {
		t.Fatal("0644 应拒绝")
	}
	os.Chmod(p, 0o600)
	k, err := readKey(p)
	if err != nil || string(k) != "0123456789abcdef0123" {
		t.Fatal(err, string(k))
	}
}

func TestSymlinkTaskRejected(t *testing.T) {
	setupFake(t)
	a := newTestAgent(t)
	target := filepath.Join(t.TempDir(), "x.json")
	os.WriteFile(target, []byte("{}"), 0o644)
	os.Symlink(target, filepath.Join(a.dir, "inbox", "sym.json"))
	a.scanInbox(context.Background())
	if r := result(t, a, "sym"); r.OK || r.Error != "bad_request" {
		t.Fatalf("%+v", r)
	}
}

func TestIDMismatchFilename(t *testing.T) {
	setupFake(t)
	a := newTestAgent(t)
	ts := time.Now().UTC().Format(time.RFC3339)
	task := diagsign.Task{ID: "other", Action: "ping", Params: map[string]any{}, IssuedAt: ts,
		Sig: diagsign.Sign(testKey, "other", "ping", ts, map[string]any{})}
	b, _ := json.Marshal(task)
	os.WriteFile(filepath.Join(a.dir, "inbox", "mine.json"), b, 0o644)
	a.scanInbox(context.Background())
	if r := result(t, a, "mine"); r.OK {
		t.Fatal("文件名与 id 不一致应拒绝")
	}
}
