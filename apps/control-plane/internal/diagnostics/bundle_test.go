package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

var t15Secrets = []string{"sk-abcdef1234567890abcd", "Bearer xyz", "password=hunter2", "postgres://u:p@h/db"}

const t15Tenant = "tenant-secret-abc123"
const t15User = "user-secret-xyz789"

func t15Session() BundleSession {
	leak := strings.Join(t15Secrets, " ")
	out, _ := json.Marshal(map[string]string{"log": "上游返回 " + leak})
	now := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	reqID := "req_01234567-89ab-cdef-0123-456789abcdef"
	return BundleSession{
		ID: "sess-1", TenantID: t15Tenant, UserID: t15User,
		Input: Input{Kind: "request", Text: "我的请求 " + reqID + " 报错了，我的口令是 topsecretpw", Ref: reqID, WindowH: 1},
		Report: &Report{
			ID: "r1", Tier: TierL2, Degraded: "模型不可用，已降级为规则排查",
			Findings: []Finding{{
				CheckID: "c1", Severity: SevError, Level: LevelConfirmed,
				Title: "上游拒绝了 max_tokens 参数", Impact: "该模型所有请求失败",
				Advice:   []Advice{{Text: "改用 max_completion_tokens", Link: "/model-operations"}},
				Excluded: []string{"额度充足"},
				Evidence: []Evidence{{Kind: "request", Ref: "req_1", Summary: "上游返回 400", Raw: leak}},
			}},
			Steps: []Step{{Tool: "get_request", Summary: "查询请求详情"}},
		},
		Steps:     []Step{{Tool: "get_request", Args: json.RawMessage(`{"id":"req_1"}`), Summary: "查询请求详情", Output: out}},
		Messages:  json.RawMessage(`[{"role":"user","content":"正文机密"},{"role":"assistant","content":"回复机密"}]`),
		Host:      &HostSnapshot{At: "2026-10-24T10:00:00Z", Errors: []string{leak}},
		CreatedAt: now, FinishedAt: now.Add(time.Minute), Version: "1.2.3",
	}
}

func t15Unzip(t *testing.T, b []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		d, _ := io.ReadAll(rc)
		rc.Close()
		m[f.Name] = string(d)
	}
	return m
}

func TestT15BundleRedactsAndShape(t *testing.T) {
	b, err := BuildBundle(context.Background(), t15Session())
	if err != nil {
		t.Fatal(err)
	}
	files := t15Unzip(t, b)
	for _, n := range []string{"report.json", "report.md", "steps.jsonl", "host_snapshot.json", "meta.json"} {
		if _, ok := files[n]; !ok {
			t.Fatalf("缺少 %s", n)
		}
	}
	for name, c := range files {
		for _, s := range t15Secrets {
			if strings.Contains(c, s) {
				t.Errorf("%s 含有原值 %q", name, s)
			}
		}
		for _, s := range []string{"正文机密", "回复机密", "topsecretpw", t15User, t15Tenant} {
			if strings.Contains(c, s) {
				t.Errorf("%s 含有不应出现的 %q", name, s)
			}
		}
	}
	md := files["report.md"]
	for _, want := range []string{"## 结论", "上游拒绝了 max_tokens 参数", "## 排查过程", "已排除", "证据", "降级原因"} {
		if !strings.Contains(md, want) {
			t.Errorf("report.md 缺少 %q:\n%s", want, md)
		}
	}
	if !strings.Contains(md, "req_01234567-89ab-cdef-0123-456789abcdef") {
		t.Error("应保留提取出的请求编号")
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(files["meta.json"]), &meta); err != nil {
		t.Fatal(err)
	}
	if meta["version"] != "1.2.3" || len(meta["tenant_hash"].(string)) != 12 {
		t.Errorf("meta 异常: %v", meta)
	}
	if !strings.Contains(files["steps.jsonl"], "\"output\"") {
		t.Error("steps.jsonl 应含 output")
	}
}

func TestT15BundleNoHostSnapshot(t *testing.T) {
	s := t15Session()
	s.Host = nil
	b, err := BuildBundle(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := t15Unzip(t, b)["host_snapshot.json"]; ok {
		t.Error("无快照时不应有 host_snapshot.json")
	}
}

func TestT15BundleTruncatesOverLimit(t *testing.T) {
	old := t15MaxBundleBytes
	t15MaxBundleBytes = 50 * 1024
	defer func() { t15MaxBundleBytes = old }()
	s := t15Session()
	// 伪随机内容，避免被压缩得过小
	var sb strings.Builder
	x := uint32(12345)
	for i := 0; i < 400000; i++ {
		x = x*1664525 + 1013904223
		sb.WriteByte(byte('a' + (x>>24)%26))
	}
	out, _ := json.Marshal(map[string]string{"log": sb.String()})
	s.Steps = []Step{{Tool: "get_request", Summary: "x", Output: out}}
	b, err := BuildBundle(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > t15MaxBundleBytes {
		t.Fatalf("包大小 %d 超过上限 %d", len(b), t15MaxBundleBytes)
	}
	var meta map[string]any
	_ = json.Unmarshal([]byte(t15Unzip(t, b)["meta.json"]), &meta)
	if meta["truncated"] != true {
		t.Errorf("meta 应标注 truncated: %v", meta)
	}
}
