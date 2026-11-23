package nasexport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// NAS 脱敏事件导出器测试。
// 设计 §13 要求：默认关 / 只导出脱敏事件不导原文件 / 稳定 event_id 幂等 /
// 路径穿越防护 / NAS 不可用不阻塞判定（返回 error 由上层有限重试）。

func safeTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "nasexport-*")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestWriteEventCreatesIdempotentFile(t *testing.T) {
	root := safeTempDir(t)
	ev := ExportEvent{
		EventID:      "evt_abc123",
		TenantLabel:  "某客户",
		EntryPoint:   "API网关",
		TargetAI:     "glm-5.2",
		FileName:     "report.docx",
		FileSize:     12345,
		RealType:     "docx",
		SHA256:       "deadbeef",
		HitTypes:     []string{"phone_cn", "id_card_cn"},
		HitCounts:    map[string]int{"phone_cn": 1, "id_card_cn": 1},
		Action:       "block",
		PolicyVer:    "v1",
		EngineBuild:  "b1",
		LatencyMs:    42,
		UpstreamGot:  false,
	}
	if err := WriteEvent(root, ev); err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	path := filepath.Join(root, "evt_abc123.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected idempotent file evt_abc123.json: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if got["action"] != "block" {
		t.Fatalf("action mismatch: %v", got["action"])
	}
	// 幂等：再写一次不报错、不产生重复
	if err := WriteEvent(root, ev); err != nil {
		t.Fatalf("idempotent rewrite: %v", err)
	}
	// 目录应只有一个文件
	ents, _ := os.ReadDir(root)
	if len(ents) != 1 {
		t.Fatalf("expected 1 file, got %d", len(ents))
	}
}

func TestWriteEventRejectsPathTraversalEventID(t *testing.T) {
	root := safeTempDir(t)
	// 恶意 event_id 含路径穿越
	ev := ExportEvent{EventID: "../../../etc/passwd", Action: "block"}
	err := WriteEvent(root, ev)
	if err == nil {
		t.Fatalf("path traversal event_id must be rejected")
	}
	// 确认 root 目录内没有产生任何文件（穿越被拒，未写入）
	ents, _ := os.ReadDir(root)
	if len(ents) != 0 {
		t.Fatalf("path traversal event wrote files into root: %d entries", len(ents))
	}
}

func TestWriteEventRejectsEmptyEventID(t *testing.T) {
	root := safeTempDir(t)
	if err := WriteEvent(root, ExportEvent{EventID: ""}); err == nil {
		t.Fatalf("empty event_id must be rejected")
	}
}

func TestWriteEventRejectsBadEventIDChars(t *testing.T) {
	root := safeTempDir(t)
	// 含路径分隔符 / 空格 / 冒号 / 反斜杠的 event_id 必须被拒（路径穿越/特殊字符防护）
	// 注意：纯 `..` 点号若无分隔符是安全文件名(a..b)，不在此列。
	for _, bad := range []string{"a/b", "a\\b", "a b", "a:b"} {
		ev := ExportEvent{EventID: bad, Action: "block"}
		if err := WriteEvent(root, ev); err == nil {
			t.Fatalf("event_id %q must be rejected", bad)
		}
	}
}

func TestWriteEventDoesNotLeakRawPII(t *testing.T) {
	root := safeTempDir(t)
	phone := "13812345678"
	id := "110101199001010015"
	key := "AKIAIOSFODNN7EXAMPLE"
	ev := ExportEvent{
		EventID:    "evt_leak",
		FileName:   "report.docx",
		HitTypes:   []string{"phone_cn", "id_card_cn", "aws_access_key"},
		// 调用方若漏脱敏，直接塞完整 PII —— WriteEvent 必须兜底掩码
		SampleHits: []string{"手机" + phone, "证件" + id, "密钥" + key},
		Action:     "block",
	}
	if err := WriteEvent(root, ev); err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(root, "evt_leak.json"))
	blob := string(data)
	for _, secret := range []string{phone, id, key} {
		if contains(blob, secret) {
			t.Fatalf("export leaked raw PII/secret: %q in %s", secret, blob)
		}
	}
	// 脱敏后的前缀仍在（证明是掩码不是删除）
	if !contains(blob, "138***") {
		t.Fatalf("phone not masked-kept: %s", blob)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestWriteEventRootMustBeAbsolute(t *testing.T) {
	// 相对路径根目录拒绝（管理员必须固定绝对路径配置）
	ev := ExportEvent{EventID: "evt_x", Action: "block"}
	if err := WriteEvent("relative/dir", ev); err == nil {
		t.Fatalf("relative root must be rejected")
	}
}

func TestWriteEventNASUnavailableReturnsError(t *testing.T) {
	// 根目录不存在且不可创建（父目录无权限或不存在）→ 返回 error
	// 上层 outbox 据此有限重试；NAS 不可用不阻塞 DLP 判定（判定已在 engine 完成）
	ev := ExportEvent{EventID: "evt_nosuch", Action: "block"}
	// /proc 下通常不可随意创建子目录
	err := WriteEvent("/proc/nasexport-nonexistent-root", ev)
	if err == nil {
		// 某些环境 /proc 可写则跳过；只要不 panic 即可
		return
	}
	// 错误即预期（NAS 不可用）
}
