package handler

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestParseTurnMemberIDsCapsUntrustedMemberList(t *testing.T) {
	parts := make([]string, 0, 600)
	for i := 0; i < 600; i++ {
		parts = append(parts, fmt.Sprintf("req-%03d", i))
	}
	got := parseTurnMemberIDs(strings.Join(parts, ","), "self")
	if len(got) != 500 {
		t.Fatalf("member list len = %d, want capped 500", len(got))
	}
	if got[0] != "self" {
		t.Fatalf("self request must remain anchor, got first=%q", got[0])
	}
}
func TestParseTurnMemberIDsAlwaysIncludesSelfAndDedupes(t *testing.T) {
	got := parseTurnMemberIDs("b, a , b,, c", "self")
	want := []string{"self", "b", "a", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	// 空 members → 退回单请求（仅含 self）。
	if single := parseTurnMemberIDs("", "self"); len(single) != 1 || single[0] != "self" {
		t.Fatalf("empty members should fall back to [self], got %v", single)
	}
}

func TestMergeTurnAccessContentLogsMergesBodiesAndFileMetadata(t *testing.T) {
	t1 := time.Date(2026, 6, 27, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 27, 11, 0, 0, 0, time.UTC)
	logs := []repository.AccessContentLog{
		{RequestID: "old", RequestContent: "问题一", ResponseContent: "回答一",
			FileMetadataJSON: []byte(`[{"file_name":"a.png"}]`), RetentionUntil: &t1},
		{RequestID: "new", RequestContent: "问题二", ResponseContent: "回答二",
			FileMetadataJSON: []byte(`[{"file_name":"b.png"}]`), RetentionUntil: &t2},
	}

	merged := mergeTurnAccessContentLogs("new", []string{"new", "old"}, logs)
	if merged == nil {
		t.Fatal("merged should not be nil")
	}
	// 代表行 request_id 不变（单请求可寻址 / 图片代理鉴权按它走）。
	if merged.RequestID != "new" {
		t.Fatalf("merged request_id = %q, want 'new'", merged.RequestID)
	}
	// 正文按轮次拼接，含两轮内容与序号标注。
	for _, want := range []string{"问题一", "问题二", "第 1/2 轮", "第 2/2 轮"} {
		if !strings.Contains(merged.RequestContent, want) {
			t.Fatalf("merged request_content missing %q:\n%s", want, merged.RequestContent)
		}
	}
	for _, want := range []string{"回答一", "回答二"} {
		if !strings.Contains(merged.ResponseContent, want) {
			t.Fatalf("merged response_content missing %q:\n%s", want, merged.ResponseContent)
		}
	}
	// file_metadata 并集，两条文件都在。
	var meta []map[string]interface{}
	if err := json.Unmarshal(merged.FileMetadataJSON, &meta); err != nil {
		t.Fatalf("unmarshal merged metadata: %v", err)
	}
	if len(meta) != 2 {
		t.Fatalf("merged file_metadata len = %d, want 2: %s", len(meta), merged.FileMetadataJSON)
	}
	// retention_until 取最晚。
	if merged.RetentionUntil == nil || !merged.RetentionUntil.Equal(t2) {
		t.Fatalf("merged retention_until = %v, want %v (latest)", merged.RetentionUntil, t2)
	}
}

func TestMergeTurnAccessContentLogsCollapsesPhysicalRequestsIntoConversationRounds(t *testing.T) {
	logs := []repository.AccessContentLog{
		{RequestID: "turn1-old", SectionID: "turn-1", RequestContent: "问题一", ResponseContent: "中间回答"},
		{RequestID: "turn1-new", SectionID: "turn-1", RequestContent: "问题一", ResponseContent: "最终回答一"},
		{RequestID: "turn2", SectionID: "turn-2", RequestContent: "问题二", ResponseContent: "最终回答二"},
	}

	merged := mergeTurnAccessContentLogs("turn2", []string{"turn2", "turn1-old", "turn1-new"}, logs)
	if merged == nil {
		t.Fatal("merged should not be nil")
	}
	if strings.Count(merged.RequestContent, "问题一") != 1 {
		t.Fatalf("same turn prompt should appear once, got:\n%s", merged.RequestContent)
	}
	if strings.Contains(merged.ResponseContent, "中间回答") {
		t.Fatalf("intermediate physical response must be hidden, got:\n%s", merged.ResponseContent)
	}
	for _, want := range []string{"第 1/2 轮", "第 2/2 轮", "最终回答一", "最终回答二"} {
		if !strings.Contains(merged.RequestContent+merged.ResponseContent, want) {
			t.Fatalf("conversation detail missing %q:\nrequest=%s\nresponse=%s", want, merged.RequestContent, merged.ResponseContent)
		}
	}
}

func TestMergeTurnAccessContentLogsSingleMemberNoPrefix(t *testing.T) {
	logs := []repository.AccessContentLog{
		{RequestID: "solo", RequestContent: "唯一问题", ResponseContent: "唯一回答",
			FileMetadataJSON: []byte(`[]`)},
	}
	merged := mergeTurnAccessContentLogs("solo", []string{"solo"}, logs)
	if merged == nil {
		t.Fatal("merged should not be nil")
	}
	// 单成员不应加「第 N/M 次请求」前缀。
	if strings.Contains(merged.RequestContent, "次请求") {
		t.Fatalf("single-member merge should not add member prefix: %s", merged.RequestContent)
	}
	if merged.RequestContent != "唯一问题" {
		t.Fatalf("single-member request_content = %q, want '唯一问题'", merged.RequestContent)
	}
}

func TestMergeTurnAccessContentLogsEmptyReturnsNil(t *testing.T) {
	if merged := mergeTurnAccessContentLogs("x", []string{"x"}, nil); merged != nil {
		t.Fatalf("empty logs should return nil, got %+v", merged)
	}
}

// 同一文件（同 sha256）在两个成员里各出现一次：合并后只剩 1 条，且保留带 object_key 的那条。
func TestMergeTurnAccessContentLogsDedupesSameFileKeepsBytes(t *testing.T) {
	logs := []repository.AccessContentLog{
		// 成员一：同一 sha256 的文件，不带字节（仅元数据）。
		{RequestID: "m1", RequestContent: "问题一", ResponseContent: "回答一",
			FileMetadataJSON: []byte(`[{"file_name":"report.pdf","sha256":"deadbeef"}]`)},
		// 成员二：同一 sha256，带 object_key（可预览/下载）。
		{RequestID: "m2", RequestContent: "问题二", ResponseContent: "回答二",
			FileMetadataJSON: []byte(`[{"file_name":"report.pdf","sha256":"deadbeef","object_key":"tenant/obj/report.pdf"}]`)},
	}
	merged := mergeTurnAccessContentLogs("m2", []string{"m2", "m1"}, logs)
	if merged == nil {
		t.Fatal("merged should not be nil")
	}
	var meta []map[string]interface{}
	if err := json.Unmarshal(merged.FileMetadataJSON, &meta); err != nil {
		t.Fatalf("unmarshal merged metadata: %v", err)
	}
	if len(meta) != 1 {
		t.Fatalf("dedup should fold same-sha256 file into 1 entry, got %d: %s", len(meta), merged.FileMetadataJSON)
	}
	if ok, _ := meta[0]["object_key"].(string); ok == "" {
		t.Fatalf("dedup should keep the entry WITH bytes (object_key), got: %v", meta[0])
	}
}

func TestDedupeTurnFileMetadataDistinctAndKeyless(t *testing.T) {
	// 不同 sha256 不被误并；reference_id / file_name 作为次级键；键全空条目原样保留。
	entries := []map[string]interface{}{
		{"file_name": "a.png", "sha256": "aaa"},
		{"file_name": "b.png", "sha256": "bbb"},          // 不同 sha256 → 保留
		{"file_name": "a.png", "sha256": "aaa"},          // 同 sha256 → 折叠
		{"reference_id": "ref-1"},                        // 次级键 reference_id
		{"reference_id": "ref-1", "data_base64": "Qg=="}, // 同 reference_id 且带字节 → 升级
		{"text_preview": "无键条目一"},                        // 键全空 → 保留
		{"text_preview": "无键条目二"},                        // 键全空 → 保留（不与上一条折叠）
	}
	out := dedupeTurnFileMetadata(entries)
	// 期望：a.png(1) + b.png(1) + ref-1(1) + 两条无键 = 5
	if len(out) != 5 {
		t.Fatalf("dedup result len = %d, want 5: %+v", len(out), out)
	}
	// 不同 sha256 都在。
	shas := map[string]bool{}
	for _, e := range out {
		if s, _ := e["sha256"].(string); s != "" {
			shas[s] = true
		}
	}
	if !shas["aaa"] || !shas["bbb"] {
		t.Fatalf("distinct sha256 must not be merged, got shas=%v", shas)
	}
	// ref-1 折叠为带字节的那条。
	var refEntry map[string]interface{}
	for _, e := range out {
		if r, _ := e["reference_id"].(string); r == "ref-1" {
			refEntry = e
		}
	}
	if refEntry == nil {
		t.Fatal("ref-1 entry missing")
	}
	if b, _ := refEntry["data_base64"].(string); b == "" {
		t.Fatalf("same reference_id should fold to the entry with bytes, got: %v", refEntry)
	}
	// 两条无键条目都保留。
	keyless := 0
	for _, e := range out {
		if turnFileMetadataDedupKey(e) == "" {
			keyless++
		}
	}
	if keyless != 2 {
		t.Fatalf("keyless entries should be preserved as-is, got %d", keyless)
	}
}
