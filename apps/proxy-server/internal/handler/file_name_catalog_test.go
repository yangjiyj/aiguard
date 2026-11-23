package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 网页大模型上传文件时，首个请求载荷里 file-id 与文件名同时出现；后续对话轮次往往只带裸
// file-id。本组用例锁定「进程内有界目录」的契约：上传那次登记文件名，后续只带裸 id 的轮次
// 据此还原成人类可读文件名，且不得跨租户/跨厂商串名。对应用户要求："不要出现编码与ID，要给人看"。

func TestResolveAttachmentFileNames_RestoresBareFileIDAcrossRequests(t *testing.T) {
	cat := newFileNameCatalog(0)
	const fileID = "file-238c74b9-c8ed-4a86-8563-07b9b5fe656b"

	// 第一次：网页上传，附件对象带 id+name，走 json_file_object，已能拿到文件名。
	regBody := `{"messages":[{"role":"user","content":"请总结这份报表","metadata":{"attachments":[{"id":"` + fileID + `","name":"上传报表.xlsx","mime_type":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet","size":51200}]}}]}`
	regReq := httptest.NewRequest(http.MethodPost, "https://chat.deepseek.com/api/v0/chat/completion", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regContent := extractRequestContent(regReq, []byte(regBody))
	if len(regContent.Attachments) != 1 || regContent.Attachments[0].FileName != "上传报表.xlsx" {
		t.Fatalf("precondition: upload should carry filename: %+v", regContent.Attachments)
	}
	// 登记上传轮次的 id+name。
	resolveAttachmentFileNames(cat, "tenant_a", "deepseek", regContent)

	// 后续轮次：只带裸 file-id，无文件名，走 json_file_reference，文本里是 [ref_file_ids] file-...。
	bareBody := `{"prompt":"基于刚才上传的报表回答","ref_file_ids":["` + fileID + `"]}`
	bareReq := httptest.NewRequest(http.MethodPost, "https://chat.deepseek.com/api/v0/chat/completion", strings.NewReader(bareBody))
	bareReq.Header.Set("Content-Type", "application/json")
	bareContent := extractRequestContent(bareReq, []byte(bareBody))
	if len(bareContent.Attachments) != 1 || bareContent.Attachments[0].FileName != "" || bareContent.Attachments[0].ReferenceID != fileID {
		t.Fatalf("precondition: follow-up turn should be a bare reference: %+v", bareContent.Attachments)
	}
	if !strings.Contains(bareContent.Text, fileID) {
		t.Fatalf("precondition: bare text should carry the raw id before restore: %q", bareContent.Text)
	}

	restored := resolveAttachmentFileNames(cat, "tenant_a", "deepseek", bareContent)
	if restored.Attachments[0].FileName != "上传报表.xlsx" {
		t.Fatalf("attachment filename not restored across requests: %+v", restored.Attachments[0])
	}
	if restored.Attachments[0].ContentType == "reference/file-id" || restored.Attachments[0].ContentType == "" {
		t.Fatalf("content type should be inferred from filename after restore: %+v", restored.Attachments[0])
	}
	if strings.Contains(restored.Text, fileID) {
		t.Fatalf("raw file-id must not leak into retained text after restore: %q", restored.Text)
	}
	if !strings.Contains(restored.Text, "上传报表.xlsx") {
		t.Fatalf("restored text should show the human filename: %q", restored.Text)
	}
}

func TestResolveAttachmentFileNames_TenantIsolation(t *testing.T) {
	cat := newFileNameCatalog(0)
	const fileID = "file-aaaaaaaa-1111-2222-3333-444444444444"
	upload := ExtractedContent{Attachments: []ExtractedAttachment{{
		Source: "json_file_object", FileName: "甲租户机密.pdf", ReferenceID: fileID, ContentType: "application/pdf",
	}}}
	resolveAttachmentFileNames(cat, "tenant_a", "openai", upload)

	bare := ExtractedContent{
		Text:        "[attachments] " + fileID,
		Attachments: []ExtractedAttachment{{Source: "json_file_reference", FieldName: "attachments", ReferenceID: fileID, ContentType: "reference/file-id"}},
	}
	got := resolveAttachmentFileNames(cat, "tenant_b", "openai", bare)
	if got.Attachments[0].FileName != "" {
		t.Fatalf("filename must not bleed across tenants: %+v", got.Attachments[0])
	}
	if !strings.Contains(got.Text, fileID) {
		t.Fatalf("unmatched tenant should leave text untouched: %q", got.Text)
	}
}

func TestResolveAttachmentFileNames_ProviderIsolation(t *testing.T) {
	cat := newFileNameCatalog(0)
	const fileID = "file-bbbbbbbb-5555-6666-7777-888888888888"
	upload := ExtractedContent{Attachments: []ExtractedAttachment{{
		Source: "json_file_object", FileName: "豆包侧文件.docx", ReferenceID: fileID, ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	}}}
	resolveAttachmentFileNames(cat, "tenant_a", "doubao", upload)

	bare := ExtractedContent{
		Attachments: []ExtractedAttachment{{Source: "json_file_reference", FieldName: "attachments", ReferenceID: fileID, ContentType: "reference/file-id"}},
	}
	got := resolveAttachmentFileNames(cat, "tenant_a", "openai", bare)
	if got.Attachments[0].FileName != "" {
		t.Fatalf("filename must not bleed across providers: %+v", got.Attachments[0])
	}
}

func TestResolveAttachmentFileNames_RegisterThenRestoreWithinSameContent(t *testing.T) {
	cat := newFileNameCatalog(0)
	const fileID = "file-cccccccc-9999-0000-aaaa-bbbbbbbbbbbb"
	// 同一次内容里既有上传对象（id+name），又有靠后的裸引用：登记-还原应一次完成。
	content := ExtractedContent{
		Text: "[attachments] " + fileID,
		Attachments: []ExtractedAttachment{
			{Source: "json_file_object", FileName: "同批上传.csv", ReferenceID: fileID, ContentType: "text/csv"},
			{Source: "json_file_reference", FieldName: "attachments", ReferenceID: fileID, ContentType: "reference/file-id"},
		},
	}
	got := resolveAttachmentFileNames(cat, "tenant_a", "kimi", content)
	if got.Attachments[1].FileName != "同批上传.csv" {
		t.Fatalf("bare reference in same content not restored: %+v", got.Attachments[1])
	}
	if strings.Contains(got.Text, fileID) {
		t.Fatalf("raw id should be cleaned from text within same content: %q", got.Text)
	}
}

func TestResolveAttachmentFileNames_NilCatalogAndEmpty(t *testing.T) {
	content := ExtractedContent{Text: "纯文本无附件", Attachments: nil}
	if got := resolveAttachmentFileNames(nil, "t", "p", content); got.Text != "纯文本无附件" {
		t.Fatalf("nil catalog must be a no-op: %+v", got)
	}
	if got := resolveAttachmentFileNames(newFileNameCatalog(0), "t", "p", content); len(got.Attachments) != 0 {
		t.Fatalf("no attachments must stay no-op: %+v", got)
	}
}

func TestFileNameCatalog_BoundedLRUEviction(t *testing.T) {
	cat := newFileNameCatalog(2)
	cat.put("t", "p", "id1", "n1")
	cat.put("t", "p", "id2", "n2")
	cat.put("t", "p", "id3", "n3") // 超出容量，最久未用的 id1 应被淘汰
	if _, ok := cat.get("t", "p", "id1"); ok {
		t.Fatal("id1 should have been evicted by capacity bound")
	}
	if name, ok := cat.get("t", "p", "id2"); !ok || name != "n2" {
		t.Fatalf("id2 should survive: ok=%v name=%q", ok, name)
	}
	if name, ok := cat.get("t", "p", "id3"); !ok || name != "n3" {
		t.Fatalf("id3 should survive: ok=%v name=%q", ok, name)
	}

	// LRU：最近用过的不该被先淘汰。
	cat2 := newFileNameCatalog(2)
	cat2.put("t", "p", "a", "na")
	cat2.put("t", "p", "b", "nb")
	if _, ok := cat2.get("t", "p", "a"); !ok { // 触碰 a，使其成为最近使用
		t.Fatal("a should be present before touch")
	}
	cat2.put("t", "p", "c", "nc") // 应淘汰最久未用的 b
	if _, ok := cat2.get("t", "p", "b"); ok {
		t.Fatal("b should be evicted as least-recently-used")
	}
	if _, ok := cat2.get("t", "p", "a"); !ok {
		t.Fatal("recently-used a should survive")
	}
	if _, ok := cat2.get("t", "p", "c"); !ok {
		t.Fatal("newest c should survive")
	}
}
