package handler

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
)

// 构造一个豆包网页版 /chat/completion 请求,用于请求侧测试。
func newDoubaoWebRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://www.doubao.com/samantha/chat/completion", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.URL = &url.URL{Scheme: "https", Host: "www.doubao.com", Path: "/samantha/chat/completion"}
	req.Host = "www.doubao.com"
	req.Header.Set("Content-Type", "application/json")
	return req
}

// SP2:用户随提问上传的非图片文件(type:3,带 file 子对象)应被请求侧捕获为附件元数据。
// file.url 为空、uri 是 TOS key(无下载签名)→ 只登记元数据(文件名/大小/引用),DownloadURL 留空。
// 同时文本仍须被抽到。
func TestDecodeDoubaoWebRequest_CapturesUploadedFileMeta(t *testing.T) {
	const body = `{
		"messages": [
			{
				"content_block": [
					{"content": {"text_block": {"text": "总结"}}},
					{"content": {"attachment_block": {"attachments": [
						{
							"type": 3,
							"identifier": "273b5190-aaaa-bbbb",
							"file": {
								"uri": "tos-cn-i-ik7evvg4ik/a539b.docx",
								"url": "",
								"file_type": 0,
								"name": "测试文件.docx",
								"size": 123456
							},
							"parse_state": 1,
							"review_state": 1,
							"upload_status": 1,
							"progress": 100
						}
					]}}}
				]
			}
		],
		"client_meta": {"conversation_id": "convF", "section_id": "secF"}
	}`

	req := newDoubaoWebRequest(t, []byte(body))
	got, ok := decodeDoubaoWebRequest(req, []byte(body), "application/json")
	if !ok {
		t.Fatalf("expected decode to succeed")
	}
	// 文本仍须抽到。
	if got.Text != "总结" {
		t.Fatalf("text mismatch: got %q want %q", got.Text, "总结")
	}
	// 文件附件须被登记。
	if len(got.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d (%+v)", len(got.Attachments), got.Attachments)
	}
	a := got.Attachments[0]
	if a.FileName != "测试文件.docx" {
		t.Fatalf("file_name mismatch: got %q want %q", a.FileName, "测试文件.docx")
	}
	if a.Size != 123456 {
		t.Fatalf("size mismatch: got %d want %d", a.Size, 123456)
	}
	if a.DownloadURL != "" {
		t.Fatalf("download_url 应留空(无可下载字节): got %q", a.DownloadURL)
	}
	// ReferenceID 优先 uri(TOS key,稳定引用)。
	if a.ReferenceID != "tos-cn-i-ik7evvg4ik/a539b.docx" {
		t.Fatalf("reference_id mismatch: got %q want %q", a.ReferenceID, "tos-cn-i-ik7evvg4ik/a539b.docx")
	}
	// ContentType 应从 .docx 扩展名推出。
	if a.ContentType == "" {
		t.Fatalf("content_type 应从 .docx 推出,不应为空")
	}
	// turn 分组键不退化。
	if got.ConversationID != "convF" || got.SectionID != "secF" {
		t.Fatalf("分组键退化: conv=%q sec=%q", got.ConversationID, got.SectionID)
	}
}

// 图片附件(type:1,带 image 子对象)归响应侧 collectStreamAttachments 捕获,
// 请求侧必须跳过,避免一张图被登记两次。
func TestDecodeDoubaoWebRequest_SkipsImageAttachment(t *testing.T) {
	const body = `{
		"messages": [
			{
				"content_block": [
					{"content": {"text_block": {"text": "看图"}}},
					{"content": {"attachment_block": {"attachments": [
						{
							"type": 1,
							"identifier": "img-1",
							"image": {
								"uri": "tos-cn/x.jpg",
								"url": "",
								"name": "id-card.jpg"
							},
							"review_state": 1
						}
					]}}}
				]
			}
		]
	}`

	req := newDoubaoWebRequest(t, []byte(body))
	got, ok := decodeDoubaoWebRequest(req, []byte(body), "application/json")
	if !ok {
		t.Fatalf("expected decode to succeed")
	}
	if got.Text != "看图" {
		t.Fatalf("text mismatch: got %q want %q", got.Text, "看图")
	}
	// 图片不在请求侧登记(归响应侧)。
	if len(got.Attachments) != 0 {
		t.Fatalf("图片附件不应在请求侧登记,got %d (%+v)", len(got.Attachments), got.Attachments)
	}
}

// Size 以 JSON 字符串形态出现时也应被兼容(以防万一)。
func TestDecodeDoubaoWebRequest_FileSizeAsString(t *testing.T) {
	const body = `{
		"messages": [
			{
				"content_block": [
					{"content": {"text_block": {"text": "看文件"}}},
					{"content": {"attachment_block": {"attachments": [
						{
							"type": 3,
							"identifier": "id-2",
							"file": {"uri": "tos-cn/y.pdf", "url": "", "name": "报告.pdf", "size": "789012"}
						}
					]}}}
				]
			}
		]
	}`

	req := newDoubaoWebRequest(t, []byte(body))
	got, ok := decodeDoubaoWebRequest(req, []byte(body), "application/json")
	if !ok {
		t.Fatalf("expected decode to succeed")
	}
	if len(got.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(got.Attachments))
	}
	if got.Attachments[0].Size != 789012 {
		t.Fatalf("size(string) mismatch: got %d want %d", got.Attachments[0].Size, 789012)
	}
}
