package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 这些测试钉死 ChatGPT 网页版「访问留存」对图片/文件的抓取链路。三处缺口对应三条断言：
//
//  1. /backend-api/estuary/content 是图片/文件字节经正向代理的唯一可见副本，其分类必须为
//     "content"，否则 ContentRetained=false，proxy.go 永远不会落库这些字节。
//  2. estuary 的 file-id 在 query(?id=file_xxx) 而非 path 上，请求侧需据此产出一个
//     reference-only 附件，让 ResolveUploadedFileBytes 能按 reference_id 在同一行内交叉匹配字节。
//  3. 非图片二进制（PDF 等）响应也要产出带 DataBase64 的附件——此前仅 image/* 会，文件因此丢失。
//
// 全部使用合成、不含任何真实留存明文的占位字节。

// 缺口 1：estuary content 端点的留存级别必须是 content。
func TestChatGPTEstuaryContentIsRetainedAsContent(t *testing.T) {
	match := detectLLMProvider("chatgpt.com", "/backend-api/estuary/content")
	if !match.Known {
		t.Fatalf("estuary content 端点应被识别为已知 LLM 端点，实际 %+v", match)
	}
	if match.RetainLevel != "content" {
		t.Fatalf("estuary content 端点 RetainLevel = %q，期望 \"content\"（否则字节永不留存）", match.RetainLevel)
	}
}

// 缺口 2：estuary GET 请求需从 query 的 id= 解析出 file-id 并产出引用附件。
func TestExtractRequestContent_ChatGPTEstuaryIDQueryYieldsReference(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/estuary/content?id=file_00000000abcdef&ts=123", nil)

	extracted := extractRequestContent(req, nil)

	var found *ExtractedAttachment
	for i := range extracted.Attachments {
		if extracted.Attachments[i].ReferenceID == "file_00000000abcdef" {
			found = &extracted.Attachments[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("estuary GET 应产出 ReferenceID=file_00000000abcdef 的引用附件，实际 %+v", extracted.Attachments)
	}
}

// 缺口 3：非图片二进制（PDF）响应也要保留 DataBase64。
func TestExtractResponseContent_KeepsNonImageFileBodyAsAttachment(t *testing.T) {
	// 一个最小的合法 PDF 头（非图片二进制），合成数据，不含任何真实留存明文。
	body := []byte("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj<<>>endobj\n")

	extracted := extractResponseContent(body, "application/pdf")

	if len(extracted.Attachments) != 1 {
		t.Fatalf("非图片文件响应附件数 = %d，期望 1：%+v", len(extracted.Attachments), extracted.Attachments)
	}
	got := extracted.Attachments[0]
	if got.DataBase64 == "" {
		t.Fatalf("非图片文件响应应保留 DataBase64，实际为空：%+v", got)
	}
}

// 综合：同一个 estuary 请求/响应对抽取后，请求侧给出 file-id 引用、响应侧给出字节，二者会写入
// 同一行 file_metadata_json，ResolveUploadedFileBytes 据此在一行内交叉匹配 reference_id↔data_base64。
func TestChatGPTEstuaryRowHasReferenceAndBytesForResolution(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/estuary/content?id=file_00000000abcdef", nil)
	reqContent := extractRequestContent(req, nil)

	pngBody := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d}
	respContent := extractResponseContent(pngBody, "image/png")

	reqContent, respContent = resolveRetainedContents("tenant-A", "openai_chatgpt", reqContent, respContent)

	combined := append(append([]ExtractedAttachment{}, reqContent.Attachments...), respContent.Attachments...)

	var hasRef, hasBytes bool
	for _, att := range combined {
		if att.ReferenceID == "file_00000000abcdef" {
			hasRef = true
		}
		if att.DataBase64 != "" {
			hasBytes = true
		}
	}
	if !hasRef {
		t.Fatalf("合并后的 estuary 行附件缺少 reference_id=file_00000000abcdef：%+v", combined)
	}
	if !hasBytes {
		t.Fatalf("合并后的 estuary 行附件缺少非空 DataBase64：%+v", combined)
	}
}
