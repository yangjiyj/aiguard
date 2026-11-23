package handler

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func testAWSAccessKeyID() string {
	return "AKIA" + "IOSFODNN7EXAMPLE"
}

func testGitHubPAT() string {
	return "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
}

func testOpenAIProjectKey() string {
	return "sk-proj-" + "abcdefghijklmnopqrstuvwxyz1234567890"
}

func testOpenAILiveKey() string {
	return "sk-live-" + "1234567890abcdef"
}

func TestExtractRequestContent_CompressedRequestBodyDecoded(t *testing.T) {
	// 复现线上 bug：VSCode 系客户端对【请求体】做了压缩（CodeBuddy → gzip 的 chat/completions、
	// GitHub Copilot → br 的 Responses）。响应侧在 proxy.go 用 decodeContentEncoding 解压后才抽取，
	// 请求侧却把原始压缩字节直接喂给 extractRequestContent：gzip 命中 isCompressedPayload 早退返回
	// 空 Text；br 无魔数被 safeText 过滤成空 → 用户提问抓不到。修复后须先按 Content-Encoding 解压。

	gzipBytes := func(s string) []byte {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
		return buf.Bytes()
	}
	brotliBytes := func(s string) []byte {
		var buf bytes.Buffer
		w := brotli.NewWriter(&buf)
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatalf("brotli write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("brotli close: %v", err)
		}
		return buf.Bytes()
	}

	// ---- CodeBuddy 形态：gzip 压缩的 OpenAI chat/completions 请求 ----
	chatJSON := `{"model":"gpt-4","messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"什么东西"}]}`
	chatBody := gzipBytes(chatJSON)
	chatReq := httptest.NewRequest(http.MethodPost, "https://copilot.tencent.com/v2/chat/completions", bytes.NewReader(chatBody))
	chatReq.Header.Set("Content-Type", "application/json")
	chatReq.Header.Set("Content-Encoding", "gzip")
	chatExtracted := extractRequestContent(chatReq, chatBody)
	if !strings.Contains(chatExtracted.Text, "什么东西") {
		t.Fatalf("gzip chat 请求用户提问未被捕获: %q", chatExtracted.Text)
	}

	// ---- GitHub Copilot 形态：brotli 压缩的 Responses API 请求（input 数组，br 无魔数）----
	respJSON := `{"model":"gpt-4o","input":[{"role":"user","content":[{"type":"input_text","text":"什么东西"}]}]}`
	respBody := brotliBytes(respJSON)
	respReq := httptest.NewRequest(http.MethodPost, "https://api.individual.githubcopilot.com/responses", bytes.NewReader(respBody))
	respReq.Header.Set("Content-Type", "application/json")
	respReq.Header.Set("Content-Encoding", "br")
	respExtracted := extractRequestContent(respReq, respBody)
	if !strings.Contains(respExtracted.Text, "什么东西") {
		t.Fatalf("brotli responses 请求用户提问未被捕获: %q", respExtracted.Text)
	}
}

func TestExtractRequestContent_JSONMessagesAndBase64Image(t *testing.T) {
	body := `{
		"model":"doubao-seed-1-6",
		"messages":[{"role":"user","content":[
			{"type":"text","text":"请总结这份客户名单，手机号 13812345678"},
			{"type":"image_url","image_url":{"url":"data:image/png;base64,aGVsbG8="}}
		]}]
	}`
	req := httptest.NewRequest(http.MethodPost, "https://ark.cn-beijing.volces.com/api/v3/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	extracted := extractRequestContent(req, []byte(body))
	if !strings.Contains(extracted.Text, "手机号 13812345678") {
		t.Fatalf("extracted text missing prompt content: %q", extracted.Text)
	}
	if len(extracted.Attachments) != 1 {
		t.Fatalf("attachments len = %d, want 1", len(extracted.Attachments))
	}
	if extracted.Attachments[0].ContentType != "image/png" {
		t.Fatalf("attachment content type = %s, want image/png", extracted.Attachments[0].ContentType)
	}
	if extracted.Attachments[0].Size != 5 {
		t.Fatalf("attachment size = %d, want 5", extracted.Attachments[0].Size)
	}
	if extracted.Attachments[0].DataBase64 == "" {
		t.Fatal("image attachment should carry bounded base64 for OCR")
	}
}

func TestExtractRequestContent_WorkBuddyInvokeKeepsShortUserFields(t *testing.T) {
	body := `{
		"requestId":"7d05dabf-79d7-4344-a8cf-e24589ccd2e8",
		"mode":"chat",
		"payload":{
			"projectId":"p_1234567890",
			"userInput":"sdf",
			"value":"ni ganma",
			"description":"完成规划",
			"callbackUrl":"https://ride-3-live-webapp.azurewebsites.net/api/stream"
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "https://ride-3-live-webapp.azurewebsites.net/api/invoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	extracted := extractRequestContent(req, []byte(body))
	for _, want := range []string{"sdf", "ni ganma", "完成规划"} {
		if !strings.Contains(extracted.Text, want) {
			t.Fatalf("WorkBuddy invoke prompt missing %q: %q", want, extracted.Text)
		}
	}
	for _, noise := range []string{"7d05dabf", "p_1234567890", "mode", "callbackUrl", "ride-3-live-webapp"} {
		if strings.Contains(extracted.Text, noise) {
			t.Fatalf("WorkBuddy invoke extraction leaked protocol noise %q: %q", noise, extracted.Text)
		}
	}
}

func TestExtractRequestContent_JSONFileReferences(t *testing.T) {
	body := `{"prompt":"请结合上传的 Excel 文件做摘要","ref_file_ids":["file-238c74b9-c8ed-4a86-8563-07b9b5fe656b"]}`
	req := httptest.NewRequest(http.MethodPost, "https://chat.deepseek.com/api/v0/chat/completion", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	extracted := extractRequestContent(req, []byte(body))
	if !strings.Contains(extracted.Text, "请结合上传的 Excel 文件做摘要") || !strings.Contains(extracted.Text, "[ref_file_ids] file-238c74b9") {
		t.Fatalf("file reference text not preserved: %q", extracted.Text)
	}
	if len(extracted.Attachments) != 1 {
		t.Fatalf("attachments len = %d, want 1", len(extracted.Attachments))
	}
	got := extracted.Attachments[0]
	if got.Source != "json_file_reference" || got.FieldName != "ref_file_ids" || got.ReferenceID != "file-238c74b9-c8ed-4a86-8563-07b9b5fe656b" {
		t.Fatalf("unexpected file reference attachment: %+v", got)
	}
}

func TestExtractRequestContent_JSONFileObjectKeepsFileNameNotBareID(t *testing.T) {
	// ChatGPT/Claude/DeepSeek 网页在对话请求里挂载文件时，附件是一个带 id+name 但没有下载 URL 的对象。
	// 访问留存必须展示人类可读的文件名，而不是裸的 file-id 编码。
	body := `{"messages":[{"role":"user","content":"请总结这份财报","metadata":{"attachments":[{"id":"file-AbC123XyZ456","name":"季度财报.pdf","mime_type":"application/pdf","size":284512}]}}]}`
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/conversation", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	extracted := extractRequestContent(req, []byte(body))
	if len(extracted.Attachments) != 1 {
		t.Fatalf("attachments len = %d, want 1: %+v", len(extracted.Attachments), extracted.Attachments)
	}
	got := extracted.Attachments[0]
	if got.FileName != "季度财报.pdf" {
		t.Fatalf("file name not restored: %+v", got)
	}
	if got.ReferenceID != "file-AbC123XyZ456" {
		t.Fatalf("reference id not carried: %+v", got)
	}
	if got.ContentType != "application/pdf" {
		t.Fatalf("content type = %q, want application/pdf: %+v", got.ContentType, got)
	}
	if got.Size != 284512 {
		t.Fatalf("size = %d, want 284512: %+v", got.Size, got)
	}
	// 用户明确禁止"编码/ID"展示：有了文件名后不得再冒出裸 file-id 的引用附件或文本。
	if got.Source == "json_file_reference" {
		t.Fatalf("bare file-id reference must be suppressed when filename is known: %+v", got)
	}
	if strings.Contains(extracted.Text, "file-AbC123XyZ456") {
		t.Fatalf("raw file-id leaked into retained text: %q", extracted.Text)
	}
}

func TestExtractRequestContent_MultipartTextFileAndImageMetadata(t *testing.T) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.WriteField("prompt", "分析上传材料是否包含内部资料"); err != nil {
		t.Fatal(err)
	}
	textPart, err := w.CreateFormFile("file", "customer-list.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = textPart.Write([]byte("客户名单: 张三 13812345678 internal_doc"))
	imgPart, err := w.CreateFormFile("image", "id-card.png")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = imgPart.Write([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://dashscope.aliyuncs.com/api/v1/files", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", w.FormDataContentType())
	extracted := extractRequestContent(req, body.Bytes())

	for _, want := range []string{"分析上传材料", "客户名单", "13812345678", "customer-list.txt", "id-card.png"} {
		if !strings.Contains(extracted.Text, want) {
			t.Fatalf("extracted text missing %q: %q", want, extracted.Text)
		}
	}
	if len(extracted.Attachments) != 2 {
		t.Fatalf("attachments len = %d, want 2", len(extracted.Attachments))
	}
	if extracted.Attachments[1].FileName != "id-card.png" || extracted.Attachments[1].SHA256 == "" {
		t.Fatalf("image metadata not captured: %+v", extracted.Attachments[1])
	}
}

func TestExtractResponseContent_SSEChunks(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"客户手机号"}}]}`,
		`data: {"choices":[{"delta":{"content":"13812345678"}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "客户手机号") || !strings.Contains(extracted.Text, "13812345678") {
		t.Fatalf("SSE content not extracted: %q", extracted.Text)
	}
}

func TestExtractResponseContent_KeepsReasoningDeltasSeparateFromAnswer(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"reasoning_content":"用户问这个市什么，看起来是打字错误，我应该先理解意图。"}}]}`,
		`data: {"choices":[{"delta":{"content":"哎呀，我猜你可能是想问“你是什么”吧。"}}]}`,
		`data: {"choices":[{"delta":{"content":"我是一个由深度求索公司创造的助手。"}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "[reasoning] 用户问这个市什么，看起来是打字错误，我应该先理解意图。") {
		t.Fatalf("extracted response should keep reasoning with a marker: %q", extracted.Text)
	}
	for _, want := range []string{"哎呀，我猜你可能是想问", "我是一个由深度求索公司创造的助手"} {
		if !strings.Contains(extracted.Text, want) {
			t.Fatalf("extracted response missing final content %q: %q", want, extracted.Text)
		}
	}
	if strings.Contains(extracted.Text, "[reasoning_content]") {
		t.Fatalf("reasoning should use an audit display marker, not raw protocol path: %q", extracted.Text)
	}
}

func TestExtractResponseContent_SkipsGzipBodyEvenWithJSONContentType(t *testing.T) {
	extracted := extractResponseContent([]byte{0x1f, 0x8b, 0x08, 0x00, 0xff, 0x00, 0x13, 0x37}, "application/json")

	if strings.TrimSpace(extracted.Text) != "" || len(extracted.Attachments) != 0 {
		t.Fatalf("gzip response body should not be retained as text: %+v", extracted)
	}
}

func TestExtractResponseContent_SkipsOpaqueBinaryResponse(t *testing.T) {
	body := []byte{0x1f, 0x8b, 0x08, 0x00, 0xff, 0x00, 0x13, 0x37, 0x00, 0x01}

	extracted := extractResponseContent(body, "application/octet-stream")

	if strings.TrimSpace(extracted.Text) != "" {
		t.Fatalf("opaque binary response should not be rendered as model text: %q", extracted.Text)
	}
	if len(extracted.Attachments) != 0 {
		t.Fatalf("opaque binary response should not create attachments: %+v", extracted.Attachments)
	}
}

func TestExtractResponseContent_SkipsBinaryLikeJSONResponse(t *testing.T) {
	body := []byte{'\f', ':', '$', 'H', 'm', '|', '?', 0x18, 'a', 0x19, '6', 'u', '+', 'e', 'b', 'q', 0x05, 0x17, 'D', 'T', 0x0e, 'G', 'm'}

	extracted := extractResponseContent(body, "application/json")

	if strings.TrimSpace(extracted.Text) != "" {
		t.Fatalf("binary-like JSON response should not be rendered as model text: %q", extracted.Text)
	}
}

func TestExtractResponseContent_KeepsImageBodyAsReturnedAttachment(t *testing.T) {
	body := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00}

	extracted := extractResponseContent(body, "image/png")

	if strings.TrimSpace(extracted.Text) != "" {
		t.Fatalf("image response should not render binary bytes as text: %q", extracted.Text)
	}
	if len(extracted.Attachments) != 1 {
		t.Fatalf("image response attachments len = %d, want 1", len(extracted.Attachments))
	}
	got := extracted.Attachments[0]
	if got.Source != "response_body" || got.ContentType != "image/png" || got.Size != int64(len(body)) || got.DataBase64 == "" {
		t.Fatalf("unexpected image response attachment: %+v", got)
	}
}

func TestExtractResponseContent_SkipsTemporaryRedirectHTML(t *testing.T) {
	body := []byte(`<a href="https://prod-chat-kimi.example/object">Temporary Redirect</a>.`)

	extracted := extractResponseContent(body, "text/html; charset=utf-8")

	if strings.TrimSpace(extracted.Text) != "" {
		t.Fatalf("temporary redirect HTML should not be retained as model answer: %q", extracted.Text)
	}
}

func TestExtractRequestContent_KimiWebJSONSkipsProtocolMetadata(t *testing.T) {
	body := `{"scenario":"SCENARIO_K2D5","tool_type":"TOOL_TYPE_SEARCH","conversation_id":"19eba503-04c2-8402-8000-09eec6438f14","messages":[{"role":"user","content":"怎么样"}]}`
	req := httptest.NewRequest(http.MethodPost, "https://www.kimi.com/apiv2/kimi.gateway.chat.v1.ChatService/Chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	extracted := extractRequestContent(req, []byte(body))
	if strings.TrimSpace(extracted.Text) != "怎么样" {
		t.Fatalf("extracted Kimi prompt = %q, want only user text", extracted.Text)
	}
}

func TestExtractResponseContent_WebModelConnectJSONSkipsProtocolMetadata(t *testing.T) {
	body := appendConnectJSONFrame(nil, []byte(`{"event":"set","created_at":"2026-06-12T05:31:18.033698701Z","conversation_id":"19eba503-04c2-8402-8000-09eec6438f14","name":"未命名会话","tool_type":"TOOL_TYPE_SEARCH","scenario":"SCENARIO_K2D5","message_status":"MESSAGE_STATUS_COMPLETED","message":{"role":"assistant","content":[{"block_type":10000,"content":{"text_block":{"text":"你好！"}}}]}}`))
	body = appendConnectJSONFrame(body, []byte(`{"patch_op":{"op":"set","path":"block.text.content","patch_value":{"content_block":{"content":{"text_block":{"text":"之前问的是“怎么样”。"}}}}}}`))

	extracted := extractResponseContent(body, "application/connect+json")
	for _, want := range []string{"你好！", "之前问的是“怎么样”。"} {
		if !strings.Contains(extracted.Text, want) {
			t.Fatalf("extracted response missing %q: %q", want, extracted.Text)
		}
	}
	for _, noise := range []string{"SCENARIO_K2D5", "TOOL_TYPE_SEARCH", "MESSAGE_STATUS_COMPLETED", "19eba503", "block.text.content", "未命名会话"} {
		if strings.Contains(extracted.Text, noise) {
			t.Fatalf("extracted response leaked protocol %q: %q", noise, extracted.Text)
		}
	}
}

func TestExtractResponseContent_DoubaoWebJSONSkipsIntentMetadata(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"ack_cost_time":"15","agent_id":"19457456070409730","agent_name":"豆包","first_packet_cost_time":"15","llm_intention":"seed_main","llm_intention_detail":"knowledge"}`,
		`data: {"plugin_intention":"","plugin_generalize_intention":"无","branch_intention":"Branch-Knowledge","intention_ori_score":"{\"AgentECommerceRawValue\":0.7025300573952054,\"SearchRawValue\":0.879146767509}"}`,
		`data: {"bot_id":"7338286299411103781","bot_name":"豆包","agent_name":"豆包","agent_id":"19457456070409730","intent_agent_name":"Agent-Knowledge"}`,
		`data: {"content":{"text_block":{"text":"品牌质量不能一概而论。"}}}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "品牌质量不能一概而论。") {
		t.Fatalf("extracted response missing answer text: %q", extracted.Text)
	}
	for _, noise := range []string{"ack_cost_time", "19457456070409730", "豆包", "Branch-Knowledge", "AgentECommerceRawValue", "SearchRawValue", "无"} {
		if strings.Contains(extracted.Text, noise) {
			t.Fatalf("extracted response leaked Doubao metadata %q: %q", noise, extracted.Text)
		}
	}
}

func TestExtractResponseContent_KimiWebFileURLReferences(t *testing.T) {
	fileURL := "https://www.kimi.com/apiv2-files/sign-obj/kimi-fs%2Ffiles%2Fblob%2Fa4d8112c7ab15f661211e7b5de645562383d4e75348d8f3dd844355fe4ed2298?filename=QAgent+%E9%85%8D%E7%BD%AE%E8%93%9D%E4%BF%A1%E9%80%9A%E9%81%93%E6%93%8D%E4%BD%9C%E6%96%87%E6%A1%A3_V1.1.docx&demo=1&t=o"
	body := appendConnectJSONFrame(nil, []byte(`{"chat":{"files":[{"meta":{"type":"FILE_TYPE_DOCUMENT"},"blob":{"signUrl":"`+fileURL+`","previewUrl":"https://www.kimi.com/apiv2-files/sign-obj/kimi-fs%2Ffiles%2Fblob%2Fa4d8112c7ab15f661211e7b5de645562383d4e75348d8f3dd844355fe4ed2298?filename=a4d811.docx&preview=1&t=o"}}]}}`))
	body = appendConnectJSONFrame(body, []byte(`{"patch_op":{"op":"append","path":"block.text.content","patch_value":{"content_block":{"content":{"text_block":{"text":"这是"}}}}}}`))
	body = appendConnectJSONFrame(body, []byte(`{"patch_op":{"op":"append","path":"block.text.content","patch_value":{"content_block":{"content":{"text_block":{"text":"Q"}}}}}}`))
	body = appendConnectJSONFrame(body, []byte(`{"patch_op":{"op":"append","path":"block.text.content","patch_value":{"content_block":{"content":{"text_block":{"text":"Agent"}}}}}}`))
	body = appendConnectJSONFrame(body, []byte(`{"patch_op":{"op":"append","path":"block.text.content","patch_value":{"content_block":{"content":{"text_block":{"text":"配置蓝信通道操作文档"}}}}}}`))

	extracted := extractResponseContent(body, "application/connect+json")

	for _, want := range []string{"这是", "Q", "Agent", "配置蓝信通道操作文档"} {
		if !strings.Contains(extracted.Text, want) {
			t.Fatalf("extracted Kimi response missing %q: %q", want, extracted.Text)
		}
	}
	for _, noise := range []string{"FILE_TYPE_DOCUMENT", "signUrl", "previewUrl", "https://www.kimi.com", "block.text.content"} {
		if strings.Contains(extracted.Text, noise) {
			t.Fatalf("extracted Kimi response leaked file/protocol noise %q: %q", noise, extracted.Text)
		}
	}
	// chat.files 是会话已挂载的用户文件回显（已由 /file/upload 请求侧带原始字节捕获），
	// 不是模型新产出的文件，故响应侧不得登记为附件，否则后台会误显示「模型返回了文件/图片」。
	if len(extracted.Attachments) != 0 {
		t.Fatalf("chat.files echo must not be a response attachment, got %d: %+v", len(extracted.Attachments), extracted.Attachments)
	}
}

func TestExtractResponseContent_KimiChatFilesEchoNotModelAttachment(t *testing.T) {
	// 复现线上 bug：用户在 Kimi 网页上传了一张图片（已由 /file/upload 请求侧捕获）。
	// /Chat 响应体的 chat.files 只是把这张「会话已挂载的用户文件」回显出来，模型本身只回了文字。
	// 过去整棵 chat.files 被当成响应侧附件抓取并被 audit 打上 stage:response，
	// 于是后台错误地显示「模型返回了图片」。修复后 chat.files 回显不得登记为附件。
	imageURL := "https://prod-chat-kimi.tos-cn-beijing.volces.com/contrib/blob/8cbf7fd4ccddeeff?filename=image.png&t=o"
	body := appendConnectJSONFrame(nil, []byte(`{"chat":{"files":[{"meta":{"type":"FILE_TYPE_IMAGE","name":"image.png"},"blob":{"signUrl":"`+imageURL+`","previewUrl":"`+imageURL+`&preview=1"}}]}}`))
	body = appendConnectJSONFrame(body, []byte(`{"patch_op":{"op":"append","path":"block.text.content","patch_value":{"content_block":{"content":{"text_block":{"text":"这张图片"}}}}}}`))
	body = appendConnectJSONFrame(body, []byte(`{"patch_op":{"op":"append","path":"block.text.content","patch_value":{"content_block":{"content":{"text_block":{"text":"显示的是一只猫。"}}}}}}`))

	extracted := extractResponseContent(body, "application/connect+json")

	for _, want := range []string{"这张图片", "显示的是一只猫。"} {
		if !strings.Contains(extracted.Text, want) {
			t.Fatalf("model reply text missing %q: %q", want, extracted.Text)
		}
	}
	if len(extracted.Attachments) != 0 {
		t.Fatalf("chat.files echo must not be a model attachment, got %d: %+v", len(extracted.Attachments), extracted.Attachments)
	}
	for _, noise := range []string{"signUrl", "previewUrl", "tos-cn-beijing", "FILE_TYPE_IMAGE"} {
		if strings.Contains(extracted.Text, noise) {
			t.Fatalf("text leaked file/protocol noise %q: %q", noise, extracted.Text)
		}
	}
}

func TestExtractRequestContent_FormURLEncodedGeminiWebDoubleEncoded(t *testing.T) {
	// 复现线上 bug：Gemini 网页 StreamGenerate 的 f.req 是双层编码——外层只是信封
	// [null,"<内层JSON>"]，真正的 prompt/附件埋在内层 JSON 字符串里。过去只解一层信封，内层 JSON
	// 整体因含中文被 looksLikeHumanText 判为人类文本、原样写入访问留存 → 用户提问显示成乱码数组。
	// 用 json.Marshal([]interface{}{nil, inner}) 精确模拟浏览器的双层编码线上形态。

	// ---- 纯文本轮次：真实 prompt "你咋样" 埋在 inner[0][0] ----
	innerText := `[["你咋样",0,null,null,null,null,0],["zh-CN"],["","","",null,null,null,null,null,null,""],"!SUqlSi7NToken"]`
	fReqText, err := json.Marshal([]interface{}{nil, innerText})
	if err != nil {
		t.Fatalf("marshal text f.req: %v", err)
	}
	textValues := url.Values{}
	textValues.Set("f.req", string(fReqText))
	textValues.Set("_reqid", "47302461230667522")
	textValues.Set("at", "AFGh2kpq")
	textBody := textValues.Encode()
	textReq := httptest.NewRequest(http.MethodPost, "https://gemini.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate", strings.NewReader(textBody))
	textReq.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")

	textExtracted := extractRequestContent(textReq, []byte(textBody))
	if strings.TrimSpace(textExtracted.Text) != "你咋样" {
		t.Fatalf("double-encoded Gemini prompt = %q, want only %q", textExtracted.Text, "你咋样")
	}
	for _, noise := range []string{"zh-CN", "SUqlSi7N", "f.req", "_reqid", "47302461230667522", "AFGh2kpq", "[[", "null"} {
		if strings.Contains(textExtracted.Text, noise) {
			t.Fatalf("double-encoded Gemini text leaked protocol noise %q: %q", noise, textExtracted.Text)
		}
	}
	if len(textExtracted.Attachments) != 0 {
		t.Fatalf("text-turn attachments = %d, want 0: %+v", len(textExtracted.Attachments), textExtracted.Attachments)
	}

	// ---- 文件轮次：两份附件三元组 [[<签名路径>,<n>,null,<mime>],<文件名>] 埋在 inner[0][3] ----
	innerFile := `[["",0,null,[[["/contrib_service/ttl_1d/AfXU2NaIDqqQst",1,null,"image/png"],"image_555aa9.png"],[["/contrib_service/ttl_1d/AfXU2NY3",10,null,"application/vnd.openxmlformats-officedocument.wordprocessingml.document"],"4+1参考信息.docx"]],null,null,0],["zh-CN"],["c_1e4030c541e19a65","r_f1439569e268c1b0","rc_5c4fbe15a18333e1",null,null,null,null,null,null,"AwAAAAAAAAAQANM7mBjXKZQpboVS7Bk"],"!c3ClcBTNToken"]`
	fReqFile, err := json.Marshal([]interface{}{nil, innerFile})
	if err != nil {
		t.Fatalf("marshal file f.req: %v", err)
	}
	fileValues := url.Values{}
	fileValues.Set("f.req", string(fReqFile))
	fileValues.Set("_reqid", "47302461230667600")
	fileValues.Set("at", "AFGh2kpq")
	fileBody := fileValues.Encode()
	fileReq := httptest.NewRequest(http.MethodPost, "https://gemini.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate", strings.NewReader(fileBody))
	fileReq.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")

	fileExtracted := extractRequestContent(fileReq, []byte(fileBody))
	if strings.TrimSpace(fileExtracted.Text) != "" {
		t.Fatalf("file-turn text should be empty (no prompt), got %q", fileExtracted.Text)
	}
	for _, noise := range []string{"contrib_service", "ttl_1d", "AfXU2N", "image/png", "c_1e4030", "r_f1439569", "rc_5c4fbe15", "c3ClcBTN", "AwAAAAAA", "[[", "zh-CN"} {
		if strings.Contains(fileExtracted.Text, noise) {
			t.Fatalf("file-turn text leaked signed-path/mime/id/token noise %q: %q", noise, fileExtracted.Text)
		}
	}
	if len(fileExtracted.Attachments) != 2 {
		t.Fatalf("file-turn attachments = %d, want 2: %+v", len(fileExtracted.Attachments), fileExtracted.Attachments)
	}
	byName := map[string]ExtractedAttachment{}
	for _, a := range fileExtracted.Attachments {
		byName[a.FileName] = a
	}
	img, ok := byName["image_555aa9.png"]
	if !ok || img.Source != "gemini_web_upload" || img.ContentType != "image/png" {
		t.Fatalf("missing/incorrect image attachment: %+v", fileExtracted.Attachments)
	}
	doc, ok := byName["4+1参考信息.docx"]
	if !ok || doc.Source != "gemini_web_upload" || doc.ContentType != "application/vnd.openxmlformats-officedocument.wordprocessingml.document" {
		t.Fatalf("missing/incorrect docx attachment: %+v", fileExtracted.Attachments)
	}
}

func TestExtractRequestContent_FormURLEncodedGeminiWebContent(t *testing.T) {
	imageURL := "https://lh3.googleusercontent.com/uploaded-user-image.png"
	values := url.Values{}
	values.Set("f.req", `[["请识别这张图片里的文字",{"image_url":"`+imageURL+`"}]]`)
	values.Set("_reqid", "47302461230667522")
	values.Set("at", "AFGh2kpq")
	body := values.Encode()
	req := httptest.NewRequest(http.MethodPost, "https://gemini.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")

	extracted := extractRequestContent(req, []byte(body))
	if strings.TrimSpace(extracted.Text) != "请识别这张图片里的文字" {
		t.Fatalf("Gemini form prompt = %q, want only human prompt", extracted.Text)
	}
	for _, noise := range []string{"f.req", "_reqid", "47302461230667522", "AFGh2kpq", imageURL} {
		if strings.Contains(extracted.Text, noise) {
			t.Fatalf("Gemini form extraction leaked protocol/url %q: %q", noise, extracted.Text)
		}
	}
	if len(extracted.Attachments) != 1 {
		t.Fatalf("attachments len = %d, want 1: %+v", len(extracted.Attachments), extracted.Attachments)
	}
	if got := extracted.Attachments[0]; got.Source != "json_image_url" || got.DownloadURL != imageURL || got.ContentType != "image/png" {
		t.Fatalf("unexpected Gemini image attachment: %+v", got)
	}
}

func TestExtractResponseContent_GeminiBatchExecuteSurfacesAnswerNotXSSINoise(t *testing.T) {
	// Gemini 网页端走 Google batchexecute：响应以 )]}' 反劫持前缀打头，后跟"长度前缀数字 + 嵌套
	// 数组"分块流，真正的回答藏在 wrb.fr 行第 3 个元素——一个【JSON 编码字符串】里，需要二次解析。
	answer := "杭州明天多云转晴，气温18到26摄氏度，适合安排户外活动。"
	body := []byte(")]}'\n\n171\n" +
		`[["wrb.fr","hNvQHb","[[\"rc_abc123def456\"],[\"` + answer + `\"],null,null,null,[\"rc_abc123def456\"]]",null,null,null,"generic"]]` +
		"\n31\n" +
		`[["di",18],["af.httprm",18,"-7281930456120017345",55]]` +
		"\n26\n" +
		`[["e",4,null,null,1462]]`)

	extracted := extractResponseContent(body, "application/json")
	if !strings.Contains(extracted.Text, answer) {
		t.Fatalf("batchexecute response missing human answer: %q", extracted.Text)
	}
	for _, noise := range []string{")]}'", "wrb.fr", "rc_abc123def456", "af.httprm", "generic", "hNvQHb"} {
		if strings.Contains(extracted.Text, noise) {
			t.Fatalf("batchexecute extraction leaked XSSI/protocol noise %q: %q", noise, extracted.Text)
		}
	}
}

func TestExtractResponseContent_GeminiBatchExecuteEnvelopeOnlyYieldsNoRawDump(t *testing.T) {
	// 只有协议外壳、无任何人类可读正文时，必须退化为占位（仅 ContentType），绝不把含 )]}'、wrb.fr、
	// rc_ 等编码与 ID 的原文直接吐进访问留存——这是"不要出现什么编码、什么ID"的兜底保证。
	body := []byte(")]}'\n\n44\n" +
		`[["wrb.fr","hNvQHb","[[\"rc_onlyids789\"],null,null,null,[\"rc_onlyids789\"]]",null,null,null,"generic"]]` +
		"\n31\n" +
		`[["di",6],["af.httprm",6,"-1029384756",12]]`)

	extracted := extractResponseContent(body, "application/json")
	if strings.TrimSpace(extracted.Text) != "" {
		t.Fatalf("envelope-only batchexecute should yield no text, got: %q", extracted.Text)
	}
	for _, noise := range []string{")]}'", "wrb.fr", "rc_onlyids789", "af.httprm"} {
		if strings.Contains(extracted.Text, noise) {
			t.Fatalf("envelope-only batchexecute leaked noise %q: %q", noise, extracted.Text)
		}
	}
}

func TestExtractResponseContent_GstaticSVGUIIconsNotModelImages(t *testing.T) {
	// 复现线上 bug（acl_472b6d9f2a2446cf）：Gemini 网页对话留存的「模型返回图片」里混进 4 个 gstatic
	// Material Symbols 矢量图标（image/svg+xml、0 字节、fonts.gstatic.com/.../24px.svg）。根因是
	// looksLikeImageURL 把 .svg 当作图片：路径含 image 时走 hasImagePathContext 放行，否则回退到
	// fileExtensionLooksImage（.svg=true）。这些是网页 UI 图标，不是模型真实图片，必须统一排除——
	// 既不作为图片附件，也不作为文本泄露。
	base := "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/"
	expand := base + "expand/default/24px.svg"
	compress := base + "compress/default/24px.svg"
	personCancel := base + "person_cancel/default/24px.svg"
	refresh := base + "refresh/default/24px.svg"
	body := []byte(`{"message":{"content":"你好！看这架势，我是 Gemini。","refs":{"images":[{"originUrl":"` + expand + `"},{"originUrl":"` + compress + `"},{"originUrl":"` + personCancel + `"},{"originUrl":"` + refresh + `"}]}}}`)

	extracted := extractResponseContent(body, "application/json")
	if !strings.Contains(extracted.Text, "你好！看这架势，我是 Gemini。") {
		t.Fatalf("response text missing answer: %q", extracted.Text)
	}
	for _, noise := range []string{"gstatic", "24px.svg", "googlesymbols", "https://"} {
		if strings.Contains(extracted.Text, noise) {
			t.Fatalf("response text leaked svg icon url %q: %q", noise, extracted.Text)
		}
	}
	if len(extracted.Attachments) != 0 {
		t.Fatalf("attachments len = %d, want zero (svg ui icons are not model images): %+v", len(extracted.Attachments), extracted.Attachments)
	}
}

func TestExtractResponseContent_JSONImageURLsBecomeAttachmentsNotText(t *testing.T) {
	imageURL := "https://kimi-web-img.moonshot.cn/img/assets.weforum.org/5224ccce7831be64e981aaf2b19f2de3625a322.png"
	thumbURL := imageURL + "?x-oss-process=image/resize,w_546"
	body := []byte(`{"message":{"content":"世界经济论坛给你两张老虎的图片。","refs":{"images":[{"originUrl":"` + imageURL + `","thumbnailUrl":"` + thumbURL + `","sourceSiteUrl":"https://cn.weforum.org/stories/2022/02/tiger"}]}}}`)

	extracted := extractResponseContent(body, "application/json")
	if !strings.Contains(extracted.Text, "世界经济论坛给你两张老虎的图片。") {
		t.Fatalf("response text missing answer: %q", extracted.Text)
	}
	for _, noise := range []string{"originUrl", "thumbnailUrl", "sourceSiteUrl", "https://"} {
		if strings.Contains(extracted.Text, noise) {
			t.Fatalf("response text leaked image metadata %q: %q", noise, extracted.Text)
		}
	}
	if len(extracted.Attachments) != 1 {
		t.Fatalf("attachments len = %d, want one full-size image: %+v", len(extracted.Attachments), extracted.Attachments)
	}
	got := extracted.Attachments[0]
	if got.Source != "json_image_url" || got.DownloadURL != imageURL || got.FileName != "5224ccce7831be64e981aaf2b19f2de3625a322.png" || got.ContentType != "image/png" {
		t.Fatalf("unexpected image attachment: %+v", got)
	}
}

func TestExtractResponseContent_JSONGeneratedFileURLBecomesAttachment(t *testing.T) {
	fileURL := "https://files.example.com/generated/audit-report.docx?download=1"
	body := []byte(`{"content":"已生成审计报告。","artifacts":[{"file_name":"audit-report.docx","mime_type":"application/vnd.openxmlformats-officedocument.wordprocessingml.document","download_url":"` + fileURL + `","size":4096}]}`)

	extracted := extractResponseContent(body, "application/json")
	if strings.TrimSpace(extracted.Text) != "已生成审计报告。" {
		t.Fatalf("generated file response text = %q, want only answer", extracted.Text)
	}
	if len(extracted.Attachments) != 1 {
		t.Fatalf("attachments len = %d, want 1: %+v", len(extracted.Attachments), extracted.Attachments)
	}
	got := extracted.Attachments[0]
	if got.Source != "json_file_url" || got.FileName != "audit-report.docx" || got.ContentType != "application/vnd.openxmlformats-officedocument.wordprocessingml.document" || got.Size != 4096 || got.DownloadURL != fileURL {
		t.Fatalf("unexpected generated file attachment: %+v", got)
	}
}

func TestExtractResponseContent_DeepSeekSignedDownloadPathNotLeakedAsText(t *testing.T) {
	// DeepSeek 网页版「取文件」响应：biz_data.files[] 同时带 file_name（人类可读文件名）与
	// signed_path（/file?file_id=<uuid>&state=<超长 base64 签名 token> 的相对下载短链）。
	// signed_path 是下载凭证（协议管线），绝不能把超长 state 编码、file_id 原样塞进给人看的
	// 留存内容——对应「不要出现什么编码、什么ID，需要正式一点的给人看的」。file_name 必须保留。
	// 绝对 http(s) 下载链早已在 looksLikeRetainedFileURL 处被丢弃，这里补齐相对短链的同等处理。
	signedPath := "/file?file_id=2a0e17b6-e458-4c99-b683-d578cea067c5&state=szvzXzvSMZXsO4NyXx3TmVYMAyS2kQbO9YpM3X0Zigt6Mwdv8wxdmFMJ%2Fx00112233445566778899aabbccddeeff%2Bxyz%3D"
	body := []byte(`{"data":{"biz_data":{"files":[{"file_name":"季度审计报告.docx","signed_path":"` + signedPath + `"}]}}}`)

	extracted := extractResponseContent(body, "application/json")

	if !strings.Contains(extracted.Text, "季度审计报告.docx") {
		t.Fatalf("response text missing human-readable file name: %q", extracted.Text)
	}
	for _, noise := range []string{"state=", "file_id=", "signed_path", "/file?", "2a0e17b6"} {
		if strings.Contains(extracted.Text, noise) {
			t.Fatalf("response text leaked signed download path noise %q: %q", noise, extracted.Text)
		}
	}
}

func TestExtractResponseContent_SignedPathCapturedAsDownloadURL(t *testing.T) {
	// biz_data.files[].signed_path 是自签下载短链:必须保留到附件 DownloadURL(供留证旁路抓字节),
	// 但绝不能泄露进给人看的文本。这是豆包/DeepSeek 网页版文件取字节的关键。
	signedPath := "/file?file_id=2a0e17b6-e458-4c99-b683-d578cea067c5&state=szvzXzvSMZXsO4NyXx3TmVYMAyS2kQbO9YpM3X0Zigt6Mwdv8wxdmFMJ%2Fx00112233445566778899aabbccddeeff%2Bxyz%3D"
	body := []byte(`{"data":{"biz_data":{"files":[{"file_name":"图表.png","content_type":"image/png","signed_path":"` + signedPath + `"}]}}}`)

	extracted := extractResponseContent(body, "application/json")

	var found *ExtractedAttachment
	for i := range extracted.Attachments {
		if extracted.Attachments[i].Source == "json_file_object" {
			found = &extracted.Attachments[i]
		}
	}
	if found == nil {
		t.Fatalf("missing json_file_object attachment; got %+v", extracted.Attachments)
	}
	if found.DownloadURL != signedPath {
		t.Fatalf("signed_path not captured as DownloadURL: got %q", found.DownloadURL)
	}
	for _, noise := range []string{"state=", "signed_path", "2a0e17b6", "/file?"} {
		if strings.Contains(extracted.Text, noise) {
			t.Fatalf("text leaked signed download path noise %q: %q", noise, extracted.Text)
		}
	}
}

func TestExtractResponseContent_DoubaoImageWrapperResolvesToOriginalURL(t *testing.T) {
	// 豆包 image 对象:外层只有 name/uri(非 http),内嵌 image_ori/image_thumb/image_preview 各带 url。
	// 期望:把原图(image_ori.url)提到外层附件;变体子对象不再各自冒一条 json_image_url。
	body := []byte(`{"message":{"content_block":{"content":{"attachment_block":{"attachments":{"image":{` +
		`"name":"image.png","uri":"tos-cn-x/abc",` +
		`"image_ori":{"url":"https://p1.byteimg.com/ori.png","width":800,"height":600},` +
		`"image_thumb":{"url":"https://p1.byteimg.com/thumb.jpg","width":80,"height":60},` +
		`"image_preview":{"url":"https://p1.byteimg.com/prev.jpg"}}}}}}}}`)

	extracted := extractResponseContent(body, "application/json")

	foundOri := false
	for _, a := range extracted.Attachments {
		if a.DownloadURL == "https://p1.byteimg.com/thumb.jpg" || a.DownloadURL == "https://p1.byteimg.com/prev.jpg" {
			t.Fatalf("image variant URL leaked as a separate attachment: %q (attachments=%+v)", a.DownloadURL, extracted.Attachments)
		}
		if a.DownloadURL == "https://p1.byteimg.com/ori.png" {
			foundOri = true
		}
	}
	if !foundOri {
		t.Fatalf("original image_ori.url not lifted onto wrapper attachment; got %+v", extracted.Attachments)
	}
}

func TestExtractRequestContent_ConnectJSONFrames(t *testing.T) {
	githubToken := testGitHubPAT()
	body := appendConnectJSONFrame(nil, []byte(`{"prompt":"请检查这段代码，token=`+githubToken+`"}`))
	body = appendConnectJSONFrame(body, []byte(`{"payload":"读取 repo path /src/private/payment.go 后生成修复建议"}`))

	req := httptest.NewRequest(http.MethodPost, "https://api5.cursor.sh/aiserver.v1.AgentService/StreamBidi", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/connect+json")

	extracted := extractRequestContent(req, body)
	if extracted.ContentType != "application/connect+json" {
		t.Fatalf("content type = %s, want application/connect+json", extracted.ContentType)
	}
	if strings.ContainsRune(extracted.Text, '\x00') {
		t.Fatalf("connect json frame header leaked into extracted text: %q", extracted.Text)
	}
	for _, want := range []string{"请检查这段代码", githubToken, "/src/private/payment.go"} {
		if !strings.Contains(extracted.Text, want) {
			t.Fatalf("connect json content missing %q: %q", want, extracted.Text)
		}
	}
}

func appendConnectJSONFrame(dst, payload []byte) []byte {
	header := make([]byte, 5)
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	dst = append(dst, header...)
	dst = append(dst, payload...)
	return dst
}

func TestSecurityClientSendsExtractedConnectJSONContent(t *testing.T) {
	var seen map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"action":"audit","findings":[]}`))
	}))
	defer server.Close()

	githubToken := testGitHubPAT()
	body := appendConnectJSONFrame(nil, []byte(`{"prompt":"检查代码片段，发现 token=`+githubToken+`"}`))
	body = appendConnectJSONFrame(body, []byte(`{"file":"/workspace/src/billing.ts"}`))
	req := httptest.NewRequest(http.MethodPost, "https://api5.cursor.sh/aiserver.v1.AgentService/StreamBidi", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/connect+json")

	s := NewSecurityClient(server.URL)
	action, _, _ := s.CheckInput(req.Context(), "tenant_default", "test-req", req)
	if action != "audit" {
		t.Fatalf("action = %s, want audit", action)
	}
	content, _ := seen["content"].(string)
	if strings.ContainsRune(content, '\x00') {
		t.Fatalf("security payload contains connect frame header bytes: %q", content)
	}
	for _, want := range []string{"检查代码片段", githubToken, "/workspace/src/billing.ts"} {
		if !strings.Contains(content, want) {
			t.Fatalf("security payload missing %q: %#v", want, seen)
		}
	}
	ctx, ok := seen["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("context missing: %#v", seen)
	}
	if ctx["provider"] != "cursor" || ctx["endpoint_kind"] != "coding" {
		t.Fatalf("cursor context not attached: %#v", ctx)
	}
}

func TestSecurityClientSendsExtractedMultipartContent(t *testing.T) {
	seenContent := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		seenContent = buf.String()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"action":"audit","findings":[]}`))
	}))
	defer server.Close()

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("file", "secret.env")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("API_KEY=" + testOpenAIProjectKey()))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/files", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", w.FormDataContentType())
	s := NewSecurityClient(server.URL)
	action, _, _ := s.CheckInput(req.Context(), "tenant_default", "test-req", req)
	if action != "audit" {
		t.Fatalf("action = %s, want audit", action)
	}
	if !strings.Contains(seenContent, "secret.env") || !strings.Contains(seenContent, "sk-proj") {
		t.Fatalf("security payload missing extracted file content: %s", seenContent)
	}
}

func TestExtractResponseContent_ReassemblesOpenAIDeltaTokenSplits(t *testing.T) {
	// OpenAI 风格 delta 流：手机号被切分到多个 token 帧。逐帧 "\n" 拼接会把
	// "13812345678" 断成 "138\n1234\n5678"，让基于正则的 PII/密钥检测漏报。
	// 必须按帧顺序连续重组，同时以 [reasoning] 标记保留推理增量。
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"reasoning_content":"用户在询问联系方式。"}}]}`,
		`data: {"choices":[{"delta":{"content":"我的手机号是138"}}]}`,
		`data: {"choices":[{"delta":{"content":"1234"}}]}`,
		`data: {"choices":[{"delta":{"content":"5678"}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "我的手机号是13812345678") {
		t.Fatalf("OpenAI delta 流应连续重组出完整手机号，实际: %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "[reasoning] 用户在询问联系方式。") {
		t.Fatalf("OpenAI delta 流应以 [reasoning] 标记保留推理增量，实际: %q", extracted.Text)
	}
}

func TestExtractResponseContent_ReassemblesOpenAIResponsesAPIStream(t *testing.T) {
	// GitHub Copilot / VS Code Copilot Chat 经正向代理后走 OpenAI Responses API 的流式 SSE
	// （api.individual.githubcopilot.com /responses，text/event-stream）。它没有 choices[]，
	// 而是 {"type":"response.output_text.delta","delta":"..."} 增量；回答在 output_text.delta
	// 增量、又在 output_text.done.text、再在 response.completed 的整个 response 对象里各出现一遍，
	// reasoning item 带 encrypted_content 加密块、各 item 带 rs_/msg_/resp_ 等 ID。旧代码三个
	// 重组器都不命中（DeepSeek 看 {o,p,v}、OpenAI-delta 看 choices[]、Claude 看 content_block_delta），
	// 跌到通用 collectJSONText 兜底：回答被记三遍、思考无 [reasoning] 标记，违背「不要出现编码/ID，
	// 正式一点给人看」。新增 Responses 重组器后：回答只留一份、思考以 [reasoning] 标记、无 ID/加密块。
	body := []byte(strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_abc123","object":"response","status":"in_progress","model":"gpt-4o"}}`,
		`data: {"type":"response.output_item.added","output_index":0,"item":{"id":"rs_xyz789","type":"reasoning","encrypted_content":"gAAAAABmZW5jcnlwdGVkX3JlYXNvbmluZ19ibG9iX3h4eHh4eHh4","summary":[]}}`,
		`data: {"type":"response.reasoning_summary_text.delta","item_id":"rs_xyz789","output_index":0,"summary_index":0,"delta":"用户在问"}`,
		`data: {"type":"response.reasoning_summary_text.delta","item_id":"rs_xyz789","output_index":0,"summary_index":0,"delta":"手机号"}`,
		`data: {"type":"response.reasoning_summary_text.done","item_id":"rs_xyz789","output_index":0,"summary_index":0,"text":"用户在问手机号"}`,
		`data: {"type":"response.output_item.added","output_index":1,"item":{"id":"msg_001","type":"message","role":"assistant","content":[]}}`,
		`data: {"type":"response.content_part.added","item_id":"msg_001","output_index":1,"content_index":0,"part":{"type":"output_text","text":""}}`,
		`data: {"type":"response.output_text.delta","item_id":"msg_001","output_index":1,"content_index":0,"delta":"手机号是138"}`,
		`data: {"type":"response.output_text.delta","item_id":"msg_001","output_index":1,"content_index":0,"delta":"1234"}`,
		`data: {"type":"response.output_text.delta","item_id":"msg_001","output_index":1,"content_index":0,"delta":"5678"}`,
		`data: {"type":"response.output_text.done","item_id":"msg_001","output_index":1,"content_index":0,"text":"手机号是13812345678"}`,
		`data: {"type":"response.output_item.done","output_index":1,"item":{"id":"msg_001","type":"message","role":"assistant","content":[{"type":"output_text","text":"手机号是13812345678","annotations":[]}]}}`,
		`data: {"type":"response.completed","response":{"id":"resp_abc123","object":"response","status":"completed","output":[{"id":"rs_xyz789","type":"reasoning","encrypted_content":"gAAAAABmZW5jcnlwdGVkX3JlYXNvbmluZ19ibG9iX3h4eHh4eHh4"},{"id":"msg_001","type":"message","role":"assistant","content":[{"type":"output_text","text":"手机号是13812345678"}]}],"usage":{"input_tokens":10,"output_tokens":8}}}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	if !strings.Contains(extracted.Text, "手机号是13812345678") {
		t.Fatalf("Responses 流应重组出完整回答，实际: %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "[reasoning] 用户在问手机号") {
		t.Fatalf("Responses 流应以 [reasoning] 标记保留 reasoning_summary 增量，实际: %q", extracted.Text)
	}
	if n := strings.Count(extracted.Text, "手机号是13812345678"); n != 1 {
		t.Fatalf("回答应只留一份(增量重组)，不得被 .done/.completed 整对象重复记 %d 遍，实际: %q", n, extracted.Text)
	}
	if strings.Contains(extracted.Text, "gAAAAABmZW5jcnlwdGVk") {
		t.Fatalf("reasoning 的 encrypted_content 加密块不得落入留存正文，实际: %q", extracted.Text)
	}
	if strings.Contains(extracted.Text, "resp_abc123") || strings.Contains(extracted.Text, "msg_001") || strings.Contains(extracted.Text, "rs_xyz789") {
		t.Fatalf("response/item ID 不得落入留存正文，实际: %q", extracted.Text)
	}
}

func TestExtractResponseContent_ReassemblesOpenAIResponsesPureToolSnapshots(t *testing.T) {
	// Responses API can emit a tool-only stream without output_text/tool deltas. The
	// response.created frame carries the request's complete tool definitions, while
	// output_item.done and response.completed carry the actual calls. Falling back to
	// generic JSON traversal leaks the definitions and protocol IDs into retained text.
	body := []byte(strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_tool_only","status":"in_progress","tools":[{"type":"function","name":"lookup_customer","description":"INTERNAL TOOL DEFINITION SHOULD NEVER APPEAR","parameters":{"type":"object","properties":{"query":{"description":"SYSTEM PROMPT SHOULD NEVER APPEAR"}}}}]}}`,
		`data: {"type":"response.output_item.done","output_index":0,"item":{"id":"fc_001","type":"function_call","call_id":"call_001","name":"lookup_customer","arguments":"{\"query\":\"客户手机号13812345678\"}","status":"completed"}}`,
		`data: {"type":"response.output_item.done","output_index":1,"item":{"id":"ctc_001","type":"custom_tool_call","call_id":"call_002","name":"risk_lookup","input":"检查邮箱 alice@example.com","status":"completed"}}`,
		`data: {"type":"response.output_item.done","output_index":2,"item":{"id":"cc_001","type":"computer_call","call_id":"call_003","action":{"type":"type","text":"银行卡号6222021234567890"},"status":"completed"}}`,
		`data: {"type":"response.completed","response":{"id":"resp_tool_only","status":"completed","output":[{"id":"fc_001","type":"function_call","call_id":"call_001","name":"lookup_customer","arguments":"{\"query\":\"客户手机号13812345678\"}","status":"completed"},{"id":"ctc_001","type":"custom_tool_call","call_id":"call_002","name":"risk_lookup","input":"检查邮箱 alice@example.com","status":"completed"},{"id":"cc_001","type":"computer_call","call_id":"call_003","action":{"type":"type","text":"银行卡号6222021234567890"},"status":"completed"}]}}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	if !extracted.VisibleTextKnown || extracted.VisibleText != "" {
		t.Fatalf("pure tool Responses stream has no customer-visible model text: %+v", extracted)
	}
	for _, want := range []string{"客户手机号13812345678", "alice@example.com", "6222021234567890"} {
		if !strings.Contains(extracted.Text, want) {
			t.Fatalf("actual tool payload %q must remain available to security scanning: %q", want, extracted.Text)
		}
		if got := strings.Count(extracted.Text, want); got != 1 {
			t.Fatalf("tool payload %q must be deduplicated across done/completed snapshots, got %d: %q", want, got, extracted.Text)
		}
	}
	for _, leak := range []string{
		"INTERNAL TOOL DEFINITION SHOULD NEVER APPEAR",
		"SYSTEM PROMPT SHOULD NEVER APPEAR",
		"resp_tool_only",
		"fc_001",
		"call_001",
		"lookup_customer",
	} {
		if strings.Contains(extracted.Text, leak) {
			t.Fatalf("Responses protocol/tool definition value %q must not leak into retained text: %q", leak, extracted.Text)
		}
	}
}

func TestExtractResponseContent_ReassemblesOpenAIResponsesCompletedTextSnapshot(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_snapshot","status":"in_progress","tools":[{"type":"function","name":"internal_lookup","description":"INTERNAL TOOL DESCRIPTION MUST STAY HIDDEN"}]}}`,
		`data: {"type":"response.completed","response":{"id":"resp_snapshot","status":"completed","output":[{"id":"msg_snapshot","type":"message","role":"assistant","content":[{"type":"output_text","text":"最终答复：客户手机号是13812345678"}]}]}}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	const want = "最终答复：客户手机号是13812345678"
	if extracted.Text != want {
		t.Fatalf("completed-only Responses snapshot should retain only assistant output: %q", extracted.Text)
	}
	if !extracted.VisibleTextKnown || extracted.VisibleText != want {
		t.Fatalf("completed-only assistant output must be customer-visible: %+v", extracted)
	}
	for _, leak := range []string{"INTERNAL TOOL DESCRIPTION MUST STAY HIDDEN", "resp_snapshot", "msg_snapshot", "internal_lookup"} {
		if strings.Contains(extracted.Text, leak) {
			t.Fatalf("completed snapshot leaked Responses metadata %q: %q", leak, extracted.Text)
		}
	}
}

func TestExtractResponseContent_RecognizesEmptyOpenAIResponsesLifecycle(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_empty","status":"in_progress","tools":[{"type":"function","name":"internal_lookup","description":"EMPTY RESPONSE TOOL DEFINITION MUST STAY HIDDEN"}]}}`,
		`data: {"type":"response.completed","response":{"id":"resp_empty","status":"completed","output":[]}}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	if extracted.Text != "" {
		t.Fatalf("empty Responses lifecycle must not fall back to protocol flattening: %q", extracted.Text)
	}
	if !extracted.VisibleTextKnown || extracted.VisibleText != "" {
		t.Fatalf("empty Responses lifecycle has known-empty customer-visible text: %+v", extracted)
	}
}

func TestExtractResponseContent_UnknownOpenAIResponsesEventFailsClosed(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"type":"response.future_internal_event","payload":{"text":"UNKNOWN INTERNAL FIELD MUST NOT BE FLATTENED"}}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	if extracted.Text != "" || !extracted.VisibleTextKnown || extracted.VisibleText != "" {
		t.Fatalf("unknown confirmed Responses event must fail closed instead of generic flattening: %+v", extracted)
	}
}

func TestExtractResponseContent_OpenAIResponsesSnapshotMessageRequiresAssistantRole(t *testing.T) {
	tests := []struct {
		name  string
		event string
		leak  string
	}{
		{
			name:  "missing role in completed snapshot",
			event: `data: {"type":"response.completed","response":{"output":[{"id":"msg_missing","type":"message","content":[{"type":"output_text","text":"MISSING_ROLE_MUST_NOT_LEAK"}]}]}}`,
			leak:  "MISSING_ROLE_MUST_NOT_LEAK",
		},
		{
			name:  "user role in done snapshot",
			event: `data: {"type":"response.output_item.done","output_index":0,"item":{"id":"msg_user","type":"message","role":"user","content":[{"type":"output_text","text":"USER_ROLE_MUST_NOT_LEAK"}]}}`,
			leak:  "USER_ROLE_MUST_NOT_LEAK",
		},
		{
			name:  "tool role in completed snapshot",
			event: `data: {"type":"response.completed","response":{"output":[{"id":"msg_tool","type":"message","role":"tool","content":[{"type":"output_text","text":"TOOL_ROLE_MUST_NOT_LEAK"}]}]}}`,
			leak:  "TOOL_ROLE_MUST_NOT_LEAK",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(test.event + "\ndata: [DONE]\n")
			extracted := extractResponseContent(body, "text/event-stream")
			if strings.Contains(extracted.Text, test.leak) || extracted.Text != "" {
				t.Fatalf("non-assistant snapshot message must fail closed: %+v", extracted)
			}
			if !extracted.VisibleTextKnown || extracted.VisibleText != "" {
				t.Fatalf("non-assistant snapshot has known-empty visible text: %+v", extracted)
			}
		})
	}
}

func TestExtractResponseContent_OpenAIResponsesSnapshotsOverrideGroupedConcurrentDeltas(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"delta":"客户答复前缀"}`,
		`data: {"type":"response.output_item.added","output_index":3,"item":{"id":"ctc_c","type":"custom_tool_call","input":""}}`,
		`data: {"type":"response.output_item.added","output_index":4,"item":{"id":"ctc_d","type":"custom_tool_call","input":""}}`,
		`data: {"type":"response.function_call_arguments.delta","item_id":"fc_a","delta":"{\"query\":\"DELTA_A_"}`,
		`data: {"type":"response.function_call_arguments.delta","output_index":2,"delta":"{\"query\":\"工具B前缀"}`,
		`data: {"type":"response.custom_tool_call_input.delta","item_id":"ctc_c","output_index":3,"delta":"并发C-"}`,
		`data: {"type":"response.custom_tool_call_input.delta","item_id":"ctc_d","output_index":4,"delta":"并发D-"}`,
		`data: {"type":"response.function_call_arguments.delta","item_id":"fc_a","delta":"SHOULD_DISAPPEAR\"}"}`,
		`data: {"type":"response.function_call_arguments.delta","output_index":2,"delta":"与delta后缀\"}"}`,
		`data: {"type":"response.custom_tool_call_input.delta","item_id":"ctc_c","output_index":3,"delta":"完整"}`,
		`data: {"type":"response.custom_tool_call_input.delta","item_id":"ctc_d","output_index":4,"delta":"完整"}`,
		`data: {"type":"response.output_item.done","output_index":1,"item":{"id":"fc_a","type":"function_call","arguments":"{\"query\":\"SNAPSHOT_A_AUTHORITATIVE\"}"}}`,
		`data: {"type":"response.completed","response":{"output":[{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"客户答复前缀与权威完整后缀"}]},{"id":"fc_a","type":"function_call","arguments":"{\"query\":\"SNAPSHOT_A_AUTHORITATIVE\"}"},{"id":"fc_b","type":"function_call","arguments":"{\"query\":\"工具B前缀与权威完整后缀\"}"}]}}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	for _, want := range []string{
		"客户答复前缀与权威完整后缀",
		"SNAPSHOT_A_AUTHORITATIVE",
		"工具B前缀与权威完整后缀",
		"并发C-完整",
		"并发D-完整",
	} {
		if !strings.Contains(extracted.Text, want) {
			t.Fatalf("grouped Responses projection missing %q: %q", want, extracted.Text)
		}
	}
	if strings.Contains(extracted.Text, "DELTA_A_SHOULD_DISAPPEAR") {
		t.Fatalf("authoritative done snapshot must replace same-item delta: %q", extracted.Text)
	}
	for _, once := range []string{"客户答复前缀", "SNAPSHOT_A_AUTHORITATIVE", "工具B前缀"} {
		if count := strings.Count(extracted.Text, once); count != 1 {
			t.Fatalf("snapshot prefix %q should occur once, got %d: %q", once, count, extracted.Text)
		}
	}
	if extracted.VisibleText != "客户答复前缀与权威完整后缀" || !extracted.VisibleTextKnown {
		t.Fatalf("visible projection must prefer the assistant snapshot: %+v", extracted)
	}
}

func TestExtractResponseContent_OpenAIResponsesAttachmentsIgnoreCreatedAndUnknownEvents(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"type":"response.created","response":{"tools":[{"type":"function","description":"internal","icon":"data:image/png;base64,Y3JlYXRlZA=="}]}}`,
		`data: {"type":"response.future_internal_event","payload":{"image_url":"data:image/png;base64,dW5rbm93bg=="}}`,
		`data: {"type":"response.output_item.done","output_index":0,"item":{"id":"msg_image","type":"message","role":"assistant","content":[{"type":"output_text","text":"图片已生成"},{"type":"output_image","image_url":"data:image/png;base64,b3V0cHV0"}]}}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	if len(extracted.Attachments) != 1 {
		t.Fatalf("only known output-event attachment should remain, got %+v", extracted.Attachments)
	}
	if extracted.Attachments[0].DataBase64 != "b3V0cHV0" || extracted.Attachments[0].Size != 6 {
		t.Fatalf("unexpected retained Responses attachment: %+v", extracted.Attachments[0])
	}
}

func TestExtractResponseContent_OpenAIResponsesToolSnapshotWhitelist(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"type":"response.completed","response":{"output":[` +
			`{"id":"fn","type":"function_call","arguments":"KNOWN_FUNCTION_ARGUMENTS"},` +
			`{"id":"custom","type":"custom_tool_call","input":"KNOWN_CUSTOM_INPUT"},` +
			`{"id":"computer","type":"computer_call","action":{"type":"type","text":"KNOWN_COMPUTER_ACTION"}},` +
			`{"id":"files","type":"file_search_call","queries":["KNOWN_FILE_QUERY"]},` +
			`{"id":"code","type":"code_interpreter_call","code":"KNOWN_CODE_INTERPRETER_CODE"},` +
			`{"id":"web","type":"web_search_call","action":{"type":"search","query":"KNOWN_WEB_ACTION"}},` +
			`{"id":"local","type":"local_shell_call","action":{"command":"KNOWN_LOCAL_SHELL_ACTION"}},` +
			`{"id":"shell","type":"shell_call","action":{"command":"KNOWN_SHELL_ACTION"}},` +
			`{"id":"mcp","type":"mcp_call","arguments":"KNOWN_MCP_ARGUMENTS"},` +
			`{"id":"future","type":"future_tool_call","arguments":"UNKNOWN_TOOL_ARGUMENTS_MUST_NOT_LEAK"}` +
			`]}}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	for _, want := range []string{
		"KNOWN_FUNCTION_ARGUMENTS",
		"KNOWN_CUSTOM_INPUT",
		"KNOWN_COMPUTER_ACTION",
		"KNOWN_FILE_QUERY",
		"KNOWN_CODE_INTERPRETER_CODE",
		"KNOWN_WEB_ACTION",
		"KNOWN_LOCAL_SHELL_ACTION",
		"KNOWN_SHELL_ACTION",
		"KNOWN_MCP_ARGUMENTS",
	} {
		if !strings.Contains(extracted.Text, want) {
			t.Fatalf("known Responses tool payload %q was not retained for scanning: %q", want, extracted.Text)
		}
	}
	if strings.Contains(extracted.Text, "UNKNOWN_TOOL_ARGUMENTS_MUST_NOT_LEAK") {
		t.Fatalf("unknown Responses tool type must fail closed: %q", extracted.Text)
	}
	if !extracted.VisibleTextKnown || extracted.VisibleText != "" {
		t.Fatalf("tool-only whitelist stream has known-empty visible output: %+v", extracted)
	}
}

func TestExtractResponseContent_OpenAIResponsesIdentityConflictsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		events []string
		leaks  []string
	}{
		{
			name: "same item id changes output index",
			events: []string{
				`data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_conflict","type":"message","role":"assistant","content":[]}}`,
				`data: {"type":"response.output_text.delta","item_id":"msg_conflict","output_index":0,"content_index":0,"delta":"CONFLICT_ID_DELTA"}`,
				`data: {"type":"response.output_item.done","output_index":1,"item":{"id":"msg_conflict","type":"message","role":"assistant","content":[{"type":"output_text","text":"CONFLICT_ID_SNAPSHOT"}]}}`,
			},
			leaks: []string{"CONFLICT_ID_DELTA", "CONFLICT_ID_SNAPSHOT"},
		},
		{
			name: "same output index changes item id",
			events: []string{
				`data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_first","type":"message","role":"assistant","content":[]}}`,
				`data: {"type":"response.output_text.delta","item_id":"msg_first","output_index":0,"content_index":0,"delta":"CONFLICT_INDEX_DELTA"}`,
				`data: {"type":"response.output_item.done","output_index":0,"item":{"id":"msg_second","type":"message","role":"assistant","content":[{"type":"output_text","text":"CONFLICT_INDEX_SNAPSHOT"}]}}`,
			},
			leaks: []string{"CONFLICT_INDEX_DELTA", "CONFLICT_INDEX_SNAPSHOT"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(strings.Join(append(test.events, "data: [DONE]", ""), "\n"))
			extracted := extractResponseContent(body, "text/event-stream")
			for _, leak := range test.leaks {
				if strings.Contains(extracted.Text, leak) {
					t.Fatalf("conflicting Responses identity leaked %q: %+v", leak, extracted)
				}
			}
			if !extracted.VisibleTextKnown || extracted.VisibleText != "" {
				t.Fatalf("identity conflict must have known-empty visible output: %+v", extracted)
			}
		})
	}
}

func TestExtractResponseContent_OpenAIResponsesEmptyOrMalformedSnapshotsKeepValidDeltas(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_delta","type":"message","role":"assistant","content":[]}}`,
		`data: {"type":"response.output_text.delta","item_id":"msg_delta","output_index":0,"content_index":0,"delta":"VALID_ASSISTANT_DELTA"}`,
		`data: {"type":"response.output_text.done","item_id":"msg_delta","output_index":0,"content_index":0,"text":""}`,
		`data: {"type":"response.output_item.done","output_index":0,"item":{"id":"msg_delta","type":"message","role":"assistant","content":"malformed"}}`,
		`data: {"type":"response.output_item.added","output_index":1,"item":{"id":"fn_delta","type":"function_call"}}`,
		`data: {"type":"response.function_call_arguments.delta","item_id":"fn_delta","output_index":1,"delta":"VALID_TOOL_DELTA"}`,
		`data: {"type":"response.output_item.done","output_index":1,"item":{"id":"fn_delta","type":"function_call","arguments":{}}}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	for _, want := range []string{"VALID_ASSISTANT_DELTA", "VALID_TOOL_DELTA"} {
		if !strings.Contains(extracted.Text, want) {
			t.Fatalf("empty/malformed snapshot replaced valid delta %q: %+v", want, extracted)
		}
	}
	if !extracted.VisibleTextKnown || extracted.VisibleText != "VALID_ASSISTANT_DELTA" {
		t.Fatalf("valid assistant delta should remain customer-visible: %+v", extracted)
	}
}

func TestExtractResponseContent_OpenAIResponsesDeltaAndContentPartRequireVerifiedItem(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"type":"response.output_text.delta","item_id":"msg_unbound","output_index":0,"content_index":0,"delta":"UNBOUND_DELTA_MUST_NOT_LEAK"}`,
		`data: {"type":"response.content_part.done","item_id":"msg_unbound","output_index":0,"content_index":1,"part":{"type":"output_image","image_url":"data:image/png;base64,dW5ib3VuZA=="}}`,
		`data: {"type":"response.output_item.added","output_index":1,"item":{"id":"msg_verified","type":"message","role":"assistant","content":[]}}`,
		`data: {"type":"response.output_text.delta","item_id":"msg_verified","output_index":1,"content_index":0,"delta":"VERIFIED_ASSISTANT_DELTA"}`,
		`data: {"type":"response.content_part.done","item_id":"msg_verified","output_index":1,"content_index":1,"part":{"type":"output_image","image_url":"data:image/png;base64,dmVyaWZpZWQ="}}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	if strings.Contains(extracted.Text, "UNBOUND_DELTA_MUST_NOT_LEAK") || !strings.Contains(extracted.Text, "VERIFIED_ASSISTANT_DELTA") {
		t.Fatalf("only deltas bound to a verified assistant item may be projected: %+v", extracted)
	}
	if len(extracted.Attachments) != 1 || extracted.Attachments[0].DataBase64 != "dmVyaWZpZWQ=" {
		t.Fatalf("only content parts bound to a verified item may create attachments: %+v", extracted.Attachments)
	}
}

func TestExtractResponseContent_OpenAIResponsesImageGenerationResultBecomesAttachment(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"type":"response.output_item.done","output_index":0,"item":{"id":"img_1","type":"image_generation_call","result":"iVBORw0KGgo="}}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	if len(extracted.Attachments) != 1 {
		t.Fatalf("image_generation_call.result should create one attachment: %+v", extracted.Attachments)
	}
	attachment := extracted.Attachments[0]
	if attachment.ContentType != "image/png" || attachment.Size != 8 || attachment.DataBase64 != "iVBORw0KGgo=" {
		t.Fatalf("unexpected ImageGen result attachment: %+v", attachment)
	}
	if extracted.Text != "" || !extracted.VisibleTextKnown || extracted.VisibleText != "" {
		t.Fatalf("ImageGen bytes must not become customer-visible text: %+v", extracted)
	}
}

func TestExtractResponseContent_OpenAIResponsesSnapshotsOverrideOnlyMatchingLanes(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_lanes","type":"message","role":"assistant","content":[]}}`,
		`data: {"type":"response.output_text.delta","item_id":"msg_lanes","output_index":0,"content_index":0,"delta":"ANSWER_LANE_ZERO_DELTA"}`,
		`data: {"type":"response.output_text.delta","item_id":"msg_lanes","output_index":0,"content_index":1,"delta":"ANSWER_LANE_ONE_DELTA"}`,
		`data: {"type":"response.output_text.done","item_id":"msg_lanes","output_index":0,"content_index":0,"text":"ANSWER_LANE_ZERO_SNAPSHOT"}`,
		`data: {"type":"response.output_item.added","output_index":1,"item":{"id":"reason_lanes","type":"reasoning","summary":[]}}`,
		`data: {"type":"response.reasoning_summary_text.delta","item_id":"reason_lanes","output_index":1,"summary_index":0,"delta":"REASON_LANE_ZERO_DELTA"}`,
		`data: {"type":"response.reasoning_summary_text.delta","item_id":"reason_lanes","output_index":1,"summary_index":1,"delta":"REASON_LANE_ONE_DELTA"}`,
		`data: {"type":"response.reasoning_summary_text.done","item_id":"reason_lanes","output_index":1,"summary_index":0,"text":"REASON_LANE_ZERO_SNAPSHOT"}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	for _, want := range []string{
		"ANSWER_LANE_ZERO_SNAPSHOT",
		"ANSWER_LANE_ONE_DELTA",
		"[reasoning] REASON_LANE_ZERO_SNAPSHOT",
		"[reasoning] REASON_LANE_ONE_DELTA",
	} {
		if !strings.Contains(extracted.Text, want) {
			t.Fatalf("lane-aware Responses projection missing %q: %q", want, extracted.Text)
		}
	}
	for _, replaced := range []string{"ANSWER_LANE_ZERO_DELTA", "REASON_LANE_ZERO_DELTA"} {
		if strings.Contains(extracted.Text, replaced) {
			t.Fatalf("same-lane delta should be replaced by its snapshot %q: %q", replaced, extracted.Text)
		}
	}
}

func TestExtractResponseContent_ReassemblesDeepSeekPatchTokenSplits(t *testing.T) {
	// DeepSeek 网页 {o,p,v} JSON-patch 流：THINK 片段进入推理，RESPONSE 片段的
	// 正文同样被切分到多个 patch。逐帧处理既会丢弃纯数字增量（不过人类文本启发），
	// 也无法连续重组，必须按 fragment 索引顺序拼接。
	body := []byte(strings.Join([]string{
		`data: {"o":"APPEND","p":"response/fragments","v":{"type":"THINK","content":""}}`,
		`data: {"o":"APPEND","p":"response/fragments/0/content","v":"用户在问手机号"}`,
		`data: {"o":"APPEND","p":"response/fragments","v":{"type":"RESPONSE","content":""}}`,
		`data: {"o":"APPEND","p":"response/fragments/1/content","v":"手机号是138"}`,
		`data: {"o":"APPEND","p":"response/fragments/1/content","v":"1234"}`,
		`data: {"o":"APPEND","p":"response/fragments/1/content","v":"5678"}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "手机号是13812345678") {
		t.Fatalf("DeepSeek patch 流应连续重组出完整正文，实际: %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "[reasoning] 用户在问手机号") {
		t.Fatalf("DeepSeek patch 流应以 [reasoning] 标记保留 THINK 片段，实际: %q", extracted.Text)
	}
}

func TestExtractResponseContent_ReassemblesDeepSeekRealWireFormat(t *testing.T) {
	// 真实抓包（/tmp/ds-diag 落盘）确认 DeepSeek 网页版的 {o,p,v} 流不是理想化的「每帧都带
	// o+p+数字索引」，而是三种增量帧混合，正是它们让 22KB 回答塌成 1 字符、思考过程全丢：
	//
	//   1) 初始快照帧：{"v":{"response":{...,"fragments":[{"type":"THINK","content":"我们"}]}}}
	//      —— 无 p 无 o，v 是整个 response 对象，确立首个 THINK 片段与其种子内容；
	//   2) sticky 裸帧：{"v":"9.11"} —— 无 p 无 o，继承上一帧明示的 path 与 op（APPEND），
	//      正文/思考的绝大多数 token 都走这种帧；
	//   3) 隐式 op 帧：{"p":"response/fragments/-1/content","v":"."} —— 有 p 无 o，
	//      DeepSeek 对 content 的隐式 op 是 APPEND，而非 RESET。
	//
	// 旧代码：快照帧 path="" 落 default 被丢（THINK 与全部思考随之消失）；sticky 裸帧
	// path/op 都为空落 default 被丢（正文/思考 token 整段蒸发）；隐式 op 帧走 else 分支 RESET
	// 而非 APPEND（把已累积的种子内容清掉）。三者叠加，回答只剩最后一个 RESPONSE 片段的种子。
	//
	// fragment 索引用 "-1"（最后一个片段），与真实流一致，不是 0/1。
	body := []byte(strings.Join([]string{
		`event: ready`,
		`data: {"request_message_id":7}`,
		`event: update_session`,
		`data: {"updated_at":1}`,
		// 1) 初始快照帧：确立 THINK 片段，种子 "我们"
		`data: {"v":{"response":{"status":"WIP","fragments":[{"id":2,"type":"THINK","content":"我们","stage_id":1}]}}}`,
		// 2) 明示 APPEND 到最后片段 content：把 stickyPath/op 钉到 content+APPEND
		`data: {"p":"response/fragments/-1/content","o":"APPEND","v":"比较"}`,
		// 3) sticky 裸帧（思考 token 主体）：继承 content+APPEND
		`data: {"v":"9.11和"}`,
		`data: {"v":"9.10，十分位1>0。"}`,
		// elapsed_secs SET：非 content，路径切走但随后被显式帧重置，不应吞掉裸帧
		`data: {"p":"response/fragments/-1/elapsed_secs","o":"SET","v":1.1}`,
		// 4) APPEND 新 RESPONSE 片段，种子 "9"
		`data: {"p":"response/fragments","o":"APPEND","v":[{"id":3,"type":"RESPONSE","content":"9","stage_id":2}]}`,
		// 5) 隐式 op 帧（有 p 无 o）：对 content 应 APPEND 出 "9."，而非 RESET 成 "."
		`data: {"p":"response/fragments/-1/content","v":"."}`,
		// 6) sticky 裸帧（回答 token 主体）：继承 content+APPEND
		`data: {"v":"11 比 9.10 大"}`,
		// 收尾 BATCH + status，不应破坏前面的重组
		`data: {"p":"response","o":"BATCH","v":[{"p":"accumulated_token_usage","v":5897},{"p":"quasi_status","v":"FINISHED"}]}`,
		`data: {"p":"response/status","o":"SET","v":"FINISHED"}`,
		`event: close`,
		`data: {"v":"close"}`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	// (A) 回答连续重组：RESPONSE 种子 "9" + 隐式 op "." + sticky "11 比 9.10 大" = "9.11 比 9.10 大"。
	//     若隐式 op 误 RESET，会丢掉种子 "9" 变成 ".11 比 9.10 大"；若 sticky 裸帧被丢，只剩 "9."。
	if !strings.Contains(extracted.Text, "9.11 比 9.10 大") {
		t.Fatalf("真实 wire 流应连续重组出完整回答「9.11 比 9.10 大」(种子+隐式APPEND+sticky 裸帧)，实际: %q", extracted.Text)
	}
	// (B) 思考过程：快照种子 "我们" + 明示 APPEND "比较" + sticky 思考裸帧，且带 [reasoning] 标记。
	if !strings.Contains(extracted.Text, "[reasoning] 我们比较9.11和9.10") {
		t.Fatalf("真实 wire 流应抓到完整思考过程并带 [reasoning] 标记(快照THINK种子+明示+sticky)，实际: %q", extracted.Text)
	}
}

func TestExtractResponseContent_MarksEachReasoningLine(t *testing.T) {
	// 推理模型会在 reasoning_content 里输出换行（多段思考）。流式重组把各帧连续
	// 拼接后，若只在整段思考前加一个 [reasoning] 标记，前端按行解析（AccessRetention.tsx
	// 的 splitReasoningAndAnswer 逐行匹配 ^\s*\[reasoning\]）时，第二段及之后会漏进
	// 回答面板 —— 相对 CANON 逐帧标记的行为构成能力回退。每一行非空思考都必须带标记。
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"reasoning_content":"第一段思考。\n"}}]}`,
		`data: {"choices":[{"delta":{"reasoning_content":"第二段思考。"}}]}`,
		`data: {"choices":[{"delta":{"content":"最终回答。"}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "[reasoning] 第一段思考。") {
		t.Fatalf("第一段思考应带 [reasoning] 标记，实际: %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "[reasoning] 第二段思考。") {
		t.Fatalf("多段思考的每一段都应带 [reasoning] 标记（避免前端漏进回答面板），实际: %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "最终回答。") {
		t.Fatalf("最终回答应保留，实际: %q", extracted.Text)
	}
}

func TestExtractResponseContent_FallsBackWhenOpenAIDeltaCarriesNoKnownText(t *testing.T) {
	// 纯函数调用（function calling）流：每帧 choices[].delta 都存在，reassembler 会
	// matched=true，但正文只在 tool_calls[].function.arguments 里，reassembler 当前不读
	// 该字段，answer/reasoning 都为空。若此时仍返回（空, true），extractSSEContent 会直接
	// 吐出空正文，再也不回退到逐帧 collectJSONText —— 相对 CANON 始终逐帧解析构成能力回退
	// （security.go 拿到空串将漏检全部风险）。匹配但抽取为空时必须回退到逐帧解析。
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"role":"assistant","tool_calls":[{"index":0,"function":{"name":"lookup","arguments":""}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"用户的手机号是13812345678需要核对"}}]}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "13812345678") {
		t.Fatalf("reassembler 匹配但未抽取出正文时必须回退到逐帧解析，不能吐空正文，实际: %q", extracted.Text)
	}
}

func TestExtractResponseContent_FallsBackWhenDeepSeekReassemblyEmpty(t *testing.T) {
	// ChatGPT 网页流的 {p,o,v} 帧同样带 o(string)+p，会被 looksLikeDeepSeekPatch 误判为
	// DeepSeek（matched=true），但其路径是 /message/content/parts/0 之类，全部落到
	// applyDeepSeekPath 的 default 分支被丢弃，fragments 为空、answer/reasoning 为空。
	// 若仍返回（空, true），真实正文（在 v 里）会被整段吞掉。匹配但抽取为空必须回退。
	body := []byte(strings.Join([]string{
		`data: {"p":"/message/content/parts/0","o":"append","v":"用户的身份证号是110101199003078888请核对"}`,
		`data: {"v":"，谢谢配合。"}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "110101199003078888") {
		t.Fatalf("误判为 DeepSeek 但抽取为空时必须回退到逐帧解析，实际: %q", extracted.Text)
	}
}

func TestLooksLikeDeepSeekPatch_RejectsChatGPTPartsPath(t *testing.T) {
	// ChatGPT 网页流的补丁帧 {p:"/message/content/parts/0",o:"append",v:...} 与 DeepSeek 的
	// {p:"response/...",o:"APPEND",v:...} 结构同形（都带 o(string)+p）。SSE 正文里没有 host，
	// 只能靠路径区分：DeepSeek 的 p 以 "response" 开头，ChatGPT 的 p 以 "/message" 开头。
	// 若把 ChatGPT 误判为 DeepSeek，整段正文会落到 applyDeepSeekPath 的 default 分支被丢弃。
	// looksLikeDeepSeekPatch 必须拒绝 ChatGPT 的 parts 路径。
	chatgpt := parseSSEDataEvents([]byte(`data: {"p":"/message/content/parts/0","o":"append","v":"hi"}`))
	if len(chatgpt) != 1 {
		t.Fatalf("应解析出 1 个事件，实际 %d", len(chatgpt))
	}
	if looksLikeDeepSeekPatch(chatgpt[0]) {
		t.Fatalf("ChatGPT 的 /message/content/parts 帧不应被判定为 DeepSeek 补丁")
	}

	// 真正的 DeepSeek 补丁帧（p 以 response 开头）必须继续被识别，避免误伤。
	deepseek := parseSSEDataEvents([]byte(`data: {"p":"response/fragments","o":"APPEND","v":"x"}`))
	if len(deepseek) != 1 {
		t.Fatalf("应解析出 1 个事件，实际 %d", len(deepseek))
	}
	if !looksLikeDeepSeekPatch(deepseek[0]) {
		t.Fatalf("真正的 DeepSeek response 补丁帧必须仍被识别为 DeepSeek")
	}

	// BATCH 顶层补丁帧没有 p 字段，仍必须靠 o=="BATCH" 短路识别。
	batch := parseSSEDataEvents([]byte(`data: {"o":"BATCH","v":[{"p":"response/fragments","o":"APPEND","v":"y"}]}`))
	if len(batch) != 1 {
		t.Fatalf("应解析出 1 个事件，实际 %d", len(batch))
	}
	if !looksLikeDeepSeekPatch(batch[0]) {
		t.Fatalf("BATCH 顶层补丁帧必须仍被识别为 DeepSeek")
	}
}

func TestExtractResponseContentWithDecoder_ChatGPTWebIsolationSurvivesLooseDeepSeekSniff(t *testing.T) {
	// 隔离不变量：ChatGPT-web 与 DeepSeek-web 的网页 SSE 都可能是 {p,o,v} patch 形态。
	// 即便后续有人放宽 DeepSeek 嗅探条件（例如只看 o+p），只要 catalog 已指定 chatgpt_web，
	// ChatGPT 流就必须走 ChatGPT 自己的解码器，不能被 DeepSeek 的 first-ok-wins 误吞。
	original := deepSeekPatchSniffer
	deepSeekPatchSniffer = func(ev sseEvent) bool {
		m, ok := ev.decoded.(map[string]interface{})
		if !ok {
			return false
		}
		_, hasOp := m["o"].(string)
		_, hasPath := m["p"].(string)
		return hasOp && hasPath
	}
	t.Cleanup(func() { deepSeekPatchSniffer = original })

	body := []byte(strings.Join([]string{
		`data: {"p":"/message/content/parts/0","o":"append","v":"ChatGPT网页回答：手机号138"}`,
		`data: {"p":"/message/content/parts/0","o":"append","v":"12345678"}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContentWithDecoder(body, "text/event-stream", "chatgpt_web")
	if !strings.Contains(extracted.Text, "ChatGPT网页回答：手机号138") || !strings.Contains(extracted.Text, "12345678") {
		t.Fatalf("chatgpt_web 指定解码器必须绕开 DeepSeek 嗅探误判，实际: %q", extracted.Text)
	}
}

func TestExtractResponseContent_ReassemblesToolCallArgumentsAlongsideContent(t *testing.T) {
	// 混合流：先有正文 content，再有 token 切分的 tool_calls.arguments（自然语言、含敏感号码）。
	// CANON 逐帧解析会把两段 arguments 都按人类文本抓出；MINE 的重组器此前只读 content，
	// content 非空时不回退，把 tool_calls 整段丢弃 —— 对混合流构成相对 CANON 的能力回退
	//（敏感信息漏检）。tool_calls.arguments 必须按 token 重组并保留。
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"role":"assistant","content":"好的，正在为您查询。"}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"query_identity","arguments":"查询手机号13812345678"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"的实名登记信息"}}]}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "好的，正在为您查询。") {
		t.Fatalf("混合流的正文 content 应保留，实际: %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "13812345678") {
		t.Fatalf("混合流里 token 切分的 tool_calls.arguments 不能被丢弃，实际: %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "实名登记信息") {
		t.Fatalf("tool_calls.arguments 的后续片段也应重组保留，实际: %q", extracted.Text)
	}
	if !extracted.VisibleTextKnown || extracted.VisibleText != "好的，正在为您查询。" {
		t.Fatalf("客户可见投影只能保留正文 content，不含工具入参: %+v", extracted)
	}
}

func TestExtractResponseContent_ReassemblesRefusalAlongsideContent(t *testing.T) {
	// delta.refusal 是模型拒答内容，属于回答的一部分。混合流里 content 非空时重组器不回退，
	// 此前只读 content 会把 refusal 丢弃 —— 相对 CANON 逐帧解析构成能力回退。
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"role":"assistant","content":"关于这个问题，"}}]}`,
		`data: {"choices":[{"delta":{"refusal":"抱歉，我无法提供进一步的危险操作细节。"}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "关于这个问题，") {
		t.Fatalf("混合流的正文 content 应保留，实际: %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "抱歉，我无法提供进一步的危险操作细节。") {
		t.Fatalf("delta.refusal 是回答的一部分，不能被丢弃，实际: %q", extracted.Text)
	}
}

func TestExtractResponseContent_ReassemblesArrayFormContentAlongsideReasoning(t *testing.T) {
	// 部分网关把 delta.content 以数组分段形式下发（[{type:text,text:...}]）。混合流里
	// reasoning_content 非空时重组器不回退，此前 delta["content"].(string) 断言失败会把数组
	// 形式的回答整段丢弃 —— 相对 CANON 逐帧解析构成能力回退。数组形式的 content 必须取出。
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"reasoning_content":"先想一下用户的诉求。"}}]}`,
		`data: {"choices":[{"delta":{"content":[{"type":"text","text":"这是数组形式下发的回答。"}]}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "[reasoning] 先想一下用户的诉求。") {
		t.Fatalf("思考应带 [reasoning] 标记并保留，实际: %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "这是数组形式下发的回答。") {
		t.Fatalf("数组形式 content 的回答不能被丢弃，实际: %q", extracted.Text)
	}
}

func TestExtractResponseContent_KeepsTrailingMessageContentNotInDelta(t *testing.T) {
	// 部分 OpenAI 兼容网关在 delta 流式之外，于末帧补发完整 choices[].message。当
	// message.content 含 delta 未携带的正文时，reassembler 只读 delta 会把它整段丢弃 ——
	// 相对 CANON 逐帧 collectJSONText 构成能力回退（末帧里的敏感正文漏检）。
	// message.content 里 delta 未覆盖的正文必须保留。
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"role":"assistant","content":"流式增量部分。"}}]}`,
		`data: {"choices":[{"message":{"role":"assistant","content":"末帧补发：用户的手机号是13812345678。"}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "流式增量部分。") {
		t.Fatalf("delta 增量正文应保留，实际: %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "13812345678") {
		t.Fatalf("末帧 message.content 里 delta 未携带的正文不能被丢弃，实际: %q", extracted.Text)
	}
}

func TestExtractResponseContent_DeduplicatesTrailingMessageMatchingDelta(t *testing.T) {
	// 很多 OpenAI 兼容网关在 delta 逐 token 下发完后，于末帧把同一段正文以完整 message
	// 再补发一次。若无条件把 message.content 追加到已重组的 answer，正文会被记两遍 ——
	// 审计正文虚高、且同一敏感号码出现两次会放大下游检测误报。末帧 message 与 delta 重复时
	// 不能重复计入。
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"role":"assistant","content":"用户的身份证号是"}}]}`,
		`data: {"choices":[{"delta":{"content":"110101199003078888。"}}]}`,
		`data: {"choices":[{"message":{"role":"assistant","content":"用户的身份证号是110101199003078888。"}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "110101199003078888") {
		t.Fatalf("正文应保留，实际: %q", extracted.Text)
	}
	if got := strings.Count(extracted.Text, "110101199003078888"); got != 1 {
		t.Fatalf("末帧 message 与 delta 重复时不能重复计入，期望出现 1 次，实际 %d 次: %q", got, extracted.Text)
	}
}

func TestExtractResponseContent_DeduplicatesPerFrameCumulativeMessageSnapshots(t *testing.T) {
	// 部分 OpenAI 兼容网关每帧同时下发：delta（增量 token）+ message（截至当前的完整快照）。
	// 若无条件把每帧的 message.content 累加，messageText 会变成多个快照的拼接，再整段补到
	// answer 后，同一敏感串被记两遍 —— 审计正文虚高、放大下游检测误报。只应保留最完整的
	// 那一份快照，且与 delta 重组结果重复时不重复计入。
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"role":"assistant","content":"用户的银行卡号是"},"message":{"role":"assistant","content":"用户的银行卡号是"}}]}`,
		`data: {"choices":[{"delta":{"content":"6225880137"},"message":{"role":"assistant","content":"用户的银行卡号是6225880137"}}]}`,
		`data: {"choices":[{"delta":{"content":"000000。"},"message":{"role":"assistant","content":"用户的银行卡号是6225880137000000。"}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "6225880137000000") {
		t.Fatalf("逐帧累积快照场景下正文应保留，实际: %q", extracted.Text)
	}
	if got := strings.Count(extracted.Text, "6225880137000000"); got != 1 {
		t.Fatalf("逐帧累积 message 快照不能重复计入，期望出现 1 次，实际 %d 次: %q", got, extracted.Text)
	}
}

func TestExtractResponseContent_DeduplicatesTrailingMessageSupersetOfDelta(t *testing.T) {
	// 末帧补发的完整 message 常是 delta 重组结果的「超集」：例如多出一个尾部句号、或对空白
	// 做了规整化。整串相等才去重（whole-string Contains）会漏掉这种情形，把整段 message 再
	// 追加一遍 —— 同一敏感串出现两次。message ⊇ answer 时应以更完整的 message 取代，而不是叠加。
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"role":"assistant","content":"用户的护照号是E12345678"}}]}`,
		`data: {"choices":[{"message":{"role":"assistant","content":"用户的护照号是E12345678。"}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "E12345678") {
		t.Fatalf("超集 message 场景下正文应保留，实际: %q", extracted.Text)
	}
	if got := strings.Count(extracted.Text, "E12345678"); got != 1 {
		t.Fatalf("末帧 message 为 delta 超集时不能重复计入，期望出现 1 次，实际 %d 次: %q", got, extracted.Text)
	}
}

func TestExtractResponseContent_FallsBackWhenOpenAIDeltaCarriesOnlyLegacyFunctionCall(t *testing.T) {
	// 覆盖 reassembleOpenAIDeltaStream 的「匹配到 delta 结构但已知字段全空」回退护栏。
	// 部分 OpenAI 兼容网关仍用已废弃的 delta.function_call（单数）而非 tool_calls（复数）
	// 下发工具调用入参，重组器不解析单数字段 —— answer/reasoning/附件都为空，matched=true。
	// 若此时返回 (空, true)，extractSSEContent 会跳过逐帧 collectJSONText 兜底，藏在
	// function_call.arguments 里的用户正文（手机号）会被整段吞掉漏检。护栏应在 matched
	// 且已知字段全空时返回 (空, false)，让逐帧解析兜底捕获。
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"role":"assistant","function_call":{"name":"lookup","arguments":""}}}]}`,
		`data: {"choices":[{"delta":{"function_call":{"arguments":"用户的手机号是13812345678需要核对"}}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "13812345678") {
		t.Fatalf("delta 仅含 legacy function_call 时，正文应由逐帧兜底捕获，实际: %q", extracted.Text)
	}
	if got := strings.Count(extracted.Text, "13812345678"); got != 1 {
		t.Fatalf("兜底捕获的手机号期望出现 1 次，实际 %d 次: %q", got, extracted.Text)
	}
}

func TestExtractResponseContent_FallsBackWhenDeepSeekResponsePatchYieldsNoFragment(t *testing.T) {
	// 覆盖 reassembleDeepSeekPatchStream 的「匹配为 DeepSeek 但 fragments 为空」回退护栏。
	// 帧 p 以 "response" 开头，looksLikeDeepSeekPatch 判定为 DeepSeek（matched=true）；但
	// response/content 不在 applyDeepSeekPath 处理的 response / response/fragments /
	// response/fragments/<idx>/content 路径集合内，落到 default 分支被丢弃，fragments 为空。
	// 若此时返回 (空, true)，DeepSeek 重组器先于其它路径被采用，会吞掉整段流，藏在 v 里的
	// 身份证号漏检。护栏应在全空时返回 (空, false)，让逐帧解析兜底捕获。
	body := []byte(strings.Join([]string{
		`data: {"p":"response/content","o":"APPEND","v":"用户的身份证号是110101199003078888请核对"}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "110101199003078888") {
		t.Fatalf("DeepSeek 误判且 fragments 为空时，正文应由逐帧兜底捕获，实际: %q", extracted.Text)
	}
	if got := strings.Count(extracted.Text, "110101199003078888"); got != 1 {
		t.Fatalf("兜底捕获的身份证号期望出现 1 次，实际 %d 次: %q", got, extracted.Text)
	}
}

func TestExtractResponseContent_ReassemblesClaudeWebBlockDeltas(t *testing.T) {
	// claude.ai 网页端 Messages 风格 SSE：思考用 thinking_delta，正文用 text_delta，
	// 都按 token 连续下发。重组后正文必须连续拼接、思考用 [reasoning] 标记分开，
	// 且不得泄漏任何协议字段或消息 ID。
	body := []byte(strings.Join([]string{
		`data: {"type":"message_start","message":{"id":"msg_01ABCdef","role":"assistant","content":[]}}`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"用户问的是客户的手机"}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"号，我需要谨慎处理。"}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig_abc123=="}}`,
		`data: {"type":"content_block_stop","index":0}`,
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"客户的手机号是"}}`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"138"}}`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"12345678"}}`,
		`data: {"type":"content_block_stop","index":1}`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")

	if !strings.Contains(extracted.Text, "客户的手机号是13812345678") {
		t.Fatalf("Claude 网页正文应连续拼接，不能被换行切碎: %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "[reasoning] 用户问的是客户的手机号，我需要谨慎处理。") {
		t.Fatalf("Claude 网页思考应以 [reasoning] 标记保留并连续拼接: %q", extracted.Text)
	}
	for _, leak := range []string{"content_block_delta", "text_delta", "thinking_delta", "msg_01ABCdef", "signature", "sig_abc123"} {
		if strings.Contains(extracted.Text, leak) {
			t.Fatalf("Claude 网页正文不得泄漏协议字段/ID %q: %q", leak, extracted.Text)
		}
	}
}

func TestExtractResponseContent_ReassemblesClaudeWebToolInputJSON(t *testing.T) {
	// 工具调用入参 input_json_delta 常携带自然语言，按 token 下发；拼回回答避免敏感正文漏检。
	body := []byte(strings.Join([]string{
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01","name":"search","input":{}}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"query\":\"客户"}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"手机号\"}"}}`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
	}, "\n"))

	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "客户手机号") {
		t.Fatalf("Claude 工具入参 JSON 应被连续重组: %q", extracted.Text)
	}
	if !extracted.VisibleTextKnown || extracted.VisibleText != "" {
		t.Fatalf("纯工具调用没有客户可见模型正文: %+v", extracted)
	}
}

func TestDecodeContentEncoding_RoundTripsAllCodecs(t *testing.T) {
	plain := []byte(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"你好世界"}}`)

	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(plain); err != nil {
		t.Fatal(err)
	}
	gw.Close()
	if got := decodeContentEncoding(gz.Bytes(), "gzip"); !bytes.Equal(got, plain) {
		t.Fatalf("gzip 解压不匹配: %q", got)
	}

	var br bytes.Buffer
	bw := brotli.NewWriter(&br)
	if _, err := bw.Write(plain); err != nil {
		t.Fatal(err)
	}
	bw.Close()
	if got := decodeContentEncoding(br.Bytes(), "br"); !bytes.Equal(got, plain) {
		t.Fatalf("brotli 解压不匹配: %q", got)
	}

	zw, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	zb := zw.EncodeAll(plain, nil)
	zw.Close()
	if got := decodeContentEncoding(zb, "zstd"); !bytes.Equal(got, plain) {
		t.Fatalf("zstd 解压不匹配: %q", got)
	}

	var fl bytes.Buffer
	fw := zlib.NewWriter(&fl)
	if _, err := fw.Write(plain); err != nil {
		t.Fatal(err)
	}
	fw.Close()
	if got := decodeContentEncoding(fl.Bytes(), "deflate"); !bytes.Equal(got, plain) {
		t.Fatalf("deflate 解压不匹配: %q", got)
	}
}

func TestDecodeContentEncoding_PassthroughAndCorrupt(t *testing.T) {
	plain := []byte("普通明文 hello")
	for _, enc := range []string{"", "identity", "weird-codec"} {
		if got := decodeContentEncoding(plain, enc); !bytes.Equal(got, plain) {
			t.Fatalf("编码 %q 应原样透传: %q", enc, got)
		}
	}
	corrupt := []byte{0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad}
	if got := decodeContentEncoding(corrupt, "gzip"); !bytes.Equal(got, corrupt) {
		t.Fatalf("损坏的 gzip 应回退原始字节、不 panic: %q", got)
	}
}

func TestExtractResponseContent_DecodesBrotliClaudeStreamThenReassembles(t *testing.T) {
	// 端到端模拟正向代理：网页大模型响应几乎都带 Content-Encoding（br/gzip/zstd），
	// 代理按头解压副本后再喂给抽取，正文才能人读。
	plain := []byte(strings.Join([]string{
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"客户的手机号是"}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"13812345678"}}`,
		``,
	}, "\n"))
	var br bytes.Buffer
	bw := brotli.NewWriter(&br)
	if _, err := bw.Write(plain); err != nil {
		t.Fatal(err)
	}
	bw.Close()

	inspect := decodeContentEncoding(br.Bytes(), "br")
	extracted := extractResponseContent(inspect, "text/event-stream")
	if !strings.Contains(extracted.Text, "客户的手机号是13812345678") {
		t.Fatalf("brotli 压缩的 Claude 流应先解压再重组: %q", extracted.Text)
	}
}
