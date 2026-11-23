package handler

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestVSCodeXDecoder_UserRequestExtraction 验证 <userRequest> 标签抽取（干净路径）：
// - 只保留 userRequest 内文本，丢弃 environment_info/context 等上下文包。
// - 多轮对话多个 userRequest 都抽到。
// - 同时包含 input_image 时附件也被抓取。
func TestVSCodeXDecoder_UserRequestExtraction(t *testing.T) {
	body, err := os.ReadFile("testdata/vscodex-github-copilot-responses-with-image.req")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://api.individual.githubcopilot.com/responses", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	decoder, ok := getWebDecoder("copilot")
	if !ok {
		t.Fatal("web decoder 'copilot' not registered")
	}
	extracted, matched := decoder.DecodeRequest(req, body, "application/json")
	if !matched {
		t.Fatal("copilot decoder did not match fixture with image")
	}

	// 真问题应该在 Text 里
	if !strings.Contains(extracted.Text, "介绍一下这张图") {
		t.Errorf("userRequest 第一条未抽到，got Text=%q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "能看出是什么语言吗") {
		t.Errorf("userRequest 第二条（多轮）未抽到，got Text=%q", extracted.Text)
	}

	// 上下文噪音不应出现
	noiseKeywords := []string{"environment_info", "workspace_info", "reminderInstructions", "context"}
	for _, kw := range noiseKeywords {
		if strings.Contains(extracted.Text, kw) {
			t.Errorf("上下文噪音 %q 出现在 Text 中，got Text=%q", kw, extracted.Text)
		}
	}

	// 图片附件应被抓取
	if len(extracted.Attachments) == 0 {
		t.Fatal("input_image 未被抓取为附件")
	}
	found := false
	for _, att := range extracted.Attachments {
		if strings.Contains(att.DownloadURL, "abc123def456") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("input_image DownloadURL 未命中，attachments=%+v", extracted.Attachments)
	}
}

// TestVSCodeXDecoder_MultipleUserRequests 验证多个 <userRequest> 全抽到（含历史多轮）。
func TestVSCodeXDecoder_MultipleUserRequests(t *testing.T) {
	bodyJSON := `{"model":"gpt-5-mini","input":[
		{"role":"user","content":[{"type":"input_text","text":"<environment_info>Windows</environment_info><userRequest>第一个问题</userRequest>"}]},
		{"role":"assistant","content":[{"type":"output_text","text":"回答"}]},
		{"role":"user","content":[{"type":"input_text","text":"<reminderInstructions>do X</reminderInstructions><userRequest>第二个问题</userRequest>"}]}
	]}`
	body := []byte(bodyJSON)
	req := httptest.NewRequest(http.MethodPost, "https://api.individual.githubcopilot.com/responses", strings.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")

	decoder, ok := getWebDecoder("copilot")
	if !ok {
		t.Fatal("web decoder 'copilot' not registered")
	}
	extracted, matched := decoder.DecodeRequest(req, body, "application/json")
	if !matched {
		t.Fatal("decoder did not match")
	}
	if !strings.Contains(extracted.Text, "第一个问题") {
		t.Errorf("第一个问题未抽到，got %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "第二个问题") {
		t.Errorf("第二个问题未抽到，got %q", extracted.Text)
	}
	if strings.Contains(extracted.Text, "environment_info") || strings.Contains(extracted.Text, "reminderInstructions") {
		t.Errorf("噪音出现在 Text 中，got %q", extracted.Text)
	}
}

// TestVSCodeXDecoder_LegacyFallback 验证无 <userRequest> 无 input_image 时兜底抽所有 user text。
func TestVSCodeXDecoder_LegacyFallback(t *testing.T) {
	body, err := os.ReadFile("testdata/vscodex-github-copilot-responses-legacy.req")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://api.individual.githubcopilot.com/responses", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	decoder, ok := getWebDecoder("copilot")
	if !ok {
		t.Fatal("web decoder 'copilot' not registered")
	}
	extracted, matched := decoder.DecodeRequest(req, body, "application/json")
	if !matched {
		t.Fatal("decoder did not match legacy fixture")
	}
	if !strings.Contains(extracted.Text, "帮我解释这段代码") {
		t.Errorf("兜底路径未抽到 user text，got %q", extracted.Text)
	}
}

// TestVSCodeXDecoder_ExistingFixtureStillMatchesViaUserRequest 确认现有 fixture 走新路径
// （因为 fixture 含 <userRequest>GWTEST-R2-0621-1531-vscodex-01 用一句话介绍你自己</userRequest>）。
func TestVSCodeXDecoder_ExistingFixtureStillMatchesViaUserRequest(t *testing.T) {
	body, err := os.ReadFile("testdata/vscodex-github-copilot-responses.req")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://api.individual.githubcopilot.com/responses", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	decoder, ok := getWebDecoder("copilot")
	if !ok {
		t.Fatal("web decoder 'copilot' not registered")
	}
	extracted, matched := decoder.DecodeRequest(req, body, "application/json")
	if !matched {
		t.Fatal("decoder did not match existing fixture")
	}
	// 真问题应该在
	if !strings.Contains(extracted.Text, "GWTEST-R2-0621-1531-vscodex-01 用一句话介绍你自己") {
		t.Errorf("真问题未抽到，got Text前200字节=%q", truncate(extracted.Text, 200))
	}
	// environment_info 噪音不应出现（走干净路径）
	if strings.Contains(extracted.Text, "environment_info") {
		t.Errorf("environment_info 噪音出现了，说明没走 userRequest 干净路径")
	}
}

// TestCopilotChatCompletionsAuxSuppressed 验证 /chat/completions → summary（辅助噪音降级）。
// /responses → content（不变）。
func TestCopilotChatCompletionsAuxSuppressed(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		path       string
		wantRetain string
		wantKnown  bool
	}{
		{
			name:       "/chat/completions 辅助调用降噪",
			host:       "api.individual.githubcopilot.com",
			path:       "/chat/completions",
			wantRetain: "summary",
			wantKnown:  true,
		},
		{
			name:       "/responses 真对话不变",
			host:       "api.individual.githubcopilot.com",
			path:       "/responses",
			wantRetain: "content",
			wantKnown:  true,
		},
		{
			name:       "其他 githubcopilot 路径 /chat/completions",
			host:       "api.githubcopilot.com",
			path:       "/v1/chat/completions",
			wantRetain: "summary",
			wantKnown:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectLLMProvider(tc.host, tc.path)
			if got.Known != tc.wantKnown {
				t.Fatalf("detectLLMProvider(%q,%q) known=%v want %v", tc.host, tc.path, got.Known, tc.wantKnown)
			}
			if got.RetainLevel != tc.wantRetain {
				t.Fatalf("detectLLMProvider(%q,%q) retain=%q want %q", tc.host, tc.path, got.RetainLevel, tc.wantRetain)
			}
		})
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// makePNGBytes 生成一个合法的 1×1 PNG 图片字节切片，用于测试。
func makePNGBytes(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 255, G: 0, B: 0, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	return buf.Bytes()
}

// TestDecodeGitHubCopilotAttachmentUpload_PNG 验证 PNG 图片上传被正确捕获落盘。
func TestDecodeGitHubCopilotAttachmentUpload_PNG(t *testing.T) {
	pngBytes := makePNGBytes(t)
	req := httptest.NewRequest(http.MethodPost, "https://uploads.github.com/copilot/chat/attachments", bytes.NewReader(pngBytes))
	req.Header.Set("Content-Type", "application/octet-stream")

	extracted, matched := decodeGitHubCopilotAttachmentUpload(req, pngBytes, "application/octet-stream")
	if !matched {
		t.Fatal("expected matched=true for PNG upload, got false")
	}
	if len(extracted.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(extracted.Attachments))
	}
	att := extracted.Attachments[0]
	if att.ContentType != "image/png" {
		t.Errorf("ContentType=%q, want image/png", att.ContentType)
	}
	if att.SHA256 == "" {
		t.Error("SHA256 should not be empty")
	}
	if att.Size <= 0 {
		t.Errorf("Size=%d, want >0", att.Size)
	}
	if att.DataBase64 == "" {
		t.Error("DataBase64 should not be empty for image attachment (should be retained)")
	}
	if !strings.HasSuffix(att.FileName, ".png") {
		t.Errorf("FileName=%q, want suffix .png", att.FileName)
	}
}

// TestDecodeGitHubCopilotAttachmentUpload_NonImage 验证非图片 body 不被捕获。
func TestDecodeGitHubCopilotAttachmentUpload_NonImage(t *testing.T) {
	body := []byte("hello, this is plain text, not an image")
	req := httptest.NewRequest(http.MethodPost, "https://uploads.github.com/copilot/chat/attachments", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")

	_, matched := decodeGitHubCopilotAttachmentUpload(req, body, "application/octet-stream")
	if matched {
		t.Fatal("expected matched=false for non-image body, got true")
	}
}

// TestDecodeGitHubCopilotAttachmentUpload_WrongHost 验证非 uploads.github.com host 不匹配。
func TestDecodeGitHubCopilotAttachmentUpload_WrongHost(t *testing.T) {
	pngBytes := makePNGBytes(t)
	req := httptest.NewRequest(http.MethodPost, "https://api.individual.githubcopilot.com/copilot/chat/attachments", bytes.NewReader(pngBytes))
	req.Header.Set("Content-Type", "application/octet-stream")

	_, matched := decodeGitHubCopilotAttachmentUpload(req, pngBytes, "application/octet-stream")
	if matched {
		t.Fatal("expected matched=false for wrong host, got true")
	}
}

// TestDecodeGitHubCopilotAttachmentUpload_EmptyBody 验证空 body 不匹配。
func TestDecodeGitHubCopilotAttachmentUpload_EmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://uploads.github.com/copilot/chat/attachments", nil)
	_, matched := decodeGitHubCopilotAttachmentUpload(req, []byte{}, "application/octet-stream")
	if matched {
		t.Fatal("expected matched=false for empty body, got true")
	}
}

// TestGetWebDecoder_GithubCopilotUpload 验证 github_copilot_upload 已在注册表中。
func TestGetWebDecoder_GithubCopilotUpload(t *testing.T) {
	decoder, ok := getWebDecoder("github_copilot_upload")
	if !ok {
		t.Fatal("web decoder 'github_copilot_upload' not registered")
	}
	if decoder.Name() != "github_copilot_upload" {
		t.Errorf("Name()=%q, want github_copilot_upload", decoder.Name())
	}

	// 通过注册路径走 DecodeRequest。
	pngBytes := makePNGBytes(t)
	req := httptest.NewRequest(http.MethodPost, "https://uploads.github.com/copilot/chat/attachments", bytes.NewReader(pngBytes))
	req.Header.Set("Content-Type", "application/octet-stream")
	extracted, matched := decoder.DecodeRequest(req, pngBytes, "application/octet-stream")
	if !matched {
		t.Fatal("DecodeRequest via registered decoder: expected matched=true")
	}
	if len(extracted.Attachments) != 1 {
		t.Fatalf("expected 1 attachment via registered decoder, got %d", len(extracted.Attachments))
	}
}

// TestImageExtFromContentType 验证各 MIME 类型返回正确扩展名。
func TestImageExtFromContentType(t *testing.T) {
	cases := []struct {
		ct   string
		want string
	}{
		{"image/png", ".png"},
		{"image/jpeg", ".jpg"},
		{"image/gif", ".gif"},
		{"image/webp", ".webp"},
		{"image/bmp", ".bmp"},
		{"image/tiff", ".img"},
		{"application/octet-stream", ".img"},
	}
	for _, tc := range cases {
		got := imageExtFromContentType(tc.ct)
		if got != tc.want {
			t.Errorf("imageExtFromContentType(%q)=%q, want %q", tc.ct, got, tc.want)
		}
	}
}

// ===== Copilot 图片留证内联关联（裸 attachment id）=====

func TestVSCodeXDecoderCarriesRuntimeConversationID(t *testing.T) {
	body := []byte(`{"input":[{"role":"user","content":[{"type":"input_text","text":"<current_datetime>2026-09-03T04:51:10.219+08:00</current_datetime>\n继续\n<system_reminder><sql_tables>todos</sql_tables></system_reminder>"}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "https://api.individual.githubcopilot.com/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	extracted, matched := decodeVSCodeXWebRequest(req, body, "application/json")
	if !matched {
		t.Fatal("VS Code runtime request was not decoded")
	}
	if extracted.ConversationID != "vscode-runtime:2026-09-03T04:51:10.219+08:00" {
		t.Fatalf("conversation_id=%q", extracted.ConversationID)
	}
}

// TestBareGitHubCopilotAttachmentID 验证从 chat/attachments URL 取裸 id（最后一段），
// 非该形态 URL 返回空。两侧（上传响应 url、/responses input_image.image_url）共用此派生。
func TestBareGitHubCopilotAttachmentID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://github.com/github-copilot/chat/attachments/5cc11ece-b21b-4dac-ab25-399b1a49ca95", "5cc11ece-b21b-4dac-ab25-399b1a49ca95"},
		{"https://github.com/github-copilot/chat/attachments/5cc11ece-b21b-4dac-ab25-399b1a49ca95/", "5cc11ece-b21b-4dac-ab25-399b1a49ca95"},
		{"https://github.com/github-copilot/chat/attachments/abc?foo=bar", "abc"},
		{"https://github.com/github-copilot/chat/attachments/", ""}, // 畸形:有 marker 但无 id 段,不可误返回 "attachments"
		{"https://github.com/github-copilot/chat/attachments", ""},  // 同上,无尾斜杠
		{"https://example.com/foo.png", ""},
		{"", ""},
		{"not a url at all", ""},
	}
	for _, tc := range cases {
		if got := bareGitHubCopilotAttachmentID(tc.in); got != tc.want {
			t.Errorf("bareGitHubCopilotAttachmentID(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestVSCodeXDecoder_InputImageReferenceIDIsBareAttachmentID 验证 (b)：/responses 的 input_image
// 附件 ReferenceID 被归一成裸 attachment id（与上传响应一致，作为跨请求关联键），DownloadURL 保留原 URL。
func TestVSCodeXDecoder_InputImageReferenceIDIsBareAttachmentID(t *testing.T) {
	const attURL = "https://github.com/github-copilot/chat/attachments/5cc11ece-b21b-4dac-ab25-399b1a49ca95"
	const bareID = "5cc11ece-b21b-4dac-ab25-399b1a49ca95"
	bodyJSON := `{"model":"gpt-5-mini","input":[{"role":"user","content":[` +
		`{"type":"input_text","text":"<userRequest>这张图是什么</userRequest>"},` +
		`{"type":"input_image","image_url":"` + attURL + `"}` +
		`]}]}`
	body := []byte(bodyJSON)
	req := httptest.NewRequest(http.MethodPost, "https://api.individual.githubcopilot.com/responses", strings.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")

	decoder, ok := getWebDecoder("copilot")
	if !ok {
		t.Fatal("web decoder 'copilot' not registered")
	}
	extracted, matched := decoder.DecodeRequest(req, body, "application/json")
	if !matched {
		t.Fatal("copilot decoder did not match input_image body")
	}
	var img *ExtractedAttachment
	for i := range extracted.Attachments {
		if extracted.Attachments[i].Source == "json_image_url" {
			img = &extracted.Attachments[i]
			break
		}
	}
	if img == nil {
		t.Fatalf("input_image attachment not found, attachments=%+v", extracted.Attachments)
	}
	if img.ReferenceID != bareID {
		t.Errorf("ReferenceID=%q, want bare id %q（跨请求关联键须与上传响应一致）", img.ReferenceID, bareID)
	}
	if img.DownloadURL != attURL {
		t.Errorf("DownloadURL=%q, want 原始 url %q", img.DownloadURL, attURL)
	}
}

// TestDecodeGitHubCopilotAttachmentUploadResponse_ExtractsBareID 验证 (a)：上传响应
// {"url":".../chat/attachments/<id>"} 被解成一个无字节标记附件，携带裸 id。
func TestDecodeGitHubCopilotAttachmentUploadResponse_ExtractsBareID(t *testing.T) {
	const bareID = "5cc11ece-b21b-4dac-ab25-399b1a49ca95"
	body := []byte(`{"url":"https://github.com/github-copilot/chat/attachments/` + bareID + `"}`)
	extracted, matched := decodeGitHubCopilotAttachmentUploadResponse(body, "application/json; charset=utf-8")
	if !matched {
		t.Fatal("expected matched=true for upload response JSON")
	}
	if len(extracted.Attachments) != 1 {
		t.Fatalf("expected 1 marker attachment, got %d (%+v)", len(extracted.Attachments), extracted.Attachments)
	}
	m := extracted.Attachments[0]
	if m.Source != githubCopilotUploadRefSource {
		t.Errorf("Source=%q, want %q", m.Source, githubCopilotUploadRefSource)
	}
	if m.ReferenceID != bareID {
		t.Errorf("ReferenceID=%q, want %q", m.ReferenceID, bareID)
	}
	if m.DataBase64 != "" || m.DownloadURL != "" {
		t.Errorf("marker 不应携带字节/URL, got DataBase64=%q DownloadURL=%q", m.DataBase64, m.DownloadURL)
	}
}

// TestDecodeGitHubCopilotAttachmentUploadResponse_Rejects 验证非目标响应不匹配（不乱抓 URL）。
func TestDecodeGitHubCopilotAttachmentUploadResponse_Rejects(t *testing.T) {
	cases := []struct {
		name, ct, body string
	}{
		{"non-json", "text/html", "<html></html>"},
		{"json 非 attachments url", "application/json", `{"url":"https://example.com/foo.png"}`},
		{"empty", "application/json", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, matched := decodeGitHubCopilotAttachmentUploadResponse([]byte(tc.body), tc.ct)
			if matched {
				t.Fatalf("expected matched=false for %s", tc.name)
			}
		})
	}
}

// TestGithubCopilotUploadResponseDecoderRegistered 验证 github_copilot_upload 已挂上 decodeResponse。
func TestGithubCopilotUploadResponseDecoderRegistered(t *testing.T) {
	const bareID = "5cc11ece-b21b-4dac-ab25-399b1a49ca95"
	decoder, ok := getWebDecoder("github_copilot_upload")
	if !ok {
		t.Fatal("web decoder 'github_copilot_upload' not registered")
	}
	body := []byte(`{"url":"https://github.com/github-copilot/chat/attachments/` + bareID + `"}`)
	extracted, matched := decoder.DecodeResponse(body, "application/json")
	if !matched {
		t.Fatal("DecodeResponse via registered decoder: expected matched=true")
	}
	if len(extracted.Attachments) != 1 || extracted.Attachments[0].ReferenceID != bareID {
		t.Fatalf("registered DecodeResponse 未产出带裸 id 的标记, got %+v", extracted.Attachments)
	}
}

// TestLinkGitHubCopilotUploadReference_TiesBytesAndStripsMarker 验证关联钩子：把标记里的裸 id 贴到
// 请求字节附件的 ReferenceID，并把标记从 respContent 剥离（绝不落库）。
func TestLinkGitHubCopilotUploadReference_TiesBytesAndStripsMarker(t *testing.T) {
	const bareID = "5cc11ece-b21b-4dac-ab25-399b1a49ca95"
	reqContent := ExtractedContent{Attachments: []ExtractedAttachment{
		{Source: "upload", FieldName: "copilot/chat/attachments", FileName: "copilot_upload.png", ContentType: "image/png", DataBase64: "QQ==", Size: 1},
	}}
	respContent := ExtractedContent{Attachments: []ExtractedAttachment{
		{Source: githubCopilotUploadRefSource, ReferenceID: bareID},
	}}
	linkGitHubCopilotUploadReference("uploads.github.com:443", &reqContent, &respContent)

	if got := reqContent.Attachments[0].ReferenceID; got != bareID {
		t.Errorf("字节附件 ReferenceID=%q, want %q", got, bareID)
	}
	for _, a := range respContent.Attachments {
		if a.Source == githubCopilotUploadRefSource {
			t.Errorf("标记附件必须从 respContent 剥离, 仍存在: %+v", a)
		}
	}
}

// TestLinkGitHubCopilotUploadReference_WrongHostNoop 验证非 uploads.github.com host 完全不动。
func TestLinkGitHubCopilotUploadReference_WrongHostNoop(t *testing.T) {
	const bareID = "5cc11ece-b21b-4dac-ab25-399b1a49ca95"
	reqContent := ExtractedContent{Attachments: []ExtractedAttachment{
		{Source: "upload", FieldName: "copilot/chat/attachments"},
	}}
	respContent := ExtractedContent{Attachments: []ExtractedAttachment{
		{Source: githubCopilotUploadRefSource, ReferenceID: bareID},
	}}
	linkGitHubCopilotUploadReference("api.individual.githubcopilot.com", &reqContent, &respContent)
	if reqContent.Attachments[0].ReferenceID != "" {
		t.Errorf("非目标 host 应 no-op, ReferenceID 被设成了 %q", reqContent.Attachments[0].ReferenceID)
	}
	if len(respContent.Attachments) != 1 {
		t.Errorf("非目标 host 不应剥离标记, attachments=%+v", respContent.Attachments)
	}
}

// TestCopilotUploadInlineRelinkViaCatalog 端到端验证关联引擎：上传那次按裸 id 登记字节(有 ObjectKey)，
// /responses 那次 url_only 引用(同一裸 id)被回填 ObjectKey → 对话留证内联显示。
func TestCopilotUploadInlineRelinkViaCatalog(t *testing.T) {
	const tenant = "tenant_default"
	const provider = "github"
	const bareID = "5cc11ece-b21b-4dac-ab25-399b1a49ca95"
	catalog := newRetainedUploadCatalog(16)

	uploadMeta := []retainedAttachmentMetadata{{
		Source: "upload", Stage: "request", FieldName: "copilot/chat/attachments",
		FileName: "copilot_upload.jpg", ContentType: "image/jpeg",
		ReferenceID: bareID, ObjectKey: strings.Join([]string{"ret", "obj", "abc123"}, "/"), RetentionStatus: "externalized", Size: 1234,
	}}
	_ = resolveRetainedUploadMetadata(catalog, tenant, provider, uploadMeta)

	refMeta := []retainedAttachmentMetadata{{
		Source: "json_image_url", Stage: "request", FieldName: "input_image.image_url",
		ReferenceID: bareID, RetentionStatus: "url_only",
		DownloadURL: "https://github.com/github-copilot/chat/attachments/" + bareID,
	}}
	out := resolveRetainedUploadMetadata(catalog, tenant, provider, refMeta)

	if len(out) != 1 {
		t.Fatalf("expected 1 item, got %d", len(out))
	}
	if out[0].ObjectKey != "ret/obj/abc123" {
		t.Errorf("input_image 未从 catalog 回填 ObjectKey, got ObjectKey=%q status=%q（内联失败）", out[0].ObjectKey, out[0].RetentionStatus)
	}
	if out[0].RetentionStatus != "externalized" {
		t.Errorf("回填后 RetentionStatus=%q, want externalized", out[0].RetentionStatus)
	}
}

func TestVSCodeXPlainQuestionWithImage(t *testing.T) {
	body := []byte(`{"input":[{"role":"user","content":[{"type":"input_text","text":"分析下这个图片"},{"type":"input_image","image_url":"https://example.invalid/test.png"}]}]}`)
	req := httptest.NewRequest("POST", "https://api.individual.githubcopilot.com/responses", bytes.NewReader(body))
	got, ok := decodeVSCodeXWebRequest(req, body, "application/json")
	if !ok || !strings.Contains(got.Text, "分析下这个图片") || len(got.Attachments) != 1 {
		t.Fatalf("text and image must survive together: matched=%v text=%q attachments=%d", ok, got.Text, len(got.Attachments))
	}
}

func TestCopilotHistoryRemainsOneConversation(t *testing.T) {
	key := func(extra string) string {
		body := []byte(`{"input":[{"role":"user","content":[{"type":"input_text","text":"<userRequest>检查项目</userRequest>"}]}` + extra + `]}`)
		req := httptest.NewRequest("POST", "https://api.individual.githubcopilot.com/responses", bytes.NewReader(body))
		got, _ := decodeVSCodeXWebRequest(req, body, "application/json")
		enrichAPIConversationKey("tenant", "github-copilot", &got, req)
		return got.ConversationID
	}
	first := key("")
	later := key(`,{"role":"assistant","content":[{"type":"output_text","text":"已检查"}]},{"role":"user","content":[{"type":"input_text","text":"<userRequest>继续修复</userRequest>"}]}`)
	if first == "" || first != later {
		t.Fatalf("conversation split: first=%q later=%q", first, later)
	}
}
