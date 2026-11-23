package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestVendorDirectedWebRequestDecodersExtractFixturePrompts(t *testing.T) {
	tests := []struct {
		name        string
		fixture     string
		url         string
		decoderName string
		contentType string
		want        string
	}{
		{
			name:        "doubao content block text",
			fixture:     "testdata/doubao-web-chat-completion.req",
			url:         "https://www.doubao.com/chat/completion",
			decoderName: "doubao_web",
			want:        "GWTEST-R2-0621-1531-豆包-01 用一句话介绍你自己",
		},
		{
			name:        "deepseek top level prompt",
			fixture:     "testdata/deepseek-web-chat-completion.req",
			url:         "https://chat.deepseek.com/api/v0/chat/completion",
			decoderName: "deepseek_web",
			want:        "GWTEST-R2-0621-1531-DeepSeek-01 用一句话介绍你自己",
		},
		{
			name:        "kimi connect json message block text",
			fixture:     "testdata/kimi-web-chat-connect-json.req",
			url:         "https://www.kimi.com/apiv2/kimi.gateway.chat.v1.ChatService/Chat",
			decoderName: "kimi_web",
			contentType: "application/connect+json",
			want:        "什么东西",
		},
		{
			name:        "codebuddy Parameters Content",
			fixture:     "testdata/codebuddy-web-api-stream.req",
			url:         "https://ride-3-live-webapp.azurewebsites.net/api/stream",
			decoderName: "codebuddy_web",
			want:        "GWTEST-R2-0621-1531-CodeBuddy-01 用一句话介绍你自己",
		},
		{
			name:        "vscodex responses input content text",
			fixture:     "testdata/vscodex-github-copilot-responses.req",
			url:         "https://api.individual.githubcopilot.com/responses",
			decoderName: "copilot",
			want:        "GWTEST-R2-0621-1531-vscodex-01 用一句话介绍你自己",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := os.ReadFile(tt.fixture)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, tt.url, strings.NewReader(string(body)))
			contentType := tt.contentType
			if contentType == "" {
				contentType = "application/json"
			}
			req.Header.Set("Content-Type", contentType)

			decoder, ok := getWebDecoder(tt.decoderName)
			if !ok {
				t.Fatalf("web decoder %q not registered", tt.decoderName)
			}
			extracted, matched := decoder.DecodeRequest(req, body, contentType)
			if !matched {
				t.Fatalf("web decoder %q did not match fixture", tt.decoderName)
			}
			if !strings.Contains(extracted.Text, tt.want) {
				t.Fatalf("extracted prompt missing %q:\n%s", tt.want, extracted.Text)
			}
		})
	}
}

func TestDeepSeekWebRequestDecoderKeepsUserUploadedImage(t *testing.T) {
	body, err := os.ReadFile("testdata/deepseek-web-chat-completion-with-image.req")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://chat.deepseek.com/api/v0/chat/completion", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	decoder, ok := getWebDecoder("deepseek_web")
	if !ok {
		t.Fatal("web decoder deepseek_web is not registered")
	}
	extracted, matched := decoder.DecodeRequest(req, body, "application/json")
	if !matched {
		t.Fatal("deepseek_web request decoder did not match fixture")
	}
	// 文本侧：提问必须仍被还原。
	if !strings.Contains(extracted.Text, "GWTEST-R2-0621-1531-DeepSeek-02 帮我看看这张图里写了什么") {
		t.Fatalf("extracted prompt missing user question:\n%s", extracted.Text)
	}
	// 附件侧：用户随提问上传的图片必须救回（旧实现只回 prompt、丢附件）。
	if len(extracted.Attachments) == 0 {
		t.Fatal("deepseek_web request decoder dropped user-uploaded image attachment")
	}
	// 去重侧：同一张图同时来自 ref_file_ids（裸 file-id 空壳）和 biz_data.files（带 signed_path
	// 能抓字节），ReferenceID 相同必须去重成 1 条，且保留带 DownloadURL（能抓真字节）的那条，
	// 不能留空壳。
	if len(extracted.Attachments) != 1 {
		t.Fatalf("expected exactly 1 deduped attachment, got %d: %+v", len(extracted.Attachments), extracted.Attachments)
	}
	att := extracted.Attachments[0]
	if att.FileName != "季度财报截图.png" {
		t.Fatalf("user image 季度财报截图.png not found in attachment: %+v", att)
	}
	if att.DownloadURL == "" {
		t.Fatalf("deduped attachment lost its byte-fetchable DownloadURL (kept the empty shell): %+v", att)
	}

	// 会话/turn 键：必须从请求体 lift（响应流不带，本就只能靠请求侧）。
	if extracted.ConversationID != "5f9e95ee-7747-454b-b84f-4e1576be320b" {
		t.Fatalf("conversation_id not lifted from chat_session_id, got %q", extracted.ConversationID)
	}
	// 该夹具 parent_message_id 为 null → section_id 为空串（写侧 NULLIF 落 NULL）。
	if extracted.SectionID != "" {
		t.Fatalf("section_id should be empty for null parent_message_id, got %q", extracted.SectionID)
	}

	// 防泄露（负向回归护栏）：正文只能等于 prompt，绝不能把 signed_path 短链、其 state 签名 token、
	// 或裸 file-id 塞进给人看的留存文本。这是本次改动最大的留证安全点。
	const (
		stateToken  = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkc191cGxvYWQiLCJleHAiOjI1NTUyMDAwMDB9.QkFTRTY0X1NJR05BVFVSRV9UT0tFTl9QTEFDRUhPTERFUg"
		signedPath  = "/file?file_id="
		bareFileID  = "file-7c9d2a1e-3b4f-4a6c-8e21-0f5b6d8a9c33"
	)
	for _, leaked := range []struct {
		label string
		token string
	}{
		{"signed_path state 签名 token", stateToken},
		{"signed_path 短链", signedPath},
		{"裸 file-id", bareFileID},
	} {
		if strings.Contains(extracted.Text, leaked.token) {
			t.Fatalf("留证正文泄露了%s：\n%s", leaked.label, extracted.Text)
		}
	}
}

func TestCatalogDirectedWebRequestDecodersForFixtureHosts(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		path        string
		wantRequest string
	}{
		{
			name:        "doubao web chat",
			host:        "www.doubao.com",
			path:        "/chat/completion",
			wantRequest: "doubao_web",
		},
		{
			name:        "deepseek web chat",
			host:        "chat.deepseek.com",
			path:        "/api/v0/chat/completion",
			wantRequest: "deepseek_web",
		},
		{
			name:        "kimi connect json chat",
			host:        "www.kimi.com",
			path:        "/apiv2/kimi.gateway.chat.v1.ChatService/Chat",
			wantRequest: "kimi_web",
		},
		{
			name:        "codebuddy web stream",
			host:        "ride-3-live-webapp.azurewebsites.net",
			path:        "/api/stream",
			wantRequest: "codebuddy_web",
		},
		{
			name:        "vscodex github copilot responses",
			host:        "api.individual.githubcopilot.com",
			path:        "/responses",
			wantRequest: "copilot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestDecoder, _ := detectLLMDecoders(tt.host, tt.path)
			if requestDecoder != tt.wantRequest {
				t.Fatalf("detectLLMDecoders(%q, %q) request = %q, want %q", tt.host, tt.path, requestDecoder, tt.wantRequest)
			}
			if _, ok := getWebDecoder(requestDecoder); !ok {
				t.Fatalf("catalog request decoder %q is not registered", requestDecoder)
			}
		})
	}
}

func TestCodeBuddyWebResponseDecoderExtractsLastAIMessageFromNDJSON(t *testing.T) {
	body, err := os.ReadFile("testdata/codebuddy-web-api-stream.resp.ndjson")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	decoder, ok := getWebDecoder("codebuddy_web")
	if !ok {
		t.Fatal("web decoder codebuddy_web is not registered")
	}
	extracted, matched := decoder.DecodeResponse(body, "application/x-ndjson")
	if !matched {
		t.Fatal("codebuddy_web response decoder did not match NDJSON fixture")
	}
	if extracted.Text != "最终回答：中文已还原，银行卡号 6222020202020202020" {
		t.Fatalf("unexpected decoded text: %q", extracted.Text)
	}
	if strings.Contains(extracted.Text, `\u`) {
		t.Fatalf("decoded text should not contain JSON unicode escapes: %q", extracted.Text)
	}
}

func TestCatalogDirectedCodeBuddyStreamUsesCodeBuddyResponseDecoder(t *testing.T) {
	requestDecoder, responseDecoder := detectLLMDecoders("ride-3-live-webapp.azurewebsites.net", "/api/stream")
	if requestDecoder != "codebuddy_web" {
		t.Fatalf("request decoder = %q, want codebuddy_web", requestDecoder)
	}
	if responseDecoder != "codebuddy_web" {
		t.Fatalf("response decoder = %q, want codebuddy_web", responseDecoder)
	}
}

func TestDeepSeekWebRequestLiftsConversationAndSectionKeys(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantConv string
		wantSec  string
	}{
		{
			name:     "first turn null parent",
			body:     `{"chat_session_id":"bf2aa67a-0349-4f83-8bf3-468d52967de1","parent_message_id":null,"prompt":"DSKEY first turn","ref_file_ids":[]}`,
			wantConv: "bf2aa67a-0349-4f83-8bf3-468d52967de1",
			wantSec:  "",
		},
		{
			name:     "second turn numeric parent",
			body:     `{"chat_session_id":"bf2aa67a-0349-4f83-8bf3-468d52967de1","parent_message_id":2,"prompt":"DSKEY second turn","ref_file_ids":["file-x"]}`,
			wantConv: "bf2aa67a-0349-4f83-8bf3-468d52967de1",
			wantSec:  "2",
		},
		{
			name:     "string parent id",
			body:     `{"chat_session_id":"bf2aa67a-0349-4f83-8bf3-468d52967de1","parent_message_id":"42","prompt":"DSKEY string parent","ref_file_ids":[]}`,
			wantConv: "bf2aa67a-0349-4f83-8bf3-468d52967de1",
			wantSec:  "42",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			req := httptest.NewRequest(http.MethodPost, "https://chat.deepseek.com/api/v0/chat/completion", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			decoder, ok := getWebDecoder("deepseek_web")
			if !ok {
				t.Fatal("web decoder deepseek_web is not registered")
			}
			extracted, matched := decoder.DecodeRequest(req, body, "application/json")
			if !matched {
				t.Fatal("deepseek_web request decoder did not match body")
			}
			if extracted.ConversationID != tc.wantConv {
				t.Fatalf("conversation_id = %q, want %q", extracted.ConversationID, tc.wantConv)
			}
			if extracted.SectionID != tc.wantSec {
				t.Fatalf("section_id = %q, want %q", extracted.SectionID, tc.wantSec)
			}
		})
	}
}
