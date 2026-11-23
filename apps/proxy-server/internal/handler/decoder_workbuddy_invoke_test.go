package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWorkBuddyInvokeAttachmentsRequest_TelemetryClaimedButEmpty 验证遥测/元数据请求(无附件)→
// **认领(matched=true)但空内容**(无文本无附件)。关键:必须认领以短路回退链——否则回退到老贪婪
// workbuddy_web(decodeWorkBuddyInvokeRequest)会把 HTTP 头(User-Agent/Accept-Encoding)抽成 prompt,
// 噪音复发(尤其双斜杠 //api/invoke)。空内容在 audit 侧不产 content 行 → 噪音消失。
func TestWorkBuddyInvokeAttachmentsRequest_TelemetryClaimedButEmpty(t *testing.T) {
	// InsightsManager.LogInvocation 遥测请求——含 HTTP 头噪音文本,无附件
	body := []byte(`{"ManagerName":"InsightsManager","MethodName":"LogInvocation","Parameters":[{"RequestHeaders":{"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36","Accept-Encoding":"gzip, deflate, br, zstd","Accept":"*/*","Content-Type":"application/json"}}]}`)
	req := httptest.NewRequest(http.MethodPost, "https://ride-3-live-webapp.azurewebsites.net/api/invoke", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	extracted, matched := decodeWorkBuddyInvokeAttachmentsRequest(req, body, "application/json")
	if !matched {
		t.Fatal("遥测调用必须认领(matched=true)以短路回退,否则回退到老贪婪解码器抽 HTTP 头噪音")
	}
	// 认领但空内容:无文本(HTTP 头噪音被丢弃,绝未被当 prompt 抽出)+ 无附件
	if extracted.Text != "" {
		t.Fatalf("遥测调用 Text 必须为空(证明 HTTP 头未被抽成 prompt),实际: %q", extracted.Text)
	}
	if len(extracted.Attachments) != 0 {
		t.Fatalf("遥测调用无附件,实际抽到 %d 条: %+v", len(extracted.Attachments), extracted.Attachments)
	}
}

// TestWorkBuddyInvokeAttachmentsRequest_MetadataClaimedButEmpty 验证 UserManager/元数据请求(无附件)→ 认领但空内容
func TestWorkBuddyInvokeAttachmentsRequest_MetadataClaimedButEmpty(t *testing.T) {
	body := []byte(`{"ManagerName":"UserManager","MethodName":"GetCurrentUser","Parameters":[]}`)
	req := httptest.NewRequest(http.MethodPost, "https://ride-3-live-webapp.azurewebsites.net/api/invoke", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	extracted, matched := decodeWorkBuddyInvokeAttachmentsRequest(req, body, "application/json")
	if !matched {
		t.Fatal("元数据调用必须认领(matched=true)以短路回退")
	}
	if extracted.Text != "" {
		t.Fatalf("元数据调用 Text 必须为空,实际: %q", extracted.Text)
	}
	if len(extracted.Attachments) != 0 {
		t.Fatalf("元数据调用无附件,实际抽到 %d 条", len(extracted.Attachments))
	}
}

// TestWorkBuddyInvokeAttachmentsResponse_TelemetryClaimedButEmpty 验证遥测响应(无附件)→ 认领但空内容
func TestWorkBuddyInvokeAttachmentsResponse_TelemetryClaimedButEmpty(t *testing.T) {
	body := []byte(`{"Success":true,"Message":"Invocation logged"}`)
	extracted, matched := decodeWorkBuddyInvokeAttachmentsResponse(body, "application/json")
	if !matched {
		t.Fatal("遥测响应必须认领(matched=true)以短路回退(否则 sniff/extractHTTPContent 贪婪抽 JSON 文本)")
	}
	if extracted.Text != "" {
		t.Fatalf("遥测响应 Text 必须为空(证明 'Invocation logged' 等未被抽出),实际: %q", extracted.Text)
	}
	if len(extracted.Attachments) != 0 {
		t.Fatalf("遥测响应无附件,实际抽到 %d 条", len(extracted.Attachments))
	}
}

// TestWorkBuddyInvokeAttachmentsResponse_MetadataVersionClaimedButEmpty 验证版本元数据响应(无附件)→ 认领但空内容
func TestWorkBuddyInvokeAttachmentsResponse_MetadataVersionClaimedButEmpty(t *testing.T) {
	body := []byte(`{"Version":28,"Features":["chat","stream"],"BuildId":"20250101"}`)
	extracted, matched := decodeWorkBuddyInvokeAttachmentsResponse(body, "application/json")
	if !matched {
		t.Fatal("版本元数据响应必须认领(matched=true)以短路回退")
	}
	if extracted.Text != "" {
		t.Fatalf("版本元数据响应 Text 必须为空,实际: %q", extracted.Text)
	}
	if len(extracted.Attachments) != 0 {
		t.Fatalf("版本元数据响应无附件,实际抽到 %d 条", len(extracted.Attachments))
	}
}

// TestWorkBuddyInvokeAttachmentsResponse_ImageAttachmentMatches 验证响应侧图片附件被抽取
// 真实场景: file_metadata stage=response, field_name=Messages.Attachments, source=json_image_url
func TestWorkBuddyInvokeAttachmentsResponse_ImageAttachmentMatches(t *testing.T) {
	// Messages.Attachments 路径 → hasImagePathContext(path) 不会命中(path不含image词),
	// 但对象内包含 image/jpeg ContentType + 图片 URL → jsonObjectHasImageURLContext 会识别
	body := []byte(`{"Messages":[{"Role":"user","Attachments":[{"FileName":"x_image.jpg","Url":"https://example.blob.core.windows.net/uploads/x_image.jpg","ContentType":"image/jpeg","Size":204800}]}]}`)

	extracted, matched := decodeWorkBuddyInvokeAttachmentsResponse(body, "application/json")
	if !matched {
		t.Fatal("含图片附件的响应应产 content (matched=true)")
	}
	if len(extracted.Attachments) == 0 {
		t.Fatal("响应侧图片附件未被抽取")
	}
	// 文本必须为空(只抽附件,丢文本)
	if extracted.Text != "" {
		t.Fatalf("只抽附件模式下 Text 应为空,实际: %q", extracted.Text)
	}
	// 验证附件存在
	found := false
	for _, att := range extracted.Attachments {
		if strings.Contains(att.FileName, "image") || strings.Contains(strings.ToLower(att.ContentType), "image") || strings.Contains(att.DownloadURL, "image") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("附件列表中未找到图片附件: %+v", extracted.Attachments)
	}
}

// TestWorkBuddyInvokeAttachmentsRequest_WithAttachmentMatches 验证请求侧带附件时抽取附件、无文本
func TestWorkBuddyInvokeAttachmentsRequest_WithAttachmentMatches(t *testing.T) {
	body := []byte(`{"ManagerName":"FileManager","MethodName":"UploadFile","Parameters":[{"Files":[{"FileName":"report.jpg","Url":"https://example.blob.core.windows.net/uploads/report.jpg","ContentType":"image/jpeg","Size":102400}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "https://ride-3-live-webapp.azurewebsites.net/api/invoke", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	extracted, matched := decodeWorkBuddyInvokeAttachmentsRequest(req, body, "application/json")
	if !matched {
		t.Fatal("含附件的 invoke 请求应产 content")
	}
	if len(extracted.Attachments) == 0 {
		t.Fatal("请求侧图片附件未被抽取")
	}
	if extracted.Text != "" {
		t.Fatalf("只抽附件模式下 Text 应为空,实际: %q", extracted.Text)
	}
}

// TestWorkBuddyInvokeAttachmentsRequest_WrongHost 验证非 ride-3 host 不匹配
func TestWorkBuddyInvokeAttachmentsRequest_WrongHost(t *testing.T) {
	body := []byte(`{"ManagerName":"InsightsManager","MethodName":"LogInvocation","Parameters":[]}`)
	req := httptest.NewRequest(http.MethodPost, "https://copilot.tencent.com/api/invoke", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	_, matched := decodeWorkBuddyInvokeAttachmentsRequest(req, body, "application/json")
	if matched {
		t.Fatal("非 ride-3 host 不应匹配 workbuddy_invoke 请求解码器")
	}
}

// TestGetWebDecoderWorkBuddyInvokeIsRegistered 通过注册路径验证 workbuddy_invoke decoder 可用
func TestGetWebDecoderWorkBuddyInvokeIsRegistered(t *testing.T) {
	decoder, ok := getWebDecoder("workbuddy_invoke")
	if !ok {
		t.Fatal("workbuddy_invoke decoder 未注册到 webDecoders")
	}
	if decoder.Name() != "workbuddy_invoke" {
		t.Fatalf("decoder.Name() = %q, want workbuddy_invoke", decoder.Name())
	}

	// 通过注册路径测试:遥测请求认领但空内容(matched=true 且 Text 空 + 无附件)
	body := []byte(`{"ManagerName":"InsightsManager","MethodName":"LogInvocation","Parameters":[{"RequestHeaders":{"User-Agent":"Mozilla/5.0","Accept-Encoding":"gzip, deflate, br, zstd"}}]}`)
	req := httptest.NewRequest(http.MethodPost, "https://ride-3-live-webapp.azurewebsites.net/api/invoke", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	extracted, matched := decoder.DecodeRequest(req, body, "application/json")
	if !matched {
		t.Fatal("通过注册路径: 遥测调用必须认领(matched=true)以短路回退")
	}
	if extracted.Text != "" || len(extracted.Attachments) != 0 {
		t.Fatalf("通过注册路径: 遥测调用应空内容,实际 Text=%q Attachments=%d", extracted.Text, len(extracted.Attachments))
	}

	// 通过注册路径测试:遥测响应认领但空内容
	respBody := []byte(`{"Success":true,"Message":"Invocation logged"}`)
	respExtracted, matched := decoder.DecodeResponse(respBody, "application/json")
	if !matched {
		t.Fatal("通过注册路径: 遥测响应必须认领(matched=true)以短路回退")
	}
	if respExtracted.Text != "" || len(respExtracted.Attachments) != 0 {
		t.Fatalf("通过注册路径: 遥测响应应空内容,实际 Text=%q Attachments=%d", respExtracted.Text, len(respExtracted.Attachments))
	}
}

// TestWorkBuddyInvokeAttachmentsResponse_NonJSONNoMatch 验证非 JSON 响应仍返回 false(让正常流量走回退)
func TestWorkBuddyInvokeAttachmentsResponse_NonJSONNoMatch(t *testing.T) {
	body := []byte(`plain text not json`)
	_, matched := decodeWorkBuddyInvokeAttachmentsResponse(body, "text/plain")
	if matched {
		t.Fatal("非 JSON 响应不应被 workbuddy_invoke 认领")
	}
}

// TestCatalogWorkBuddyInvokeUsesWorkBuddyInvokeDecoder 验证 catalog 路由到正确 decoder
func TestCatalogWorkBuddyInvokeUsesWorkBuddyInvokeDecoder(t *testing.T) {
	requestDecoder, responseDecoder := detectLLMDecoders("ride-3-live-webapp.azurewebsites.net", "/api/invoke")
	if requestDecoder != "workbuddy_invoke" {
		t.Fatalf("detectLLMDecoders request = %q, want workbuddy_invoke", requestDecoder)
	}
	if responseDecoder != "workbuddy_invoke" {
		t.Fatalf("detectLLMDecoders response = %q, want workbuddy_invoke", responseDecoder)
	}
}

// TestCatalogWorkBuddyStreamUnchanged 验证 /api/stream 路由不受影响
func TestCatalogWorkBuddyStreamUnchanged(t *testing.T) {
	requestDecoder, responseDecoder := detectLLMDecoders("ride-3-live-webapp.azurewebsites.net", "/api/stream")
	if requestDecoder != "codebuddy_web" {
		t.Fatalf("/api/stream request decoder = %q, want codebuddy_web", requestDecoder)
	}
	if responseDecoder != "codebuddy_web" {
		t.Fatalf("/api/stream response decoder = %q, want codebuddy_web", responseDecoder)
	}
}
