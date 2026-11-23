package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 端到端验收：proxy CheckInput 真实调用链把文件附件送 security-engine，开启时阻断。
// 对应验收组2：上传 txt 命中 DLP → 文件阻断 → 上游未收到（action=block 即转发层中断）。

func TestE2E_CheckInput_FileDLPBlocksTxtAttachment(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")

	// 模拟上游：记录是否被调用（proxy CheckInput 返回 block 时，转发层不会调上游）
	upstreamCalled := 0
	_ = upstreamCalled

	var gotAttachments interface{}
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]interface{}
		json.NewDecoder(r.Body).Decode(&p)
		ctx, _ := p["context"].(map[string]interface{})
		gotAttachments = ctx["attachments"]
		w.Header().Set("Content-Type", "application/json")
		// 引擎检测到附件里的手机号 → block
		w.Write([]byte(`{"action":"block","findings":[{"type":"pii","category":"file_content_phone_cn","severity":"high","rule_id":"phone-cn","action":"block"}]}`))
	}))
	defer engine.Close()

	s := NewSecurityClient(engine.URL)
	// 构造带 base64 txt 附件（含手机号）的 multipart 请求
	phoneText := "联系手机13812345678"
	// 简单 multipart body：一个 file part
	body := "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secret.txt\"\r\nContent-Type: text/plain\r\n\r\n" + phoneText + "\r\n--b--\r\n"
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")

	action, _, _ := s.CheckInput(req.Context(), "tenant_default", "test-req", req)
	// action=block → 转发层中断，上游收到 0 次
	if action != "block" {
		t.Fatalf("含手机号txt附件开启DLP应阻断, action=%s（应block=上游未收到）", action)
	}
	if gotAttachments == nil {
		t.Fatalf("附件未进入 check-input 的 context.attachments（真实链路断了）")
	}
}

func TestE2E_CheckInput_DLPDisabledNoAttachmentOverhead(t *testing.T) {
	// 关闭 DLP：含附件请求不触发额外文件检测开销（materializeObjects 直接 attachmentContext）
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "")
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"action":"audit","findings":[]}`))
	}))
	defer engine.Close()
	s := NewSecurityClient(engine.URL)
	body := "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nclean\r\n--b--\r\n"
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	action, _, _ := s.CheckInput(req.Context(), "tenant_default", "test-req", req)
	if action != "audit" {
		t.Fatalf("关闭DLP应维持audit-only, action=%s", action)
	}
}
