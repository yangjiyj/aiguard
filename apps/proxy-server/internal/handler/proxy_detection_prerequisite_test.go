package handler

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

type proxyDetectionFailedBody struct{}

func (proxyDetectionFailedBody) Read([]byte) (int, error) {
	return 0, errors.New("request body read failed")
}

// 2.9.22 审查第三轮第 5 项改动：附件字节送检失败（大附件对象化上传失败）原先跟“检测服务不可用即拦”
// （PROXY_DETECTION_FAIL_MODE）走；现在只看控制台 upload_inspection_failure_action，缺省转发并告警，
// 选 block 时在防护模式下拦，与网关 /v1/files、门户上传一致。请求体读不出仍按检测失败策略。
// 用例因此给附件分支加上传处置维度，断言随之改为看上传处置而不是检测失败模式。
func TestProxyDetectionFailurePolicyIncludesUnreadableBodyAndUnavailableObjects(t *testing.T) {
	for _, objects := range []bool{false, true} {
		uploadActions := []string{""}
		if objects {
			uploadActions = []string{"", "block"}
		}
		for _, uploadAction := range uploadActions {
			for _, auditOnly := range []bool{false, true} {
				for _, mode := range []string{"open", "closed"} {
					t.Run("objects="+strconv.FormatBool(objects)+"/upload="+uploadAction+"/record="+strconv.FormatBool(auditOnly)+"/mode="+mode, func(t *testing.T) {
						t.Setenv("SECURITY_AUDIT_ONLY", strconv.FormatBool(auditOnly))
						t.Setenv("PROXY_DETECTION_FAIL_MODE", mode)
						t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
						engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInsufficientStorage) }))
						defer engine.Close()
						request := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", io.NopCloser(proxyDetectionFailedBody{}))
						request.Header.Set("Content-Type", "application/json")
						if objects {
							body := "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"large.docx\"\r\nContent-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\n" + string(bytes.Repeat([]byte("x"), objectIDThreshold+1)) + "\r\n--b--\r\n"
							request = httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", strings.NewReader(body))
							request.Header.Set("Content-Type", "multipart/form-data; boundary=b")
						}
						client := NewSecurityClient(engine.URL)
						if uploadAction != "" {
							client.WithInspectionScope(runtimeOptionScope{fixedInspectionPolicy: fullInspectionPolicy(), options: map[string]string{"upload_inspection_failure_action": uploadAction}})
						}
						action, findings, meta := client.CheckInput(request.Context(), "tenant", "prerequisite-failure", request)
						want := "audit"
						failClosed := mode == "closed"
						if objects {
							failClosed = uploadAction == "block"
						}
						if failClosed && !auditOnly {
							want = "block"
						}
						if action != want || meta == nil || meta.SemanticStatus != "incomplete" {
							t.Fatalf("inspection prerequisites must consume failure policy: action=%s want=%s meta=%+v findings=%v", action, want, meta, findings)
						}
						if action == "block" {
							if status, code := inputBlockResponse(meta, findings); status != http.StatusServiceUnavailable || code != "inspection_unavailable" {
								t.Fatalf("prerequisite gap must return503 without fabricating rule403: status=%d code=%s findings=%v", status, code, findings)
							}
						}
					})
				}
			}
		}
	}
}
