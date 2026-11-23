package handler

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestProxyDetectionFailurePolicyPreservesGapAcrossInputAndOutput(t *testing.T) {
	for _, input := range []bool{true, false} {
		for _, auditOnly := range []bool{false, true} {
			for _, mode := range []string{"", "open", "closed", "invalid"} {
				t.Run("input="+strconv.FormatBool(input)+"/record="+strconv.FormatBool(auditOnly)+"/mode="+mode, func(t *testing.T) {
					t.Setenv("SECURITY_AUDIT_ONLY", strconv.FormatBool(auditOnly))
					t.Setenv("PROXY_DETECTION_FAIL_MODE", mode)
					t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", "true")
					engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						http.Error(w, "detector unavailable", http.StatusServiceUnavailable)
					}))
					defer engine.Close()
					client := NewSecurityClient(engine.URL)
					var action string
					var findings []map[string]interface{}
					var meta *FingerprintScanMeta
					if input {
						request := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"hello"}]}`))
						request.Header.Set("Content-Type", "application/json")
						action, findings, meta = client.CheckInput(context.Background(), "tenant", "detection-failure", request)
					} else {
						action, findings, meta = client.CheckOutputDetailed(context.Background(), "tenant", detectLLMProvider("api.openai.com", "/v1/chat/completions"), []byte(`{"choices":[{"message":{"role":"assistant","content":"hello"}}]}`), "application/json")
					}
					want := "audit"
					if (mode == "closed" || mode == "invalid") && !auditOnly {
						want = "block"
					}
					if action != want || meta == nil || meta.SemanticStatus != "incomplete" || len(findings) != 0 {
						t.Fatalf("ordinary detection failure must consume switch and retain gap: action=%s want=%s meta=%+v findings=%v", action, want, meta, findings)
					}
					if action == "block" {
						status, code := inputBlockResponse(meta, findings)
						if status != http.StatusServiceUnavailable || code != "inspection_unavailable" {
							t.Fatalf("ordinary failure must return503: status=%d code=%s", status, code)
						}
					}
				})
			}
		}
	}
}

func TestProxyDetectionFailureClosedPlainHTTPRejectsBeforeForwarding(t *testing.T) {
	for _, auditOnly := range []bool{false, true} {
		t.Run(strconv.FormatBool(auditOnly), func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", strconv.FormatBool(auditOnly))
			t.Setenv("PROXY_DETECTION_FAIL_MODE", "closed")
			t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
			engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "detector unavailable", http.StatusServiceUnavailable)
			}))
			defer engine.Close()
			calls := 0
			h := NewProxyHandler(successfulEmptyWhitelistChecker(), nil, NewSecurityClient(engine.URL), NewAuditWriter(nil), nil)
			h.transport = fileDLPTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("forwarded")), Request: r}, nil
			})
			request := httptest.NewRequest(http.MethodPost, "http://files.example.test/upload/report.pdf", strings.NewReader("%PDF-1.4\nsafe text"))
			request.Header.Set("Content-Type", "application/pdf")
			response := httptest.NewRecorder()
			h.handleHTTP(response, request)
			wantStatus, wantCalls := http.StatusServiceUnavailable, 0
			if auditOnly {
				wantStatus, wantCalls = http.StatusOK, 1
			}
			if response.Code != wantStatus || calls != wantCalls {
				t.Fatalf("ordinary fail-closed must govern plaintext: status=%d want=%d upstream=%d want=%d body=%s", response.Code, wantStatus, calls, wantCalls, response.Body.String())
			}
		})
	}
}
