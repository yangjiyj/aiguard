package handler

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

type proxyDurableFailedBody struct{}

func (proxyDurableFailedBody) Read([]byte) (int, error) {
	return 0, errors.New("request body read failed")
}

func TestProxyDetectionFailureDurablePrerequisites(t *testing.T) {
	for _, source := range []string{"body", "encoding", "json"} {
		for _, auditOnly := range []bool{false, true} {
			for _, mode := range []string{"open", "closed"} {
				t.Run(source+"/record="+strconv.FormatBool(auditOnly)+"/mode="+mode, func(t *testing.T) {
					t.Setenv("SECURITY_AUDIT_ONLY", strconv.FormatBool(auditOnly))
					t.Setenv("PROXY_DETECTION_FAIL_MODE", mode)
					client := NewSecurityClient("http://127.0.0.1:1")
					client.inspectionQueue = &InspectionQueue{slots: make(chan struct{}, 1)}
					request := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", strings.NewReader("invalid payload"))
					request.Header.Set("Content-Type", "application/json")
					reason := "inspection_invalid_json"
					if source == "body" {
						request.Body, reason = io.NopCloser(proxyDurableFailedBody{}), "inspection_body_read_failed"
					} else if source == "encoding" {
						request.Header.Set("Content-Encoding", "gzip")
						reason = "inspection_decode_failed"
					}
					action, findings, meta := client.CheckInput(request.Context(), "tenant", "durable-prerequisite", request)
					want := "audit"
					if mode == "closed" && !auditOnly {
						want = "block"
					}
					if action != want || meta == nil || meta.SemanticStatus != "incomplete" || meta.SemanticReason != reason || len(findings) != 0 {
						t.Fatalf("durable prerequisite must consume policy and retain exact reason: action=%s want=%s meta=%+v reason=%s findings=%v", action, want, meta, reason, findings)
					}
					if action == "block" {
						if status, code := inputBlockResponse(meta, findings); status != http.StatusServiceUnavailable || code != "inspection_unavailable" {
							t.Fatalf("durable prerequisite must reject503: status=%d code=%s", status, code)
						}
					}
				})
			}
		}
	}
}
