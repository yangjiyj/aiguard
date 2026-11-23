package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCapacityProxyEnginePoolPolicy(t *testing.T) {
	for _, input := range []bool{true, false} {
		for _, auditOnly := range []bool{true, false} {
			for _, closed := range []bool{false, true} {
				t.Run("input="+strconv.FormatBool(input)+"/record="+strconv.FormatBool(auditOnly)+"/closed="+strconv.FormatBool(closed), func(t *testing.T) {
					t.Setenv("SECURITY_AUDIT_ONLY", strconv.FormatBool(auditOnly))
					t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", strconv.FormatBool(closed))
					reason := "input_capacity_overflow"
					if !input {
						reason = "output_capacity_overflow"
					}
					engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusServiceUnavailable)
						_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": reason, "inspection_status": "incomplete"}})
					}))
					defer engine.Close()
					client := NewSecurityClient(engine.URL)
					var action string
					var findings []map[string]interface{}
					var meta *FingerprintScanMeta
					if input {
						request := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"hello"}]}`))
						request.Header.Set("Content-Type", "application/json")
						action, findings, meta = client.CheckInput(context.Background(), "tenant", "capacity", request)
					} else {
						action, findings, meta = client.CheckOutputDetailed(context.Background(), "tenant", detectLLMProvider("api.openai.com", "/v1/chat/completions"), []byte(`{"choices":[{"message":{"role":"assistant","content":"hello"}}]}`), "application/json")
					}
					want := "audit"
					if closed && !auditOnly {
						want = "block"
					}
					if action != want || meta == nil || meta.SemanticStatus != "incomplete" || len(findings) != 0 {
						t.Fatalf("capacity must be an operational coverage gap: action=%s want=%s meta=%+v findings=%+v", action, want, meta, findings)
					}
					if action == "block" {
						status, _ := inputBlockResponse(meta, findings)
						if status != http.StatusServiceUnavailable {
							t.Fatalf("capacity rejection must map to 503, got=%d meta=%+v", status, meta)
						}
					}
				})
			}
		}
	}
}

func TestCapacityProxyDurableAdmissionReadsIndependentPolicy(t *testing.T) {
	for _, auditOnly := range []bool{true, false} {
		t.Run(strconv.FormatBool(auditOnly), func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", strconv.FormatBool(auditOnly))
			t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", "true")
			queue := &InspectionQueue{slots: make(chan struct{}, 1)}
			queue.slots <- struct{}{}
			client := NewSecurityClient("http://127.0.0.1:1")
			queue.client = client
			client.inspectionQueue = queue
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
			defer cancel()
			request := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"hello"}]}`))
			request.Header.Set("Content-Type", "application/json")
			action, findings, meta := client.CheckInput(ctx, "tenant", "capacity", request)
			want := "block"
			if auditOnly {
				want = "audit"
			}
			if action != want || meta == nil || meta.SemanticStatus != "incomplete" || len(findings) != 0 {
				t.Fatalf("full detector slots must read capacity policy: action=%s want=%s meta=%+v findings=%+v", action, want, meta, findings)
			}
		})
	}
}
