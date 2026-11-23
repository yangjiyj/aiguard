package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

func TestCapacityHTTPPolicyIsIndependentFromDetectionFailure(t *testing.T) {
	for _, test := range []struct {
		name, reason                                         string
		auditOnly, detectionClosed, capacityClosed, rejected bool
	}{
		{"pool/default", "input_capacity_overflow", false, false, false, false},
		{"pool/closed", "input_capacity_overflow", false, false, true, true},
		{"pool/detection-only", "input_capacity_overflow", false, true, false, false},
		{"pool/both", "input_capacity_overflow", false, true, true, true},
		{"pool/record", "input_capacity_overflow", true, true, true, false},
		{"ordinary/capacity-only", "input_failed", false, false, true, false},
		{"ordinary/detection-only", "input_failed", false, true, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := failClosedClient(t, test.auditOnly, test.detectionClosed)
			t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", strconv.FormatBool(test.capacityClosed))
			engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": test.reason, "inspection_status": "incomplete"}})
			}))
			defer engine.Close()
			cfg := &config.Config{SecurityEngineURL: engine.URL}
			audit := &MockAuditWriter{}
			handler := NewEmbeddingsHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, NewRealSecurityChecker(cfg), audit, &MockProviderAdapterFactory{})
			handler.SetRuntimeConfigClient(client)
			body, _ := json.Marshal(EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello world"})
			request := httptest.NewRequest(http.MethodPost, "/v1/embeddings", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request = request.WithContext(setAuthInfo(request.Context(), "tenant-123", "project-123", "user-123", "key-123", ""))
			response := httptest.NewRecorder()
			handler.Handler().ServeHTTP(response, request)
			if test.rejected {
				if response.Code != http.StatusServiceUnavailable {
					t.Fatalf("pool failure must return retryable 503: code=%d body=%s", response.Code, response.Body.String())
				}
			} else if response.Code < 200 || response.Code >= 300 {
				t.Fatalf("fail-open or record must forward: code=%d body=%s", response.Code, response.Body.String())
			}
			if !hasSecurityEvent(audit, "security_check_failed") {
				t.Fatalf("coverage gap must be recorded: %+v", audit.SecurityEventWrites)
			}
		})
	}
}
