package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestWriteMCPConfirmationResolutionMapsSafeHTTPStates(t *testing.T) {
	tests := []struct {
		name       string
		state      repository.MCPConfirmationExecution
		wantStatus int
		wantText   string
		wantRetry  bool
	}{
		{
			name: "executing is accepted",
			state: repository.MCPConfirmationExecution{
				ConfirmationID: "cf-1", InvocationID: "inv-1", ConfirmationStatus: "approved",
				ExecutionStatus: "executing", EvidenceStatus: "pending", ExpiresAt: time.Now().Add(time.Minute),
			},
			wantStatus: http.StatusAccepted, wantText: "\"execution_status\":\"executing\"", wantRetry: true,
		},
		{
			name: "executed is terminal",
			state: repository.MCPConfirmationExecution{
				ConfirmationID: "cf-2", InvocationID: "inv-2", ConfirmationStatus: "approved",
				ExecutionStatus: "executed", EvidenceStatus: "complete", AuditRequestID: "req-2",
				ToolLogID: "tc-2", ResultAvailable: true, ExpiresAt: time.Now().Add(time.Minute),
			},
			wantStatus: http.StatusOK, wantText: "\"audit_request_id\":\"req-2\"",
		},
		{
			name: "expired approval conflicts",
			state: repository.MCPConfirmationExecution{
				ConfirmationID: "cf-3", InvocationID: "inv-3", ConfirmationStatus: "approved",
				ExecutionStatus: "failed", EvidenceStatus: "failed", ErrorCode: "approval_expired",
			},
			wantStatus: http.StatusConflict, wantText: "\"code\":\"approval_expired\"",
		},
		{
			name: "rejection is terminal without execution",
			state: repository.MCPConfirmationExecution{
				ConfirmationID: "cf-4", InvocationID: "inv-4", ConfirmationStatus: "rejected",
				ExecutionStatus: "pending", EvidenceStatus: "pending",
			},
			wantStatus: http.StatusOK, wantText: "\"status\":\"rejected\"",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.state.AttemptID = "attempt-secret"
			test.state.ReplayCiphertext = "cipher-secret"
			response := httptest.NewRecorder()
			writeMCPConfirmationResolution(response, &test.state)
			if response.Code != test.wantStatus || !strings.Contains(response.Body.String(), test.wantText) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if test.wantRetry != (response.Header().Get("Retry-After") != "") {
				t.Fatalf("Retry-After=%q", response.Header().Get("Retry-After"))
			}
			if strings.Contains(response.Body.String(), "attempt-secret") ||
				strings.Contains(response.Body.String(), "cipher-secret") {
				t.Fatalf("safe projection leaked execution secret: %s", response.Body.String())
			}
		})
	}
}

func TestGatewayMCPConfirmationExecutorAcceptsKnownAsyncAndTerminalStates(t *testing.T) {
	tests := []struct {
		name       string
		httpStatus int
		body       string
		wantError  bool
	}{
		{name: "executing", httpStatus: http.StatusAccepted, body: `{"execution_status":"executing"}`},
		{name: "executed", httpStatus: http.StatusOK, body: `{"execution_status":"executed"}`},
		{name: "expired terminal", httpStatus: http.StatusConflict, body: `{"execution_status":"failed","error_code":"approval_expired"}`},
		{name: "unexpected response", httpStatus: http.StatusServiceUnavailable, body: `{"error":"down"}`, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Tenant-ID") != "tenant-a" || r.Header.Get(InternalAPISecretHeader) != "secret" {
					t.Fatalf("missing internal identity headers: %#v", r.Header)
				}
				w.WriteHeader(test.httpStatus)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			executor := NewGatewayMCPConfirmationExecutor(server.URL, "secret")
			err := executor.ExecuteMCPConfirmation(context.Background(), "tenant-a", "cf-a", "attempt-a")
			if test.wantError != (err != nil) {
				t.Fatalf("error=%v want_error=%v", err, test.wantError)
			}
		})
	}
}
