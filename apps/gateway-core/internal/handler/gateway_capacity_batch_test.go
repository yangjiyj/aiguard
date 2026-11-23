package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/security"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

func TestCapacityBatchAdapterPreservesPerItemCause(t *testing.T) {
	for _, reason := range []string{"batch_capacity_overflow", "batch_timeout"} {
		t.Run(reason, func(t *testing.T) {
			engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path != "/check-input/batch" {
					w.WriteHeader(http.StatusServiceUnavailable)
					_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": reason, "inspection_status": "incomplete"}})
					return
				}
				var requests []*security.CheckInputRequest
				if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
					t.Error(err)
					return
				}
				w.WriteHeader(http.StatusMultiStatus)
				_ = json.NewEncoder(w).Encode([]map[string]any{{"request_id": requests[0].RequestID, "inspection_status": "incomplete", "inspection_reason": reason}})
			}))
			defer engine.Close()
			checker := NewRealSecurityChecker(&config.Config{SecurityEngineURL: engine.URL})
			results, err := checker.CheckInputBatchDetailed(context.Background(), &modelrouter.RequestEnvelope{RequestID: "capacity", TenantID: "tenant"}, []InputCheckBatchItem{{Content: "hello", MessageRole: "user", ContentSource: "user"}})
			if err != nil || len(results) != 1 || results[0].Err == nil {
				t.Fatalf("incomplete result was lost: results=%+v err=%v", results, err)
			}
			var carrier interface{ InspectionCause() securityexit.Cause }
			capacity := errors.As(results[0].Err, &carrier) && carrier.InspectionCause() == securityexit.Capacity
			if capacity != (reason == "batch_capacity_overflow") {
				t.Fatalf("batch item reason=%s capacity=%t err=%v", reason, capacity, results[0].Err)
			}
			if reason == "batch_timeout" && !errors.Is(results[0].Err, context.DeadlineExceeded) {
				t.Fatalf("timeout cause lost: %v", results[0].Err)
			}
		})
	}
}
