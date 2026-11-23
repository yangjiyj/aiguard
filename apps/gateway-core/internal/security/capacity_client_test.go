package security

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

type inspectionCauseCarrier interface {
	InspectionCause() securityexit.Cause
}

func TestCapacityClientPreservesStructuredPoolFailureCause(t *testing.T) {
	for _, reason := range []string{"input_capacity_overflow", "output_capacity_overflow", "batch_capacity_overflow", "input_timeout", "output_failed"} {
		t.Run(reason, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": reason, "inspection_status": "incomplete"}})
			}))
			defer server.Close()
			client := NewClient(server.URL)
			for name, check := range map[string]func() error{
				"input": func() error {
					_, err := client.CheckInput(context.Background(), &CheckInputRequest{RequestID: "capacity", Content: "hello"})
					return err
				},
				"output": func() error {
					_, err := client.CheckOutput(context.Background(), "capacity", "hello", map[string]any{})
					return err
				},
				"batch": func() error {
					_, err := client.CheckInputBatch(context.Background(), []*CheckInputRequest{{RequestID: "capacity", Content: "hello"}})
					return err
				},
			} {
				err := check()
				if err == nil {
					t.Fatalf("%s must preserve inspection failure", name)
				}
				var carrier inspectionCauseCarrier
				isCapacity := errors.As(err, &carrier) && carrier.InspectionCause() == securityexit.Capacity
				wantCapacity := reason == "input_capacity_overflow" || reason == "output_capacity_overflow" || reason == "batch_capacity_overflow"
				if isCapacity != wantCapacity {
					t.Fatalf("%s reason=%s capacity=%t want=%t err=%v", name, reason, isCapacity, wantCapacity, err)
				}
			}
		})
	}
}
