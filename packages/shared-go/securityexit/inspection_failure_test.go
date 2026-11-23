package securityexit

import (
	"fmt"
	"net/http"
	"testing"
)

func TestCapacityHTTPFailureRequiresStructuredKnownPoolCode(t *testing.T) {
	for _, test := range []struct {
		status   int
		body     string
		capacity bool
	}{
		{503, `{"detail":{"code":"input_capacity_overflow","inspection_status":"incomplete"}}`, true},
		{503, `{"detail":{"code":"output_capacity_overflow","inspection_status":"incomplete"}}`, true},
		{503, `{"detail":{"code":"batch_capacity_overflow","inspection_status":"incomplete"}}`, true},
		{http.StatusBadGateway, `{"detail":{"code":"input_capacity_overflow","inspection_status":"incomplete"}}`, false},
		{503, `{"detail":{"code":"input_timeout","inspection_status":"incomplete"}}`, false},
		{503, `{"detail":{"code":"request_body_limit_exceeded","inspection_status":"incomplete"}}`, false},
		{503, `{"detail":{"code":"judge_capacity_overflow","inspection_status":"incomplete"}}`, false},
		{503, `{"detail":{"code":"input_capacity_overflow","inspection_status":"completed"}}`, false},
		{503, `pool full`, false},
	} {
		err := HTTPInspectionError(test.status, []byte(test.body))
		if (FailureCause(err) == Capacity) != test.capacity {
			t.Fatalf("status=%d body=%s cause=%v capacity=%t", test.status, test.body, FailureCause(err), test.capacity)
		}
	}
}

func TestCapacityFailureSurvivesWrapping(t *testing.T) {
	err := HTTPInspectionError(503, []byte(`{"detail":{"code":"input_capacity_overflow","inspection_status":"incomplete"}}`))
	err = NewInspectionFailure("output_check_failed", fmt.Errorf("proxy check: %w", err))
	if FailureCause(err) != Capacity || FailureReason(err, "fallback") != "input_capacity_overflow" {
		t.Fatalf("wrapping lost pool cause: cause=%v reason=%s err=%v", FailureCause(err), FailureReason(err, "fallback"), err)
	}
}

func TestCapacityPolicyDefaultsToOpen(t *testing.T) {
	for _, test := range []struct {
		value  string
		closed bool
	}{{"", false}, {"false", false}, {"true", true}, {"1", true}, {"invalid", false}} {
		t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", test.value)
		if got := CapacityPolicy().FailClosedOnCapacity; got != test.closed {
			t.Fatalf("capacity env=%q closed=%t want=%t", test.value, got, test.closed)
		}
	}
}
