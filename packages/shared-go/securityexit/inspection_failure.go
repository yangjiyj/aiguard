package securityexit

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type inspectionFailure struct {
	reason string
	err    error
}

func (f *inspectionFailure) Error() string {
	if f.err != nil {
		return fmt.Sprintf("security inspection incomplete (%s): %v", f.reason, f.err)
	}
	return "security inspection incomplete: " + f.reason
}

func (f *inspectionFailure) Unwrap() error            { return f.err }
func (f *inspectionFailure) InspectionReason() string { return f.reason }
func (f *inspectionFailure) InspectionCause() Cause {
	if IsCapacityReason(f.reason) || FailureCause(f.err) == Capacity {
		return Capacity
	}
	return DetectionFailure
}

// IsCapacityReason recognizes detector pool/queue exhaustion, not size limits
// or a partial semantic stage that retained a valid fast-layer verdict.
func IsCapacityReason(reason string) bool {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "input_capacity_overflow", "output_capacity_overflow", "batch_capacity_overflow",
		"inspection_queue_capacity", "inspection_admission_timeout":
		return true
	default:
		return false
	}
}

func NewInspectionFailure(reason string, err error) error {
	if FailureCause(err) == Capacity && !IsCapacityReason(reason) {
		reason = FailureReason(err, reason)
	}
	return &inspectionFailure{reason: strings.TrimSpace(reason), err: err}
}

func FailureCause(err error) Cause {
	var failure interface{ InspectionCause() Cause }
	if errors.As(err, &failure) {
		return failure.InspectionCause()
	}
	return DetectionFailure
}

func FailureReason(err error, fallback string) string {
	var failure interface{ InspectionReason() string }
	if errors.As(err, &failure) && strings.TrimSpace(failure.InspectionReason()) != "" {
		return failure.InspectionReason()
	}
	return fallback
}

// HTTPInspectionError preserves only structured, known 503 capacity codes.
// Other HTTP errors retain detection-failure policy rather than acquiring the
// independent capacity policy merely because their status is 503.
func HTTPInspectionError(status int, body []byte) error {
	err := fmt.Errorf("security engine returned HTTP %d", status)
	if status != http.StatusServiceUnavailable {
		return err
	}
	var payload struct {
		Detail struct {
			Code   string `json:"code"`
			Status string `json:"inspection_status"`
		} `json:"detail"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.Detail.Status == "incomplete" && IsCapacityReason(payload.Detail.Code) {
		return NewInspectionFailure(payload.Detail.Code, err)
	}
	return err
}
