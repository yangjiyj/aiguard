package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// guardrailDetectionUnavailableCode is the error code returned when the
// explicit fail-closed option rejects a request whose inspection failed.
const guardrailDetectionUnavailableCode = "guardrail_detection_unavailable"

const guardrailDetectionUnavailableMessage = "security inspection is unavailable; the request was rejected by the fail-closed policy"

// errGuardrailDetectionUnavailable marks a detection failure that the
// explicit fail-closed option turned into a rejection (protect mode only).
var errGuardrailDetectionUnavailable = errors.New(guardrailDetectionUnavailableCode)

func isGuardrailDetectionUnavailable(err error) bool {
	return errors.Is(err, errGuardrailDetectionUnavailable)
}

// guardrailPolicy is the single resolver of the explicit fail-closed option
// (system_settings.guardrail_fail_closed_enabled via the signed gateway
// projection). A missing client, an unloaded snapshot, or an older control
// plane that does not send the key keeps detection fail-open. Capacity reads the
// signed security_capacity_fail_mode, falling back to SECURITY_CAPACITY_FAIL_CLOSED
// only while the console has not stored a value (2.9.22).
func guardrailPolicy(ctx context.Context, client *ToolRiskClient) securityexit.Policy {
	policy := securityexit.CapacityPolicy()
	if client != nil {
		policy.FailClosedOnDetectionFailure = client.GuardrailFailClosedEnabled(ctx)
		policy.FailClosedOnCapacity = client.CapacityFailClosed()
	}
	return policy
}

// writeGuardrailDetectionUnavailable answers a fail-closed rejection with a
// 503 (retryable availability condition), never a block notice. Every caller
// runs before any response byte is written, so a streaming request also gets a
// plain JSON 503 instead of a 200 event stream.
func writeGuardrailDetectionUnavailable(w http.ResponseWriter, requestID string, actionHeader bool) {
	setSecurityActionHeader(w, "block", actionHeader)
	writeErrorResponse(w, guardrailDetectionUnavailableCode, guardrailDetectionUnavailableMessage, requestID)
}

// rejectGuardrailDetectionUnavailable finalizes the request log as a 503
// security_blocked and writes the rejection. It returns false (and does
// nothing) unless err is a fail-closed rejection, so buffered exits can call it
// first and fall through to their existing block handling otherwise.
func rejectGuardrailDetectionUnavailable(ctx context.Context, w http.ResponseWriter, writer AuditWriter, envelope *modelrouter.RequestEnvelope, requestID string, startedAt time.Time, auditResult *AuditResult, actionHeader bool, err error) bool {
	if !isGuardrailDetectionUnavailable(err) {
		return false
	}
	if writer != nil {
		writer.FinalizeRequestLog(ctx, envelope, nil, "security_blocked", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), auditResult)
	}
	writeGuardrailDetectionUnavailable(w, requestID, actionHeader)
	return true
}
