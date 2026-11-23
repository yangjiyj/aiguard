package securityexit

import (
	"os"
	"strconv"
	"strings"
)

// Policy carries customer options that change how a cause is decided. The
// zero value is the P0-3 behaviour.
type Policy struct {
	// FailClosedOnDetectionFailure rejects a request whose inspection could not
	// complete. It only takes effect in protect mode; record mode never
	// enforces. Capacity uses its own independent option.
	FailClosedOnDetectionFailure bool
	// FailClosedOnCapacity rejects inspection pool or queue exhaustion in
	// protect mode. Its default remains fail-open for availability.
	FailClosedOnCapacity bool
}

// CapacityPolicy resolves the deployment's independent pool/queue policy.
func CapacityPolicy() Policy {
	enabled, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv("SECURITY_CAPACITY_FAIL_CLOSED")))
	return Policy{FailClosedOnCapacity: enabled}
}

// ProxyDetectionPolicy resolves the forward proxy's ordinary failure mode and
// the independent capacity option. An invalid explicit mode fails closed.
func ProxyDetectionPolicy() Policy {
	policy := CapacityPolicy()
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("PROXY_DETECTION_FAIL_MODE")))
	policy.FailClosedOnDetectionFailure = mode != "" && mode != "open"
	return policy
}

// DecideWithPolicy is Decide with customer policy options applied. It is the
// only sanctioned fail-closed path for inspection failures and capacity.
func DecideWithPolicy(mode Mode, raw string, cause Cause, policy Policy) Outcome {
	if mode == Protect && ((cause == DetectionFailure && policy.FailClosedOnDetectionFailure) ||
		(cause == Capacity && policy.FailClosedOnCapacity)) {
		return Outcome{Enforce: true, Action: "block", Gap: true}
	}
	return Decide(mode, raw, cause)
}
