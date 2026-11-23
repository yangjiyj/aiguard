package governor

import "log"

// failOpen preserves service availability while emitting an observational
// decision that the handler persists as a governor runtime fault.
func failOpen(reason string) Decision {
	log.Printf("[governor.fail_open] %s", reason)
	return Decision{
		Action:          ActionAlert,
		AlertOnly:       true,
		TriggeredMetric: "runtime_fault",
		Reason:          "fail-open: " + reason,
	}
}
