// Package securityexit decides whether a security finding may interrupt a
// data-plane request. Every service calls Decide at the point where it would
// write a non-2xx response, replace a response, drop a tool call or abort a
// stream, so the record-mode guarantee lives in one place:
//
//   - Record mode never enforces.
//   - A detection that could not run is a coverage gap. Decide defaults to
//     fail-open; DecideWithPolicy applies explicit failure/capacity policies.
//   - Only protect mode with an action in the single blocking set enforces.
//
// Transport failures (a body that cannot be read, a request above the
// physical transport limit) are not security decisions and are not routed
// through Decide; they keep a transport status code such as 400 or 413.
package securityexit

import "strings"

// Mode is the resolved execution mode for a request.
type Mode int

const (
	// Record observes and records; it never interrupts traffic.
	Record Mode = iota
	// Protect enforces configured blocking actions.
	Protect
)

// ModeFromAuditOnly maps the services' existing boolean to a Mode.
func ModeFromAuditOnly(auditOnly bool) Mode {
	if auditOnly {
		return Record
	}
	return Protect
}

// Cause says why an exit is being considered.
type Cause int

const (
	// RuleHit is a detection rule or engine verdict.
	RuleHit Cause = iota
	// ExplicitFileType is an administrator's blocked-file-type rule.
	ExplicitFileType
	// ToolPolicy is an agent/MCP tool or restricted-file policy.
	ToolPolicy
	// DetectionFailure means the inspection itself could not complete.
	DetectionFailure
	// Capacity means inspection was skipped for lack of capacity.
	Capacity
)

// Outcome is the decision for one exit.
type Outcome struct {
	// Enforce reports whether the caller may interrupt the request.
	Enforce bool
	// Action is the action_taken to record.
	Action string
	// Gap reports whether the request must be recorded as a coverage gap.
	Gap bool
}

// Blocks reports whether action belongs to the single blocking set.
// mask/redact are rewrites, not blocks.
func Blocks(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "reply", "deny", "quarantine":
		return true
	default:
		return false
	}
}

// Decide returns the outcome for raw under mode and cause.
func Decide(mode Mode, raw string, cause Cause) Outcome {
	switch cause {
	case DetectionFailure, Capacity:
		return Outcome{Action: "audit", Gap: true}
	}
	if !Blocks(raw) {
		// Non-blocking actions (allow/audit/mask/…) pass through unchanged.
		return Outcome{Action: raw}
	}
	if mode != Protect {
		return Outcome{Action: "audit"}
	}
	return Outcome{Enforce: true, Action: raw}
}

// Clamp returns the action to record for raw under mode. It is the
// action-only form of Decide for callers that carry the action forward.
func Clamp(mode Mode, raw string) string {
	return Decide(mode, raw, RuleHit).Action
}
