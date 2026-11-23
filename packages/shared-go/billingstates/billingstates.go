// Package billingstates holds the shared billing terminal-state decision
// tables used by both the gateway's real-time accounting path and the control
// plane's reconciliation compensation path, so the two can never drift.
//
// Authoritative usage_source enum (produced only by the gateway's real-time
// accounting path and persisted in request_logs.output_audit_result
// .response_metadata.usage_source):
//
//	upstream, upstream_total_adjusted        verified provider usage — settle
//	estimated_reservation,                    provider usage missing/invalid,
//	  estimated_reservation_invalid_usage,    the admission estimate was used —
//	  estimated_incomplete,                   settle only when the reservation
//	  estimated_incomplete_invalid_usage      admission snapshot exists
//	synthetic_no_upstream                    no upstream work happened — NOT
//	                                         billable, never settles
//	NULL (legacy rows before the marker)     success may settle as legacy
//	                                         recovered; the incomplete family
//	                                         (cancel/abort/timeout) stays
//	                                         pending
//
// Evidence decision table (request_log status × durable evidence → action):
//
//	request_log status                        | usage_source + admission snapshot       | real-time | reconciliation
//	------------------------------------------+-----------------------------------------+-----------+------------------
//	success                                   | upstream / upstream_total_adjusted      | settle    | settle from request_log tokens
//	success                                   | estimated_reservation[_invalid_usage]   | settle    | settle iff admission snapshot exists
//	incomplete family (incl. cancel/abort/    | estimated_incomplete[_invalid_usage]    | settle    | settle iff admission snapshot exists
//	  timeout)                                |                                         |           |
//	any settle-family status                  | synthetic_no_upstream                   | n/a       | PENDING — no upstream work
//	                                          |                                         |           | happened, so a prepaid
//	                                          |                                         |           | settle would bill for
//	                                          |                                         |           | nothing
//	success                                   | NULL (legacy row)                       | n/a       | settle, marked legacy_recovered
//	incomplete family                         | NULL (legacy row)                       | n/a       | PENDING — finalize + non-NULL tokens
//	                                          |                                         |           | alone is not a verified source
//	any status                                | billing_outcome=released                | n/a       | PENDING — contradicts the gateway's
//	                                          |                                         |           | recorded real-time decision
//	definitive failures (see list)            | evidence independent                    | release   | release (idempotent re-release)
//	error, provider_error                     | any                                     | release*  | PENDING — generic failure strings do
//	                                          |                                         |           | not prove non-dispatch
//	received, "", unknown status              | any                                     | n/a       | PENDING
//	no request_log row at all                 | none                                    | n/a       | PENDING (stale_reservation exception)
//
//	* the real-time path releases on the response it holds in hand; the
//	  compensation path only sees the status string and must not infer.
package billingstates

// Settlement statuses that carry durable usage evidence and are settled from
// it. client_canceled, stream_aborted and provider_timeout share the
// incomplete terminal state with the gateway's real-time mapping
// (accountingStatus in gateway-core billing.go), so compensation settles them
// from the request_log usage evidence instead of releasing them.
var SettleStatuses = map[string]bool{
	"success":          true,
	"incomplete":       true,
	"client_canceled":  true,
	"stream_aborted":   true,
	"provider_timeout": true,
}

// DefinitiveFailureStatuses lists request_log statuses that prove the request
// never reached upstream work, matching the statuses the gateway itself
// releases in real time WITHOUT holding upstream usage. Generic error and
// provider_error are deliberately absent: they can occur after a request was
// dispatched, so they are not evidence of non-dispatch and stay pending in
// reconciliation.
var DefinitiveFailureStatuses = map[string]bool{
	"concurrency_limit":            true,
	"forbidden":                    true,
	"forbidden_model":              true,
	"governor_blocked":             true,
	"invalid_request":              true,
	"model_not_configured":         true,
	"model_not_found":              true,
	"model_route_unavailable":      true,
	"provider_not_configured":      true,
	"provider_unavailable":         true,
	"provider_unsupported":         true,
	"quota_exceeded":               true,
	"rate_limited":                 true,
	"responses_native_unavailable": true,
	"security_blocked":             true,
	"unauthorized":                 true,
}

// AccountingStatus maps a raw request status to the gateway's real-time
// accounting status: cancel, stream abort and provider timeout share the
// incomplete terminal state.
func AccountingStatus(status string) string {
	if SettleStatuses[status] && status != "success" {
		return "incomplete"
	}
	return status
}

// TerminalKind classifies a raw request_log status for reconciliation.
type TerminalKind string

const (
	TerminalSettle  TerminalKind = "settle"
	TerminalRelease TerminalKind = "release"
	TerminalPending TerminalKind = "pending"
)

// Classify maps a raw request_log status to its reconciliation terminal kind.
// The settle family is checked separately from the definitive-failure family:
// the SQL prefilter uses their union, so the classification itself must never
// consult the union or every release status would settle.
func Classify(status string) TerminalKind {
	if SettleStatuses[status] {
		return TerminalSettle
	}
	if DefinitiveFailureStatuses[status] {
		return TerminalRelease
	}
	return TerminalPending
}

// TerminalStatuses reports whether the status is executable at all (settle or
// release family). Only executable statuses may occupy a reconciliation batch
// limit; everything else is counted as pending without consuming it.
func TerminalStatuses(status string) bool {
	return SettleStatuses[status] || DefinitiveFailureStatuses[status]
}

// Evidence carries the durable usage proof read from the request_log row that
// the status string alone cannot provide. UsageRecorded must reflect the raw
// token columns WITHOUT coalescing: input_tokens/output_tokens are written by
// the gateway's FinalizeRequestLog as plain integers and are therefore never
// NULL once finalize ran; NULL means finalize never executed and no usage
// proof exists. UsageSource is the authoritative marker the gateway persisted
// in output_audit_result.response_metadata.usage_source (see the package enum
// above). HasApprovedEstimate records that the reservation admission snapshot
// was verified to exist, which is required to honor estimated_* sources. The
// evidence is the frozen price binding (billing_reservations.price_id, tied
// to model_name + customer_group by ck_billing_reservation_quote) together
// with a non-NULL admitted_at: admitted_at alone is NOT NULL DEFAULT NOW()
// and the amount constraint already forces a positive micros-or-tokens
// reservation, so testing only those would approve every row and make this
// flag hardcoded true. A legitimately free admission (reserved_micros 0 with
// reserved tokens) still has a price_id, so free is admitted, not rejected.
// UpstreamOutcome is
// request_logs.upstream_outcome and BillingOutcome the gateway's persisted
// real-time billing decision; both act as cross-checks against contradicting
// the gateway.
type Evidence struct {
	UsageRecorded       bool
	PromptTokens        int64
	OutputTokens        int64
	UsageSource         string
	HasApprovedEstimate bool
	UpstreamOutcome     string
	BillingOutcome      string
}

// Verified usage sources: the gateway validated the usage against the
// provider response. These two are the ONLY markers that can authorize a
// charge on their own. synthetic_no_upstream is deliberately absent: it
// records that no upstream work happened at all, so there is no provider
// usage behind it and it must never charge a prepaid wallet. Anything not
// enumerated here or in estimatedUsageSources is unrecognized and stays
// pending rather than being trusted.
var verifiedUsageSources = map[string]bool{
	"upstream":                true,
	"upstream_total_adjusted": true,
}

// estimatedUsageSources is the CLOSED set of markers that admit the
// admission estimate instead of verified provider usage. It must stay an
// explicit enumeration, never a "estimated" prefix test: a prefix match
// would let an unknown marker such as "estimated_anything" reach the
// settle branch, which is exactly the open-ended trust this table exists
// to prevent. A value that is not enumerated here is treated like any
// other unrecognized source and stays pending.
var estimatedUsageSources = map[string]bool{
	"estimated_reservation":               true,
	"estimated_reservation_invalid_usage": true,
	"estimated_incomplete":                true,
	"estimated_incomplete_invalid_usage":  true,
}

// isEstimatedUsageSource reports whether the marker is one of the four
// authoritative estimated_* values.
func isEstimatedUsageSource(source string) bool {
	return estimatedUsageSources[source]
}

// Decide refines Classify with the durable evidence and returns all three
// terminal kinds. Callers MUST keep the three branches distinct:
//
//   - TerminalSettle: charge from the recorded evidence.
//   - TerminalRelease: provably never dispatched upstream, refund.
//   - TerminalPending: evidence insufficient or self-contradictory. The
//     wallet freeze MUST survive untouched. Pending is NOT a release and
//     must never be collapsed into one: releasing on missing evidence
//     returns money the request may well have spent, and the row then
//     looks settled to every later reader.
//
// A settle decision can never rest on the status string or bare token
// columns alone. The release family stays evidence independent
// (provider_unavailable with recorded tokens is still released — the
// gateway already released it in real time and re-releasing is
// idempotent). Generic error / provider_error and unknown statuses are
// pending on BOTH paths: they do not prove non-dispatch. Missing or
// unapproved usage sources and gateway-contradicting outcomes are pending
// so the freeze survives until an operator or a later, evidence-carrying
// run resolves the row. Legacy rows without any usage_source marker keep
// the compatible success recovery (marked legacy_recovered by the
// caller); the incomplete family never recovers from a missing source.
func Decide(status string, evidence Evidence) TerminalKind {
	switch Classify(status) {
	case TerminalRelease:
		return TerminalRelease
	case TerminalSettle:
		if !evidence.UsageRecorded {
			return TerminalPending
		}
		if evidence.BillingOutcome == "released" {
			// The gateway's real-time path explicitly released this request;
			// compensating with a settle would contradict recorded state.
			return TerminalPending
		}
		switch {
		case verifiedUsageSources[evidence.UsageSource]:
			return TerminalSettle
		case isEstimatedUsageSource(evidence.UsageSource):
			if evidence.HasApprovedEstimate {
				return TerminalSettle
			}
			return TerminalPending
		case evidence.UsageSource == "synthetic_no_upstream":
			// No upstream work happened: there is no provider usage to charge
			// for, so this must never settle a prepaid reservation. Kept as an
			// explicit case (not the default fall-through) so re-adding it to
			// verifiedUsageSources cannot silently re-grant settle.
			return TerminalPending
		case evidence.UsageSource == "" && status == "success":
			// Legacy row: no source marker existed before the audit metadata
			// was introduced; success recovery stays compatible.
			return TerminalSettle
		default:
			return TerminalPending
		}
	default:
		return TerminalPending
	}
}
