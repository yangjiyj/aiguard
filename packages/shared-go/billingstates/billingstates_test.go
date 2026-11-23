package billingstates

import "testing"

// Independent probe for the shared decision tables: the classification must
// stay aligned with the gateway's real-time mapping, and generic error /
// provider_error must never be classified as releasable non-dispatch.
func TestClassifyMatchesGatewayRealtimeMapping(t *testing.T) {
	settle := []string{"success", "incomplete", "client_canceled", "stream_aborted", "provider_timeout"}
	for _, status := range settle {
		if got := Classify(status); got != TerminalSettle {
			t.Fatalf("Classify(%q)=%q want settle", status, got)
		}
		if status != "success" && AccountingStatus(status) != "incomplete" {
			t.Fatalf("AccountingStatus(%q)=%q want incomplete", status, AccountingStatus(status))
		}
		if !TerminalStatuses(status) {
			t.Fatalf("TerminalStatuses(%q)=false", status)
		}
	}
	if AccountingStatus("success") != "success" {
		t.Fatal("AccountingStatus(success) must stay success")
	}
	release := []string{
		"concurrency_limit", "forbidden", "forbidden_model", "governor_blocked",
		"invalid_request", "model_not_configured", "model_not_found", "model_route_unavailable",
		"provider_not_configured", "provider_unavailable", "provider_unsupported",
		"quota_exceeded", "rate_limited", "responses_native_unavailable",
		"security_blocked", "unauthorized",
	}
	for _, status := range release {
		if got := Classify(status); got != TerminalRelease {
			t.Fatalf("Classify(%q)=%q want release", status, got)
		}
		if AccountingStatus(status) != status {
			t.Fatalf("AccountingStatus(%q) must be identity", status)
		}
		if !TerminalStatuses(status) {
			t.Fatalf("TerminalStatuses(%q)=false", status)
		}
	}
	pending := []string{"", "received", "error", "provider_error", "some_future_status"}
	for _, status := range pending {
		if got := Classify(status); got != TerminalPending {
			t.Fatalf("Classify(%q)=%q want pending", status, got)
		}
		if TerminalStatuses(status) {
			t.Fatalf("TerminalStatuses(%q)=true", status)
		}
	}
}

// The estimated_* family must be CLOSED: exactly the four authoritative
// values are honored with an approved estimate, and any other marker —
// including an unknown string that merely starts with "estimated" — stays
// pending. A prefix test would let estimated_anything reach the settle
// branch, which is the open-ended trust the table exists to prevent.
func TestEstimatedSourceFamilyIsClosed(t *testing.T) {
	approved := Evidence{UsageRecorded: true, PromptTokens: 4, OutputTokens: 2, HasApprovedEstimate: true}
	for _, source := range []string{
		"estimated_reservation", "estimated_reservation_invalid_usage",
		"estimated_incomplete", "estimated_incomplete_invalid_usage",
	} {
		evidence := approved
		evidence.UsageSource = source
		if got := Decide("success", evidence); got != TerminalSettle {
			t.Fatalf("Decide(success, %s)=%q want settle", source, got)
		}
	}
	for _, source := range []string{
		"estimated", "estimated_", "estimated_anything", "estimated_reservation_v2",
		"Estimated_Reservation", "estimated_reservation ", "upstream_estimated",
	} {
		evidence := approved
		evidence.UsageSource = source
		if got := Decide("success", evidence); got != TerminalPending {
			t.Fatalf("Decide(success, %q)=%q want pending (not an enumerated source)", source, got)
		}
	}
	// A closed family also means an approved estimate alone cannot promote an
	// unrecognized verified-looking source.
	if got := Decide("success", Evidence{UsageRecorded: true, UsageSource: "totally_verified"}); got != TerminalPending {
		t.Fatalf("Decide(success, totally_verified)=%q want pending", got)
	}
}

// The evidence-gated decision: settle requires a verified usage source (or an
// approved estimate backed by the admission snapshot), release stays evidence
// independent, legacy success recovery stays compatible, and a gateway
// release outcome blocks a compensating settle.
func TestDecideRequiresUsageEvidenceForSettle(t *testing.T) {
	verified := Evidence{UsageRecorded: true, PromptTokens: 10, OutputTokens: 5, UsageSource: "upstream", BillingOutcome: "settled"}
	for _, status := range []string{"success", "incomplete", "client_canceled", "stream_aborted", "provider_timeout"} {
		if got := Decide(status, verified); got != TerminalSettle {
			t.Fatalf("Decide(%q, verified)=%q want settle", status, got)
		}
		// synthetic_no_upstream records that NO upstream work happened: it is
		// a metering-only marker and must never settle a prepaid reservation.
		if got := Decide(status, Evidence{UsageRecorded: true, UsageSource: "synthetic_no_upstream"}); got != TerminalPending {
			t.Fatalf("Decide(%q, synthetic)=%q want pending (no upstream work)", status, got)
		}
		// Not even an approved estimate or recorded tokens can promote it.
		if got := Decide(status, Evidence{UsageRecorded: true, UsageSource: "synthetic_no_upstream", HasApprovedEstimate: true, PromptTokens: 10, OutputTokens: 5}); got != TerminalPending {
			t.Fatalf("Decide(%q, synthetic+estimate)=%q want pending", status, got)
		}
		// Legacy row without a source marker: success recovers, the
		// incomplete family does not.
		if got := Decide("success", Evidence{UsageRecorded: true}); got != TerminalSettle {
			t.Fatalf("legacy success recovery=%q want settle", got)
		}
		if status != "success" {
			if got := Decide(status, Evidence{UsageRecorded: true}); got != TerminalPending {
				t.Fatalf("legacy %q without source=%q want pending", status, got)
			}
		}
		// Estimated sources are only honored with a verified admission snapshot.
		estimated := Evidence{UsageRecorded: true, UsageSource: "estimated_incomplete", HasApprovedEstimate: true}
		if got := Decide(status, estimated); got != TerminalSettle {
			t.Fatalf("Decide(%q, approved estimate)=%q want settle", status, got)
		}
		estimated.HasApprovedEstimate = false
		if got := Decide(status, estimated); got != TerminalPending {
			t.Fatalf("Decide(%q, unapproved estimate)=%q want pending", status, got)
		}
		// Non-NULL tokens plus a finalize are NOT proof without a source —
		// except for legacy success recovery, which stays compatible.
		if status != "success" {
			if got := Decide(status, Evidence{UsageRecorded: true, PromptTokens: 10, BillingOutcome: "failed"}); got != TerminalPending {
				t.Fatalf("Decide(%q, tokens without source)=%q want pending", status, got)
			}
		}
		if got := Decide(status, Evidence{UsageRecorded: true, UsageSource: "upstream", BillingOutcome: "released"}); got != TerminalPending {
			t.Fatalf("Decide(%q, released outcome)=%q want pending", status, got)
		}
	}
	for _, status := range []string{"provider_unavailable", "forbidden", "security_blocked"} {
		if got := Decide(status, Evidence{}); got != TerminalRelease {
			t.Fatalf("Decide(%q, no evidence)=%q want release", status, got)
		}
		if got := Decide(status, Evidence{UsageRecorded: true, PromptTokens: 3, UsageSource: "upstream", BillingOutcome: "released"}); got != TerminalRelease {
			t.Fatalf("Decide(%q, with tokens)=%q want release (compat)", status, got)
		}
	}
	for _, status := range []string{"", "received", "error", "provider_error"} {
		if got := Decide(status, verified); got != TerminalPending {
			t.Fatalf("Decide(%q, verified evidence)=%q want pending", status, got)
		}
	}
}

// The fund-safety invariant, pinned at the level both consumers depend on:
// TerminalPending must never be actionable. Both the gateway's real-time
// Finalize and control-plane reconciliation branch on this table, and the
// damage from collapsing pending into either neighbour is asymmetric — a
// mistaken release refunds money the request may have spent upstream, while a
// mistaken settle charges for usage that was never proven. So pending is
// checked against BOTH neighbours explicitly, for every status the gateway can
// observe, and no evidence combination may turn it into money movement.
func TestTerminalPendingIsNeverActionable(t *testing.T) {
	statuses := []string{
		// Settle family with every evidence permutation.
		"success", "incomplete", "client_canceled", "stream_aborted", "provider_timeout",
		// Definitive failures are releasable regardless of evidence.
		"provider_unavailable", "forbidden", "security_blocked", "model_route_unavailable",
		// Everything else.
		"error", "provider_error", "received", "", "some_future_status",
	}
	sources := []string{
		"", "upstream", "upstream_total_adjusted",
		"estimated_reservation", "estimated_reservation_invalid_usage",
		"estimated_incomplete", "estimated_incomplete_invalid_usage",
		"synthetic_no_upstream", "estimated_anything", "mystery",
	}
	// The gateway's real-time path always reports UsageRecorded=true and
	// BillingOutcome=""; reconciliation adds the recorded gateway outcome.
	outcomes := []string{"", "settled", "recorded", "failed"}
	for _, status := range statuses {
		for _, source := range sources {
			for _, outcome := range outcomes {
				for _, approved := range []bool{false, true} {
					for _, recorded := range []bool{false, true} {
						got := Decide(status, Evidence{
							UsageRecorded:       recorded,
							PromptTokens:        7,
							OutputTokens:        3,
							UsageSource:         source,
							HasApprovedEstimate: approved,
							BillingOutcome:      outcome,
						})
						// Assert the verdict is one of exactly three values, so a
						// future edit that lets pending alias a money-moving
						// branch, or returns something undefined, is caught here
						// rather than in a wallet.
						switch got {
						case TerminalSettle, TerminalRelease, TerminalPending:
						default:
							t.Fatalf("status=%q source=%q outcome=%q approved=%v recorded=%v: undefined terminal kind %q",
								status, source, outcome, approved, recorded, got)
						}
						// Enumerated invariant: the (status, evidence) pairs that
						// must stay pending. A source outside the two verified
						// markers and the four estimated ones can only settle
						// when it is the legacy empty source on a success row
						// with recorded usage; everything else that reaches
						// "settle" has quietly widened trust.
						if isEnumeratedSource(source) && recorded {
							continue
						}
						// The one deliberate non-enumerated settle: a legacy
						// success row with no usage_source marker predates the
						// audit metadata and keeps its compatible recovery. It
						// is scoped to success precisely because the incomplete
						// family must never recover this way.
						if source == "" && status == "success" && recorded {
							continue
						}
						// The release family is evidence independent by design:
						// a definitive non-dispatch refunds whether or not usage
						// was recorded, so it is not part of the settle-trust
						// invariant being checked here.
						if DefinitiveFailureStatuses[status] {
							if got != TerminalRelease {
								t.Fatalf("status=%q: definitive failure must release, got %q", status, got)
							}
							continue
						}
						if got != TerminalPending {
							t.Fatalf("status=%q source=%q outcome=%q approved=%v recorded=%v: non-enumerated evidence reached %q, want pending",
								status, source, outcome, approved, recorded, got)
						}
					}
				}
			}
		}
	}
	// The two money-moving verdicts stay reachable, so the check above is not
	// vacuous: exactly the evidenced sources settle, exactly the definitive
	// failures release.
	if got := Decide("success", Evidence{UsageRecorded: true, UsageSource: "upstream"}); got != TerminalSettle {
		t.Fatalf("verified upstream must still settle, got %q", got)
	}
	if got := Decide("client_canceled", Evidence{UsageRecorded: true, UsageSource: "estimated_incomplete", HasApprovedEstimate: true}); got != TerminalSettle {
		t.Fatalf("approved estimate must still settle, got %q", got)
	}
	if got := Decide("provider_unavailable", Evidence{}); got != TerminalRelease {
		t.Fatalf("definitive failure must still release, got %q", got)
	}
}

// isEnumeratedSource reports whether the marker is one the table enumerates as
// chargeable evidence: the two verified provider sources or the four estimated
// ones. Anything else (including the empty legacy marker) is outside the
// enumeration.
//
// The membership of both sets is pinned by this test rather than read from the
// maps, so adding a marker to either map is a deliberate act that shows up here
// instead of silently widening what may charge a wallet.
func isEnumeratedSource(source string) bool {
	return verifiedUsageSources[source] || estimatedUsageSources[source]
}

func TestEnumeratedSourceMembershipIsExact(t *testing.T) {
	// Exactly these two may charge on their own: the gateway validated the
	// usage against the provider response.
	wantVerified := map[string]bool{
		"upstream": true, "upstream_total_adjusted": true,
	}
	if len(verifiedUsageSources) != len(wantVerified) {
		t.Fatalf("verifiedUsageSources has %d entries %v, want exactly %d %v",
			len(verifiedUsageSources), verifiedUsageSources, len(wantVerified), wantVerified)
	}
	for source := range wantVerified {
		if !verifiedUsageSources[source] {
			t.Fatalf("verified source %q was removed; provider-verified usage must still settle", source)
		}
	}
	// synthetic_no_upstream must never be here: no upstream work happened, so
	// there is no usage to charge for. It is the specific value a careless
	// "one more source" edit would add back.
	for _, forbidden := range []string{
		"synthetic_no_upstream", "estimated", "estimated_anything", "", "upstream_estimated",
	} {
		if verifiedUsageSources[forbidden] {
			t.Fatalf("%q must not be a verified (self-authorizing) usage source", forbidden)
		}
	}
	// Exactly these four estimated markers, no more.
	wantEstimated := map[string]bool{
		"estimated_reservation": true, "estimated_reservation_invalid_usage": true,
		"estimated_incomplete": true, "estimated_incomplete_invalid_usage": true,
	}
	if len(estimatedUsageSources) != len(wantEstimated) {
		t.Fatalf("estimatedUsageSources has %d entries %v, want exactly %d %v",
			len(estimatedUsageSources), estimatedUsageSources, len(wantEstimated), wantEstimated)
	}
	for source := range wantEstimated {
		if !estimatedUsageSources[source] {
			t.Fatalf("estimated source %q was removed; an approved estimate must still settle", source)
		}
	}
	for _, forbidden := range []string{"estimated", "estimated_", "estimated_anything", "estimatedx"} {
		if estimatedUsageSources[forbidden] {
			t.Fatalf("%q must not be an enumerated estimated source", forbidden)
		}
	}
}
