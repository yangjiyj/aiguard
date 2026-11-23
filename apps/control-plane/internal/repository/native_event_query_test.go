package repository

import (
	"strings"
	"testing"
)

func TestNativeEventListQueryScopesAllRelationships(t *testing.T) {
	f := NativeEventFilter{EndpointID: "ep-a", SourceID: strings.Repeat("a", 64), RefHash: strings.Repeat("b", 64), BeforeSequence: 99, Limit: 50}
	q, args, err := nativeEventListQuery("tenant-a", f)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"e.tenant_id=$1", "e.endpoint_id=$2", "e.source_id=$3", "e.sequence_id<$4", "match.tenant_id=e.tenant_id", "match.endpoint_id=e.endpoint_id", "match.source_id=e.source_id", "match.event_id=e.event_id", "r.tenant_id=e.tenant_id", "r.endpoint_id=e.endpoint_id", "r.source_id=e.source_id", "r.event_id=e.event_id", "match.ref_hash=$5", "ae.tenant_id=e.tenant_id", "ae.endpoint_id=e.endpoint_id", "ae.id=e.payload->>'legacy_event_id'",
		"e.event_type='action.observed'", "s.tenant_id=e.tenant_id", "s.session_id=legacy.session_id", "s.endpoint_id=e.endpoint_id",
		"se.tenant_id=e.tenant_id", "se.id=legacy.security_event_id", "se.matched_summary->>'source'='agent_endpoint'",
		"se.matched_summary->>'endpoint_id'=e.endpoint_id", "se.matched_summary->>'agent_event_id'=legacy.matched_id",
		"LIMIT $6"} {
		if !strings.Contains(q, scope) {
			t.Fatalf("missing scope %s", scope)
		}
	}
	if len(args) != 6 || args[0] != "tenant-a" || args[5] != 50 {
		t.Fatalf("args=%v", args)
	}
}
func TestNativeEventListQueryRejectsUnscopedOrUnbounded(t *testing.T) {
	for _, f := range []NativeEventFilter{
		{Limit: 0}, {Limit: 201}, {Limit: 50, RefHash: strings.Repeat("b", 64)},
		{Limit: 50, SourceID: "bad"}, {Limit: 50, BeforeSequence: -1},
	} {
		if _, _, err := nativeEventListQuery("tenant", f); err == nil {
			t.Fatalf("accepted %+v", f)
		}
	}
	if _, _, err := nativeEventListQuery("", NativeEventFilter{Limit: 50}); err == nil {
		t.Fatal("empty tenant accepted")
	}
}

func TestBuildNativeEventInvestigationResolutionStates(t *testing.T) {
	tests := []struct {
		name                                    string
		eventType, legacyClaim                  string
		legacyCount                             int
		matchedLegacyID, sessionClaim           string
		sessionCount                            int
		matchedSessionID, alertClaim            string
		alertCount                              int
		matchedAlertID                          string
		legacyStatus, legacyReason, legacyID    string
		sessionStatus, sessionReason, sessionID string
		alertStatus, alertReason, alertID       string
	}{
		{
			name: "exact legacy session and alert", eventType: "action.observed", legacyClaim: "agent-event",
			legacyCount: 1, matchedLegacyID: "agent-event", sessionClaim: "session", sessionCount: 1, matchedSessionID: "session",
			alertClaim: "security-event", alertCount: 1, matchedAlertID: "security-event",
			legacyStatus: "matched", legacyID: "agent-event", sessionStatus: "matched", sessionID: "session", alertStatus: "matched", alertID: "security-event",
		},
		{
			name: "non action event", eventType: "run.started",
			legacyStatus: "not_applicable", legacyReason: "not_action_observed",
			sessionStatus: "not_applicable", sessionReason: "not_action_observed", alertStatus: "not_applicable", alertReason: "not_action_observed",
		},
		{
			name: "missing source claim", eventType: "action.observed",
			legacyStatus: "missing", legacyReason: "no_legacy_event_id",
			sessionStatus: "unavailable", sessionReason: "legacy_event_unresolved", alertStatus: "unavailable", alertReason: "legacy_event_unresolved",
		},
		{
			name: "no exact tenant endpoint event", eventType: "action.observed", legacyClaim: "agent-event",
			legacyStatus: "missing", legacyReason: "no_same_tenant_endpoint_match",
			sessionStatus: "unavailable", sessionReason: "legacy_event_unresolved", alertStatus: "unavailable", alertReason: "legacy_event_unresolved",
		},
		{
			name: "ambiguous legacy match", eventType: "action.observed", legacyClaim: "agent-event", legacyCount: 2,
			legacyStatus: "ambiguous", legacyReason: "multiple_same_tenant_endpoint_matches",
			sessionStatus: "unavailable", sessionReason: "legacy_event_unresolved", alertStatus: "unavailable", alertReason: "legacy_event_unresolved",
		},
		{
			name: "missing same endpoint session", eventType: "action.observed", legacyClaim: "agent-event", legacyCount: 1, matchedLegacyID: "agent-event",
			sessionClaim: "session", alertClaim: "security-event", alertCount: 1, matchedAlertID: "security-event",
			legacyStatus: "matched", legacyID: "agent-event", sessionStatus: "missing", sessionReason: "no_same_tenant_endpoint_session",
			alertStatus: "matched", alertID: "security-event",
		},
		{
			name: "ambiguous session", eventType: "action.observed", legacyClaim: "agent-event", legacyCount: 1, matchedLegacyID: "agent-event",
			sessionClaim: "session", sessionCount: 2,
			legacyStatus: "matched", legacyID: "agent-event", sessionStatus: "ambiguous", sessionReason: "multiple_same_tenant_endpoint_sessions",
			alertStatus: "missing", alertReason: "no_security_event_id",
		},
		{
			name: "alert summary does not match", eventType: "action.observed", legacyClaim: "agent-event", legacyCount: 1, matchedLegacyID: "agent-event",
			sessionClaim: "session", sessionCount: 1, matchedSessionID: "session", alertClaim: "security-event",
			legacyStatus: "matched", legacyID: "agent-event", sessionStatus: "matched", sessionID: "session",
			alertStatus: "missing", alertReason: "no_exact_agent_endpoint_alert",
		},
		{
			name: "ambiguous exact alert", eventType: "action.observed", legacyClaim: "agent-event", legacyCount: 1, matchedLegacyID: "agent-event",
			alertClaim: "security-event", alertCount: 2,
			legacyStatus: "matched", legacyID: "agent-event", sessionStatus: "missing", sessionReason: "no_session_id",
			alertStatus: "ambiguous", alertReason: "multiple_exact_agent_endpoint_alerts",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildNativeEventInvestigation(tc.eventType, tc.legacyClaim, tc.legacyCount, tc.matchedLegacyID,
				tc.sessionClaim, tc.sessionCount, tc.matchedSessionID, tc.alertClaim, tc.alertCount, tc.matchedAlertID)
			if got.LegacyEvent.Status != tc.legacyStatus || got.LegacyEvent.Reason != tc.legacyReason || got.LegacyEvent.ID != tc.legacyID {
				t.Fatalf("legacy=%+v", got.LegacyEvent)
			}
			if got.Session.Status != tc.sessionStatus || got.Session.Reason != tc.sessionReason || got.Session.ID != tc.sessionID {
				t.Fatalf("session=%+v", got.Session)
			}
			if got.Alert.Status != tc.alertStatus || got.Alert.Reason != tc.alertReason || got.Alert.ID != tc.alertID {
				t.Fatalf("alert=%+v", got.Alert)
			}
		})
	}
}
