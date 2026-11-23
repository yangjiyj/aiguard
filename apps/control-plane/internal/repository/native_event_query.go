package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type NativeEventFilter struct {
	EndpointID, SourceID, RefHash string
	BeforeSequence                int64
	Limit                         int
}
type NativeEventResolution struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	ID     string `json:"id,omitempty"`
}
type NativeEventInvestigation struct {
	LegacyEvent NativeEventResolution `json:"legacy_event"`
	Session     NativeEventResolution `json:"session"`
	Alert       NativeEventResolution `json:"alert"`
}
type NativeEventObservation struct {
	SequenceID    int64                     `json:"sequence_id"`
	EndpointID    string                    `json:"endpoint_id"`
	EventID       string                    `json:"event_id"`
	SourceID      string                    `json:"source_id"`
	Producer      json.RawMessage           `json:"producer"`
	EventType     string                    `json:"event_type"`
	OccurredAt    time.Time                 `json:"occurred_at"`
	ReceivedAt    time.Time                 `json:"received_at"`
	References    json.RawMessage           `json:"references"`
	Outcome       string                    `json:"outcome,omitempty"`
	Status        string                    `json:"status,omitempty"`
	Payload       json.RawMessage           `json:"payload,omitempty"`
	Investigation *NativeEventInvestigation `json:"investigation,omitempty"`
}
type NativeEventPage struct {
	Items              []NativeEventObservation `json:"items"`
	NextBeforeSequence int64                    `json:"next_before_sequence,omitempty"`
	OrderBasis         string                   `json:"order_basis"`
	Provenance         string                   `json:"provenance"`
}

func buildNativeEventInvestigation(eventType, legacyClaim string, legacyCount int, matchedLegacyID, sessionClaim string, sessionCount int, matchedSessionID, alertClaim string, alertCount int, matchedAlertID string) *NativeEventInvestigation {
	links := &NativeEventInvestigation{}
	if eventType != "action.observed" {
		links.LegacyEvent = NativeEventResolution{Status: "not_applicable", Reason: "not_action_observed"}
		links.Session = NativeEventResolution{Status: "not_applicable", Reason: "not_action_observed"}
		links.Alert = NativeEventResolution{Status: "not_applicable", Reason: "not_action_observed"}
		return links
	}
	switch {
	case legacyClaim == "":
		links.LegacyEvent = NativeEventResolution{Status: "missing", Reason: "no_legacy_event_id"}
	case legacyCount == 0:
		links.LegacyEvent = NativeEventResolution{Status: "missing", Reason: "no_same_tenant_endpoint_match"}
	case legacyCount > 1:
		links.LegacyEvent = NativeEventResolution{Status: "ambiguous", Reason: "multiple_same_tenant_endpoint_matches"}
	case matchedLegacyID != legacyClaim:
		links.LegacyEvent = NativeEventResolution{Status: "missing", Reason: "exact_legacy_id_mismatch"}
	default:
		links.LegacyEvent = NativeEventResolution{Status: "matched", ID: matchedLegacyID}
	}
	if links.LegacyEvent.Status != "matched" {
		links.Session = NativeEventResolution{Status: "unavailable", Reason: "legacy_event_unresolved"}
		links.Alert = NativeEventResolution{Status: "unavailable", Reason: "legacy_event_unresolved"}
		return links
	}
	switch {
	case sessionClaim == "":
		links.Session = NativeEventResolution{Status: "missing", Reason: "no_session_id"}
	case sessionCount == 0:
		links.Session = NativeEventResolution{Status: "missing", Reason: "no_same_tenant_endpoint_session"}
	case sessionCount > 1:
		links.Session = NativeEventResolution{Status: "ambiguous", Reason: "multiple_same_tenant_endpoint_sessions"}
	case matchedSessionID != sessionClaim:
		links.Session = NativeEventResolution{Status: "missing", Reason: "exact_session_id_mismatch"}
	default:
		links.Session = NativeEventResolution{Status: "matched", ID: matchedSessionID}
	}
	switch {
	case alertClaim == "":
		links.Alert = NativeEventResolution{Status: "missing", Reason: "no_security_event_id"}
	case alertCount == 0:
		links.Alert = NativeEventResolution{Status: "missing", Reason: "no_exact_agent_endpoint_alert"}
	case alertCount > 1:
		links.Alert = NativeEventResolution{Status: "ambiguous", Reason: "multiple_exact_agent_endpoint_alerts"}
	case matchedAlertID != alertClaim:
		links.Alert = NativeEventResolution{Status: "missing", Reason: "exact_security_event_id_mismatch"}
	default:
		links.Alert = NativeEventResolution{Status: "matched", ID: matchedAlertID}
	}
	return links
}

func validNativeHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func nativeEventListQuery(tenant string, f NativeEventFilter) (string, []any, error) {
	if tenant == "" || len(f.EndpointID) > 256 || f.BeforeSequence < 0 || f.Limit < 1 || f.Limit > 200 ||
		(f.SourceID != "" && !validNativeHash(f.SourceID)) ||
		(f.RefHash != "" && (!validNativeHash(f.RefHash) || f.SourceID == "")) {
		return "", nil, ErrNativeEventInvalid
	}
	args := []any{tenant}
	where := []string{"e.tenant_id=$1"}
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if f.EndpointID != "" {
		add("e.endpoint_id=$%d", f.EndpointID)
	}
	if f.SourceID != "" {
		add("e.source_id=$%d", f.SourceID)
	}
	if f.BeforeSequence > 0 {
		add("e.sequence_id<$%d", f.BeforeSequence)
	}
	if f.RefHash != "" {
		add(`EXISTS(SELECT 1 FROM agent_native_event_refs match
   WHERE match.tenant_id=e.tenant_id AND match.endpoint_id=e.endpoint_id
    AND match.event_id=e.event_id AND match.source_id=e.source_id AND match.ref_hash=$%d)`, f.RefHash)
	}
	args = append(args, f.Limit)
	query := `SELECT e.sequence_id,e.endpoint_id,e.event_id::text,e.source_id,e.producer,
 e.event_type,e.source_occurred_at,e.received_at,
 COALESCE((SELECT jsonb_agg(jsonb_build_object('role',r.role,'ref_hash',r.ref_hash,'ref',r.native_ref) ORDER BY r.role)
  FROM agent_native_event_refs r WHERE r.tenant_id=e.tenant_id AND r.endpoint_id=e.endpoint_id
   AND r.event_id=e.event_id AND r.source_id=e.source_id),'[]'::jsonb),
 COALESCE(e.payload->>'outcome',''),COALESCE(e.payload->>'status',''),e.payload,
 CASE WHEN e.event_type='action.observed' THEN COALESCE(e.payload->>'legacy_event_id','') ELSE '' END,
 legacy.match_count,legacy.matched_id,legacy.session_id,
 session_match.match_count,session_match.session_id,
 legacy.security_event_id,alert_match.match_count,alert_match.id
 FROM agent_native_events e
 LEFT JOIN LATERAL (
  SELECT count(*)::int AS match_count,COALESCE(min(ae.id),'') AS matched_id,
   COALESCE(min(ae.session_id),'') AS session_id,COALESCE(min(ae.security_event_id),'') AS security_event_id
  FROM agent_events ae
  WHERE e.event_type='action.observed' AND COALESCE(e.payload->>'legacy_event_id','')<>''
   AND ae.tenant_id=e.tenant_id AND ae.endpoint_id=e.endpoint_id AND ae.id=e.payload->>'legacy_event_id'
 ) legacy ON TRUE
 LEFT JOIN LATERAL (
  SELECT count(*)::int AS match_count,COALESCE(min(s.session_id),'') AS session_id
  FROM agent_sessions s
  WHERE legacy.match_count=1 AND legacy.session_id<>''
   AND s.tenant_id=e.tenant_id AND s.session_id=legacy.session_id AND s.endpoint_id=e.endpoint_id
 ) session_match ON TRUE
 LEFT JOIN LATERAL (
  SELECT count(*)::int AS match_count,COALESCE(min(se.id),'') AS id
  FROM security_events se
  WHERE legacy.match_count=1 AND legacy.security_event_id<>''
   AND se.tenant_id=e.tenant_id AND se.id=legacy.security_event_id
   AND se.matched_summary->>'source'='agent_endpoint'
   AND se.matched_summary->>'endpoint_id'=e.endpoint_id
   AND se.matched_summary->>'agent_event_id'=legacy.matched_id
 ) alert_match ON TRUE
 WHERE ` + strings.Join(where, " AND ") + fmt.Sprintf(" ORDER BY e.sequence_id DESC LIMIT $%d", len(args))
	return query, args, nil
}

// List returns presentation order only. The cursor is for bounded pagination,
// not a commit watermark, causal ordering, or an ingestion/change-feed ACK.
func (r *NativeEventLedger) List(ctx context.Context, tenant string, f NativeEventFilter) (*NativeEventPage, error) {
	q, args, err := nativeEventListQuery(tenant, f)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := &NativeEventPage{Items: []NativeEventObservation{}, OrderBasis: "server_sequence_desc_not_causal", Provenance: "authenticated_endpoint_with_reported_native_claims"}
	for rows.Next() {
		var v NativeEventObservation
		var legacyClaim, matchedLegacyID, sessionClaim, matchedSessionID, alertClaim, matchedAlertID string
		var legacyCount, sessionCount, alertCount int
		if err = rows.Scan(&v.SequenceID, &v.EndpointID, &v.EventID, &v.SourceID, &v.Producer, &v.EventType, &v.OccurredAt, &v.ReceivedAt, &v.References, &v.Outcome, &v.Status, &v.Payload,
			&legacyClaim, &legacyCount, &matchedLegacyID, &sessionClaim, &sessionCount, &matchedSessionID, &alertClaim, &alertCount, &matchedAlertID); err != nil {
			return nil, err
		}
		v.Investigation = buildNativeEventInvestigation(v.EventType, legacyClaim, legacyCount, matchedLegacyID, sessionClaim, sessionCount, matchedSessionID, alertClaim, alertCount, matchedAlertID)
		result.Items = append(result.Items, v)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(result.Items) == f.Limit {
		result.NextBeforeSequence = result.Items[len(result.Items)-1].SequenceID
	}
	return result, nil
}
