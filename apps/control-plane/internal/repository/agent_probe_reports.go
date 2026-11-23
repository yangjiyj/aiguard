package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/probereports"
	"github.com/jackc/pgx/v5"
)

var (
	ErrAiprobeReportInvalid  = errors.New("invalid aiprobe report")
	ErrAiprobeReportConflict = errors.New("aiprobe report identity conflicts with stored content")
)

type AiprobeReportReceipt struct {
	SchemaVersion string `json:"schema_version"`
	ReportID      string `json:"report_id"`
	Accepted      bool   `json:"accepted"`
	Duplicate     bool   `json:"duplicate"`
	AssetCount    int    `json:"asset_count"`
}

func (r *AgentEndpointRepository) AcceptAiprobeReport(ctx context.Context, tenant, endpoint string, report *probereports.Report) (*AiprobeReportReceipt, error) {
	if report == nil || strings.TrimSpace(tenant) == "" || strings.TrimSpace(endpoint) == "" ||
		report.EndpointID != endpoint || report.Validate() != nil {
		return nil, ErrAiprobeReportInvalid
	}
	occurredAt, err := time.Parse(time.RFC3339, report.ScannedAt)
	if err != nil {
		return nil, ErrAiprobeReportInvalid
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshal aiprobe report: %w", err)
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,859))`, tenant+"\x1f"+endpoint+"\x1f"+report.ReportID); err != nil {
		return nil, err
	}
	var existingEndpoint, existingType string
	var samePayload bool
	err = tx.QueryRow(ctx, `SELECT endpoint_id,event_type,payload=$3::jsonb FROM agent_events WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, report.ReportID, payload).Scan(&existingEndpoint, &existingType, &samePayload)
	if err == nil {
		if existingEndpoint != endpoint || existingType != "aiprobe.report.v1" || !samePayload {
			return nil, ErrAiprobeReportConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &AiprobeReportReceipt{SchemaVersion: "aiprobe.report.ack.v1", ReportID: report.ReportID, Duplicate: true, AssetCount: len(report.Assets)}, nil
	}
	if err != pgx.ErrNoRows {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO agent_events(id,tenant_id,endpoint_id,event_type,occurred_at,payload)
		VALUES($1,$2,$3,'aiprobe.report.v1',$4,$5::jsonb)`, report.ReportID, tenant, endpoint, occurredAt, payload); err != nil {
		return nil, fmt.Errorf("insert aiprobe report ledger row: %w", err)
	}
	for _, item := range report.Assets {
		destinationVerdicts, verifyErr := verifyAiprobeAssetDestinations(ctx, tx, tenant, item)
		if verifyErr != nil {
			return nil, fmt.Errorf("verify aiprobe destination approvals %s: %w", item.SourceID, verifyErr)
		}
		if err = persistAiprobeDestinationApprovalObservations(ctx, tx, tenant, endpoint, report.ReportID, item, destinationVerdicts, occurredAt); err != nil {
			return nil, fmt.Errorf("persist aiprobe destination approvals %s: %w", item.SourceID, err)
		}
		evidence, marshalErr := projectAiprobeAssetEvidence(report, item, destinationVerdicts)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal aiprobe asset evidence: %w", marshalErr)
		}
		record := &agentEventRecord{
			ID: report.ReportID, EventType: "aiprobe.report.v1", EndpointID: endpoint,
			OccurredAt: occurredAt, InstanceKey: "aiprobe:" + item.SourceID, UnifiedNativeID: "aiprobe:" + item.SourceID,
			Asset: &agentEventAsset{
				AssetType: item.Kind, Name: item.Name, Version: item.Version, Source: "aiprobe",
				Hash: item.ContentHash, Evidence: evidence, Present: true, ScanStatus: item.CollectionStatus,
			},
		}
		if err = upsertAgentEndpointAsset(ctx, tx, tenant, endpoint, record); err != nil {
			return nil, fmt.Errorf("project aiprobe asset %s: %w", item.SourceID, err)
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_endpoints SET
		last_event_at=GREATEST(COALESCE(last_event_at,to_timestamp(0)),$3),
		event_count=(SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND endpoint_id=$2),
		updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, endpoint, occurredAt); err != nil {
		return nil, fmt.Errorf("update aiprobe endpoint receipt: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AiprobeReportReceipt{SchemaVersion: "aiprobe.report.ack.v1", ReportID: report.ReportID, Accepted: true, AssetCount: len(report.Assets)}, nil
}

// aiprobeDestinationVerdict pairs one reported destination (official or relay
// alike — classification never changes the check) with the server's own
// verification, keeping the client's claim and the server's verdict distinct
// all the way through to storage. destinationRef distinguishes the asset's
// singular Evidence.Endpoint (ref "endpoint") from Evidence.Destinations[i]
// (ref "destinations[i]") for the observation table's per-destination key.
type aiprobeDestinationVerdict struct {
	destinationRef string
	index          int
	destination    probereports.Destination
	verification   DestinationApprovalVerification
}

// verifyAiprobeAssetDestinations re-derives server-side approval for every
// destination an asset reported — the single Evidence.Endpoint plus the full
// Evidence.Destinations list — using the same tenant catalog check for both
// official- and relay-classified entries. It never reads
// destination.ApprovalStatus/ApprovalBasis/ApprovalRuleID as the answer; that
// is the client's claim, verified independently here.
func verifyAiprobeAssetDestinations(ctx context.Context, tx destinationApprovalQueryer, tenant string, asset probereports.Asset) ([]aiprobeDestinationVerdict, error) {
	var verdicts []aiprobeDestinationVerdict
	if asset.Evidence.Endpoint != nil {
		verification, err := verifyDestinationApprovalTx(ctx, tx, tenant, *asset.Evidence.Endpoint)
		if err != nil {
			return nil, err
		}
		verdicts = append(verdicts, aiprobeDestinationVerdict{destinationRef: "endpoint", index: -1, destination: *asset.Evidence.Endpoint, verification: verification})
	}
	for i, destination := range asset.Evidence.Destinations {
		verification, err := verifyDestinationApprovalTx(ctx, tx, tenant, destination)
		if err != nil {
			return nil, err
		}
		verdicts = append(verdicts, aiprobeDestinationVerdict{destinationRef: "destinations", index: i, destination: destination, verification: verification})
	}
	return verdicts, nil
}

// persistAiprobeDestinationApprovalObservations records, for every reported
// destination, the client's claimed approval fields and the server's verified
// verdict as two separate rows of columns. A forged, disabled, or
// non-matching rule_id is recorded as whatever verifyAiprobeAssetDestinations
// resolved (not_listed/unreviewed/invalid_claim), never silently promoted to
// approved.
func persistAiprobeDestinationApprovalObservations(ctx context.Context, tx unifiedAssetExecTx, tenant, endpoint, reportID string, asset probereports.Asset, verdicts []aiprobeDestinationVerdict, observedAt time.Time) error {
	for _, v := range verdicts {
		destinationIndex := v.index
		if v.destinationRef == "endpoint" {
			// The singular Evidence.Endpoint has no natural array index; -1
			// is reserved for it and Destinations[] use their real index
			// (>=0), so the two can never collide under the observation
			// table's (report_id, asset_source_id, destination_index) key.
			destinationIndex = -1
		}
		var matchedRowID *string
		if v.verification.MatchedRowID != "" {
			id := v.verification.MatchedRowID
			matchedRowID = &id
		}
		obs := AgentDestinationApprovalObservation{
			EndpointID: endpoint, ReportID: reportID, AssetSourceID: asset.SourceID, DestinationIndex: destinationIndex,
			Origin: v.destination.Origin, Classification: v.destination.Classification,
			ClientClaimedStatus: v.destination.ApprovalStatus, ClientClaimedBasis: v.destination.ApprovalBasis, ClientClaimedRuleID: v.destination.ApprovalRuleID,
			ServerVerifiedStatus: v.verification.Status, ServerVerifiedRuleID: v.verification.MatchedRuleID, ServerMatchedRuleRowID: matchedRowID,
			ObservedAt: observedAt,
		}
		if err := insertDestinationApprovalObservation(ctx, tx, tenant, obs); err != nil {
			return err
		}
	}
	return nil
}

func projectAiprobeAssetEvidence(report *probereports.Report, asset probereports.Asset, verdicts []aiprobeDestinationVerdict) ([]byte, error) {
	if report == nil {
		return nil, ErrAiprobeReportInvalid
	}
	destinationApprovals := make([]map[string]any, 0, len(verdicts))
	for _, v := range verdicts {
		destinationApprovals = append(destinationApprovals, map[string]any{
			"ref":            v.destinationRef,
			"index":          v.index,
			"origin":         v.destination.Origin,
			"classification": v.destination.Classification,
			"client_claimed": map[string]any{
				"approval_status":  v.destination.ApprovalStatus,
				"approval_basis":   v.destination.ApprovalBasis,
				"approval_rule_id": v.destination.ApprovalRuleID,
			},
			"server_verified": map[string]any{
				"status":  v.verification.Status,
				"rule_id": v.verification.MatchedRuleID,
			},
		})
	}
	return json.Marshal(map[string]any{
		"report_status":         report.Status,
		"collection_status":     asset.CollectionStatus,
		"collectors":            report.Collectors,
		"source_id":             asset.SourceID,
		"name":                  asset.Name,
		"display_name":          asset.DisplayName,
		"running":                asset.Running,
		"confidence":             asset.Confidence,
		"evidence_labels":        asset.EvidenceLabels,
		"risk_flags":             asset.RiskFlags,
		"destination_approvals":  destinationApprovals,
		"values":                 asset.Evidence,
	})
}
