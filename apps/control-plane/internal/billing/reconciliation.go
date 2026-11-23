package billing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	billingstates "github.com/yangjiyj/aiguard/packages/shared-go/billingstates"
)

type ReconciliationResult struct {
	Released int
	Settled  int
	Pending  int
	// Failed counts items whose settlement or release errored out without
	// being a concurrent-finalization race. Errors are isolated per item so
	// one bad row can no longer stall the whole batch.
	Failed int
}

// Reconciliation terminal decisions delegate to the shared billingstates
// package so reconciliation and the gateway's real-time accounting path can
// never drift (see packages/shared-go/billingstates for the full evidence
// decision table). A settle decision is never made from the status string
// alone: it requires the request log's raw token columns (the usage evidence
// FinalizeRequestLog persists) and must not contradict the gateway's
// recorded billing_outcome.

// ReconcileFailedReservations preserves the legacy released-count API while
// ReconcileStaleReservations also recovers durable successful/incomplete calls.
func (s *Store) ReconcileFailedReservations(ctx context.Context, olderThan time.Duration, limit int) (int, error) {
	result, err := s.ReconcileStaleReservations(ctx, olderThan, limit)
	return result.Released, err
}

// reconcileTarget is one stale reservation row with its whole durable
// evidence chain read from the reservation and request_logs join.
type reconcileTarget struct {
	tenantID, requestID, status string
	promptTokens, outputTokens  sql.NullInt64
	billingOutcome              string
	upstreamOutcome             string
	usageSource                 string
	hasAdmissionSnapshot        bool
}

// ReconcileStaleReservations shares the gateway's terminal states (see
// packages/shared-go/billingstates for the full evidence decision table):
// durable success/incomplete (including cancel, stream abort and provider
// timeout) request logs are settled from their usage evidence — the raw
// request_log token columns, which are NULL exactly when the gateway
// finalize never ran, so a settle status without token evidence stays
// pending — only definitive failures are released (evidence independent, so
// provider_unavailable with recorded tokens is still released), and
// reservations without executable evidence stay reserved. Generic error and
// provider_error are NOT definitive failures — the request may have been
// dispatched upstream — so they stay pending with the wallet freeze intact.
// A reservation whose request log never appeared also stays reserved with
// its wallet freeze untouched: missing evidence is never treated as failure,
// so the operator resolves it via the stale_reservation exception instead of
// an automatic release. Rows without executable evidence (received, unknown
// status, error, provider_error, settle status without usage proof, no
// request log) never occupy the batch limit, so a backlog of pending
// requests cannot starve out compensation, and per-item errors are isolated.
func (s *Store) ReconcileStaleReservations(ctx context.Context, olderThan time.Duration, limit int) (ReconciliationResult, error) {
	return s.reconcileStaleReservations(ctx, olderThan, limit, false)
}

func (s *Store) ReconcileStaleMeteringReservations(ctx context.Context, olderThan time.Duration, limit int) (ReconciliationResult, error) {
	return s.reconcileStaleReservations(ctx, olderThan, limit, true)
}

func (s *Store) reconcileStaleReservations(ctx context.Context, olderThan time.Duration, limit int, metering bool) (ReconciliationResult, error) {
	if s == nil || s.db == nil {
		return ReconciliationResult{}, ErrInvalidWalletState
	}
	if olderThan <= 0 {
		olderThan = 15 * time.Minute
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	cutoff := time.Now().UTC().Add(-olderThan)
	// The limit is spent exclusively on rows with executable evidence: settle
	// family requires the request log's raw token columns to be present
	// (FinalizeRequestLog never writes NULL tokens, so NULL means the gateway
	// finalize never ran and no usage proof exists — the row counts as
	// pending instead), release family is evidence independent. Unknown
	// statuses and reservations without any request log are never eligible
	// for automatic settlement or release, so they cannot consume the limit
	// and starve out resolvable rows; they are only counted.
	settleStatuses := make([]string, 0, len(billingstates.SettleStatuses))
	for status := range billingstates.SettleStatuses {
		settleStatuses = append(settleStatuses, status)
	}
	releaseStatuses := make([]string, 0, len(billingstates.DefinitiveFailureStatuses))
	for status := range billingstates.DefinitiveFailureStatuses {
		releaseStatuses = append(releaseStatuses, status)
	}
	terminalStatuses := make([]string, 0, len(reconciliationTerminalStatuses))
	for status := range reconciliationTerminalStatuses {
		terminalStatuses = append(terminalStatuses, status)
	}
	// The authoritative usage_source the gateway persisted in
	// output_audit_result.response_metadata.usage_source; NULL on legacy rows.
	usageSourceExpr := `COALESCE(l.output_audit_result->'response_metadata'->>'usage_source','')`
	// The authoritative usage_source enum from packages/shared-go/billingstates.
	// synthetic_no_upstream is intentionally absent: sharedDecide marks it
	// pending, so letting it into this list would let a non-settleable row
	// occupy the batch limit and starve compensation behind it. Every value
	// listed here must be one sharedDecide can settle.
	usageSourceList := []string{
		"upstream", "upstream_total_adjusted",
		"estimated_reservation", "estimated_reservation_invalid_usage",
		"estimated_incomplete", "estimated_incomplete_invalid_usage",
	}
	// A settle-family row occupies the batch limit ONLY when its whole
	// evidence chain is executable in SQL, so any row the Go-side Decide
	// would mark pending can never consume the limit ahead of resolvable
	// rows: raw token columns present, no gateway release contradiction, and
	// a usage source that is either the legacy success case or in the
	// authoritative enum — estimated_* additionally requiring the
	// reservation admission snapshot.
	//
	// The admission snapshot is the FROZEN PRICE BINDING, not admitted_at or the
	// reserved amount: admitted_at is NOT NULL DEFAULT NOW() and the amount
	// constraint already guarantees a positive micros-or-tokens reservation, so
	// testing those approves every row and makes HasApprovedEstimate effectively
	// hardcoded true. price_id is written only by the priced admission path, and
	// ck_billing_reservation_quote ties it to model_name + customer_group. A
	// legitimately free admission (reserved_micros 0 with reserved tokens,
	// which the constraint allows) still carries its price_id, so free is
	// admitted rather than rejected.
	admissionSnapshotSQL := "r.price_id IS NOT NULL AND r.price_id <> '' AND r.admitted_at IS NOT NULL"
	settleEligible := `(
		      l.request_status = ANY($3)
		      AND l.input_tokens IS NOT NULL AND l.output_tokens IS NOT NULL
		      AND COALESCE(l.billing_outcome,'') <> 'released'
		      AND (
		           ((` + usageSourceExpr + ` = '') AND l.request_status = 'success')
		           OR ` + usageSourceExpr + ` = ANY($5)
		      )
		      AND (
		           ` + usageSourceExpr + ` NOT LIKE 'estimated%'
		           OR ` + admissionSnapshotSQL + `
		      )
		  )`
	rows, err := s.db.Query(ctx, `
		SELECT DISTINCT r.tenant_id, r.request_id, l.request_status,
		       l.input_tokens, l.output_tokens, COALESCE(l.billing_outcome,''),
		       COALESCE(l.upstream_outcome,''),
		       `+usageSourceExpr+`,
		       `+admissionSnapshotSQL+`
		FROM billing_reservations r
		JOIN request_logs l ON l.tenant_id=r.tenant_id AND l.request_id=r.request_id
		WHERE r.status='reserved' AND r.created_at < $1
		  AND COALESCE(l.output_audit_result->'response_metadata'->>'billing_ingress','model_api') NOT IN ('forward_proxy','reverse_proxy')
		  AND (`+settleEligible+` OR l.request_status = ANY($4))
		ORDER BY r.tenant_id, r.request_id
		LIMIT $2
	`, cutoff, limit, settleStatuses, releaseStatuses, usageSourceList)
	if err != nil {
		return ReconciliationResult{}, fmt.Errorf("list stale billing reservations: %w", err)
	}
	targets := make([]reconcileTarget, 0, limit)
	for rows.Next() {
		var item reconcileTarget
		if err := rows.Scan(&item.tenantID, &item.requestID, &item.status, &item.promptTokens, &item.outputTokens,
			&item.billingOutcome, &item.upstreamOutcome, &item.usageSource, &item.hasAdmissionSnapshot); err != nil {
			rows.Close()
			return ReconciliationResult{}, fmt.Errorf("scan stale billing reservation: %w", err)
		}
		targets = append(targets, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return ReconciliationResult{}, fmt.Errorf("iterate stale billing reservations: %w", err)
	}
	rows.Close()

	result := ReconciliationResult{}
	var firstErr error
	for _, item := range targets {
		// The evidence-based decision is re-checked in Go so the SQL
		// prefilter and the action can never disagree: settle requires
		// recorded usage proof, an authoritative (or legacy-success) usage
		// source, an admission snapshot behind estimated_* sources, and must
		// not contradict a gateway release.
		usageRecorded := item.promptTokens.Valid && item.outputTokens.Valid
		var promptTokens, outputTokens int64
		if usageRecorded {
			promptTokens, outputTokens = item.promptTokens.Int64, item.outputTokens.Int64
		}
		terminal := ""
		switch billingstates.Decide(item.status, billingstates.Evidence{
			UsageRecorded:       usageRecorded,
			PromptTokens:        promptTokens,
			OutputTokens:        outputTokens,
			UsageSource:         item.usageSource,
			HasApprovedEstimate: item.hasAdmissionSnapshot,
			UpstreamOutcome:     item.upstreamOutcome,
			BillingOutcome:      item.billingOutcome,
		}) {
		case billingstates.TerminalSettle:
			terminal = "settle"
		case billingstates.TerminalRelease:
			terminal = "release"
		default:
			terminal = "pending"
		}
		var err error
		switch terminal {
		case "settle":
			err = s.reconcileSettleFromRequestLogMode(ctx, item, promptTokens, outputTokens, metering)
			if err == nil {
				result.Settled++
			}
		case "release":
			_, _, err = s.Release(ctx, item.tenantID, item.requestID)
			if err == nil {
				result.Released++
			}
		default:
			result.Pending++
			continue
		}
		if err == nil {
			continue
		}
		if errors.Is(err, ErrIdempotencyConflict) || errors.Is(err, ErrReservationNotFound) {
			// A concurrent real-time finalize won the race; nothing to do.
			continue
		}
		result.Failed++
		if firstErr == nil {
			firstErr = fmt.Errorf("reconcile %s/%s: %w", item.tenantID, item.requestID, err)
		}
	}

	// Pending rows are counted, never processed: they have no executable
	// evidence yet, and counting them must not consume the batch limit. The
	// count mirrors the settle prefilter exactly: a settle-family row without
	// token evidence, with a gateway release contradiction, without a usable
	// usage source, or with an unapproved estimate counts as pending.
	var pending int64
	// The pending count is part of the operator-visible outcome: a failure to
	// count is returned as its own error instead of being swallowed by an
	// earlier per-item failure.
	if err := s.db.QueryRow(ctx, `
		/* reconciliation_pending_count */
		SELECT COUNT(DISTINCT (r.tenant_id, r.request_id))
		FROM billing_reservations r
		LEFT JOIN request_logs l ON l.tenant_id=r.tenant_id AND l.request_id=r.request_id
		WHERE r.status='reserved' AND r.created_at < $1
		  AND COALESCE(l.output_audit_result->'response_metadata'->>'billing_ingress','model_api') NOT IN ('forward_proxy','reverse_proxy')
		  AND (
		      l.request_id IS NULL
		      OR COALESCE(l.request_status,'') IN ('received','')
		      OR NOT (COALESCE(l.request_status,'') = ANY($2))
		      OR (
		          COALESCE(l.request_status,'') = ANY($3)
		          AND (
		              l.input_tokens IS NULL OR l.output_tokens IS NULL
		              OR COALESCE(l.billing_outcome,'') = 'released'
		              OR (
		                   NOT (
		                        (((`+usageSourceExpr+` = '') AND l.request_status = 'success')
		                         OR `+usageSourceExpr+` = ANY($4))
		                        AND (
		                             `+usageSourceExpr+` NOT LIKE 'estimated%'
		                             OR `+admissionSnapshotSQL+`
		                        )
		                   )
		              )
		          )
		      )
		  )
	`, cutoff, terminalStatuses, settleStatuses, usageSourceList).Scan(&pending); err != nil {
		return result, fmt.Errorf("count pending stale billing reservations: %w", err)
	}
	result.Pending += int(pending)
	if result.Failed > 0 && firstErr != nil {
		return result, fmt.Errorf("billing reconciliation isolated %d failure(s): %w", result.Failed, firstErr)
	}
	return result, nil
}

// reconciliationTerminalStatuses is the executable whitelist shared by the
// SQL pending count and documentation, sourced from the shared billingstates
// package: settle family plus definitive failures. Generic error and
// provider_error are deliberately excluded — they do not prove the request
// was never dispatched, so they stay pending and never occupy the limit.
var reconciliationTerminalStatuses = buildReconciliationTerminalStatuses()

func buildReconciliationTerminalStatuses() map[string]bool {
	statuses := make(map[string]bool, len(billingstates.SettleStatuses)+len(billingstates.DefinitiveFailureStatuses))
	for status := range billingstates.SettleStatuses {
		statuses[status] = true
	}
	for status := range billingstates.DefinitiveFailureStatuses {
		statuses[status] = true
	}
	return statuses
}

// reconcileSettleFromRequestLog settles one stale reservation from its
// request_log usage evidence. The raw_usage marker stays recovered_request_log
// so the existing cache true-up exception keeps applying to recovered charges;
// the authoritative gateway source, the upstream outcome and a legacy flag
// are recorded so operators can distinguish fully verified recoveries from
// legacy ones.
func (s *Store) reconcileSettleFromRequestLog(ctx context.Context, item reconcileTarget, promptTokens, outputTokens int64) error {
	return s.reconcileSettleFromRequestLogMode(ctx, item, promptTokens, outputTokens, false)
}

func (s *Store) reconcileSettleFromRequestLogMode(ctx context.Context, item reconcileTarget, promptTokens, outputTokens int64, metering bool) error {
	reservation, err := s.GetReservation(ctx, item.tenantID, item.requestID)
	if err != nil {
		return err
	}
	price, err := s.GetModelPriceByID(ctx, item.tenantID, reservation.PriceID)
	if err != nil {
		return err
	}
	usage := Usage{PromptTokens: promptTokens, OutputTokens: outputTokens}
	var detailed []byte
	var endpoint string
	err = s.db.QueryRow(ctx, `SELECT COALESCE(output_audit_result->'response_metadata'->'billing_usage','null'::jsonb),COALESCE(endpoint_type,'') FROM request_logs WHERE tenant_id=$1 AND request_id=$2 ORDER BY created_at DESC LIMIT 1`, item.tenantID, item.requestID).Scan(&detailed, &endpoint)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	hasDetailed := len(detailed) > 0 && string(detailed) != "null"
	if hasDetailed {
		if json.Unmarshal(detailed, &usage) != nil || usage.PromptTokens != promptTokens || usage.OutputTokens != outputTokens || validateUsage(usage) != nil {
			return ErrInvalidUsage
		}
	}
	// New image specifications cannot be reconstructed from two token columns.
	// Missing evidence must retain the hold for operator resolution.
	if price.Extensions.ImagePricing != nil && endpoint == "images" && (!hasDetailed || !usage.ImageRequest) {
		return fmt.Errorf("%w: detailed image billing evidence is missing", ErrInvalidUsage)
	}
	source := "recovered_request_log"
	if hasDetailed {
		source = "recovered_request_log_detailed"
	}
	rawUsage, _ := json.Marshal(map[string]any{
		"usage_source": source, "cache_breakdown_available": hasDetailed,
		"terminal_status":  item.status,
		"gateway_source":   item.usageSource,
		"upstream_outcome": item.upstreamOutcome,
		"legacy_recovered": item.usageSource == "",
	})
	if metering {
		wallet, e := s.GetWallet(ctx, item.tenantID, reservation.WalletID)
		if e != nil {
			return e
		}
		tariff := reservationTariff(reservation)
		ratio := reservation.CustomerGroupRatioPPM
		requestStatus := "success"
		estimated := strings.HasPrefix(item.usageSource, "estimated")
		if estimated {
			requestStatus = "incomplete"
		}
		_, e = s.RecordMeteringUsage(ctx, MeteringInput{TenantID: item.tenantID, UserID: wallet.UserID, RequestID: item.requestID, ModelName: reservation.ModelName, RequestStatus: requestStatus, Usage: usage, AdmittedAt: reservation.AdmittedAt, QuotePriceID: reservation.PriceID, QuoteGroupRatioPPM: &ratio, QuoteTariff: &tariff, Estimated: estimated, RawUsage: rawUsage})
		return e
	}
	_, _, err = s.SettleCharge(ctx, item.tenantID, item.requestID, price, usage, rawUsage, nil)
	return err
}
