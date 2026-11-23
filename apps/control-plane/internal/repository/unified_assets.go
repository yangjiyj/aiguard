package repository

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrAgentUnifiedAssetNotFound = errors.New("unified asset not found")
	ErrAgentAssetOwnerNotFound   = errors.New("asset owner is not in tenant")
	ErrAgentAssetSourceConflict  = errors.New("source identity is already linked to another asset")
	ErrAgentAssetMergeConflict   = errors.New("asset metadata conflicts; reconcile ownership or catalog first")
	ErrAgentAssetInvalidInput    = errors.New("invalid unified asset input")
)

type AgentUnifiedAssetRepository struct{ db *pgxpool.Pool }

type unifiedAssetExecTx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func unifiedAssetTenantLockKey(tenant string) string {
	return tenant + "\x1fagent_unified_assets_write_v1"
}

// All source-ref changes, endpoint projections, and merges acquire this lock
// before touching asset/ref rows. That consistent tenant-scoped order prevents
// Merge/upsert FK and source-ref row locks from forming a deadlock cycle.
func lockUnifiedAssetTenantWrite(ctx context.Context, tx unifiedAssetExecTx, tenant string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, unifiedAssetTenantLockKey(tenant))
	return err
}

func NewAgentUnifiedAssetRepository(db *pgxpool.Pool) *AgentUnifiedAssetRepository {
	return &AgentUnifiedAssetRepository{db: db}
}

type AgentUnifiedAssetFilter struct {
	AssetID, AssetType, CatalogStatus string
	Page, PageSize                    int
}

type AgentUnifiedAsset struct {
	ID                    string     `json:"id"`
	AssetType             string     `json:"asset_type"`
	Name                  string     `json:"name"`
	OwnerUserID           string     `json:"owner_user_id"`
	BusinessUnit          string     `json:"business_unit"`
	BusinessService       string     `json:"business_service"`
	CatalogStatus         string     `json:"catalog_status"`
	CatalogReason         string     `json:"catalog_reason"`
	CatalogExpiresAt      *time.Time `json:"catalog_expires_at,omitempty"`
	FirstSeen             time.Time  `json:"first_seen"`
	LastSeen              time.Time  `json:"last_seen"`
	InstanceCount         int        `json:"instance_count"`
	ManagedInstanceCount  int        `json:"managed_instance_count"`
	ObservedInstanceCount int        `json:"observed_instance_count"`
	ControlEvidenceCount  int        `json:"control_evidence_count"`
	Discovered            bool       `json:"discovered"`
	Managed               bool       `json:"managed"`
	Observed              bool       `json:"observed"`
	Controlled            bool       `json:"controlled"`
	ControlState          string     `json:"control_state"`
}

type AgentUnifiedAssetPage struct {
	Items []AgentUnifiedAsset `json:"items"`
	AgentAdminPage
}

type AgentUnifiedAssetHistoryItem struct {
	ID               string          `json:"id"`
	AssetID          string          `json:"asset_id"`
	SourceAssetID    string          `json:"source_asset_id"`
	InstanceID       string          `json:"instance_id"`
	SourceType       string          `json:"source_type"`
	SourceNamespace  string          `json:"source_namespace"`
	NativeID         string          `json:"native_id"`
	SourceEventID    string          `json:"source_event_id"`
	Provenance       string          `json:"provenance"`
	SourceOccurredAt time.Time       `json:"source_occurred_at"`
	ReceivedAt       time.Time       `json:"received_at"`
	Name             string          `json:"name"`
	Version          string          `json:"version"`
	Hash             string          `json:"hash"`
	Present          bool            `json:"present"`
	ScanStatus       string          `json:"scan_status"`
	ScanDecision     string          `json:"scan_decision"`
	Evidence         json.RawMessage `json:"evidence"`
}

type AgentUnifiedAssetHistoryPage struct {
	Items []AgentUnifiedAssetHistoryItem `json:"items"`
	AgentAdminPage
}

type AgentAssetOwnershipUpdate struct {
	OwnerUserID     string
	BusinessUnit    string
	BusinessService string
}

type AgentAssetCatalogUpdate struct {
	Status    string
	Reason    string
	ExpiresAt *time.Time
}

type AgentAssetSourceRef struct {
	SourceType      string
	SourceNamespace string
	NativeID        string
}

func stableUnifiedAssetID(prefix string, values ...string) string {
	sum := md5.Sum([]byte(strings.Join(values, "\x1f")))
	return prefix + hex.EncodeToString(sum[:])
}

func unifiedAssetIdentityKey(sourceType, sourceNamespace, nativeID string) string {
	return sourceType + "\x1f" + sourceNamespace + "\x1f" + nativeID
}

func unifiedEndpointAssetNativeID(assetType, name string) string {
	return strings.TrimSpace(assetType) + "\x1e" + strings.TrimSpace(name)
}

// T07 reports one native asset identity per endpoint but no producer-owned
// instance ID. Keep one current projection for that source identity and retain
// every version/hash in immutable observations instead of pretending versions
// are simultaneous instances.
func unifiedAssetInstanceKey() string {
	return "__source_native_identity__"
}

type agentUnifiedAssetIndicators struct {
	discovered, managed, observed, controlled bool
	controlState                              string
}

func deriveAgentUnifiedAssetIndicators(instances, managedInstances, observedInstances, controlEvidence int) agentUnifiedAssetIndicators {
	result := agentUnifiedAssetIndicators{
		discovered: instances > 0,
		managed:    managedInstances > 0,
		observed:   observedInstances > 0,
		controlled: controlEvidence > 0,
	}
	if result.controlled {
		result.controlState = "evidenced"
	} else {
		result.controlState = "not_evidenced"
	}
	return result
}

func (r *AgentUnifiedAssetRepository) List(ctx context.Context, tenant string, f AgentUnifiedAssetFilter) (*AgentUnifiedAssetPage, error) {
	clauses, args := []string{"a.tenant_id=$1", "a.merged_into_id IS NULL"}, []any{tenant}
	if f.AssetID != "" {
		args = append(args, f.AssetID)
		clauses = append(clauses, fmt.Sprintf("a.id=$%d", len(args)))
	}
	if f.AssetType != "" {
		args = append(args, f.AssetType)
		clauses = append(clauses, fmt.Sprintf("a.asset_type=$%d", len(args)))
	}
	if f.CatalogStatus != "" {
		switch f.CatalogStatus {
		case "unreviewed", "approved", "exception":
			args = append(args, f.CatalogStatus)
			clauses = append(clauses, fmt.Sprintf("a.catalog_status=$%d", len(args)))
		case "expired":
			clauses = append(clauses, "a.catalog_status='exception' AND a.catalog_expires_at<=now()")
		default:
			return nil, ErrAgentAssetInvalidInput
		}
	}
	where := " WHERE " + strings.Join(clauses, " AND ")
	page, size, offset := normalizeAgentPage(f.Page, f.PageSize)
	var total int
	if err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM agent_unified_assets a"+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	queryArgs := append(append([]any{}, args...), size, offset)
	query := `SELECT a.id,a.asset_type,a.display_name,COALESCE(a.owner_user_id,''),COALESCE(a.business_unit,''),
		COALESCE(a.business_service,''),
		CASE WHEN a.catalog_status='exception' AND a.catalog_expires_at<=now() THEN 'expired' ELSE a.catalog_status END,
		COALESCE(a.catalog_reason,''),a.catalog_expires_at,a.first_seen,
		COALESCE(stats.last_seen,a.last_seen),COALESCE(stats.instance_count,0),
		COALESCE(stats.managed_instance_count,0),COALESCE(stats.observed_instance_count,0),0::bigint
		FROM agent_unified_assets a
		LEFT JOIN LATERAL (
			SELECT COUNT(*) AS instance_count,
				COUNT(*) FILTER (WHERE i.endpoint_id IS NOT NULL AND e.id IS NOT NULL AND e.status IN ('active','stale')) AS managed_instance_count,
				COUNT(*) FILTER (WHERE i.present) AS observed_instance_count,
				MAX(i.last_observed_at) AS last_seen
			FROM agent_unified_asset_instances i
			LEFT JOIN agent_endpoints e ON e.tenant_id=i.tenant_id AND e.id=i.endpoint_id
			WHERE i.tenant_id=a.tenant_id AND i.asset_id=a.id
		) stats ON true` + where +
		fmt.Sprintf(" ORDER BY COALESCE(stats.last_seen,a.last_seen) DESC,a.id LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	rows, err := r.db.Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AgentUnifiedAsset{}
	for rows.Next() {
		var item AgentUnifiedAsset
		var expires sql.NullTime
		var instanceCount, managedCount, observedCount, controlCount int
		if err = rows.Scan(&item.ID, &item.AssetType, &item.Name, &item.OwnerUserID, &item.BusinessUnit,
			&item.BusinessService, &item.CatalogStatus, &item.CatalogReason, &expires, &item.FirstSeen, &item.LastSeen,
			&instanceCount, &managedCount, &observedCount, &controlCount); err != nil {
			return nil, err
		}
		if expires.Valid {
			value := expires.Time
			item.CatalogExpiresAt = &value
		}
		indicators := deriveAgentUnifiedAssetIndicators(instanceCount, managedCount, observedCount, controlCount)
		item.InstanceCount, item.ManagedInstanceCount = instanceCount, managedCount
		item.ObservedInstanceCount, item.ControlEvidenceCount = observedCount, controlCount
		item.Discovered, item.Managed, item.Observed = indicators.discovered, indicators.managed, indicators.observed
		item.Controlled, item.ControlState = indicators.controlled, indicators.controlState
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return &AgentUnifiedAssetPage{Items: items, AgentAdminPage: AgentAdminPage{Page: page, PageSize: size, Total: total}}, nil
}

// FindNativeReferenceAsset returns the current manual asset link for one exact
// source declaration. It is tenant-scoped and never derives a link from names or time.
func (r *AgentUnifiedAssetRepository) FindNativeReferenceAsset(ctx context.Context, tenant, sourceID, refHash string) (string, bool, error) {
	var assetID string
	query := "SELECT COALESCE(a.merged_into_id,a.id) " +
		"FROM agent_asset_source_refs s " +
		"JOIN agent_unified_assets a ON a.tenant_id=s.tenant_id AND a.id=s.asset_id " +
		"WHERE s.tenant_id=$1 AND s.source_type='identity_event' " +
		"AND s.source_namespace=$2 AND s.native_id=$3"
	err := r.db.QueryRow(ctx, query, tenant, "native:"+sourceID, refHash).Scan(&assetID)
	if err == pgx.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return assetID, true, nil
}

func (r *AgentUnifiedAssetRepository) ListHistory(ctx context.Context, tenant, assetID string, page, size int) (*AgentUnifiedAssetHistoryPage, bool, error) {
	var canonicalID string
	if err := r.db.QueryRow(ctx, `SELECT COALESCE(merged_into_id,id) FROM agent_unified_assets WHERE tenant_id=$1 AND id=$2`, tenant, assetID).Scan(&canonicalID); err != nil {
		if err == pgx.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	page, size, offset := normalizeAgentPage(page, size)
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_unified_asset_observations o
		JOIN agent_asset_source_refs s ON s.tenant_id=o.tenant_id AND s.id=o.source_ref_id
		WHERE o.tenant_id=$1 AND s.asset_id=$2`, tenant, canonicalID).Scan(&total); err != nil {
		return nil, false, err
	}
	rows, err := r.db.Query(ctx, `SELECT o.id,s.asset_id,o.source_asset_id,o.instance_id,
		s.source_type,s.source_namespace,s.native_id,o.source_event_id,o.provenance,
		o.source_occurred_at,o.received_at,o.display_name,o.version,o.content_hash,o.present,
		o.scan_status,o.scan_decision,o.evidence
		FROM agent_unified_asset_observations o
		JOIN agent_asset_source_refs s ON s.tenant_id=o.tenant_id AND s.id=o.source_ref_id
		WHERE o.tenant_id=$1 AND s.asset_id=$2
		ORDER BY o.received_at DESC,o.id LIMIT $3 OFFSET $4`, tenant, canonicalID, size, offset)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	items := []AgentUnifiedAssetHistoryItem{}
	for rows.Next() {
		var item AgentUnifiedAssetHistoryItem
		if err = rows.Scan(&item.ID, &item.AssetID, &item.SourceAssetID, &item.InstanceID,
			&item.SourceType, &item.SourceNamespace, &item.NativeID, &item.SourceEventID,
			&item.Provenance, &item.SourceOccurredAt, &item.ReceivedAt, &item.Name, &item.Version,
			&item.Hash, &item.Present, &item.ScanStatus, &item.ScanDecision, &item.Evidence); err != nil {
			return nil, false, err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	return &AgentUnifiedAssetHistoryPage{Items: items, AgentAdminPage: AgentAdminPage{Page: page, PageSize: size, Total: total}}, true, nil
}

func (r *AgentUnifiedAssetRepository) UpdateOwnership(ctx context.Context, tenant, assetID string, input AgentAssetOwnershipUpdate) (bool, error) {
	if input.OwnerUserID != "" {
		var exists bool
		if err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id=$1 AND id=$2)`, tenant, input.OwnerUserID).Scan(&exists); err != nil {
			return false, err
		}
		if !exists {
			return false, ErrAgentAssetOwnerNotFound
		}
	}
	tag, err := r.db.Exec(ctx, `UPDATE agent_unified_assets SET owner_user_id=NULLIF($3,''),business_unit=$4,business_service=$5,updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND merged_into_id IS NULL`, tenant, assetID, input.OwnerUserID, input.BusinessUnit, input.BusinessService)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() != 0, nil
}

func (r *AgentUnifiedAssetRepository) UpdateCatalog(ctx context.Context, tenant, assetID, actor string, input AgentAssetCatalogUpdate) (bool, error) {
	if input.Status != "approved" && input.Status != "exception" && input.Status != "unreviewed" {
		return false, ErrAgentAssetInvalidInput
	}
	reason := strings.TrimSpace(input.Reason)
	var expiresAt *time.Time
	if input.Status == "exception" {
		if reason == "" || input.ExpiresAt == nil || !input.ExpiresAt.After(time.Now()) {
			return false, ErrAgentAssetInvalidInput
		}
		expiresAt = input.ExpiresAt
	} else if reason != "" || input.ExpiresAt != nil {
		return false, ErrAgentAssetInvalidInput
	}
	tag, err := r.db.Exec(ctx, `UPDATE agent_unified_assets SET
		catalog_status=$3,catalog_reason=$4,catalog_expires_at=$5,
		catalog_updated_by=$6,catalog_updated_at=now(),updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND merged_into_id IS NULL`,
		tenant, assetID, input.Status, reason, expiresAt, actor)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() != 0, nil
}

func (r *AgentUnifiedAssetRepository) LinkSource(ctx context.Context, tenant, assetID, actor string, input AgentAssetSourceRef) error {
	if !validAgentAssetSourceRef(input) {
		return ErrAgentAssetInvalidInput
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = lockUnifiedAssetTenantWrite(ctx, tx, tenant); err != nil {
		return err
	}
	lockKey := tenant + "\x1f" + input.SourceType + "\x1f" + input.SourceNamespace + "\x1f" + input.NativeID
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return err
	}
	var lockedTarget string
	if err = tx.QueryRow(ctx, `SELECT id FROM agent_unified_assets WHERE tenant_id=$1 AND id=$2 AND merged_into_id IS NULL FOR UPDATE`, tenant, assetID).Scan(&lockedTarget); err != nil {
		if err == pgx.ErrNoRows {
			return ErrAgentUnifiedAssetNotFound
		}
		return err
	}
	refID := stableUnifiedAssetID("uasr_", tenant, input.SourceType, input.SourceNamespace, input.NativeID)
	_, err = tx.Exec(ctx, `INSERT INTO agent_asset_source_refs(id,tenant_id,asset_id,source_type,source_namespace,native_id,created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,source_type,source_namespace,native_id) DO NOTHING`,
		refID, tenant, assetID, input.SourceType, input.SourceNamespace, input.NativeID, actor)
	if err != nil {
		return err
	}
	var linkedAssetID string
	if err = tx.QueryRow(ctx, `SELECT asset_id FROM agent_asset_source_refs WHERE tenant_id=$1 AND source_type=$2 AND source_namespace=$3 AND native_id=$4`,
		tenant, input.SourceType, input.SourceNamespace, input.NativeID).Scan(&linkedAssetID); err != nil {
		return err
	}
	if linkedAssetID != assetID {
		return ErrAgentAssetSourceConflict
	}
	return tx.Commit(ctx)
}

func validAgentAssetSourceRef(input AgentAssetSourceRef) bool {
	// Endpoint references are created by authenticated ingestion, where the
	// server derives the endpoint namespace and structured type/name identity.
	// Manual linking is reserved for producer-authenticated identity events.
	if input.SourceType != "identity_event" {
		return false
	}
	for index, value := range []string{input.SourceNamespace, input.NativeID} {
		maxLength := 512
		if index == 0 {
			maxLength = 255
		}
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) || len(value) > maxLength || strings.ContainsAny(value, "\x1f\x1e") {
			return false
		}
	}
	return true
}

func (r *AgentUnifiedAssetRepository) Merge(ctx context.Context, tenant, sourceAssetID, targetAssetID string) (bool, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	ok, err := mergeAgentUnifiedAssetTx(ctx, tx, tenant, sourceAssetID, targetAssetID)
	if err != nil || !ok {
		return ok, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

type unifiedAssetMergeTx interface {
	unifiedAssetExecTx
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func mergeAgentUnifiedAssetTx(ctx context.Context, tx unifiedAssetMergeTx, tenant, sourceAssetID, targetAssetID string) (bool, error) {
	if sourceAssetID == "" || targetAssetID == "" {
		return false, ErrAgentAssetInvalidInput
	}
	if err := lockUnifiedAssetTenantWrite(ctx, tx, tenant); err != nil {
		return false, err
	}
	type row struct {
		id, owner, unit, service, status, reason, catalogUpdatedBy string
		expires, catalogUpdatedAt                                  sql.NullTime
		mergedID                                                   sql.NullString
		firstSeen, lastSeen                                        time.Time
	}
	rows, err := tx.Query(ctx, `SELECT id,COALESCE(owner_user_id,''),COALESCE(business_unit,''),
		COALESCE(business_service,''),catalog_status,COALESCE(catalog_reason,''),
		COALESCE(catalog_updated_by,''),catalog_expires_at,catalog_updated_at,merged_into_id,first_seen,last_seen
		FROM agent_unified_assets WHERE tenant_id=$1 AND id=ANY($2::text[]) ORDER BY id FOR UPDATE`,
		tenant, []string{sourceAssetID, targetAssetID})
	if err != nil {
		return false, err
	}
	byID := map[string]row{}
	for rows.Next() {
		var value row
		if err = rows.Scan(&value.id, &value.owner, &value.unit, &value.service, &value.status, &value.reason,
			&value.catalogUpdatedBy, &value.expires, &value.catalogUpdatedAt, &value.mergedID, &value.firstSeen, &value.lastSeen); err != nil {
			rows.Close()
			return false, err
		}
		byID[value.id] = value
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()
	source, sourceExists := byID[sourceAssetID]
	target, targetExists := byID[targetAssetID]
	if !sourceExists || !targetExists {
		return false, nil
	}
	if sourceAssetID == targetAssetID {
		return true, nil
	}
	if source.mergedID.Valid {
		if source.mergedID.String == targetAssetID {
			return true, nil
		}
		return false, ErrAgentAssetMergeConflict
	}
	if target.mergedID.Valid {
		return false, ErrAgentAssetMergeConflict
	}
	if (source.owner != "" && target.owner != "" && source.owner != target.owner) ||
		(source.unit != "" && target.unit != "" && source.unit != target.unit) ||
		(source.service != "" && target.service != "" && source.service != target.service) {
		return false, ErrAgentAssetMergeConflict
	}
	if source.status != "unreviewed" && target.status != "unreviewed" {
		expiriesEqual := (!source.expires.Valid && !target.expires.Valid) ||
			(source.expires.Valid && target.expires.Valid && source.expires.Time.Equal(target.expires.Time))
		if source.status != target.status || source.reason != target.reason || !expiriesEqual {
			return false, ErrAgentAssetMergeConflict
		}
	}
	status, reason, catalogUpdatedBy := target.status, target.reason, target.catalogUpdatedBy
	var expiresAt, catalogUpdatedAt *time.Time
	if target.expires.Valid {
		value := target.expires.Time
		expiresAt = &value
	}
	if target.catalogUpdatedAt.Valid {
		value := target.catalogUpdatedAt.Time
		catalogUpdatedAt = &value
	}
	if status == "unreviewed" && source.status != "unreviewed" {
		status, reason, catalogUpdatedBy = source.status, source.reason, source.catalogUpdatedBy
		if source.expires.Valid {
			value := source.expires.Time
			expiresAt = &value
		} else {
			expiresAt = nil
		}
		if source.catalogUpdatedAt.Valid {
			value := source.catalogUpdatedAt.Time
			catalogUpdatedAt = &value
		} else {
			catalogUpdatedAt = nil
		}
	}
	_, err = tx.Exec(ctx, `UPDATE agent_unified_assets SET
		owner_user_id=CASE WHEN COALESCE(owner_user_id,'')='' THEN NULLIF($3,'') ELSE owner_user_id END,
		business_unit=CASE WHEN business_unit='' THEN $4 ELSE business_unit END,
		business_service=CASE WHEN business_service='' THEN $5 ELSE business_service END,
		catalog_status=$6,catalog_reason=$7,catalog_expires_at=$8,catalog_updated_by=$9,catalog_updated_at=$10,
		first_seen=LEAST(first_seen,$11),last_seen=GREATEST(last_seen,$12),updated_at=now()
		WHERE tenant_id=$1 AND id=$2`, tenant, targetAssetID, source.owner, source.unit, source.service,
		status, reason, expiresAt, catalogUpdatedBy, catalogUpdatedAt, source.firstSeen, source.lastSeen)
	if err != nil {
		return false, err
	}
	for _, table := range []string{"agent_asset_source_refs", "agent_unified_asset_instances"} {
		if _, err = tx.Exec(ctx, `UPDATE `+table+` SET asset_id=$3 WHERE tenant_id=$1 AND asset_id=$2`, tenant, sourceAssetID, targetAssetID); err != nil {
			return false, err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_unified_assets SET merged_into_id=$3,updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, sourceAssetID, targetAssetID); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_unified_assets SET merged_into_id=$3,updated_at=now() WHERE tenant_id=$1 AND merged_into_id=$2`, tenant, sourceAssetID, targetAssetID); err != nil {
		return false, err
	}
	return true, nil
}

type unifiedEndpointAssetTx interface {
	unifiedAssetExecTx
	QueryRow(context.Context, string, ...any) pgx.Row
}

func upsertUnifiedEndpointAsset(ctx context.Context, tx unifiedEndpointAssetTx, tenant, endpoint string, record *agentEventRecord) error {
	if record == nil || record.Asset == nil {
		return nil
	}
	asset := record.Asset
	sourceType := "agent_endpoint"
	sourceNamespace := strings.TrimSpace(endpoint)
	nativeID := strings.TrimSpace(record.UnifiedNativeID)
	if nativeID == "" {
		nativeID = unifiedEndpointAssetNativeID(asset.AssetType, asset.Name)
	}
	if sourceNamespace == "" || len(sourceNamespace) > 255 ||
		strings.TrimSpace(asset.AssetType) == "" || strings.TrimSpace(asset.Name) == "" ||
		strings.ContainsAny(sourceNamespace, "\x1f\x1e") ||
		strings.ContainsAny(asset.AssetType, "\x1f\x1e") ||
		strings.ContainsAny(asset.Name, "\x1f\x1e") || len(nativeID) > 512 {
		return ErrAgentAssetInvalidInput
	}
	identityKey := unifiedAssetIdentityKey(sourceType, sourceNamespace, nativeID)
	if err := lockUnifiedAssetTenantWrite(ctx, tx, tenant); err != nil {
		return err
	}
	lockKey := tenant + "\x1f" + sourceType + "\x1f" + sourceNamespace + "\x1f" + nativeID
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return err
	}
	sourceRefID := stableUnifiedAssetID("uasr_", tenant, sourceType, sourceNamespace, nativeID)
	defaultAssetID := stableUnifiedAssetID("uaa_", tenant, sourceType, sourceNamespace, nativeID)
	var assetID string
	err := tx.QueryRow(ctx, `SELECT asset_id FROM agent_asset_source_refs
		WHERE tenant_id=$1 AND source_type=$2 AND source_namespace=$3 AND native_id=$4 FOR SHARE`,
		tenant, sourceType, sourceNamespace, nativeID).Scan(&assetID)
	if err == pgx.ErrNoRows {
		_, err = tx.Exec(ctx, `INSERT INTO agent_unified_assets(id,tenant_id,asset_type,identity_key,display_name,first_seen,last_seen)
			VALUES($1,$2,$3,$4,$5,LEAST($6,clock_timestamp()),LEAST($6,clock_timestamp()))
			ON CONFLICT (tenant_id,asset_type,identity_key) DO NOTHING`,
			defaultAssetID, tenant, asset.AssetType, identityKey, asset.Name, record.OccurredAt)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO agent_asset_source_refs(id,tenant_id,asset_id,source_type,source_namespace,native_id)
			VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,source_type,source_namespace,native_id) DO NOTHING`,
			sourceRefID, tenant, defaultAssetID, sourceType, sourceNamespace, nativeID)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT asset_id FROM agent_asset_source_refs
			WHERE tenant_id=$1 AND source_type=$2 AND source_namespace=$3 AND native_id=$4`,
			tenant, sourceType, sourceNamespace, nativeID).Scan(&assetID)
	}
	if err != nil {
		return err
	}
	var canonicalID string
	if err = tx.QueryRow(ctx, `SELECT COALESCE(merged_into_id,id) FROM agent_unified_assets WHERE tenant_id=$1 AND id=$2`,
		tenant, assetID).Scan(&canonicalID); err != nil {
		return err
	}
	assetID = canonicalID
	instanceKey := strings.TrimSpace(record.InstanceKey)
	if instanceKey == "" {
		instanceKey = unifiedAssetInstanceKey()
	}
	instanceID := stableUnifiedAssetID("uai_", tenant, sourceRefID, instanceKey)
	if _, err = tx.Exec(ctx, `INSERT INTO agent_unified_asset_instances(
		id,tenant_id,asset_id,source_asset_id,source_ref_id,instance_key,endpoint_id,
		display_name,version,content_hash,present,scan_status,scan_decision,evidence,first_seen,last_observed_at,last_received_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,LEAST($15,clock_timestamp()),LEAST($15,clock_timestamp()),clock_timestamp())
	ON CONFLICT (tenant_id,asset_id,source_ref_id,instance_key) DO NOTHING`,
		instanceID, tenant, assetID, assetID, sourceRefID, instanceKey, endpoint, asset.Name, asset.Version,
		asset.Hash, asset.Present, asset.ScanStatus, asset.ScanDecision, normalizedAssetEvidence(asset.Evidence), record.OccurredAt); err != nil {
		return fmt.Errorf("insert unified asset instance: %w", err)
	}
	observationID := stableUnifiedAssetID("uao_", tenant, sourceRefID, record.ID)
	var receivedAt time.Time
	err = tx.QueryRow(ctx, `INSERT INTO agent_unified_asset_observations(
		id,tenant_id,asset_id,source_asset_id,instance_id,source_ref_id,source_event_id,provenance,
		source_occurred_at,received_at,display_name,version,content_hash,present,scan_status,scan_decision,evidence
	) VALUES($1,$2,$3,$4,$5,$6,$7,'authenticated_source',$8,clock_timestamp(),$9,$10,$11,$12,$13,$14,$15::jsonb)
	ON CONFLICT (tenant_id,source_ref_id,source_event_id) DO NOTHING RETURNING received_at`,
		observationID, tenant, assetID, assetID, instanceID, sourceRefID, record.ID, record.OccurredAt,
		asset.Name, asset.Version, asset.Hash, asset.Present, asset.ScanStatus, asset.ScanDecision,
		normalizedAssetEvidence(asset.Evidence)).Scan(&receivedAt)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("append unified asset observation: %w", err)
	}
	observedAt := boundedAgentAssetObservedAt(record.OccurredAt, receivedAt)
	if _, err = tx.Exec(ctx, `UPDATE agent_unified_asset_instances SET
		display_name=$3,version=$4,content_hash=$5,present=$6,scan_status=$7,scan_decision=$8,evidence=$9::jsonb,
		first_seen=LEAST(first_seen,$10),last_observed_at=$10,last_received_at=$11
		WHERE tenant_id=$1 AND id=$2 AND last_observed_at<=$10`,
		tenant, instanceID, asset.Name, asset.Version, asset.Hash, asset.Present, asset.ScanStatus,
		asset.ScanDecision, normalizedAssetEvidence(asset.Evidence), observedAt, receivedAt); err != nil {
		return fmt.Errorf("update unified asset instance: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE agent_unified_assets SET
		display_name=CASE WHEN $3<>'' AND last_seen<=$4 THEN $3 ELSE display_name END,
		first_seen=LEAST(first_seen,$4),last_seen=GREATEST(last_seen,$4),updated_at=now()
		WHERE tenant_id=$1 AND id=$2`, tenant, assetID, asset.Name, observedAt)
	if err != nil {
		return fmt.Errorf("update unified asset metadata: %w", err)
	}
	return nil
}

func normalizedAssetEvidence(raw []byte) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	return raw
}

func boundedAgentAssetObservedAt(sourceOccurredAt, receivedAt time.Time) time.Time {
	if sourceOccurredAt.After(receivedAt) {
		return receivedAt
	}
	return sourceOccurredAt
}
