package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrSkillVersionNotApprovable = errors.New("skill version is not approvable")

// ErrSkillOverrideNotApplicable：override_reason 只用于扫描结论为阻断的版本的强制批准。
var ErrSkillOverrideNotApplicable = errors.New("override_reason only applies to a version whose scan was blocked or failed")
var ErrSkillInvocationConflict = errors.New("skill invocation identity conflicts with existing tool call")

type SkillAsset struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	CanonicalName   string    `json:"canonical_name"`
	DisplayName     string    `json:"display_name"`
	SourceType      string    `json:"source_type"`
	SourceURI       string    `json:"source_uri"`
	Publisher       string    `json:"publisher"`
	AdmissionStatus string    `json:"admission_status"`
	FirstSeenAt     time.Time `json:"first_seen_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type SkillAssetVersion struct {
	ID              string          `json:"id"`
	TenantID        string          `json:"tenant_id"`
	AssetID         string          `json:"asset_id"`
	DeclaredVersion string          `json:"declared_version"`
	SourceCommit    string          `json:"source_commit"`
	BundleHash      string          `json:"bundle_hash"`
	TreeHash        string          `json:"tree_hash"`
	SignatureStatus string          `json:"signature_status"`
	SignerIdentity  string          `json:"signer_identity"`
	ManifestJSON    json.RawMessage `json:"manifest"`
	FindingsJSON    json.RawMessage `json:"findings"`
	RiskLevel       string          `json:"risk_level"`
	Decision        string          `json:"decision"`
	ScanStatus      string          `json:"scan_status"`
	ScanErrorCode   string          `json:"scan_error_code,omitempty"`
	AdmissionStatus string          `json:"admission_status"`
	ApprovedAt      *time.Time      `json:"approved_at,omitempty"`
	ApprovedBy      string          `json:"approved_by,omitempty"`
	ReviewReason    string          `json:"review_reason,omitempty"`
	ReviewedBy      string          `json:"reviewed_by,omitempty"`
	ReviewedAt      *time.Time      `json:"reviewed_at,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	ObservedAt      time.Time       `json:"observed_at"`
}

type SkillVersionUpsert struct {
	TenantID        string
	CanonicalName   string
	DisplayName     string
	SourceType      string
	SourceURI       string
	Publisher       string
	DeclaredVersion string
	SourceCommit    string
	BundleHash      string
	TreeHash        string
	SignatureStatus string
	SignerIdentity  string
	ManifestJSON    []byte
	FindingsJSON    []byte
	RiskLevel       string
	Decision        string
	ScanStatus      string
	ScanErrorCode   string
	AdmissionStatus string
}

type SkillAdmissionResolution struct {
	AssetID   string `json:"asset_id,omitempty"`
	VersionID string `json:"version_id,omitempty"`
	Status    string `json:"status"`
	Decision  string `json:"decision,omitempty"`
	RiskLevel string `json:"risk_level,omitempty"`
}

type SkillInvocation struct {
	ID                    string          `json:"id"`
	TenantID              string          `json:"tenant_id"`
	AssetID               string          `json:"asset_id,omitempty"`
	AssetVersionID        string          `json:"asset_version_id,omitempty"`
	RequestID             string          `json:"request_id"`
	SessionID             string          `json:"session_id"`
	ToolCallID            string          `json:"tool_call_id"`
	CanonicalName         string          `json:"canonical_name"`
	DeclaredVersion       string          `json:"declared_version"`
	SourceURI             string          `json:"source_uri"`
	Status                string          `json:"status"`
	RawDecision           string          `json:"raw_decision"`
	EffectiveDecision     string          `json:"effective_decision"`
	ParametersDigest      string          `json:"parameters_digest,omitempty"`
	RedactedPreviewJSON   json.RawMessage `json:"redacted_preview"`
	ResultStatus          string          `json:"result_status,omitempty"`
	ResultFindingsJSON    json.RawMessage `json:"result_findings"`
	AttributionMode       string          `json:"attribution_mode"`
	AttributionConfidence float64         `json:"attribution_confidence"`
	ProposedAt            time.Time       `json:"proposed_at"`
	ForwardedAt           *time.Time      `json:"forwarded_at,omitempty"`
	ResultObservedAt      *time.Time      `json:"result_observed_at,omitempty"`
	CompletedAt           *time.Time      `json:"completed_at,omitempty"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
}

type SkillInvocationUpsert struct {
	TenantID              string
	AssetID               string
	AssetVersionID        string
	RequestID             string
	SessionID             string
	ToolCallID            string
	CanonicalName         string
	DeclaredVersion       string
	SourceURI             string
	Status                string
	RawDecision           string
	EffectiveDecision     string
	ParametersDigest      string
	RedactedPreviewJSON   []byte
	AttributionMode       string
	AttributionConfidence float64
}

type SkillAssetsRepository struct {
	db                   *pgxpool.Pool
	beforeAdmissionAudit func() error
}

func NewSkillAssetsRepository(db *pgxpool.Pool) *SkillAssetsRepository {
	return &SkillAssetsRepository{db: db}
}

func (r *SkillAssetsRepository) UpsertVersion(ctx context.Context, input SkillVersionUpsert) (*SkillAssetVersion, error) {
	normalizeSkillVersionInput(&input)
	if input.AdmissionStatus != "unverified" && input.AdmissionStatus != "quarantined" {
		return nil, errors.New("unsupported initial skill admission status")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	assetID := "skill_asset_" + uuid.NewString()
	var asset SkillAsset
	err = tx.QueryRow(ctx, `
		INSERT INTO skill_assets (
			id, tenant_id, canonical_name, display_name, source_type, source_uri, publisher
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (tenant_id, canonical_name, source_type) DO UPDATE SET
			display_name = CASE WHEN EXCLUDED.display_name <> '' THEN EXCLUDED.display_name ELSE skill_assets.display_name END,
			last_seen_at = NOW(),
			updated_at = NOW()
		RETURNING id, tenant_id, canonical_name, display_name, source_type, source_uri,
			publisher, admission_status, first_seen_at, last_seen_at, created_at, updated_at
	`, assetID, input.TenantID, input.CanonicalName, input.DisplayName, input.SourceType,
		input.SourceURI, input.Publisher).Scan(
		&asset.ID, &asset.TenantID, &asset.CanonicalName, &asset.DisplayName, &asset.SourceType,
		&asset.SourceURI, &asset.Publisher, &asset.AdmissionStatus, &asset.FirstSeenAt,
		&asset.LastSeenAt, &asset.CreatedAt, &asset.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	versionID := "skill_version_" + uuid.NewString()
	row := tx.QueryRow(ctx, `
		INSERT INTO skill_asset_versions (
			id, tenant_id, asset_id, declared_version, source_commit, bundle_hash, tree_hash,
			signature_status, signer_identity, manifest_json, findings_json, risk_level,
			decision, scan_status, scan_error_code, admission_status
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (tenant_id, asset_id, bundle_hash) DO UPDATE SET
			observed_at=NOW(),
			admission_status=CASE
				WHEN skill_asset_versions.admission_status='revoked' THEN 'revoked'
				WHEN EXCLUDED.admission_status='quarantined' THEN 'quarantined'
				ELSE skill_asset_versions.admission_status
			END
		WHERE skill_asset_versions.declared_version=EXCLUDED.declared_version
		  AND skill_asset_versions.source_commit=EXCLUDED.source_commit
		RETURNING id, tenant_id, asset_id, declared_version, source_commit, bundle_hash, tree_hash,
			signature_status, signer_identity, manifest_json, findings_json, risk_level,
			decision, scan_status, scan_error_code, admission_status, approved_at,
			COALESCE(approved_by,''), created_at, observed_at
	`, versionID, input.TenantID, asset.ID, input.DeclaredVersion, input.SourceCommit,
		input.BundleHash, input.TreeHash, input.SignatureStatus, input.SignerIdentity,
		input.ManifestJSON, input.FindingsJSON, input.RiskLevel, input.Decision,
		input.ScanStatus, input.ScanErrorCode, input.AdmissionStatus)
	version, err := scanSkillAssetVersion(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSkillVersionDeclarationConflict
	}
	if err != nil {
		return nil, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE skill_assets SET admission_status=$3, updated_at=NOW()
		WHERE tenant_id=$1 AND id=$2
	`, input.TenantID, asset.ID, version.AdmissionStatus)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, pgx.ErrNoRows
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return version, nil
}

func normalizeSkillVersionInput(input *SkillVersionUpsert) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.CanonicalName = strings.TrimSpace(strings.ToLower(input.CanonicalName))
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.SourceType = strings.TrimSpace(strings.ToLower(input.SourceType))
	input.SourceURI = strings.TrimSpace(input.SourceURI)
	input.Publisher = strings.TrimSpace(input.Publisher)
	input.DeclaredVersion = strings.TrimSpace(input.DeclaredVersion)
	input.SourceCommit = strings.TrimSpace(input.SourceCommit)
	input.BundleHash = strings.TrimSpace(strings.ToLower(input.BundleHash))
	input.TreeHash = strings.TrimSpace(strings.ToLower(input.TreeHash))
	input.SignatureStatus = strings.TrimSpace(strings.ToLower(input.SignatureStatus))
	if input.SignatureStatus == "" {
		input.SignatureStatus = "unknown"
	}
	input.SignerIdentity = strings.TrimSpace(input.SignerIdentity)
	if len(input.ManifestJSON) == 0 {
		input.ManifestJSON = []byte("{}")
	}
	if len(input.FindingsJSON) == 0 {
		input.FindingsJSON = []byte("[]")
	}
	input.RiskLevel = strings.TrimSpace(strings.ToLower(input.RiskLevel))
	if input.RiskLevel == "" {
		input.RiskLevel = "low"
	}
	input.Decision = strings.TrimSpace(strings.ToLower(input.Decision))
	if input.Decision == "" {
		input.Decision = "confirm"
	}
	input.ScanStatus = strings.TrimSpace(strings.ToLower(input.ScanStatus))
	if input.ScanStatus == "" {
		input.ScanStatus = "completed"
	}
	input.ScanErrorCode = strings.TrimSpace(input.ScanErrorCode)
	input.AdmissionStatus = strings.ToLower(strings.TrimSpace(input.AdmissionStatus))
	if input.AdmissionStatus == "" {
		input.AdmissionStatus = "unverified"
	}
}

func (r *SkillAssetsRepository) ListAssets(ctx context.Context, tenantID string, limit, offset int) ([]*SkillAsset, error) {
	limit, offset = boundedSkillPagination(limit, offset)
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, canonical_name, display_name, source_type, source_uri,
			publisher, admission_status, first_seen_at, last_seen_at, created_at, updated_at
		FROM skill_assets
		WHERE tenant_id=$1
		ORDER BY last_seen_at DESC, id
		LIMIT $2 OFFSET $3
	`, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*SkillAsset, 0)
	for rows.Next() {
		asset := &SkillAsset{}
		if err := rows.Scan(
			&asset.ID, &asset.TenantID, &asset.CanonicalName, &asset.DisplayName,
			&asset.SourceType, &asset.SourceURI, &asset.Publisher, &asset.AdmissionStatus,
			&asset.FirstSeenAt, &asset.LastSeenAt, &asset.CreatedAt, &asset.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, asset)
	}
	return out, rows.Err()
}

func (r *SkillAssetsRepository) ListVersions(ctx context.Context, tenantID, assetID string) ([]*SkillAssetVersion, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, asset_id, declared_version, source_commit, bundle_hash, tree_hash,
			signature_status, signer_identity, manifest_json, findings_json, risk_level,
			decision, scan_status, scan_error_code, admission_status, approved_at,
			COALESCE(approved_by,''), created_at, observed_at,
			COALESCE(review.review_reason,''),COALESCE(review.reviewed_by,''),review.reviewed_at
		FROM skill_asset_versions v
		LEFT JOIN LATERAL (
			SELECT action_detail->>'reason' AS review_reason,action_detail->>'actor_id' AS reviewed_by,created_at AS reviewed_at
			FROM audit_operations
			WHERE action_type='skill_version.admission' AND target_type='skill_asset_version'
			  AND target_id=v.id AND action_detail->>'tenant_id'=v.tenant_id
			ORDER BY created_at DESC,id DESC LIMIT 1
		) review ON TRUE
		WHERE tenant_id=$1 AND asset_id=$2
		ORDER BY created_at DESC, id
	`, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*SkillAssetVersion, 0)
	for rows.Next() {
		version, scanErr := scanSkillAssetVersionReviewed(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, version)
	}
	return out, rows.Err()
}

type skillRowScanner interface {
	Scan(dest ...any) error
}

// SkillVersionAdmissionSnapshot is the minimal context the admission-change
// alert needs: which skill/version changed and what its status was before.
type SkillVersionAdmissionSnapshot struct {
	AssetID         string
	CanonicalName   string
	DeclaredVersion string
	AdmissionStatus string
}

// GetVersionAdmissionSnapshot reads the pre-change admission state of one
// version. ErrNotFound is returned when the version does not exist in the
// tenant.
func (r *SkillAssetsRepository) GetVersionAdmissionSnapshot(ctx context.Context, tenantID, versionID string) (SkillVersionAdmissionSnapshot, error) {
	var snapshot SkillVersionAdmissionSnapshot
	err := r.db.QueryRow(ctx, `
		SELECT v.asset_id, a.canonical_name, v.declared_version, COALESCE(v.admission_status, '')
		FROM skill_asset_versions v
		JOIN skill_assets a ON a.tenant_id=v.tenant_id AND a.id=v.asset_id
		WHERE v.tenant_id=$1 AND v.id=$2
	`, tenantID, versionID).Scan(&snapshot.AssetID, &snapshot.CanonicalName, &snapshot.DeclaredVersion, &snapshot.AdmissionStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot, ErrNotFound
	}
	return snapshot, err
}

func scanSkillAssetVersion(row skillRowScanner) (*SkillAssetVersion, error) {
	return scanSkillVersion(row, false)
}
func scanSkillAssetVersionReviewed(row skillRowScanner) (*SkillAssetVersion, error) {
	return scanSkillVersion(row, true)
}
func scanSkillVersion(row skillRowScanner, withReview bool) (*SkillAssetVersion, error) {
	version := &SkillAssetVersion{}
	var manifest, findings []byte
	fields := []any{
		&version.ID, &version.TenantID, &version.AssetID, &version.DeclaredVersion,
		&version.SourceCommit, &version.BundleHash, &version.TreeHash, &version.SignatureStatus,
		&version.SignerIdentity, &manifest, &findings, &version.RiskLevel, &version.Decision,
		&version.ScanStatus, &version.ScanErrorCode, &version.AdmissionStatus,
		&version.ApprovedAt, &version.ApprovedBy, &version.CreatedAt, &version.ObservedAt,
	}
	if withReview {
		fields = append(fields, &version.ReviewReason, &version.ReviewedBy, &version.ReviewedAt)
	}
	err := row.Scan(fields...)
	version.ManifestJSON = append(json.RawMessage(nil), manifest...)
	version.FindingsJSON = append(json.RawMessage(nil), findings...)
	return version, err
}

func (r *SkillAssetsRepository) SetVersionAdmission(ctx context.Context, tenantID, versionID, status, actorID, ipAddress string) error {
	return r.setVersionAdmission(ctx, tenantID, versionID, status, actorID, ipAddress, nil)
}

func (r *SkillAssetsRepository) SetVersionAdmissionReviewed(ctx context.Context, tenantID, versionID string, review SkillAdmissionReview, actorID, ipAddress string) error {
	if err := validateSkillAdmissionReview(review); err != nil {
		return err
	}
	return r.setVersionAdmission(ctx, tenantID, versionID, review.Status, actorID, ipAddress, &review)
}

func (r *SkillAssetsRepository) setVersionAdmission(ctx context.Context, tenantID, versionID, status, actorID, ipAddress string, review *SkillAdmissionReview) error {
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "approved" && status != "quarantined" && status != "revoked" {
		return errors.New("unsupported skill admission status")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var assetID, decision, scanStatus, signatureStatus, sourceType, previousStatus, bundleHash, treeHash, declaredVersion, riskLevel string
	err = tx.QueryRow(ctx, `
		SELECT v.asset_id, v.decision, v.scan_status, v.signature_status, a.source_type,
		       v.admission_status,v.bundle_hash,v.tree_hash,v.declared_version,v.risk_level
		FROM skill_asset_versions v
		JOIN skill_assets a ON a.tenant_id=v.tenant_id AND a.id=v.asset_id
		WHERE v.tenant_id=$1 AND v.id=$2
		FOR UPDATE
	`, tenantID, versionID).Scan(&assetID, &decision, &scanStatus, &signatureStatus, &sourceType, &previousStatus, &bundleHash, &treeHash, &declaredVersion, &riskLevel)
	if err != nil {
		return err
	}
	if review != nil && (review.ExpectedStatus != previousStatus || review.ExpectedBundleHash != bundleHash) {
		return ErrSkillAdmissionConflict
	}
	// 扫描结论为阻断、或扫描失败的已上传版本可以带原因强制批准；签名无效、仅观测到的定义、
	// 扫描还没做的（pending）不行。其余版本带强制批准原因是请求错误，不当普通批准处理。
	overridden := status == "approved" && review != nil && strings.TrimSpace(review.OverrideReason) != ""
	forceable := decision == "block" || scanStatus == "failed"
	if overridden && !forceable {
		return ErrSkillOverrideNotApplicable
	}
	forced := overridden && forceable
	scanUsable := scanStatus == "completed" || (scanStatus == "failed" && forced)
	if status == "approved" && (sourceType != "uploaded" || (decision == "block" && !forced) ||
		!scanUsable || signatureStatus == "invalid" || declaredVersion == "") {
		return ErrSkillVersionNotApprovable
	}

	tag, err := tx.Exec(ctx, `
		UPDATE skill_asset_versions SET
			admission_status=$3,
			approved_at=CASE WHEN $5 THEN NOW() ELSE approved_at END,
			approved_by=CASE WHEN $5 THEN $4 ELSE approved_by END
		WHERE tenant_id=$1 AND id=$2
	`, tenantID, versionID, status, actorID, status == "approved")
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	tag, err = tx.Exec(ctx, `
		UPDATE skill_assets SET
			admission_status=(
				SELECT admission_status
				FROM skill_asset_versions
				WHERE tenant_id=$1 AND asset_id=$2
				ORDER BY observed_at DESC, created_at DESC, id DESC
				LIMIT 1
			),
			updated_at=NOW()
		WHERE tenant_id=$1 AND id=$2
	`, tenantID, assetID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	if r.beforeAdmissionAudit != nil {
		if err := r.beforeAdmissionAudit(); err != nil {
			return err
		}
	}
	auditDetail, err := json.Marshal(map[string]string{
		"tenant_id": tenantID, "version_id": versionID,
		"status": status, "actor_id": actorID,
		"previous_status": previousStatus, "bundle_hash": bundleHash, "tree_hash": treeHash, "declared_version": declaredVersion,
		"reason": skillReviewReason(review),
	})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_operations (
			id, user_id, action_type, action_detail, target_type, target_id, ip_address
		) VALUES (
			$1, (SELECT id FROM users WHERE id=$2), $3, $4::jsonb, $5, $6, $7
		)
	`, uuid.NewString(), actorID, "skill_version.admission", auditDetail,
		"skill_asset_version", versionID, boundedSkillAuditIP(ipAddress))
	if err != nil {
		return err
	}
	if forced {
		// 强制批准的审计走事务审计：与批准同一事务写 audit_operations，提交后进审计链，来源地址取请求
		// 上下文。上面的准入审计 skill_version.admission 原本就不进审计链，保持原样。
		if err := writeTransactionalOperationAudit(ctx, tx, tenantID, actorID, "skill_version.force_approved",
			"skill_asset_version", versionID, map[string]any{
				"version_id": versionID, "actor_id": actorID,
				"override_reason": strings.TrimSpace(review.OverrideReason), "reason": skillReviewReason(review),
				"scan_decision": decision, "risk_level": riskLevel, "scan_status": scanStatus, "signature_status": signatureStatus,
				"previous_status": previousStatus, "bundle_hash": bundleHash, "declared_version": declaredVersion,
			}); err != nil {
			return err
		}
	}
	return commitWithOperationAudit(ctx, tx)
}

func boundedSkillAuditIP(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 64 {
		return value[:64]
	}
	return value
}

func (r *SkillAssetsRepository) ResolveAdmission(ctx context.Context, tenantID, canonicalName, version, bundleHash string) (SkillAdmissionResolution, error) {
	resolution := SkillAdmissionResolution{Status: "unverified"}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(canonicalName) == "" ||
		strings.TrimSpace(version) == "" || strings.TrimSpace(bundleHash) == "" {
		return resolution, nil
	}
	err := r.db.QueryRow(ctx, `
		SELECT a.id, v.id, v.admission_status, v.decision, v.risk_level
		FROM skill_assets a
		JOIN skill_asset_versions v
		  ON v.tenant_id=a.tenant_id AND v.asset_id=a.id
		WHERE a.tenant_id=$1 AND a.canonical_name=$2
		  AND v.declared_version=$3 AND v.bundle_hash=$4
		  AND a.source_type='uploaded'
		  AND (v.scan_status='completed' OR (v.scan_status='failed' AND v.admission_status='approved'))
		ORDER BY CASE a.source_type WHEN 'uploaded' THEN 0 ELSE 1 END, v.created_at DESC
		LIMIT 1
	`, strings.TrimSpace(tenantID), strings.ToLower(strings.TrimSpace(canonicalName)),
		strings.TrimSpace(version), strings.ToLower(strings.TrimSpace(bundleHash))).Scan(
		&resolution.AssetID, &resolution.VersionID, &resolution.Status,
		&resolution.Decision, &resolution.RiskLevel,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return SkillAdmissionResolution{Status: "unverified"}, nil
	}
	return resolution, err
}

func (r *SkillAssetsRepository) RecordInvocation(ctx context.Context, input SkillInvocationUpsert) (*SkillInvocation, error) {
	normalizeSkillInvocationInput(&input)
	id := "skill_invocation_" + uuid.NewString()
	row := r.db.QueryRow(ctx, `
		INSERT INTO skill_invocations (
			id, tenant_id, asset_id, asset_version_id, request_id, session_id, tool_call_id,
			canonical_name, declared_version, source_uri, status, raw_decision,
			effective_decision, parameters_digest, redacted_preview_json,
			attribution_mode, attribution_confidence
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		ON CONFLICT (tenant_id, session_id, tool_call_id) WHERE session_id <> '' AND tool_call_id <> ''
		DO UPDATE SET
			request_id=EXCLUDED.request_id,
			status=EXCLUDED.status,
			raw_decision=EXCLUDED.raw_decision,
			effective_decision=EXCLUDED.effective_decision,
			updated_at=NOW()
		WHERE skill_invocations.asset_id IS NOT DISTINCT FROM EXCLUDED.asset_id
		  AND skill_invocations.asset_version_id IS NOT DISTINCT FROM EXCLUDED.asset_version_id
		  AND skill_invocations.canonical_name=EXCLUDED.canonical_name
		  AND skill_invocations.declared_version=EXCLUDED.declared_version
		  AND skill_invocations.source_uri=EXCLUDED.source_uri
		  AND skill_invocations.parameters_digest=EXCLUDED.parameters_digest
		  AND skill_invocations.redacted_preview_json=EXCLUDED.redacted_preview_json
		  AND skill_invocations.attribution_mode=EXCLUDED.attribution_mode
		  AND skill_invocations.attribution_confidence=EXCLUDED.attribution_confidence
		  AND skill_invocations.raw_decision=EXCLUDED.raw_decision
		  AND skill_invocations.effective_decision=EXCLUDED.effective_decision
		RETURNING id, tenant_id, COALESCE(asset_id,''), COALESCE(asset_version_id,''),
			request_id, session_id, tool_call_id, canonical_name, declared_version, source_uri,
			status, raw_decision, effective_decision, parameters_digest, redacted_preview_json,
			result_status, result_findings_json, attribution_mode, attribution_confidence,
			proposed_at, forwarded_at, result_observed_at, completed_at, created_at, updated_at
	`, id, input.TenantID, skillNilIfEmpty(input.AssetID), skillNilIfEmpty(input.AssetVersionID),
		input.RequestID, input.SessionID, input.ToolCallID, input.CanonicalName,
		input.DeclaredVersion, input.SourceURI, input.Status, input.RawDecision,
		input.EffectiveDecision, input.ParametersDigest, input.RedactedPreviewJSON,
		input.AttributionMode, input.AttributionConfidence)
	invocation, err := scanSkillInvocation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSkillInvocationConflict
	}
	return invocation, err
}

func normalizeSkillInvocationInput(input *SkillInvocationUpsert) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.SessionID = strings.TrimSpace(input.SessionID)
	input.ToolCallID = strings.TrimSpace(input.ToolCallID)
	input.CanonicalName = strings.ToLower(strings.TrimSpace(input.CanonicalName))
	input.DeclaredVersion = strings.TrimSpace(input.DeclaredVersion)
	input.SourceURI = strings.TrimSpace(input.SourceURI)
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	input.RawDecision = strings.ToLower(strings.TrimSpace(input.RawDecision))
	input.EffectiveDecision = strings.ToLower(strings.TrimSpace(input.EffectiveDecision))
	input.ParametersDigest = strings.ToLower(strings.TrimSpace(input.ParametersDigest))
	if len(input.RedactedPreviewJSON) == 0 {
		input.RedactedPreviewJSON = []byte("{}")
	}
	input.AttributionMode = strings.ToLower(strings.TrimSpace(input.AttributionMode))
	if input.AttributionMode == "" {
		input.AttributionMode = "explicit"
	}
}

func (r *SkillAssetsRepository) MarkInvocationResult(ctx context.Context, tenantID, sessionID, toolCallID, resultStatus string, findings []byte) error {
	tenantID, sessionID, toolCallID = strings.TrimSpace(tenantID), strings.TrimSpace(sessionID), strings.TrimSpace(toolCallID)
	if tenantID == "" || sessionID == "" || toolCallID == "" {
		return errors.New("tenant_id, session_id, and tool_call_id are required")
	}
	if len(findings) == 0 {
		findings = []byte("[]")
	}
	tag, err := r.db.Exec(ctx, `
		UPDATE skill_invocations SET
			status=CASE WHEN effective_decision IN ('block','confirm') OR status='blocked' THEN status ELSE 'result_observed' END,
			result_status=$4,
			result_findings_json=$5,
			result_observed_at=NOW(),
			updated_at=NOW()
		WHERE tenant_id=$1 AND session_id=$2 AND tool_call_id=$3
	`, tenantID, sessionID, toolCallID, strings.TrimSpace(resultStatus), findings)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}

func (r *SkillAssetsRepository) ListInvocations(ctx context.Context, tenantID string, limit, offset int) ([]*SkillInvocation, error) {
	limit, offset = boundedSkillPagination(limit, offset)
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, COALESCE(asset_id,''), COALESCE(asset_version_id,''),
			request_id, session_id, tool_call_id, canonical_name, declared_version, source_uri,
			status, raw_decision, effective_decision, parameters_digest, redacted_preview_json,
			result_status, result_findings_json, attribution_mode, attribution_confidence,
			proposed_at, forwarded_at, result_observed_at, completed_at, created_at, updated_at
		FROM skill_invocations
		WHERE tenant_id=$1
		ORDER BY created_at DESC, id
		LIMIT $2 OFFSET $3
	`, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*SkillInvocation, 0)
	for rows.Next() {
		invocation, scanErr := scanSkillInvocation(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, invocation)
	}
	return out, rows.Err()
}

func scanSkillInvocation(row skillRowScanner) (*SkillInvocation, error) {
	invocation := &SkillInvocation{}
	var preview, findings []byte
	err := row.Scan(
		&invocation.ID, &invocation.TenantID, &invocation.AssetID, &invocation.AssetVersionID,
		&invocation.RequestID, &invocation.SessionID, &invocation.ToolCallID,
		&invocation.CanonicalName, &invocation.DeclaredVersion, &invocation.SourceURI,
		&invocation.Status, &invocation.RawDecision, &invocation.EffectiveDecision,
		&invocation.ParametersDigest, &preview, &invocation.ResultStatus, &findings,
		&invocation.AttributionMode, &invocation.AttributionConfidence,
		&invocation.ProposedAt, &invocation.ForwardedAt, &invocation.ResultObservedAt,
		&invocation.CompletedAt, &invocation.CreatedAt, &invocation.UpdatedAt,
	)
	invocation.RedactedPreviewJSON = append(json.RawMessage(nil), preview...)
	invocation.ResultFindingsJSON = append(json.RawMessage(nil), findings...)
	return invocation, err
}

func boundedSkillPagination(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func skillNilIfEmpty(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}
