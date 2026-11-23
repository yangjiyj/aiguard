package repository

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

var ErrSkillInvalidRequest = errors.New("invalid skill governance request")

func skillStatus(s string) bool {
	return s == "unverified" || s == "approved" || s == "quarantined" || s == "revoked"
}
func validateSkillAdmissionReview(r SkillAdmissionReview) error {
	if !skillStatus(r.Status) || r.Status == "unverified" || !skillStatus(r.ExpectedStatus) || len(r.ExpectedBundleHash) != 64 || strings.TrimSpace(r.Reason) == "" || !utf8.ValidString(r.Reason) || len([]rune(r.Reason)) > 500 {
		return ErrSkillInvalidRequest
	}
	for _, c := range r.ExpectedBundleHash {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ErrSkillInvalidRequest
		}
	}
	if skillTextHasForbiddenRune(r.Reason) {
		return ErrSkillInvalidRequest
	}
	if r.OverrideReason != "" {
		if r.Status != "approved" || !utf8.ValidString(r.OverrideReason) || len([]rune(r.OverrideReason)) > 512 || strings.TrimSpace(r.OverrideReason) == "" {
			return ErrSkillInvalidRequest
		}
		if skillTextHasForbiddenRune(r.OverrideReason) {
			return ErrSkillInvalidRequest
		}
	}
	return nil
}

// skillTextHasForbiddenRune：审查原因等管理端文本不能带控制字符，也不能带格式字符（unicode.Cf：
// 双向覆盖、零宽字符等），审计里显示的内容与实际一致。
func skillTextHasForbiddenRune(value string) bool {
	for _, c := range value {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			return true
		}
	}
	return false
}
func skillReviewReason(r *SkillAdmissionReview) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Reason)
}
func skillPage(limit, offset int) (int, int, error) {
	if limit == 0 {
		limit = 20
	}
	if limit < 1 || limit > 200 || offset < 0 || offset > 1000000 {
		return 0, 0, ErrSkillInvalidRequest
	}
	return limit, offset, nil
}

func (r *SkillAssetsRepository) ListAssetsPage(ctx context.Context, tenant string, f SkillAssetFilter) (SkillAssetPage, error) {
	limit, offset, err := skillPage(f.Limit, f.Offset)
	if err != nil {
		return SkillAssetPage{}, err
	}
	if tenant == "" || (f.SourceType != "" && f.SourceType != "uploaded" && f.SourceType != "observed") || (f.AdmissionStatus != "" && !skillStatus(f.AdmissionStatus)) || len([]rune(f.Query)) > 255 {
		return SkillAssetPage{}, ErrSkillInvalidRequest
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return SkillAssetPage{}, err
	}
	defer tx.Rollback(context.Background())
	out := SkillAssetPage{Items: []*SkillAsset{}, Limit: limit, Offset: offset, InventoryScope: "gateway_observed_and_uploaded_scan"}
	where := ` WHERE tenant_id=$1 AND ($2='' OR source_type=$2) AND ($3='' OR admission_status=$3) AND ($4='' OR canonical_name ILIKE '%'||$4||'%' OR display_name ILIKE '%'||$4||'%')`
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM skill_assets`+where, tenant, f.SourceType, f.AdmissionStatus, f.Query).Scan(&out.Total); err != nil {
		return out, err
	}
	rows, err := tx.Query(ctx, `SELECT id,tenant_id,canonical_name,display_name,source_type,source_uri,publisher,admission_status,first_seen_at,last_seen_at,created_at,updated_at FROM skill_assets`+where+` ORDER BY last_seen_at DESC,id LIMIT $5 OFFSET $6`, tenant, f.SourceType, f.AdmissionStatus, f.Query, limit, offset)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		a := &SkillAsset{}
		err = rows.Scan(&a.ID, &a.TenantID, &a.CanonicalName, &a.DisplayName, &a.SourceType, &a.SourceURI, &a.Publisher, &a.AdmissionStatus, &a.FirstSeenAt, &a.LastSeenAt, &a.CreatedAt, &a.UpdatedAt)
		if err != nil {
			rows.Close()
			return out, err
		}
		out.Items = append(out.Items, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	err = tx.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM skill_assets WHERE tenant_id=$1 AND source_type='uploaded'),
 (SELECT count(*) FROM skill_assets WHERE tenant_id=$1 AND source_type='observed'),
 count(*) FILTER(WHERE a.source_type='uploaded' AND v.admission_status='unverified' AND v.scan_status='completed' AND v.decision<>'block' AND v.signature_status<>'invalid' AND v.declared_version<>''),
 count(*) FILTER(WHERE a.source_type='uploaded' AND v.admission_status='approved'),
 count(*) FILTER(WHERE v.admission_status='quarantined'),
 count(*) FILTER(WHERE v.admission_status='revoked'),
 count(*) FILTER(WHERE v.scan_status='failed'),
 (SELECT count(*) FROM skill_invocations WHERE tenant_id=$1)
 FROM skill_asset_versions v JOIN skill_assets a ON a.tenant_id=v.tenant_id AND a.id=v.asset_id WHERE v.tenant_id=$1`, tenant).Scan(&out.Summary.UploadedAssets, &out.Summary.ObservedAssets, &out.Summary.PendingVersions, &out.Summary.ApprovedVersions, &out.Summary.QuarantinedVersions, &out.Summary.RevokedVersions, &out.Summary.FailedScans, &out.Summary.Invocations)
	if err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}
func (r *SkillAssetsRepository) ListInvocationsPage(ctx context.Context, tenant string, f SkillInvocationFilter) (SkillInvocationPage, error) {
	limit, offset, err := skillPage(f.Limit, f.Offset)
	if err != nil {
		return SkillInvocationPage{}, err
	}
	if tenant == "" {
		return SkillInvocationPage{}, ErrSkillInvalidRequest
	}
	if f.EffectiveDecision != "" && f.EffectiveDecision != "allow" && f.EffectiveDecision != "audit" && f.EffectiveDecision != "confirm" && f.EffectiveDecision != "block" {
		return SkillInvocationPage{}, ErrSkillInvalidRequest
	}
	if f.Status != "" && f.Status != "proposed" && f.Status != "confirmed" && f.Status != "blocked" && f.Status != "forwarded" && f.Status != "result_observed" && f.Status != "completed" && f.Status != "failed" {
		return SkillInvocationPage{}, ErrSkillInvalidRequest
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return SkillInvocationPage{}, err
	}
	defer tx.Rollback(context.Background())
	out := SkillInvocationPage{Items: []*SkillInvocation{}, Limit: limit, Offset: offset, ObservationScope: "gateway_observed"}
	where := ` WHERE tenant_id=$1 AND ($2='' OR asset_id=$2) AND ($3='' OR asset_version_id=$3) AND ($4='' OR canonical_name=$4) AND ($5='' OR status=$5) AND ($6='' OR effective_decision=$6)`
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM skill_invocations`+where, tenant, f.AssetID, f.VersionID, f.CanonicalName, f.Status, f.EffectiveDecision).Scan(&out.Total); err != nil {
		return out, err
	}
	rows, err := tx.Query(ctx, `SELECT id,tenant_id,COALESCE(asset_id,''),COALESCE(asset_version_id,''),request_id,session_id,tool_call_id,canonical_name,declared_version,source_uri,status,raw_decision,effective_decision,parameters_digest,redacted_preview_json,result_status,result_findings_json,attribution_mode,attribution_confidence,proposed_at,forwarded_at,result_observed_at,completed_at,created_at,updated_at FROM skill_invocations`+where+` ORDER BY created_at DESC,id LIMIT $7 OFFSET $8`, tenant, f.AssetID, f.VersionID, f.CanonicalName, f.Status, f.EffectiveDecision, limit, offset)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		inv, err := scanSkillInvocation(rows)
		if err != nil {
			rows.Close()
			return out, err
		}
		out.Items = append(out.Items, inv)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}
