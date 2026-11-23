package repository

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// r2922 对抗复核：扫描失败的已上传版本（压缩包超限、结构违规等）原先永远批不了。改为与扫描判阻断
// 同口径，可以带 override_reason 强制批准并记审计 skill_version.force_approved，运行时按已批准处置；
// 不带原因仍不可批；签名无效、仅观测到的定义带原因也不可批。
func failedScanSkill(tenant, name, hash string) SkillVersionUpsert {
	in := uploadedSkill(tenant, name, hash)
	in.ScanStatus, in.ScanErrorCode = "failed", "archive_too_large"
	in.Decision, in.RiskLevel, in.AdmissionStatus = "block", "critical", "quarantined"
	return in
}

func TestSkillForceApprove2922PostgresFailedScanNeedsOverrideReason(t *testing.T) {
	ctx, r, p := skillGovernanceFixture(t)
	v, err := r.UpsertVersion(ctx, failedScanSkill("tenant-a", "too-large", strings.Repeat("e", 64)))
	if err != nil {
		t.Fatal(err)
	}
	if v.AdmissionStatus != "quarantined" || v.ScanStatus != "failed" {
		t.Fatalf("扫描失败的版本自动隔离：%+v", v)
	}
	review := SkillAdmissionReview{Status: "approved", ExpectedStatus: v.AdmissionStatus, ExpectedBundleHash: v.BundleHash, Reason: "Reviewed"}
	if err := r.SetVersionAdmissionReviewed(ctx, "tenant-a", v.ID, review, "reviewer", ""); !errors.Is(err, ErrSkillVersionNotApprovable) {
		t.Fatalf("不带强制批准原因仍不可批：%v", err)
	}
	review.OverrideReason = "包超出扫描上限，已人工逐个文件复核"
	if err := r.SetVersionAdmissionReviewed(ctx, "tenant-a", v.ID, review, "reviewer", ""); err != nil {
		t.Fatalf("扫描失败的版本可以强制批准：%v", err)
	}
	var raw []byte
	if err := p.QueryRow(ctx, `SELECT action_detail FROM audit_operations WHERE target_id=$1 AND action_type='skill_version.force_approved'`, v.ID).Scan(&raw); err != nil {
		t.Fatalf("强制批准要记审计：%v", err)
	}
	var detail map[string]string
	if err := json.Unmarshal(raw, &detail); err != nil || detail["override_reason"] != review.OverrideReason || detail["scan_status"] != "failed" {
		t.Fatalf("审计缺原因或扫描状态：%s", raw)
	}
	resolved, err := r.ResolveAdmission(ctx, "tenant-a", "too-large", "1", v.BundleHash)
	if err != nil || resolved.Status != "approved" || resolved.VersionID != v.ID {
		t.Fatalf("强制批准后运行时按已批准处置：%+v err=%v", resolved, err)
	}
}

func TestSkillForceApprove2922PostgresFailedScanStillRejectsInvalidSignatureAndObserved(t *testing.T) {
	ctx, r, _ := skillGovernanceFixture(t)
	invalid := failedScanSkill("tenant-a", "bad-signature", strings.Repeat("f", 64))
	invalid.SignatureStatus = "invalid"
	iv, err := r.UpsertVersion(ctx, invalid)
	if err != nil {
		t.Fatal(err)
	}
	forced := SkillAdmissionReview{Status: "approved", ExpectedStatus: iv.AdmissionStatus, ExpectedBundleHash: iv.BundleHash, Reason: "Reviewed", OverrideReason: "想用"}
	if err := r.SetVersionAdmissionReviewed(ctx, "tenant-a", iv.ID, forced, "reviewer", ""); !errors.Is(err, ErrSkillVersionNotApprovable) {
		t.Fatalf("签名无效永远不可批：%v", err)
	}
	observed := failedScanSkill("tenant-a", "observed", strings.Repeat("1", 64))
	observed.SourceType = "observed"
	ov, err := r.UpsertVersion(ctx, observed)
	if err != nil {
		t.Fatal(err)
	}
	forced.ExpectedStatus, forced.ExpectedBundleHash = ov.AdmissionStatus, ov.BundleHash
	if err := r.SetVersionAdmissionReviewed(ctx, "tenant-a", ov.ID, forced, "reviewer", ""); !errors.Is(err, ErrSkillVersionNotApprovable) {
		t.Fatalf("仅观测到的定义不可批：%v", err)
	}
	quarantined, err := r.ResolveAdmission(ctx, "tenant-a", "bad-signature", "1", iv.BundleHash)
	if err != nil || quarantined.Status != "unverified" {
		t.Fatalf("没批准的扫描失败版本运行时口径不变：%+v err=%v", quarantined, err)
	}
}
