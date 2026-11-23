package repository

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// 复审：Skill 强制批准的审计 skill_version.force_approved 走事务审计（writeTransactionalOperationAudit），
// 提交后经 commitWithOperationAudit 进审计链，来源地址取请求上下文；同函数原有的准入审计
// skill_version.admission 原本不进审计链，保持原样。

// 追加项（真库）：扫描结论为阻断的已上传版本，带 override_reason 可以批准并写审计
// skill_version.force_approved（含原因、扫描结论摘要）；不带仍不可批准；签名无效、仅观测到的定义
// 带原因也不可批准。
func TestSkillForceApprove2922PostgresBlockedScanNeedsOverrideReason(t *testing.T) {
	baseCtx, r, p := skillGovernanceFixture(t)
	var chained []CommittedOperationAudit
	ctx := WithOperationAudit(baseCtx, "203.0.113.9", func(event CommittedOperationAudit) { chained = append(chained, event) })
	upsert := uploadedSkill("tenant-a", "risky", strings.Repeat("c", 64))
	upsert.Decision, upsert.RiskLevel = "block", "high"
	v, err := r.UpsertVersion(ctx, upsert)
	if err != nil {
		t.Fatal(err)
	}
	review := SkillAdmissionReview{Status: "approved", ExpectedStatus: v.AdmissionStatus, ExpectedBundleHash: v.BundleHash, Reason: "Reviewed"}
	if err := r.SetVersionAdmissionReviewed(ctx, "tenant-a", v.ID, review, "reviewer", ""); !errors.Is(err, ErrSkillVersionNotApprovable) {
		t.Fatalf("a blocked scan without an override reason is not approvable: %v", err)
	}
	review.OverrideReason = "业务必须使用，已人工复核"
	if err := r.SetVersionAdmissionReviewed(ctx, "tenant-a", v.ID, review, "reviewer", ""); err != nil {
		t.Fatalf("force approval: %v", err)
	}
	var raw []byte
	var auditTenant, auditIP string
	if err := p.QueryRow(ctx, `SELECT action_detail, tenant_id, ip_address FROM audit_operations WHERE target_id=$1 AND action_type='skill_version.force_approved'`, v.ID).Scan(&raw, &auditTenant, &auditIP); err != nil {
		t.Fatalf("force approval must be audited: %v", err)
	}
	if auditTenant != "tenant-a" || auditIP != "203.0.113.9" {
		t.Fatalf("force approval audit row: tenant=%q ip=%q", auditTenant, auditIP)
	}
	if len(chained) != 1 || chained[0].ActionType != "skill_version.force_approved" || chained[0].TenantID != "tenant-a" ||
		chained[0].UserID != "reviewer" || chained[0].TargetID != v.ID {
		t.Fatalf("exactly the force approval reaches the audit chain after commit: %+v", chained)
	}
	var detail map[string]string
	if err := json.Unmarshal(raw, &detail); err != nil || detail["override_reason"] != review.OverrideReason ||
		detail["scan_decision"] != "block" || detail["risk_level"] != "high" || detail["bundle_hash"] != v.BundleHash {
		t.Fatalf("force approval audit lacks the reason or scan summary: %s", raw)
	}

	invalid := uploadedSkill("tenant-a", "unsigned", strings.Repeat("d", 64))
	invalid.Decision, invalid.SignatureStatus = "block", "invalid"
	iv, err := r.UpsertVersion(ctx, invalid)
	if err != nil {
		t.Fatal(err)
	}
	forced := SkillAdmissionReview{Status: "approved", ExpectedStatus: iv.AdmissionStatus, ExpectedBundleHash: iv.BundleHash, Reason: "Reviewed", OverrideReason: "想用"}
	if err := r.SetVersionAdmissionReviewed(ctx, "tenant-a", iv.ID, forced, "reviewer", ""); !errors.Is(err, ErrSkillVersionNotApprovable) {
		t.Fatalf("an invalid signature is never approvable: %v", err)
	}
}
