package repository

import (
	"errors"
	"strings"
	"testing"
)

// 复审次要项：仓库侧审查请求校验同样拒绝 unicode.Cf。
func TestSkillAdmissionReview2922RejectsFormatCharacters(t *testing.T) {
	base := SkillAdmissionReview{Status: "approved", ExpectedStatus: "unverified", ExpectedBundleHash: strings.Repeat("a", 64), Reason: "Reviewed"}
	if err := validateSkillAdmissionReview(base); err != nil {
		t.Fatalf("fixture must be valid: %v", err)
	}
	reason := base
	reason.Reason = "Reviewed\u202e"
	override := base
	override.OverrideReason = "业务\u200b需要"
	for name, review := range map[string]SkillAdmissionReview{"reason": reason, "override_reason": override} {
		if err := validateSkillAdmissionReview(review); !errors.Is(err, ErrSkillInvalidRequest) {
			t.Errorf("%s with a format character must be rejected: %v", name, err)
		}
	}
}

// 复审次要项（真库）：扫描结论不是阻断的版本带 override_reason 返回 ErrSkillOverrideNotApplicable，版本不变。
func TestSkillForceApprove2922PostgresOverrideOnNonBlockedScanRejected(t *testing.T) {
	ctx, r, _ := skillGovernanceFixture(t)
	v, err := r.UpsertVersion(ctx, uploadedSkill("tenant-a", "clean", strings.Repeat("e", 64)))
	if err != nil {
		t.Fatal(err)
	}
	review := SkillAdmissionReview{Status: "approved", ExpectedStatus: v.AdmissionStatus, ExpectedBundleHash: v.BundleHash,
		Reason: "Reviewed", OverrideReason: "业务必须使用"}
	if err := r.SetVersionAdmissionReviewed(ctx, "tenant-a", v.ID, review, "reviewer", ""); !errors.Is(err, ErrSkillOverrideNotApplicable) {
		t.Fatalf("an override reason on a non-blocked scan must be rejected: %v", err)
	}
	review.OverrideReason = ""
	if err := r.SetVersionAdmissionReviewed(ctx, "tenant-a", v.ID, review, "reviewer", ""); err != nil {
		t.Fatalf("the same version is still approvable without an override reason: %v", err)
	}
}
