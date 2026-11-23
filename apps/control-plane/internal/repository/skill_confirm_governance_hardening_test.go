package repository

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSkillScannerHardeningPostgresConfirmReasonAndAuditAlreadyEnforced(t *testing.T) {
	ctx,repo,pool := skillGovernanceFixture(t)
	in := uploadedSkill("tenant-a","confirm-skill",strings.Repeat("a",64))
	in.Decision = "confirm"
	in.RiskLevel = "medium"
	version,err := repo.UpsertVersion(ctx,in)
	if err != nil { t.Fatal(err) }
	review := SkillAdmissionReview{Status:"approved",ExpectedStatus:"unverified",ExpectedBundleHash:version.BundleHash}
	if err := repo.SetVersionAdmissionReviewed(ctx,"tenant-a",version.ID,review,"reviewer","");!errors.Is(err,ErrSkillInvalidRequest) {
		t.Fatalf("confirm package approved without reason: %v",err)
	}
	var status string
	var auditCount int
	if err:=pool.QueryRow(ctx,`SELECT admission_status FROM skill_asset_versions WHERE id=$1`,version.ID).Scan(&status);err!=nil { t.Fatal(err) }
	if err:=pool.QueryRow(ctx,`SELECT count(*) FROM audit_operations WHERE target_id=$1`,version.ID).Scan(&auditCount);err!=nil { t.Fatal(err) }
	if status!="unverified"||auditCount!=0 { t.Fatalf("invalid review changed state: status=%s audits=%d",status,auditCount) }
	review.Reason = "Reviewed confirm findings and dependency provenance"
	if err:=repo.SetVersionAdmissionReviewed(ctx,"tenant-a",version.ID,review,"reviewer","");err!=nil { t.Fatal(err) }
	var raw []byte
	if err:=pool.QueryRow(ctx,`SELECT action_detail FROM audit_operations WHERE target_id=$1`,version.ID).Scan(&raw);err!=nil { t.Fatal(err) }
	var detail map[string]any
	if err:=json.Unmarshal(raw,&detail);err!=nil||detail["reason"]!=review.Reason||detail["bundle_hash"]!=version.BundleHash||detail["previous_status"]!="unverified" {
		t.Fatalf("confirm approval audit incomplete: %s err=%v",raw,err)
	}
}
