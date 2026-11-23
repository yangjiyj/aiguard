package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func skillGovernanceFixture(t *testing.T) (context.Context, *SkillAssetsRepository, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("SKILL_GOVERNANCE_TEST_DSN")
	if dsn == "" {
		t.Skip("SKILL_GOVERNANCE_TEST_DSN not configured")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "skill_governance_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close(); admin.Close() })
	if _, err = pool.Exec(ctx, `CREATE TABLE users(id TEXT PRIMARY KEY); CREATE TABLE audit_operations(id TEXT PRIMARY KEY,tenant_id TEXT,user_id TEXT NOT NULL REFERENCES users(id),action_type TEXT NOT NULL,action_detail JSONB,target_type TEXT,target_id TEXT,ip_address TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()); INSERT INTO users VALUES('reviewer');`); err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("SKILL_GOVERNANCE_MIGRATION")
	if path == "" {
		path = filepath.Join("..", "..", "..", "..", "deploy", "migrations", "115_skill_gateway_assets.sql")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(b)); err != nil {
		t.Fatal(err)
	}
	return ctx, NewSkillAssetsRepository(pool), pool
}
func uploadedSkill(tenant, name, hash string) SkillVersionUpsert {
	return SkillVersionUpsert{TenantID: tenant, CanonicalName: name, SourceType: "uploaded", DeclaredVersion: "1", SourceCommit: "commit-1", BundleHash: hash, TreeHash: strings.Repeat("b", 64), ManifestJSON: []byte(`{"surface":"uploaded_scan","files":[]}`), FindingsJSON: []byte(`[]`), RiskLevel: "low", Decision: "allow", ScanStatus: "completed"}
}
func TestSkillGovernancePostgresDeclarationConflictPreservesApprovalAndOriginalBytes(t *testing.T) {
	ctx, r, p := skillGovernanceFixture(t)
	in := uploadedSkill("tenant-a", "pdf", strings.Repeat("a", 64))
	v, err := r.UpsertVersion(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	review := SkillAdmissionReview{Status: "approved", ExpectedStatus: "unverified", ExpectedBundleHash: v.BundleHash, Reason: "Exact package reviewed"}
	if err = r.SetVersionAdmissionReviewed(ctx, "tenant-a", v.ID, review, "reviewer", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	var before string
	if err = p.QueryRow(ctx, `SELECT row_to_json(v)::text FROM skill_asset_versions v WHERE id=$1`, v.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*SkillVersionUpsert){func(in *SkillVersionUpsert) { in.DeclaredVersion = "2" }, func(in *SkillVersionUpsert) { in.SourceCommit = "different-commit" }} {
		conflict := in
		change(&conflict)
		conflict.DisplayName = "changed name"
		if _, err = r.UpsertVersion(ctx, conflict); !errors.Is(err, ErrSkillVersionDeclarationConflict) {
			t.Fatalf("immutable declaration replaced: %v", err)
		}
	}
	var after string
	if err = p.QueryRow(ctx, `SELECT row_to_json(v)::text FROM skill_asset_versions v WHERE id=$1`, v.ID).Scan(&after); err != nil || after != before {
		t.Fatalf("conflict mutated original approval: %v", err)
	}
	resolved, err := r.ResolveAdmission(ctx, "tenant-a", "pdf", "1", v.BundleHash)
	if err != nil || resolved.Status != "approved" {
		t.Fatalf("approval anchor lost %+v %v", resolved, err)
	}
	in.BundleHash = strings.Repeat("c", 64)
	in.DeclaredVersion = "2"
	newVersion, err := r.UpsertVersion(ctx, in)
	if err != nil || newVersion.AdmissionStatus != "unverified" || newVersion.ID == v.ID {
		t.Fatalf("new bundle inherited approval %+v %v", newVersion, err)
	}
}
func TestSkillGovernancePostgresReviewCASReasonAuditTenantAndRollback(t *testing.T) {
	ctx, r, p := skillGovernanceFixture(t)
	v, err := r.UpsertVersion(ctx, uploadedSkill("tenant-a", "pdf", strings.Repeat("a", 64)))
	if err != nil {
		t.Fatal(err)
	}
	approved := SkillAdmissionReview{Status: "approved", ExpectedStatus: "unverified", ExpectedBundleHash: v.BundleHash, Reason: "Reviewed dependency and manifest"}
	if err = r.SetVersionAdmissionReviewed(ctx, "tenant-b", v.ID, approved, "reviewer", ""); err == nil {
		t.Fatal("cross tenant review succeeded")
	}
	bad := approved
	bad.ExpectedBundleHash = strings.Repeat("f", 64)
	if err = r.SetVersionAdmissionReviewed(ctx, "tenant-a", v.ID, bad, "reviewer", ""); !errors.Is(err, ErrSkillAdmissionConflict) {
		t.Fatal("wrong bundle pin accepted")
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, status := range []string{"approved", "quarantined"} {
		review := approved
		review.Status = status
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- r.SetVersionAdmissionReviewed(ctx, "tenant-a", v.ID, review, "reviewer", "")
		}()
	}
	wg.Wait()
	close(results)
	var succeeded, conflicts int
	for err := range results {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrSkillAdmissionConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || conflicts != 1 {
		t.Fatalf("CAS writers success=%d conflict=%d", succeeded, conflicts)
	}
	var audit []byte
	if err = p.QueryRow(ctx, `SELECT action_detail FROM audit_operations WHERE target_id=$1`, v.ID).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	var detail map[string]string
	if err = json.Unmarshal(audit, &detail); err != nil || detail["reason"] != approved.Reason || detail["bundle_hash"] != v.BundleHash || detail["previous_status"] != "unverified" || detail["declared_version"] != "1" {
		t.Fatalf("review audit missing anchor %s", audit)
	}
	versions, err := r.ListVersions(ctx, "tenant-a", v.AssetID)
	if err != nil || len(versions) != 1 || versions[0].ReviewReason != approved.Reason || versions[0].ReviewedBy != "reviewer" || versions[0].ReviewedAt == nil {
		t.Fatalf("review evidence absent from exact-version DTO %+v %v", versions, err)
	}
	var current string
	if err = p.QueryRow(ctx, `SELECT admission_status FROM skill_asset_versions WHERE id=$1`, v.ID).Scan(&current); err != nil {
		t.Fatal(err)
	}
	next := approved
	next.ExpectedStatus = current
	next.Status = "revoked"
	r.beforeAdmissionAudit = func() error { return errors.New("audit unavailable") }
	if err = r.SetVersionAdmissionReviewed(ctx, "tenant-a", v.ID, next, "reviewer", ""); err == nil {
		t.Fatal("missing audit reported success")
	}
	var now string
	if err = p.QueryRow(ctx, `SELECT admission_status FROM skill_asset_versions WHERE id=$1`, v.ID).Scan(&now); err != nil || now != current {
		t.Fatal("audit failure committed review")
	}
}
func TestSkillGovernancePostgresPagedFilteredTotalsAndGlobalSummary(t *testing.T) {
	ctx, r, _ := skillGovernanceFixture(t)
	for i := 0; i < 55; i++ {
		if _, err := r.UpsertVersion(ctx, uploadedSkill("tenant-a", fmt.Sprintf("skill-%02d", i), fmt.Sprintf("%064x", i+1))); err != nil {
			t.Fatal(err)
		}
	}
	observed := uploadedSkill("tenant-a", "observed", strings.Repeat("e", 64))
	observed.SourceType = "observed"
	observed.ScanStatus = "pending"
	observed.Decision = "confirm"
	if _, err := r.UpsertVersion(ctx, observed); err != nil {
		t.Fatal(err)
	}
	if _, err := r.UpsertVersion(ctx, uploadedSkill("tenant-b", "private", strings.Repeat("f", 64))); err != nil {
		t.Fatal(err)
	}
	page, err := r.ListAssetsPage(ctx, "tenant-a", SkillAssetFilter{Limit: 10, Offset: 50, SourceType: "uploaded"})
	if err != nil || page.Total != 55 || len(page.Items) != 5 || page.Summary.UploadedAssets != 55 || page.Summary.ObservedAssets != 1 || page.Summary.PendingVersions != 55 {
		t.Fatalf("page/summary based on current page or leaked tenant: %+v %v", page, err)
	}
	filtered, err := r.ListAssetsPage(ctx, "tenant-a", SkillAssetFilter{Query: "skill-01"})
	if err != nil || filtered.Total != 1 || len(filtered.Items) != 1 || filtered.Summary.UploadedAssets != 55 {
		t.Fatalf("filter/summary mismatch %+v %v", filtered, err)
	}
}
func TestSkillGovernancePostgresResultRetainsBlockedAndConfirmFactsAndFilters(t *testing.T) {
	ctx, r, _ := skillGovernanceFixture(t)
	v, err := r.UpsertVersion(ctx, uploadedSkill("tenant-a", "pdf", strings.Repeat("a", 64)))
	if err != nil {
		t.Fatal(err)
	}
	for i, decision := range []string{"block", "confirm", "allow"} {
		status := "proposed"
		if decision == "block" {
			status = "blocked"
		}
		inv, err := r.RecordInvocation(ctx, SkillInvocationUpsert{TenantID: "tenant-a", AssetID: v.AssetID, AssetVersionID: v.ID, RequestID: fmt.Sprint("request", i), SessionID: "session", ToolCallID: fmt.Sprint("tool", i), CanonicalName: "pdf", DeclaredVersion: "1", Status: status, RawDecision: decision, EffectiveDecision: decision, RedactedPreviewJSON: []byte("{}"), AttributionMode: "explicit", AttributionConfidence: 1})
		if err != nil {
			t.Fatal(err)
		}
		if err = r.MarkInvocationResult(ctx, "tenant-a", "session", inv.ToolCallID, "client_result", []byte(`[]`)); err != nil {
			t.Fatal(err)
		}
	}
	page, err := r.ListInvocationsPage(ctx, "tenant-a", SkillInvocationFilter{VersionID: v.ID, EffectiveDecision: "block"})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Status != "blocked" || page.Items[0].ResultStatus != "client_result" || page.Items[0].ResultObservedAt == nil || page.Items[0].CompletedAt != nil || page.EndpointExecutionProof {
		t.Fatalf("client result fabricated blocked execution %+v %v", page, err)
	}
	page, err = r.ListInvocationsPage(ctx, "tenant-a", SkillInvocationFilter{EffectiveDecision: "confirm"})
	if err != nil || page.Items[0].Status != "proposed" {
		t.Fatalf("result upgraded awaiting confirmation %+v %v", page, err)
	}
	page, err = r.ListInvocationsPage(ctx, "tenant-a", SkillInvocationFilter{Limit: 1, Offset: 1})
	if err != nil || page.Total != 3 || len(page.Items) != 1 {
		t.Fatalf("invocation page count %+v %v", page, err)
	}
	other, err := r.ListInvocationsPage(ctx, "tenant-b", SkillInvocationFilter{VersionID: v.ID})
	if err != nil || other.Total != 0 {
		t.Fatal("foreign version leaked invocation")
	}
}
