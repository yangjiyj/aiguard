package repository

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupSkillAssetTestDB(t *testing.T) (*pgxpool.Pool, string, string) {
	t.Helper()
	dsn := os.Getenv("SKILL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SKILL_TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	suffix := time.Now().UTC().Format("150405.000000000")
	return pool, "skill-a-" + suffix, "skill-b-" + suffix
}

func TestSkillAssetRepositoryTenantIsolationAndImmutableVersions(t *testing.T) {
	pool, tenantA, tenantB := setupSkillAssetTestDB(t)
	ctx := context.Background()
	repo := NewSkillAssetsRepository(pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM skill_invocations WHERE tenant_id = ANY($1)", []string{tenantA, tenantB})
		_, _ = pool.Exec(ctx, "DELETE FROM skill_asset_versions WHERE tenant_id = ANY($1)", []string{tenantA, tenantB})
		_, _ = pool.Exec(ctx, "DELETE FROM skill_assets WHERE tenant_id = ANY($1)", []string{tenantA, tenantB})
	})

	versionA, err := repo.UpsertVersion(ctx, SkillVersionUpsert{
		TenantID: tenantA, CanonicalName: "pdf", DisplayName: "PDF", SourceType: "uploaded",
		DeclaredVersion: "1.0.0", BundleHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TreeHash:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ManifestJSON: []byte(`{"files":[]}`), FindingsJSON: []byte("[]"),
		RiskLevel: "low", Decision: "allow", ScanStatus: "completed",
	})
	if err != nil {
		t.Fatalf("upsert A: %v", err)
	}
	again, err := repo.UpsertVersion(ctx, SkillVersionUpsert{
		TenantID: tenantA, CanonicalName: "pdf", DisplayName: "PDF renamed", SourceType: "uploaded",
		DeclaredVersion: "1.0.0", BundleHash: versionA.BundleHash, TreeHash: versionA.TreeHash,
		ManifestJSON: []byte(`{"ignored":"same bundle"}`), FindingsJSON: []byte("[]"),
		RiskLevel: "low", Decision: "allow", ScanStatus: "completed",
	})
	if err != nil {
		t.Fatalf("repeat: %v", err)
	}
	if again.ID != versionA.ID || again.AssetID != versionA.AssetID {
		t.Fatalf("same bundle created duplicate: first=%+v again=%+v", versionA, again)
	}
	versionB, err := repo.UpsertVersion(ctx, SkillVersionUpsert{
		TenantID: tenantB, CanonicalName: "pdf", SourceType: "uploaded",
		DeclaredVersion: "1.0.0", BundleHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		TreeHash:     "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		ManifestJSON: []byte("{}"), FindingsJSON: []byte("[]"),
		RiskLevel: "low", Decision: "allow", ScanStatus: "completed",
	})
	if err != nil {
		t.Fatalf("upsert B: %v", err)
	}
	if versionA.AssetID == versionB.AssetID {
		t.Fatal("cross-tenant same-name assets collapsed")
	}

	assetsA, err := repo.ListAssets(ctx, tenantA, 100, 0)
	if err != nil || len(assetsA) != 1 || assetsA[0].TenantID != tenantA {
		t.Fatalf("tenant list leaked or failed: assets=%+v err=%v", assetsA, err)
	}
	if err := repo.SetVersionAdmission(ctx, tenantB, versionA.ID, "approved", "admin-b", ""); err == nil {
		t.Fatal("tenant B approved tenant A version")
	}
	if err := repo.SetVersionAdmission(ctx, tenantA, versionA.ID, "approved", "admin-a", ""); err != nil {
		t.Fatalf("approve safe version: %v", err)
	}
	resolved, err := repo.ResolveAdmission(ctx, tenantA, "pdf", "1.0.0", versionA.BundleHash)
	if err != nil || resolved.Status != "approved" || resolved.VersionID != versionA.ID {
		t.Fatalf("resolve approved version: resolved=%+v err=%v", resolved, err)
	}

	next, err := repo.UpsertVersion(ctx, SkillVersionUpsert{
		TenantID: tenantA, CanonicalName: "pdf", SourceType: "uploaded",
		DeclaredVersion: "1.1.0", BundleHash: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		TreeHash:     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		ManifestJSON: []byte("{}"), FindingsJSON: []byte("[]"),
		RiskLevel: "low", Decision: "allow", ScanStatus: "completed",
	})
	if err != nil {
		t.Fatalf("new version: %v", err)
	}
	if next.AdmissionStatus != "unverified" {
		t.Fatalf("new bundle inherited approval: %+v", next)
	}
	assetsA, err = repo.ListAssets(ctx, tenantA, 100, 0)
	if err != nil || len(assetsA) != 1 || assetsA[0].AdmissionStatus != "unverified" {
		t.Fatalf("asset summary inherited old version approval: assets=%+v err=%v", assetsA, err)
	}
	if err := repo.SetVersionAdmission(ctx, tenantA, versionA.ID, "approved", "admin-a", ""); err != nil {
		t.Fatalf("repeat old approval: %v", err)
	}
	assetsA, err = repo.ListAssets(ctx, tenantA, 100, 0)
	if err != nil || len(assetsA) != 1 || assetsA[0].AdmissionStatus != "unverified" {
		t.Fatalf("older approval replaced newest version truth: assets=%+v err=%v", assetsA, err)
	}
}

func TestSkillObservedDefinitionCannotBeApprovedOrResolved(t *testing.T) {
	pool, tenant, _ := setupSkillAssetTestDB(t)
	ctx := context.Background()
	repo := NewSkillAssetsRepository(pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM skill_asset_versions WHERE tenant_id=$1", tenant)
		_, _ = pool.Exec(ctx, "DELETE FROM skill_assets WHERE tenant_id=$1", tenant)
	})
	version, err := repo.UpsertVersion(ctx, SkillVersionUpsert{
		TenantID: tenant, CanonicalName: "observed-only", SourceType: "observed",
		DeclaredVersion: "1.0.0",
		BundleHash:      strings.Repeat("a", 64), TreeHash: strings.Repeat("a", 64),
		ManifestJSON: []byte(`{"surface":"gateway_observed"}`), FindingsJSON: []byte("[]"),
		RiskLevel: "medium", Decision: "confirm", ScanStatus: "pending",
	})
	if err != nil {
		t.Fatalf("upsert observed: %v", err)
	}
	if err := repo.SetVersionAdmission(ctx, tenant, version.ID, "approved", "admin", ""); !errors.Is(err, ErrSkillVersionNotApprovable) {
		t.Fatalf("observed definition approval err=%v", err)
	}
	resolved, err := repo.ResolveAdmission(ctx, tenant, "observed-only", "1.0.0", version.BundleHash)
	if err != nil || resolved.Status != "unverified" || resolved.VersionID != "" {
		t.Fatalf("observed definition became runtime admission: %+v err=%v", resolved, err)
	}
}

func TestSkillAdmissionAndAuditAreOneTransaction(t *testing.T) {
	pool, tenant, _ := setupSkillAssetTestDB(t)
	ctx := context.Background()
	base := NewSkillAssetsRepository(pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM audit_operations WHERE action_detail->>'tenant_id'=$1", tenant)
		_, _ = pool.Exec(ctx, "DELETE FROM skill_asset_versions WHERE tenant_id=$1", tenant)
		_, _ = pool.Exec(ctx, "DELETE FROM skill_assets WHERE tenant_id=$1", tenant)
	})
	version, err := base.UpsertVersion(ctx, SkillVersionUpsert{
		TenantID: tenant, CanonicalName: "atomic", SourceType: "uploaded",
		DeclaredVersion: "1.0.0",
		BundleHash:      strings.Repeat("b", 64), TreeHash: strings.Repeat("c", 64),
		ManifestJSON: []byte("{}"), FindingsJSON: []byte("[]"),
		RiskLevel: "low", Decision: "allow", ScanStatus: "completed",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	failing := NewSkillAssetsRepository(pool)
	failing.beforeAdmissionAudit = func() error { return errors.New("injected audit failure") }
	if err := failing.SetVersionAdmission(ctx, tenant, version.ID, "approved", "missing-user", "192.0.2.1"); err == nil {
		t.Fatal("injected audit failure was ignored")
	}
	versions, err := base.ListVersions(ctx, tenant, version.AssetID)
	if err != nil || len(versions) != 1 || versions[0].AdmissionStatus != "unverified" {
		t.Fatalf("admission committed without audit: versions=%+v err=%v", versions, err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM audit_operations WHERE action_detail->>'tenant_id'=$1", tenant).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed transaction left audit rows: count=%d err=%v", count, err)
	}
	if err := base.SetVersionAdmission(ctx, tenant, version.ID, "approved", "missing-user", "192.0.2.1"); err != nil {
		t.Fatalf("approve with atomic audit: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_operations
		WHERE action_type='skill_version.admission'
		  AND action_detail->>'tenant_id'=$1
		  AND action_detail->>'version_id'=$2
	`, tenant, version.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("atomic admission audit missing: count=%d err=%v", count, err)
	}
}

func TestSkillAssetRepositoryRejectsAmbiguousResultLink(t *testing.T) {
	repo := &SkillAssetsRepository{}
	if err := repo.MarkInvocationResult(context.Background(), "tenant-a", "", "call-1", "completed", nil); err == nil {
		t.Fatal("session-less result link was accepted")
	}
}

func TestSkillAssetRepositoryRejectsApprovalOfBlockedScanAndLinksResult(t *testing.T) {
	pool, tenant, _ := setupSkillAssetTestDB(t)
	ctx := context.Background()
	repo := NewSkillAssetsRepository(pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM skill_invocations WHERE tenant_id=$1", tenant)
		_, _ = pool.Exec(ctx, "DELETE FROM skill_asset_versions WHERE tenant_id=$1", tenant)
		_, _ = pool.Exec(ctx, "DELETE FROM skill_assets WHERE tenant_id=$1", tenant)
	})
	version, err := repo.UpsertVersion(ctx, SkillVersionUpsert{
		TenantID: tenant, CanonicalName: "danger", SourceType: "uploaded",
		BundleHash:   "1111111111111111111111111111111111111111111111111111111111111111",
		TreeHash:     "2222222222222222222222222222222222222222222222222222222222222222",
		ManifestJSON: []byte("{}"), FindingsJSON: []byte(`[{"type":"dangerous_command"}]`),
		RiskLevel: "critical", Decision: "block", ScanStatus: "completed", AdmissionStatus: "quarantined",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if version.AdmissionStatus != "quarantined" {
		t.Fatalf("blocked scan was not quarantined atomically: %+v", version)
	}
	if err := repo.SetVersionAdmission(ctx, tenant, version.ID, "approved", "admin", ""); err == nil {
		t.Fatal("blocked scan was approved")
	}

	invocation, err := repo.RecordInvocation(ctx, SkillInvocationUpsert{
		TenantID: tenant, AssetID: version.AssetID, AssetVersionID: version.ID,
		RequestID: "request-1", SessionID: "session-1", ToolCallID: "call-1",
		CanonicalName: "danger", Status: "blocked", RawDecision: "block",
		EffectiveDecision: "block", AttributionMode: "explicit", AttributionConfidence: 1,
	})
	if err != nil {
		t.Fatalf("record invocation: %v", err)
	}
	_, err = repo.RecordInvocation(ctx, SkillInvocationUpsert{
		TenantID: tenant, AssetID: version.AssetID, AssetVersionID: version.ID,
		RequestID: "request-2", SessionID: "session-1", ToolCallID: "call-1",
		CanonicalName: "different-skill", Status: "blocked", RawDecision: "block",
		EffectiveDecision: "block", AttributionMode: "explicit", AttributionConfidence: 1,
	})
	if !errors.Is(err, ErrSkillInvocationConflict) {
		t.Fatalf("reused tool_call_id with conflicting identity err=%v", err)
	}
	if err := repo.MarkInvocationResult(ctx, tenant, "session-1", "call-1", "result_observed", []byte(`[{"type":"hidden_instruction"}]`)); err != nil {
		t.Fatalf("mark result: %v", err)
	}
	invocations, err := repo.ListInvocations(ctx, tenant, 10, 0)
	if err != nil || len(invocations) != 1 || invocations[0].ID != invocation.ID ||
		invocations[0].ResultStatus != "result_observed" {
		t.Fatalf("result link failed: invocations=%+v err=%v", invocations, err)
	}
}
func TestSkillAssetRepositoryRescanCanEscalateButNotClearAdmission(t *testing.T) {
	pool, tenant, _ := setupSkillAssetTestDB(t)
	ctx := context.Background()
	repo := NewSkillAssetsRepository(pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM skill_asset_versions WHERE tenant_id=$1", tenant)
		_, _ = pool.Exec(ctx, "DELETE FROM skill_assets WHERE tenant_id=$1", tenant)
	})
	input := SkillVersionUpsert{
		TenantID: tenant, CanonicalName: "rescanned", SourceType: "uploaded",
		DeclaredVersion: "1.0.0",
		BundleHash:      strings.Repeat("a", 64), TreeHash: strings.Repeat("b", 64),
		ManifestJSON: []byte("{}"), FindingsJSON: []byte("[]"),
		RiskLevel: "low", Decision: "allow", ScanStatus: "completed",
	}
	version, err := repo.UpsertVersion(ctx, input)
	if err != nil {
		t.Fatalf("initial scan: %v", err)
	}
	if err := repo.SetVersionAdmission(ctx, tenant, version.ID, "approved", "admin", ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	input.AdmissionStatus = "quarantined"
	escalated, err := repo.UpsertVersion(ctx, input)
	if err != nil {
		t.Fatalf("escalating rescan: %v", err)
	}
	if escalated.ID != version.ID || escalated.AdmissionStatus != "quarantined" {
		t.Fatalf("rescan did not atomically quarantine exact bundle: %+v", escalated)
	}
	input.AdmissionStatus = "unverified"
	stillQuarantined, err := repo.UpsertVersion(ctx, input)
	if err != nil {
		t.Fatalf("safe rescan: %v", err)
	}
	if stillQuarantined.AdmissionStatus != "quarantined" {
		t.Fatalf("safe rescan silently cleared quarantine: %+v", stillQuarantined)
	}
}
