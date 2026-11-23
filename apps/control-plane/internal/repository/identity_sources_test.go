package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupIdentityTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dbURL == "" {
		if os.Getenv("JJD_REQUIRE_IDENTITY_DB_TESTS") == "1" {
			t.Fatal("CONTENT_LOGS_TEST_DATABASE_URL is required when JJD_REQUIRE_IDENTITY_DB_TESTS=1")
		}
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	db, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func setupIdentityTenant(t *testing.T, db *pgxpool.Pool) string {
	t.Helper()
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID := "tis_" + sfx
	ctx := context.Background()
	_, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status) VALUES ($1, $2, 'enterprise', 'active')`, tenantID, tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM identity_dept_mappings WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM identity_sources WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
	})
	return tenantID
}

func commitTestIdentityPublication(
	ctx context.Context,
	repo *IdentitySourceRepository,
	src *IdentitySource,
	publishedBy string,
) error {
	if err := repo.MarkPublishing(ctx, src.TenantID, src.ID, src.Version); err != nil {
		return err
	}
	return repo.CommitPublication(ctx, PublicationCommit{
		TenantID: src.TenantID, SourceID: src.ID, ExpectedVersion: src.Version,
		RuntimeAlias: "enterprise", ConfigDigest: "sha256:test", PublishedBy: publishedBy,
	})
}

func TestIdentitySourceUpsertDraftAndGet(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)

	src := &IdentitySource{
		TenantID:        tenantID,
		DisplayName:     "企业 IdP",
		IssuerURL:       "https://idp.example.com",
		ClientID:        "jjdguard-client",
		ClientSecretEnc: "enc:v1:dGVzdA==",
		Scopes:          "openid profile email",
	}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatalf("UpsertDraft: %v", err)
	}
	if src.ID == "" {
		t.Fatal("ID should be set after upsert")
	}

	got, err := repo.GetDraft(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetDraft: %v", err)
	}
	if got == nil {
		t.Fatal("draft not found")
	}
	if got.DisplayName != "企业 IdP" || got.ClientID != "jjdguard-client" {
		t.Fatalf("bad draft: %+v", got)
	}
	if got.ClientSecretEnc != "enc:v1:dGVzdA==" {
		t.Fatalf("secret mismatch: %s", got.ClientSecretEnc)
	}
	if got.Status != "draft" {
		t.Fatalf("expected draft status, got %s", got.Status)
	}
}

func TestIdentitySourceTenantIsolation(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantA := setupIdentityTenant(t, db)
	tenantB := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)

	src := &IdentitySource{
		TenantID:        tenantA,
		DisplayName:     "Tenant A IdP",
		IssuerURL:       "https://idp-a.example.com",
		ClientID:        "client-a",
		ClientSecretEnc: "enc:v1:AAAA",
	}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatalf("UpsertDraft: %v", err)
	}

	got, err := repo.GetDraft(ctx, tenantB)
	if err != nil {
		t.Fatalf("GetDraft: %v", err)
	}
	if got != nil {
		t.Fatalf("tenant B should not see tenant A's draft: %+v", got)
	}
}

func TestIdentitySourceActivateDisablesOthers(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)

	src1 := &IdentitySource{
		TenantID:        tenantID,
		DisplayName:     "IdP 1",
		IssuerURL:       "https://idp1.example.com",
		ClientID:        "client-1",
		ClientSecretEnc: "enc:v1:1111",
	}
	if err := repo.UpsertDraft(ctx, src1); err != nil {
		t.Fatalf("UpsertDraft 1: %v", err)
	}
	if err := repo.UpdateTestResult(ctx, tenantID, src1.ID, src1.Version, &TestResult{Success: true, TestedAt: "now"}); err != nil {
		t.Fatalf("UpdateTestResult 1: %v", err)
	}
	if err := commitTestIdentityPublication(ctx, repo, src1, "admin_user"); err != nil {
		t.Fatalf("Activate 1: %v", err)
	}

	active1, err := repo.GetActive(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if active1 == nil || active1.ID != src1.ID {
		t.Fatalf("expected active src1, got %+v", active1)
	}

	src2 := &IdentitySource{
		TenantID:        tenantID,
		DisplayName:     "IdP 2",
		IssuerURL:       "https://idp2.example.com",
		ClientID:        "client-2",
		ClientSecretEnc: "enc:v1:2222",
	}
	if err := repo.UpsertDraft(ctx, src2); err != nil {
		t.Fatalf("UpsertDraft 2: %v", err)
	}
	if err := repo.UpdateTestResult(ctx, tenantID, src2.ID, src2.Version, &TestResult{Success: true, TestedAt: "now"}); err != nil {
		t.Fatalf("UpdateTestResult 2: %v", err)
	}
	if err := commitTestIdentityPublication(ctx, repo, src2, "admin_user"); err != nil {
		t.Fatalf("Activate 2: %v", err)
	}

	active2, err := repo.GetActive(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetActive after 2: %v", err)
	}
	if active2 == nil || active2.ID != src2.ID {
		t.Fatalf("expected active src2, got %+v", active2)
	}

	old1, err := repo.GetByID(ctx, tenantID, src1.ID)
	if err != nil {
		t.Fatalf("GetByID src1: %v", err)
	}
	if old1.Status != "disabled" {
		t.Fatalf("expected src1 disabled, got %s", old1.Status)
	}
}

func TestIdentitySourceUpdateTestResult(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)

	src := &IdentitySource{
		TenantID:        tenantID,
		DisplayName:     "Test IdP",
		IssuerURL:       "https://idp.example.com",
		ClientID:        "client-test",
		ClientSecretEnc: "enc:v1:test",
	}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatalf("UpsertDraft: %v", err)
	}

	result := &TestResult{
		Success:  false,
		TestedAt: "2026-07-14T10:00:00Z",
		Stages: []TestStage{
			{Name: "地址解析", Status: "passed", Message: "OK"},
			{Name: "获取发现文档", Status: "failed", Message: "连接超时"},
		},
		Error: "连接超时",
	}
	if err := repo.UpdateTestResult(ctx, tenantID, src.ID, src.Version, result); err != nil {
		t.Fatalf("UpdateTestResult: %v", err)
	}

	got, err := repo.GetByID(ctx, tenantID, src.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != "draft" {
		t.Fatalf("failed connection test must keep draft status, got %s", got.Status)
	}
	if err := commitTestIdentityPublication(ctx, repo, src, "admin_user"); err == nil {
		t.Fatal("failed connection test must not permit activation")
	}
	if got.LastTestResult == nil {
		t.Fatal("LastTestResult should not be nil")
	}
	if got.LastTestResult.Success != false {
		t.Fatal("expected test result success=false")
	}
	if len(got.LastTestResult.Stages) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(got.LastTestResult.Stages))
	}
}

func TestIdentitySourceSavingTestedConfigInvalidatesTestAndIncrementsVersion(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)
	src := &IdentitySource{TenantID: tenantID, DisplayName: "IdP v1", IssuerURL: "https://idp.example.com", ClientID: "client-v1", ClientSecretEnc: "enc:v1:test"}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatal(err)
	}
	firstVersion := src.Version
	if err := repo.UpdateTestResult(ctx, tenantID, src.ID, firstVersion, &TestResult{Success: true, TestedAt: "now"}); err != nil {
		t.Fatal(err)
	}
	pending, err := repo.GetPending(ctx, tenantID)
	if err != nil || pending == nil {
		t.Fatalf("tested config missing: %v", err)
	}
	pending.DisplayName = "IdP v2"
	pending.Status = "draft"
	if err := repo.UpsertDraft(ctx, pending); err != nil {
		t.Fatal(err)
	}
	if pending.ID != src.ID {
		t.Fatalf("save must reuse pending config id: %s != %s", pending.ID, src.ID)
	}
	if pending.Version != firstVersion+1 {
		t.Fatalf("version must increment on save: got %d want %d", pending.Version, firstVersion+1)
	}
	got, err := repo.GetDraft(ctx, tenantID)
	if err != nil || got == nil {
		t.Fatalf("draft missing after edit: %v", err)
	}
	if got.Status != "draft" || got.LastTestResult != nil || got.LastTestedAt != nil {
		t.Fatalf("editing tested config must invalidate test result: %+v", got)
	}
	if tested, err := repo.GetTested(ctx, tenantID); err != nil || tested != nil {
		t.Fatalf("old tested config must not remain activatable: tested=%+v err=%v", tested, err)
	}
}

func TestIdentitySourceRejectsStaleConnectionTestResult(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)
	src := &IdentitySource{TenantID: tenantID, DisplayName: "IdP v1", IssuerURL: "https://idp.example.com", ClientID: "client-v1", ClientSecretEnc: "enc:v1:test"}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatal(err)
	}
	testedVersion := src.Version
	src.DisplayName = "IdP v2"
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatal(err)
	}
	err := repo.UpdateTestResult(ctx, tenantID, src.ID, testedVersion, &TestResult{Success: true, TestedAt: "stale"})
	if !errors.Is(err, ErrIdentitySourceChanged) {
		t.Fatalf("stale test result must be rejected, got %v", err)
	}
	got, err := repo.GetDraft(ctx, tenantID)
	if err != nil || got == nil || got.Status != "draft" {
		t.Fatalf("latest edit must remain untested draft: got=%+v err=%v", got, err)
	}
}

func TestIdentitySourceRejectsSaveAfterConcurrentActivation(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)
	src := &IdentitySource{TenantID: tenantID, DisplayName: "IdP", IssuerURL: "https://idp.example.com", ClientID: "client", ClientSecretEnc: "enc:v1:test"}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateTestResult(ctx, tenantID, src.ID, src.Version, &TestResult{Success: true, TestedAt: "now"}); err != nil {
		t.Fatal(err)
	}
	pending, err := repo.GetPending(ctx, tenantID)
	if err != nil || pending == nil {
		t.Fatalf("pending config missing: %v", err)
	}
	if err := commitTestIdentityPublication(ctx, repo, pending, "admin"); err != nil {
		t.Fatal(err)
	}
	pending.DisplayName = "stale save"
	err = repo.UpsertDraft(ctx, pending)
	if !errors.Is(err, ErrIdentitySourceChanged) {
		t.Fatalf("stale save after activation must be rejected, got %v", err)
	}
	active, err := repo.GetActive(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || active.ID != src.ID || active.Status != "active" {
		t.Fatalf("concurrent stale save must not demote active config: %+v", active)
	}
}

func TestIdentityDeptMappingCRUD(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)

	src := &IdentitySource{
		TenantID:        tenantID,
		DisplayName:     "Dept IdP",
		IssuerURL:       "https://idp.example.com",
		ClientID:        "client-dept",
		ClientSecretEnc: "enc:v1:dept",
	}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatalf("UpsertDraft: %v", err)
	}

	m := &IdentityDeptMapping{
		TenantID:         tenantID,
		IdentitySourceID: src.ID,
		MatchValue:       "rd",
		Priority:         50,
		Enabled:          true,
	}
	if err := repo.UpsertDeptMapping(ctx, m); err != nil {
		t.Fatalf("UpsertDeptMapping: %v", err)
	}
	if m.ID == "" {
		t.Fatal("ID should be set")
	}

	list, err := repo.ListDeptMappings(ctx, tenantID, src.ID)
	if err != nil {
		t.Fatalf("ListDeptMappings: %v", err)
	}
	if len(list) != 1 || list[0].MatchValue != "rd" {
		t.Fatalf("bad list: %+v", list)
	}

	m.MatchValue = "研发部"
	m.Priority = 10
	if err := repo.UpsertDeptMapping(ctx, m); err != nil {
		t.Fatalf("UpdateDeptMapping: %v", err)
	}
	list2, _ := repo.ListDeptMappings(ctx, tenantID, src.ID)
	if len(list2) != 1 || list2[0].MatchValue != "研发部" || list2[0].Priority != 10 {
		t.Fatalf("bad update: %+v", list2)
	}

	if err := repo.DeleteDeptMapping(ctx, tenantID, m.ID); err != nil {
		t.Fatalf("DeleteDeptMapping: %v", err)
	}
	list3, _ := repo.ListDeptMappings(ctx, tenantID, src.ID)
	if len(list3) != 0 {
		t.Fatalf("expected empty after delete, got %d", len(list3))
	}
}

func TestIdentityDeptMappingRejectsCrossTenantSource(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantA := setupIdentityTenant(t, db)
	tenantB := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)

	src := &IdentitySource{
		TenantID: tenantA, DisplayName: "Tenant A IdP",
		IssuerURL: "https://idp-a.example.com", ClientID: "a",
		ClientSecretEnc: "enc:v1:a",
	}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatal(err)
	}

	mapping := &IdentityDeptMapping{
		TenantID: tenantB, IdentitySourceID: src.ID,
		MatchValue: "foreign-source", Enabled: true,
	}
	if err := repo.UpsertDeptMapping(ctx, mapping); err == nil {
		t.Fatal("mapping must not reference another tenant's identity source")
	}
}

func TestIdentityDeptMappingRejectsCrossTenantUpdate(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantA := setupIdentityTenant(t, db)
	tenantB := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)

	src := &IdentitySource{
		TenantID: tenantA, DisplayName: "Tenant A IdP",
		IssuerURL: "https://idp-a.example.com", ClientID: "a",
		ClientSecretEnc: "enc:v1:a",
	}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatal(err)
	}
	original := &IdentityDeptMapping{
		TenantID: tenantA, IdentitySourceID: src.ID,
		MatchValue: "original", Enabled: true,
	}
	if err := repo.UpsertDeptMapping(ctx, original); err != nil {
		t.Fatal(err)
	}

	hijack := &IdentityDeptMapping{
		ID: original.ID, TenantID: tenantB,
		MatchValue: "hijacked", Enabled: true,
	}
	if err := repo.UpsertDeptMapping(ctx, hijack); err == nil {
		t.Fatal("cross-tenant update must be rejected")
	}
}

func TestIdentityPublicationLifecycle(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)
	src := &IdentitySource{
		TenantID: tenantID, DisplayName: "企业 IdP",
		IssuerURL: "https://idp.example.com", ClientID: "client-a",
		ClientSecretEnc: "enc:v1:test",
	}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateTestResult(ctx, tenantID, src.ID, src.Version, &TestResult{Success: true, TestedAt: "now"}); err != nil {
		t.Fatal(err)
	}

	if err := repo.MarkPublishing(ctx, tenantID, src.ID, src.Version); err != nil {
		t.Fatal(err)
	}
	publishing, err := repo.GetByID(ctx, tenantID, src.ID)
	if err != nil || publishing.PublishStatus != "publishing" {
		t.Fatalf("publishing state: %#v %v", publishing, err)
	}

	if err := repo.CommitPublication(ctx, PublicationCommit{
		TenantID: tenantID, SourceID: src.ID, ExpectedVersion: src.Version,
		RuntimeAlias: "enterprise", ConfigDigest: "sha256:abc", PublishedBy: "admin-a",
	}); err != nil {
		t.Fatal(err)
	}

	active, err := repo.GetActive(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || active.PublishStatus != "active" || active.AppliedVersion != src.Version ||
		active.RuntimeAlias != "enterprise" || active.ConfigDigest != "sha256:abc" {
		t.Fatalf("unexpected active publication: %#v", active)
	}
	var eventCount int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM identity_publication_events
		WHERE tenant_id=$1 AND identity_source_id=$2 AND action='publish' AND result='succeeded'`,
		tenantID, src.ID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("publication events=%d, want 1", eventCount)
	}

	if err := repo.MarkPublicationError(ctx, tenantID, src.ID, "runtime_unavailable", "client_secret=sensitive"); err != nil {
		t.Fatal(err)
	}
	failed, err := repo.GetByID(ctx, tenantID, src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.LastPublishError != "runtime_unavailable" {
		t.Fatalf("unsafe publication error persisted: %q", failed.LastPublishError)
	}
}

func TestMarkPublishingRejectsStaleVersionAndCrossTenant(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantA := setupIdentityTenant(t, db)
	tenantB := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)
	src := &IdentitySource{
		TenantID: tenantA, DisplayName: "Tenant A IdP",
		IssuerURL: "https://idp-a.example.com", ClientID: "client-a",
		ClientSecretEnc: "enc:v1:test",
	}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateTestResult(ctx, tenantA, src.ID, src.Version, &TestResult{Success: true, TestedAt: "now"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkPublishing(ctx, tenantA, src.ID, src.Version+1); !errors.Is(err, ErrIdentitySourceChanged) {
		t.Fatalf("stale version error=%v", err)
	}
	if err := repo.MarkPublishing(ctx, tenantB, src.ID, src.Version); !errors.Is(err, ErrIdentitySourceChanged) {
		t.Fatalf("cross-tenant error=%v", err)
	}
}
