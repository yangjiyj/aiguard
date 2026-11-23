package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// unifiedAssetIntegrationFixture stands up an isolated schema against a real
// PostgreSQL instance, applies the exact 860 migration used in production,
// and seeds the minimal stub tables the migration and the repository's own
// queries (users FK, agent_endpoints LEFT JOIN) require. Every test in this
// file exercises AgentUnifiedAssetRepository against that live schema instead
// of the fake-transaction doubles used elsewhere in this package, so locking,
// ON CONFLICT semantics, and concurrent goroutines run through real SQL.
func unifiedAssetIntegrationFixture(t *testing.T) (context.Context, *pgxpool.Pool, *AgentUnifiedAssetRepository) {
	t.Helper()
	databaseURL := os.Getenv("AGENTGUARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("AGENTGUARD_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "unified_assets_it_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("clean isolated unified-assets fixture: %v", err)
		}
		admin.Close()
	})

	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	exec := func(q string) {
		t.Helper()
		if _, err := db.Exec(ctx, q); err != nil {
			t.Fatalf("fixture setup: %v\nquery: %s", err, q)
		}
	}
	// Minimal legacy source table the 860 migration reads from, and the stub
	// tables its FKs and the repository's List() LEFT JOIN reference. This
	// mirrors the minimal-stub approach already used by
	// agent_identity_integration_test.go in this same package.
	exec(`CREATE TABLE agent_endpoint_assets (
		id text PRIMARY KEY, tenant_id text NOT NULL, endpoint_id text NOT NULL,
		asset_type text NOT NULL, name text NOT NULL, version text NOT NULL DEFAULT '',
		source text NOT NULL DEFAULT '', hash text NOT NULL DEFAULT '',
		evidence jsonb NOT NULL DEFAULT '{}', first_seen timestamptz NOT NULL DEFAULT now(),
		last_seen timestamptz NOT NULL DEFAULT now(), present boolean NOT NULL DEFAULT true,
		scan_status text NOT NULL DEFAULT '', scan_decision text NOT NULL DEFAULT ''
	)`)
	exec(`CREATE TABLE users (id text, tenant_id text, username text, PRIMARY KEY (tenant_id, id))`)
	exec(`CREATE TABLE agent_endpoints (id text, tenant_id text, status text, PRIMARY KEY (tenant_id, id))`)

	migration, err := os.ReadFile("../../../../deploy/migrations/860_unified_agent_assets.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("apply 860 migration: %v", err)
	}

	return ctx, db, NewAgentUnifiedAssetRepository(db)
}

func unifiedAssetIntegrationRecord(id, endpointID, assetType, name, version, hash, instanceKey string, occurredAt time.Time) *agentEventRecord {
	return &agentEventRecord{
		ID: id, EndpointID: endpointID, OccurredAt: occurredAt,
		InstanceKey: instanceKey, UnifiedNativeID: instanceKey,
		Asset: &agentEventAsset{
			AssetType: assetType, Name: name, Version: version, Source: "aiprobe",
			Hash: hash, Present: true, ScanStatus: "complete", Evidence: []byte("{}"),
		},
	}
}

// Rescanning and re-delivering the same producer event (same source_event_id)
// must not create a second observation row, a second instance row, or a
// second asset. This is the acceptance criterion "重复扫描幂等" run against
// real PostgreSQL rather than the in-memory fake transaction.
func TestUnifiedAssetUpsertDuplicateScanIsIdempotentRealPG(t *testing.T) {
	ctx, db, repo := unifiedAssetIntegrationFixture(t)
	at := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	record := unifiedAssetIntegrationRecord("scan-1", "endpoint-a", "cli_agent", "claude-code", "v1", "sha256:one", "aiprobe:claude-code", at)

	upsert := func() {
		t.Helper()
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := upsertUnifiedEndpointAsset(ctx, tx, "tenant-a", "endpoint-a", record); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Same event delivered three times, as a retrying agent or a duplicate
	// scan sweep would.
	upsert()
	upsert()
	upsert()

	var assetCount, instanceCount, observationCount int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_unified_assets WHERE tenant_id='tenant-a'`).Scan(&assetCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_unified_asset_instances WHERE tenant_id='tenant-a'`).Scan(&instanceCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_unified_asset_observations WHERE tenant_id='tenant-a'`).Scan(&observationCount); err != nil {
		t.Fatal(err)
	}
	if assetCount != 1 || instanceCount != 1 || observationCount != 1 {
		t.Fatalf("duplicate scan was not idempotent: assets=%d instances=%d observations=%d, want 1/1/1",
			assetCount, instanceCount, observationCount)
	}

	page, err := repo.List(ctx, "tenant-a", AgentUnifiedAssetFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].InstanceCount != 1 {
		t.Fatalf("List after repeated scan: %+v", page.Items)
	}
}

// Two distinct Agent installs reporting from the same host/endpoint namespace
// (e.g. Claude Code and a second CLI agent on one machine) must be tracked as
// two separate unified assets, not folded into one, because their native
// identities (asset_type/name/instance_key) differ. This is the acceptance
// criterion "同机多 Agent 不误合并".
func TestUnifiedAssetSameHostDistinctAgentsDoNotMergeRealPG(t *testing.T) {
	ctx, db, repo := unifiedAssetIntegrationFixture(t)
	at := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

	upsert := func(record *agentEventRecord) {
		t.Helper()
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := upsertUnifiedEndpointAsset(ctx, tx, "tenant-a", "endpoint-shared-host", record); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	upsert(unifiedAssetIntegrationRecord("agent-1-report", "endpoint-shared-host", "cli_agent", "claude-code", "v1", "sha256:a", "aiprobe:claude-code", at))
	upsert(unifiedAssetIntegrationRecord("agent-2-report", "endpoint-shared-host", "cli_agent", "opencode", "v1", "sha256:b", "aiprobe:opencode", at))
	// A second report from the first agent must accumulate onto the same
	// asset, not create a third one.
	upsert(unifiedAssetIntegrationRecord("agent-1-report-2", "endpoint-shared-host", "cli_agent", "claude-code", "v2", "sha256:a2", "aiprobe:claude-code", at.Add(time.Minute)))

	var assetCount int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_unified_assets WHERE tenant_id='tenant-a'`).Scan(&assetCount); err != nil {
		t.Fatal(err)
	}
	if assetCount != 2 {
		t.Fatalf("same-host distinct agents were merged: asset_count=%d want 2", assetCount)
	}

	page, err := repo.List(ctx, "tenant-a", AgentUnifiedAssetFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]int{}
	for _, item := range page.Items {
		names[item.Name] = item.InstanceCount
	}
	if names["claude-code"] != 1 || names["opencode"] != 1 {
		t.Fatalf("expected one instance each for claude-code and opencode, got %+v", names)
	}

	// Auto-ingestion must not silently merge them; an explicit administrative
	// Merge() call remains the only path that folds one asset into another.
	var claudeID, opencodeID string
	for _, item := range page.Items {
		switch item.Name {
		case "claude-code":
			claudeID = item.ID
		case "opencode":
			opencodeID = item.ID
		}
	}
	ok, err := repo.Merge(ctx, "tenant-a", opencodeID, claudeID)
	if err != nil || !ok {
		t.Fatalf("explicit administrative merge should still succeed: ok=%v err=%v", ok, err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_unified_assets WHERE tenant_id='tenant-a' AND merged_into_id IS NULL`).Scan(&assetCount); err != nil {
		t.Fatal(err)
	}
	if assetCount != 1 {
		t.Fatalf("explicit merge did not consolidate: visible asset_count=%d want 1", assetCount)
	}
}

// Each report about an instance must be retained as an immutable observation
// even as the instance's current projection moves forward, so version/hash
// history remains fully reconstructable. This is the acceptance criterion
// "实例变化可追踪".
func TestUnifiedAssetInstanceChangeHistoryIsTraceableRealPG(t *testing.T) {
	ctx, db, repo := unifiedAssetIntegrationFixture(t)
	base := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

	upsert := func(record *agentEventRecord) {
		t.Helper()
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := upsertUnifiedEndpointAsset(ctx, tx, "tenant-a", "endpoint-a", record); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	upsert(unifiedAssetIntegrationRecord("v1-report", "endpoint-a", "cli_agent", "claude-code", "1.0.0", "sha256:v1", "aiprobe:claude-code", base))
	upsert(unifiedAssetIntegrationRecord("v2-report", "endpoint-a", "cli_agent", "claude-code", "2.0.0", "sha256:v2", "aiprobe:claude-code", base.Add(time.Hour)))
	upsert(unifiedAssetIntegrationRecord("v3-report", "endpoint-a", "cli_agent", "claude-code", "3.0.0", "sha256:v3", "aiprobe:claude-code", base.Add(2*time.Hour)))

	page, err := repo.List(ctx, "tenant-a", AgentUnifiedAssetFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("want 1 asset, got %d", len(page.Items))
	}
	assetID := page.Items[0].ID

	history, found, err := repo.ListHistory(ctx, "tenant-a", assetID, 1, 10)
	if err != nil || !found {
		t.Fatalf("ListHistory: found=%v err=%v", found, err)
	}
	if history.Total != 3 {
		t.Fatalf("history total=%d want 3", history.Total)
	}
	gotVersions := []string{history.Items[0].Version, history.Items[1].Version, history.Items[2].Version}
	wantVersions := []string{"3.0.0", "2.0.0", "1.0.0"} // received_at DESC
	for i, want := range wantVersions {
		if gotVersions[i] != want {
			t.Fatalf("history version[%d]=%s want %s (full=%v)", i, gotVersions[i], want, gotVersions)
		}
	}

	var currentVersion, currentHash string
	if err := db.QueryRow(ctx, `SELECT version,content_hash FROM agent_unified_asset_instances WHERE tenant_id='tenant-a' AND asset_id=$1`, assetID).
		Scan(&currentVersion, &currentHash); err != nil {
		t.Fatal(err)
	}
	if currentVersion != "3.0.0" || currentHash != "sha256:v3" {
		t.Fatalf("current instance projection=%s/%s want 3.0.0/sha256:v3", currentVersion, currentHash)
	}
}

// Two tenants reporting the exact same endpoint namespace and native asset
// identity must never see or affect each other's data through List,
// ListHistory, FindNativeReferenceAsset, UpdateOwnership, or UpdateCatalog.
// This is the acceptance criterion "组织/租户访问隔离".
func TestUnifiedAssetTenantIsolationRealPG(t *testing.T) {
	ctx, db, repo := unifiedAssetIntegrationFixture(t)
	at := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

	upsert := func(tenant string, record *agentEventRecord) {
		t.Helper()
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := upsertUnifiedEndpointAsset(ctx, tx, tenant, "endpoint-a", record); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// Identical endpoint namespace and native asset identity, different tenants.
	upsert("tenant-a", unifiedAssetIntegrationRecord("a-report", "endpoint-a", "cli_agent", "claude-code", "v1", "sha256:a", "aiprobe:claude-code", at))
	upsert("tenant-b", unifiedAssetIntegrationRecord("b-report", "endpoint-a", "cli_agent", "claude-code", "v1", "sha256:b", "aiprobe:claude-code", at))

	pageA, err := repo.List(ctx, "tenant-a", AgentUnifiedAssetFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	pageB, err := repo.List(ctx, "tenant-b", AgentUnifiedAssetFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(pageA.Items) != 1 || len(pageB.Items) != 1 {
		t.Fatalf("each tenant should see exactly its own asset: a=%d b=%d", len(pageA.Items), len(pageB.Items))
	}
	assetIDA, assetIDB := pageA.Items[0].ID, pageB.Items[0].ID
	if assetIDA == assetIDB {
		t.Fatalf("tenants collapsed onto the same asset row: %s", assetIDA)
	}

	// Cross-tenant history read must report not-found, not tenant B's data.
	if _, found, err := repo.ListHistory(ctx, "tenant-b", assetIDA, 1, 10); err != nil || found {
		t.Fatalf("cross-tenant ListHistory leaked: found=%v err=%v", found, err)
	}

	// Cross-tenant native reference lookup must not resolve tenant A's ref
	// under tenant B's scope.
	if _, ok, err := repo.FindNativeReferenceAsset(ctx, "tenant-b", "endpoint-a", "irrelevant"); err != nil || ok {
		t.Fatalf("cross-tenant FindNativeReferenceAsset unexpectedly resolved: ok=%v err=%v", ok, err)
	}

	// Cross-tenant ownership/catalog writes must be no-ops (zero rows
	// affected), never touching the other tenant's row.
	changed, err := repo.UpdateOwnership(ctx, "tenant-b", assetIDA, AgentAssetOwnershipUpdate{BusinessUnit: "should-not-apply"})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatalf("cross-tenant UpdateOwnership reported a change")
	}
	var businessUnit string
	if err := db.QueryRow(ctx, `SELECT business_unit FROM agent_unified_assets WHERE tenant_id='tenant-a' AND id=$1`, assetIDA).Scan(&businessUnit); err != nil {
		t.Fatal(err)
	}
	if businessUnit != "" {
		t.Fatalf("cross-tenant UpdateOwnership leaked into tenant-a row: business_unit=%q", businessUnit)
	}

	changedCatalog, err := repo.UpdateCatalog(ctx, "tenant-b", assetIDA, "attacker", AgentAssetCatalogUpdate{Status: "approved"})
	if err != nil {
		t.Fatal(err)
	}
	if changedCatalog {
		t.Fatalf("cross-tenant UpdateCatalog reported a change")
	}
	var catalogStatus string
	if err := db.QueryRow(ctx, `SELECT catalog_status FROM agent_unified_assets WHERE tenant_id='tenant-a' AND id=$1`, assetIDA).Scan(&catalogStatus); err != nil {
		t.Fatal(err)
	}
	if catalogStatus != "unreviewed" {
		t.Fatalf("cross-tenant UpdateCatalog leaked into tenant-a row: catalog_status=%q", catalogStatus)
	}
}

// The catalog approval directory (List filtered by catalog_status, and
// UpdateCatalog as the management entry point) must round-trip through real
// PostgreSQL: an administrator can list unreviewed/approved/exception/expired
// assets and transition an asset between them. This is the acceptance
// criterion "资产批准目录有管理入口".
func TestUnifiedAssetCatalogApprovalDirectoryRealPG(t *testing.T) {
	ctx, db, repo := unifiedAssetIntegrationFixture(t)
	at := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

	upsert := func(id, name string) {
		t.Helper()
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		record := unifiedAssetIntegrationRecord(id+"-report", "endpoint-a", "cli_agent", name, "v1", "sha256:"+name, "aiprobe:"+name, at)
		if err := upsertUnifiedEndpointAsset(ctx, tx, "tenant-a", "endpoint-a", record); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	upsert("unreviewed-asset", "still-unreviewed")
	upsert("approved-asset", "will-be-approved")
	upsert("exception-asset", "will-be-exception")
	upsert("expired-asset", "already-expired")

	byName := map[string]string{}
	page, err := repo.List(ctx, "tenant-a", AgentUnifiedAssetFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		byName[item.Name] = item.ID
		if item.CatalogStatus != "unreviewed" {
			t.Fatalf("new asset %s started as %q, want unreviewed", item.Name, item.CatalogStatus)
		}
	}

	future := time.Now().Add(48 * time.Hour)
	if changed, err := repo.UpdateCatalog(ctx, "tenant-a", byName["will-be-approved"], "admin-1", AgentAssetCatalogUpdate{Status: "approved"}); err != nil || !changed {
		t.Fatalf("approve: changed=%v err=%v", changed, err)
	}
	if changed, err := repo.UpdateCatalog(ctx, "tenant-a", byName["will-be-exception"], "admin-1", AgentAssetCatalogUpdate{
		Status: "exception", Reason: "temporary compensating control", ExpiresAt: &future,
	}); err != nil || !changed {
		t.Fatalf("exception: changed=%v err=%v", changed, err)
	}
	past := time.Now().Add(-time.Hour)
	if _, err := db.Exec(ctx, `UPDATE agent_unified_assets SET catalog_status='exception',catalog_reason='lapsed',catalog_expires_at=$2 WHERE tenant_id='tenant-a' AND id=$1`,
		byName["already-expired"], past); err != nil {
		t.Fatal(err)
	}

	assertFilteredNames := func(status string, want ...string) {
		t.Helper()
		filtered, err := repo.List(ctx, "tenant-a", AgentUnifiedAssetFilter{CatalogStatus: status, Page: 1, PageSize: 10})
		if err != nil {
			t.Fatalf("List catalog_status=%s: %v", status, err)
		}
		got := map[string]bool{}
		for _, item := range filtered.Items {
			got[item.Name] = true
		}
		if len(got) != len(want) {
			t.Fatalf("List catalog_status=%s items=%v want exactly %v", status, got, want)
		}
		for _, name := range want {
			if !got[name] {
				t.Fatalf("List catalog_status=%s missing %s, got %v", status, name, got)
			}
		}
	}
	assertFilteredNames("unreviewed", "still-unreviewed")
	assertFilteredNames("approved", "will-be-approved")
	// "exception" returns every exception row including lapsed ones; the
	// still-valid one is exposed distinctly through the "expired" bucket.
	assertFilteredNames("exception", "will-be-exception", "already-expired")
	assertFilteredNames("expired", "already-expired")

	// Rejecting invalid catalog input (e.g. exception without a reason) must
	// be rejected without silently mutating the row.
	if _, err := repo.UpdateCatalog(ctx, "tenant-a", byName["still-unreviewed"], "admin-1", AgentAssetCatalogUpdate{Status: "exception"}); err != ErrAgentAssetInvalidInput {
		t.Fatalf("exception without reason/expiry: err=%v want ErrAgentAssetInvalidInput", err)
	}
	var untouchedStatus string
	if err := db.QueryRow(ctx, `SELECT catalog_status FROM agent_unified_assets WHERE tenant_id='tenant-a' AND id=$1`, byName["still-unreviewed"]).Scan(&untouchedStatus); err != nil {
		t.Fatal(err)
	}
	if untouchedStatus != "unreviewed" {
		t.Fatalf("rejected catalog update still mutated row: status=%q", untouchedStatus)
	}
}

// Concurrent real-goroutine writers targeting the same tenant/source identity
// must serialize through the tenant advisory lock instead of racing: no
// duplicate assets, no duplicate instances, and every distinct observation
// event is retained. This exercises the acceptance criteria "重复扫描幂等"
// and "实例变化可追踪" under genuine PostgreSQL concurrency, which is exactly
// what the existing fake-transaction lock test (TestUnifiedAssetUpsertAndMergeSerializeOnTenantLock)
// cannot cover.
func TestUnifiedAssetConcurrentWritersSerializeWithoutDuplicationRealPG(t *testing.T) {
	ctx, db, repo := unifiedAssetIntegrationFixture(t)
	// boundedAgentAssetObservedAt clamps to min(sourceOccurredAt, receivedAt),
	// where receivedAt is the database's real clock_timestamp() at commit
	// time. base must stay safely in the past relative to wall-clock "now"
	// (not "the same calendar day") so every writer's sourceOccurredAt is the
	// value that actually governs the last-observed-at watermark instead of
	// being silently clamped to the real commit time.
	base := time.Now().Add(-24 * time.Hour)

	const writers = 12
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tx, err := db.Begin(ctx)
			if err != nil {
				errs[i] = fmt.Errorf("begin: %w", err)
				return
			}
			defer tx.Rollback(ctx)
			record := unifiedAssetIntegrationRecord(
				fmt.Sprintf("concurrent-report-%d", i), "endpoint-a", "cli_agent", "claude-code",
				fmt.Sprintf("v%d", i), fmt.Sprintf("sha256:concurrent-%d", i), "aiprobe:claude-code",
				base.Add(time.Duration(i)*time.Second),
			)
			if err := upsertUnifiedEndpointAsset(ctx, tx, "tenant-a", "endpoint-a", record); err != nil {
				errs[i] = fmt.Errorf("upsert %d: %w", i, err)
				return
			}
			errs[i] = tx.Commit(ctx)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d failed: %v", i, err)
		}
	}

	var assetCount, instanceCount, observationCount int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_unified_assets WHERE tenant_id='tenant-a'`).Scan(&assetCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_unified_asset_instances WHERE tenant_id='tenant-a'`).Scan(&instanceCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_unified_asset_observations WHERE tenant_id='tenant-a'`).Scan(&observationCount); err != nil {
		t.Fatal(err)
	}
	if assetCount != 1 {
		t.Fatalf("concurrent writers created duplicate assets: count=%d want 1", assetCount)
	}
	if instanceCount != 1 {
		t.Fatalf("concurrent writers created duplicate instances: count=%d want 1", instanceCount)
	}
	if observationCount != writers {
		t.Fatalf("concurrent writers lost distinct observations: count=%d want %d", observationCount, writers)
	}

	// The instance projection must reflect the report with the latest
	// (bounded) observed time, not an arbitrary interleaving.
	var currentVersion string
	if err := db.QueryRow(ctx, `SELECT version FROM agent_unified_asset_instances WHERE tenant_id='tenant-a'`).Scan(&currentVersion); err != nil {
		t.Fatal(err)
	}
	if currentVersion != fmt.Sprintf("v%d", writers-1) {
		t.Fatalf("instance projection after concurrent writes=%s want v%d", currentVersion, writers-1)
	}

	page, err := repo.List(ctx, "tenant-a", AgentUnifiedAssetFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].InstanceCount != 1 {
		t.Fatalf("List after concurrent writes: %+v", page.Items)
	}
}
