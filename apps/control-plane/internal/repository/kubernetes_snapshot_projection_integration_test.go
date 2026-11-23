package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	kubernetesProjectionITTenant       = "tenant-a"
	kubernetesProjectionITNamespaceUID = "namespace-uid-it"
	kubernetesProjectionITWorkloadUID  = "deployment-uid-it"
)

// kubernetesProjectionIntegrationFixture extends the T08 unified-asset real-PG
// fixture (860) with the exact T21 migration 865, so the Kubernetes projection
// writes the same agent_unified_assets rows that endpoint reports write.
func kubernetesProjectionIntegrationFixture(t *testing.T) (context.Context, *pgxpool.Pool, *AgentUnifiedAssetRepository) {
	t.Helper()
	ctx, db, repo := unifiedAssetIntegrationFixture(t)
	migration, err := os.ReadFile("../../../../deploy/migrations/865_kubernetes_asset_ingest.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("apply 865 migration: %v", err)
	}
	return ctx, db, repo
}

// projectKubernetesDeploymentForTest projects one complete namespace snapshot
// observed at observedAt through the same projectKubernetesSnapshot path that
// IngestSnapshot uses for a "projected" receipt. A non-empty name yields one
// Deployment with a stable UID; an empty name yields a complete list without
// it, which tombstones the Deployment.
func projectKubernetesDeploymentForTest(t *testing.T, ctx context.Context, db *pgxpool.Pool, sequence int64, observedAt time.Time, name string) string {
	t.Helper()
	snapshot := testKubernetesSnapshot()
	snapshot.ObservedAt = observedAt.UTC().Format(time.RFC3339Nano)
	snapshot.Namespace = KubernetesNamespaceIdentity{Name: "prod", UID: kubernetesProjectionITNamespaceUID, IdentityStatus: "uid"}
	if name != "" {
		snapshot.Workloads = []KubernetesWorkload{{
			APIVersion: "apps/v1", Kind: "Deployment", Name: name, UID: kubernetesProjectionITWorkloadUID,
			Namespace: "prod", NamespaceUID: kubernetesProjectionITNamespaceUID, IdentityStatus: "uid", OwnershipStatus: "root",
			OwnerReferences: []KubernetesOwnerReference{}, OwnerChain: []KubernetesObjectRef{}, Generation: sequence,
		}}
		for i := range snapshot.Resources {
			if snapshot.Resources[i].Resource == "deployments" {
				snapshot.Resources[i].ObjectsObserved = 1
			}
		}
	}
	scope := kubernetesRunScope{
		RegistrationID: "registration-it", ClusterLabel: "cluster-a", NamespaceName: "prod", NamespaceUID: kubernetesProjectionITNamespaceUID,
		Sequence: sequence, LatestSequence: sequence, Active: true, ReceivedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	coverage, _, _, _ := normalizedKubernetesCoverage(snapshot, scope.NamespaceUID)
	for _, status := range coverage {
		if status.Resource == "deployments" && status.Status != "complete" {
			t.Fatalf("fixture expected complete deployments coverage, got %+v", status)
		}
	}
	runID := uuid.NewString()
	report := KubernetesObservationReport{
		SchemaVersion: KubernetesReportSchemaVersion, RunID: runID,
		ReportID: fmt.Sprintf("sha256:%064x", sequence), Snapshot: snapshot,
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := projectKubernetesSnapshot(ctx, tx, kubernetesProjectionITTenant, scope, report, coverage); err != nil {
		t.Fatalf("project Kubernetes snapshot: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return runID
}

func upsertEndpointAssetForKubernetesTest(t *testing.T, ctx context.Context, db *pgxpool.Pool, eventID, name string, observedAt time.Time) {
	t.Helper()
	record := unifiedAssetIntegrationRecord(eventID, "endpoint-a", "cli_agent", name, "v1", "sha256:"+eventID, "aiprobe:api", observedAt)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := upsertUnifiedEndpointAsset(ctx, tx, kubernetesProjectionITTenant, "endpoint-a", record); err != nil {
		t.Fatalf("upsert endpoint asset: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// unifiedAssetIDForSource returns the asset that owns the only source ref of
// sourceType whose native_id matches nativeIDPattern (SQL LIKE).
func unifiedAssetIDForSource(t *testing.T, ctx context.Context, db *pgxpool.Pool, sourceType, nativeIDPattern string) string {
	t.Helper()
	var id string
	var matches int
	if err := db.QueryRow(ctx, `SELECT MIN(asset_id),COUNT(*) FROM agent_asset_source_refs WHERE tenant_id=$1 AND source_type=$2 AND native_id LIKE $3`,
		kubernetesProjectionITTenant, sourceType, nativeIDPattern).Scan(&id, &matches); err != nil {
		t.Fatalf("lookup %s asset: %v", sourceType, err)
	}
	if matches != 1 {
		t.Fatalf("lookup %s asset: %d source refs match %q, want 1", sourceType, matches, nativeIDPattern)
	}
	return id
}

func kubernetesDeploymentNativeID() string {
	return kubernetesNativeID("apps/v1", "Deployment", kubernetesProjectionITWorkloadUID)
}

func unifiedAssetNameAndLastSeen(t *testing.T, ctx context.Context, db *pgxpool.Pool, assetID string) (string, time.Time) {
	t.Helper()
	var name string
	var lastSeen time.Time
	if err := db.QueryRow(ctx, `SELECT display_name,last_seen FROM agent_unified_assets WHERE tenant_id=$1 AND id=$2`,
		kubernetesProjectionITTenant, assetID).Scan(&name, &lastSeen); err != nil {
		t.Fatal(err)
	}
	return name, lastSeen
}

// mergedKubernetesAndEndpointAsset builds the shared aggregate in which the
// T21 and T08 writers meet: a Kubernetes Deployment asset and an endpoint
// asset, both first observed three hours ago, administratively merged. When
// kubernetesIsCanonical is true the endpoint asset is folded into the
// Kubernetes asset, otherwise the other way round. It returns the canonical
// asset ID and the base time.
func mergedKubernetesAndEndpointAsset(t *testing.T, ctx context.Context, db *pgxpool.Pool, repo *AgentUnifiedAssetRepository, kubernetesIsCanonical bool) (string, time.Time) {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Microsecond)
	projectKubernetesDeploymentForTest(t, ctx, db, 1, base.Add(-3*time.Hour), "api-initial")
	upsertEndpointAssetForKubernetesTest(t, ctx, db, "endpoint-report-1", "endpoint-initial", base.Add(-3*time.Hour))
	kubernetesID := unifiedAssetIDForSource(t, ctx, db, kubernetesSourceType, kubernetesDeploymentNativeID())
	endpointID := unifiedAssetIDForSource(t, ctx, db, "agent_endpoint", "%")
	if kubernetesID == endpointID {
		t.Fatalf("fixture expected two distinct assets before merge, got %q", kubernetesID)
	}
	source, target := kubernetesID, endpointID
	if kubernetesIsCanonical {
		source, target = endpointID, kubernetesID
	}
	if ok, err := repo.Merge(ctx, kubernetesProjectionITTenant, source, target); err != nil || !ok {
		t.Fatalf("merge %s into %s: ok=%v err=%v", source, target, ok, err)
	}
	return target, base
}

// A Kubernetes snapshot observed before the endpoint's newer report must not
// roll the shared aggregate's display name (or last_seen) back, whichever of
// the two assets is canonical. Same freshness rule as the endpoint path
// (990e4250); the stale observation itself is still kept as history.
func TestKubernetesStaleSnapshotDoesNotRegressAggregateDisplayNameRealPG(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		kubernetesIsCanonical bool
	}{
		{"endpoint_asset_canonical", false},
		{"kubernetes_asset_canonical", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, db, repo := kubernetesProjectionIntegrationFixture(t)
			canonicalID, _ := mergedKubernetesAndEndpointAsset(t, ctx, db, repo, tc.kubernetesIsCanonical)
			newerAt := time.Now().UTC().Truncate(time.Microsecond)
			upsertEndpointAssetForKubernetesTest(t, ctx, db, "endpoint-report-2", "endpoint-renamed-newer", newerAt)
			if name, _ := unifiedAssetNameAndLastSeen(t, ctx, db, canonicalID); name != "endpoint-renamed-newer" {
				t.Fatalf("fixture: newer endpoint report did not rename canonical asset, got %q", name)
			}
			_, lastSeenBefore := unifiedAssetNameAndLastSeen(t, ctx, db, canonicalID)

			staleRun := projectKubernetesDeploymentForTest(t, ctx, db, 2, newerAt.Add(-time.Hour), "api-stale-rename")

			name, lastSeen := unifiedAssetNameAndLastSeen(t, ctx, db, canonicalID)
			if name != "endpoint-renamed-newer" {
				t.Fatalf("stale Kubernetes snapshot regressed aggregate display_name: got %q want %q", name, "endpoint-renamed-newer")
			}
			if !lastSeen.Equal(lastSeenBefore) {
				t.Fatalf("stale Kubernetes snapshot moved aggregate last_seen: %s -> %s", lastSeenBefore, lastSeen)
			}
			var observations int
			if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_unified_asset_observations WHERE tenant_id=$1 AND asset_id=$2 AND source_event_id=$3 AND display_name=$4`,
				kubernetesProjectionITTenant, canonicalID, "k8s-run:"+staleRun, "api-stale-rename").Scan(&observations); err != nil {
				t.Fatal(err)
			}
			if observations != 1 {
				t.Fatalf("stale Kubernetes observation must still be retained as history: got %d rows", observations)
			}
		})
	}
}

// A Kubernetes snapshot observed after the endpoint's report still renames the
// shared aggregate and advances last_seen to the snapshot's observation time.
func TestKubernetesNewerSnapshotUpdatesAggregateDisplayNameRealPG(t *testing.T) {
	for _, kubernetesIsCanonical := range []bool{false, true} {
		t.Run(fmt.Sprintf("kubernetes_canonical_%t", kubernetesIsCanonical), func(t *testing.T) {
			ctx, db, repo := kubernetesProjectionIntegrationFixture(t)
			canonicalID, base := mergedKubernetesAndEndpointAsset(t, ctx, db, repo, kubernetesIsCanonical)
			upsertEndpointAssetForKubernetesTest(t, ctx, db, "endpoint-report-2", "endpoint-renamed", base.Add(-2*time.Hour))

			observedAt := base.Add(-time.Hour)
			projectKubernetesDeploymentForTest(t, ctx, db, 2, observedAt, "api-newer-rename")

			name, lastSeen := unifiedAssetNameAndLastSeen(t, ctx, db, canonicalID)
			if name != "api-newer-rename" {
				t.Fatalf("newer Kubernetes snapshot did not rename aggregate: got %q want %q", name, "api-newer-rename")
			}
			if lastSeen.Before(observedAt) {
				t.Fatalf("newer Kubernetes snapshot did not advance last_seen: %s < %s", lastSeen, observedAt)
			}
		})
	}
}

// A late-delivered Kubernetes snapshot that tombstones the Deployment must
// advance the aggregate's last_seen only to its own observation time, not to
// the server receive time; otherwise it blocks a genuinely newer endpoint
// rename observed in between.
func TestKubernetesTombstoneDoesNotBlockNewerEndpointRenameRealPG(t *testing.T) {
	ctx, db, repo := kubernetesProjectionIntegrationFixture(t)
	canonicalID, base := mergedKubernetesAndEndpointAsset(t, ctx, db, repo, false)

	projectKubernetesDeploymentForTest(t, ctx, db, 2, base.Add(-2*time.Hour), "")
	var present bool
	if err := db.QueryRow(ctx, `SELECT i.present FROM agent_unified_asset_instances i JOIN agent_asset_source_refs s
		ON s.tenant_id=i.tenant_id AND s.id=i.source_ref_id WHERE i.tenant_id=$1 AND s.source_type=$2 AND s.native_id=$3`,
		kubernetesProjectionITTenant, kubernetesSourceType, kubernetesDeploymentNativeID()).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("fixture: complete Deployment list without the object did not tombstone it")
	}

	upsertEndpointAssetForKubernetesTest(t, ctx, db, "endpoint-report-2", "endpoint-renamed-after-tombstone", base.Add(-time.Hour))
	if name, _ := unifiedAssetNameAndLastSeen(t, ctx, db, canonicalID); name != "endpoint-renamed-after-tombstone" {
		t.Fatalf("late Kubernetes tombstone blocked a newer endpoint rename: got %q", name)
	}
}

// Without any merge, successive snapshots of one Deployment keep the newest
// observed name: a newer snapshot renames the asset, a late-delivered older
// one does not roll it back.
func TestKubernetesSnapshotNameFollowsObservationTimeUnmergedRealPG(t *testing.T) {
	ctx, db, _ := kubernetesProjectionIntegrationFixture(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	projectKubernetesDeploymentForTest(t, ctx, db, 1, base.Add(-3*time.Hour), "api-v1")
	assetID := unifiedAssetIDForSource(t, ctx, db, kubernetesSourceType, kubernetesDeploymentNativeID())

	projectKubernetesDeploymentForTest(t, ctx, db, 2, base.Add(-time.Hour), "api-v2")
	if name, _ := unifiedAssetNameAndLastSeen(t, ctx, db, assetID); name != "api-v2" {
		t.Fatalf("newer Kubernetes snapshot did not rename its own asset: got %q want %q", name, "api-v2")
	}

	projectKubernetesDeploymentForTest(t, ctx, db, 3, base.Add(-2*time.Hour), "api-stale")
	name, lastSeen := unifiedAssetNameAndLastSeen(t, ctx, db, assetID)
	if name != "api-v2" {
		t.Fatalf("older Kubernetes snapshot rolled its own asset name back: got %q want %q", name, "api-v2")
	}
	if !lastSeen.Equal(base.Add(-time.Hour)) {
		t.Fatalf("aggregate last_seen should be the newest observation time %s, got %s", base.Add(-time.Hour), lastSeen)
	}
}
