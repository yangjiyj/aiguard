package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// kubernetesHandlerCoverageNote must equal the repository contract constant;
// a drift makes the ingest below fail validation with 400 rather than pass.
const kubernetesHandlerCoverageNote = "Read-only snapshot of one explicitly requested namespace and the allowlisted resource types. It does not establish cluster-wide workload coverage, business ownership, policy authorization, or enforcement."

// TestKubernetesSnapshotIngestHTTPProjectedRealPG drives the collector HTTP
// handlers (snapshot-runs -> snapshots) over the real repository on a fully
// migrated disposable database. A complete snapshot must be accepted with 202
// and projection_status=projected, replay must be a 202 duplicate, and every
// tracked resource must then report facts_state=current_complete.
func TestKubernetesSnapshotIngestHTTPProjectedRealPG(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("KUBERNETES_INGEST_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("KUBERNETES_INGEST_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Registered first so it runs after the row cleanup below (t.Cleanup is LIFO).
	t.Cleanup(db.Close)
	var dbName string
	if err := db.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dbName, "test") {
		t.Fatalf("refusing non-test database %q", dbName)
	}

	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	tenant, endpointID, nsUID := "t21h-"+suffix, "ep-h-"+suffix, "ns-uid-h-"+suffix
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id,name,is_test) VALUES ($1,$1,true)`, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer ccancel()
		for _, table := range []string{
			"agent_kubernetes_resource_watermarks", "agent_kubernetes_snapshot_receipts", "agent_kubernetes_snapshot_runs",
			"agent_kubernetes_namespace_registrations", "agent_kubernetes_clusters",
			"agent_unified_asset_observations", "agent_unified_asset_instances", "agent_asset_source_refs", "agent_unified_assets",
			"agent_endpoints", "tenants",
		} {
			column := "tenant_id"
			if table == "tenants" {
				column = "id"
			}
			if _, err := db.Exec(cctx, "DELETE FROM "+table+" WHERE "+column+"=$1", tenant); err != nil {
				t.Errorf("cleanup %s: %v", table, err)
			}
		}
	})
	if _, err := db.Exec(ctx, `INSERT INTO agent_endpoints (id,tenant_id,machine_id,hostname,os,arch,agent_product,token_hash)
		VALUES ($1,$2,'machine-k8s','collector','linux','amd64',$3,$4)`, endpointID, tenant, repository.KubernetesCollectorProduct, "sha256:"+uuid.NewString()); err != nil {
		t.Fatalf("seed collector endpoint: %v", err)
	}
	repo := repository.NewAgentKubernetesAssetRepository(db)
	cluster, err := repo.CreateCluster(ctx, tenant, "admin-it", repository.KubernetesClusterCreate{DisplayName: "Cluster H", ClusterLabel: "cluster-h"})
	if err != nil {
		t.Fatalf("CreateCluster: %v", err)
	}
	if _, err := repo.RegisterNamespace(ctx, tenant, "admin-it", cluster.ID, repository.KubernetesNamespaceRegister{EndpointID: endpointID, Name: "prod", UID: nsUID}); err != nil {
		t.Fatalf("RegisterNamespace: %v", err)
	}

	api := NewAgentKubernetesSnapshotAPI(repo)
	endpoint := &repository.AgentEndpointContext{TenantID: tenant, EndpointID: endpointID, AgentProduct: repository.KubernetesCollectorProduct}
	post := func(h http.HandlerFunc, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		request = request.WithContext(contextWithEndpoint(ctx, endpoint))
		response := httptest.NewRecorder()
		h(response, request)
		return response
	}

	runResponse := post(api.BeginSnapshotRun, []byte(`{"request_id":"`+uuid.NewString()+`"}`))
	if runResponse.Code != http.StatusCreated {
		t.Fatalf("snapshot-runs status=%d body=%s", runResponse.Code, runResponse.Body.String())
	}
	var run repository.KubernetesSnapshotRun
	if err := json.Unmarshal(runResponse.Body.Bytes(), &run); err != nil || run.Sequence != 1 {
		t.Fatalf("snapshot-runs body=%s err=%v", runResponse.Body.String(), err)
	}

	snapshot := repository.KubernetesDiscoverySnapshot{
		SchemaVersion: repository.KubernetesSnapshotSchemaVersion,
		ObservedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		ClusterID:     "cluster-h",
		Namespace:     repository.KubernetesNamespaceIdentity{Name: "prod", UID: nsUID, IdentityStatus: "uid"},
		Status:        "complete",
		CoverageNote:  kubernetesHandlerCoverageNote,
		Workloads: []repository.KubernetesWorkload{{
			APIVersion: "apps/v1", Kind: "Deployment", Name: "api", UID: "deploy-uid-" + suffix,
			Namespace: "prod", NamespaceUID: nsUID, IdentityStatus: "uid", OwnershipStatus: "root",
			OwnerReferences: []repository.KubernetesOwnerReference{}, OwnerChain: []repository.KubernetesObjectRef{}, Generation: 1,
		}},
		Pods:   []repository.KubernetesPod{},
		Images: []repository.KubernetesImage{},
		Gaps:   []repository.KubernetesObservationGap{},
	}
	for _, resource := range []string{"cronjobs", "daemonsets", "deployments", "jobs", "pods", "replicasets", "statefulsets"} {
		status := repository.KubernetesResourceStatus{Resource: resource, Status: "complete", Pages: 1}
		if resource == "deployments" {
			status.ObjectsObserved = 1
		}
		snapshot.Resources = append(snapshot.Resources, status)
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	body, err := json.Marshal(repository.KubernetesObservationReport{
		SchemaVersion: repository.KubernetesReportSchemaVersion, RunID: run.RunID,
		ReportID: "sha256:" + hex.EncodeToString(digest[:]), Snapshot: snapshot,
	})
	if err != nil {
		t.Fatal(err)
	}

	for i, wantDuplicate := range []bool{false, true} {
		response := post(api.IngestSnapshot, body)
		var result repository.KubernetesSnapshotIngestResult
		_ = json.Unmarshal(response.Body.Bytes(), &result)
		t.Logf("ingest #%d status=%d body=%s", i+1, response.Code, strings.TrimSpace(response.Body.String()))
		if response.Code != http.StatusAccepted || result.ProjectionStatus != "projected" || result.Duplicate != wantDuplicate || result.Sequence != 1 {
			t.Fatalf("ingest #%d status=%d body=%s, want 202 projected duplicate=%t", i+1, response.Code, response.Body.String(), wantDuplicate)
		}
	}

	coverage, err := repo.GetCoverage(ctx, tenant, cluster.ID)
	if err != nil {
		t.Fatalf("GetCoverage: %v", err)
	}
	if len(coverage.Namespaces) != 1 || coverage.Namespaces[0].LatestProjectionStatus != "projected" || len(coverage.Namespaces[0].Resources) != 9 {
		t.Fatalf("coverage = %+v", coverage)
	}
	for _, resource := range coverage.Namespaces[0].Resources {
		if resource.FactsState != "current_complete" || resource.LastCompleteSequence != 1 {
			t.Fatalf("coverage resource %s = %+v, want current_complete at sequence 1", resource.Resource, resource)
		}
	}
	t.Logf("coverage: %d resources current_complete, latest_projection_status=%s", len(coverage.Namespaces[0].Resources), coverage.Namespaces[0].LatestProjectionStatus)
}
