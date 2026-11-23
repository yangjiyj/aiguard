package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// kubernetesIngestRealPG connects to a disposable database migrated with the
// full schema (865 included). It is skipped unless
// KUBERNETES_INGEST_TEST_DATABASE_URL is set and refuses databases whose name
// does not contain "test". Every test gets its own tenant and removes it.
func kubernetesIngestRealPG(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("KUBERNETES_INGEST_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("KUBERNETES_INGEST_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var name string
	if err := db.QueryRow(ctx, `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(name, "test") {
		t.Fatalf("refusing non-test database %q", name)
	}
	return ctx, db
}

type kubernetesIngestITEnv struct {
	repo      *AgentKubernetesAssetRepository
	tenant    string
	endpoint  *AgentEndpointContext
	clusterID string
	nsUID     string
}

func newKubernetesIngestITEnv(t *testing.T, ctx context.Context, db *pgxpool.Pool) kubernetesIngestITEnv {
	t.Helper()
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	tenant := "t21ing-" + hex.EncodeToString(suffix)
	endpointID := "ep-" + hex.EncodeToString(suffix)
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
				t.Errorf("cleanup %s for %s: %v", table, tenant, err)
			}
		}
	})
	if _, err := db.Exec(ctx, `INSERT INTO agent_endpoints (id,tenant_id,machine_id,hostname,os,arch,agent_product,token_hash)
		VALUES ($1,$2,'machine-k8s','collector','linux','amd64',$3,$4)`, endpointID, tenant, KubernetesCollectorProduct, "sha256:"+uuid.NewString()); err != nil {
		t.Fatalf("seed collector endpoint: %v", err)
	}
	repo := NewAgentKubernetesAssetRepository(db)
	cluster, err := repo.CreateCluster(ctx, tenant, "admin-it", KubernetesClusterCreate{DisplayName: "Cluster A", ClusterLabel: "cluster-a"})
	if err != nil {
		t.Fatalf("CreateCluster: %v", err)
	}
	nsUID := "ns-uid-" + hex.EncodeToString(suffix)
	if _, err := repo.RegisterNamespace(ctx, tenant, "admin-it", cluster.ID, KubernetesNamespaceRegister{EndpointID: endpointID, Name: "prod", UID: nsUID}); err != nil {
		t.Fatalf("RegisterNamespace: %v", err)
	}
	return kubernetesIngestITEnv{
		repo: repo, tenant: tenant, clusterID: cluster.ID, nsUID: nsUID,
		endpoint: &AgentEndpointContext{TenantID: tenant, EndpointID: endpointID, AgentProduct: KubernetesCollectorProduct},
	}
}

// report builds a valid, digest-bound report with one Deployment. A non-empty
// partial resource list downgrades those resources (and the snapshot) to partial.
func (e kubernetesIngestITEnv) report(t *testing.T, runID, deploymentName string, partial ...string) KubernetesObservationReport {
	t.Helper()
	snapshot := testKubernetesSnapshot()
	snapshot.Namespace = KubernetesNamespaceIdentity{Name: "prod", UID: e.nsUID, IdentityStatus: "uid"}
	snapshot.Workloads = []KubernetesWorkload{{
		APIVersion: "apps/v1", Kind: "Deployment", Name: deploymentName, UID: "deploy-uid-" + e.nsUID,
		Namespace: "prod", NamespaceUID: e.nsUID, IdentityStatus: "uid", OwnershipStatus: "root",
		OwnerReferences: []KubernetesOwnerReference{}, OwnerChain: []KubernetesObjectRef{}, Generation: 1,
	}}
	sort.Slice(snapshot.Resources, func(i, j int) bool { return snapshot.Resources[i].Resource < snapshot.Resources[j].Resource })
	for i := range snapshot.Resources {
		if snapshot.Resources[i].Resource == "deployments" {
			snapshot.Resources[i].ObjectsObserved = 1
		}
		for _, p := range partial {
			if snapshot.Resources[i].Resource == p {
				snapshot.Resources[i].Status = "partial"
				snapshot.Status = "partial"
			}
		}
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	return KubernetesObservationReport{
		SchemaVersion: KubernetesReportSchemaVersion, RunID: runID,
		ReportID: "sha256:" + hex.EncodeToString(digest[:]), Snapshot: snapshot,
	}
}

type kubernetesWatermarkRow struct {
	Status           string
	RunSequence      int64
	CompleteSequence int64
	CompleteAt       *time.Time
	ReportID         string
}

func (e kubernetesIngestITEnv) watermarks(t *testing.T, ctx context.Context, db *pgxpool.Pool) map[string]kubernetesWatermarkRow {
	t.Helper()
	rows, err := db.Query(ctx, `SELECT resource_kind,last_status,last_run_sequence,last_complete_sequence,last_complete_at,last_report_id
		FROM agent_kubernetes_resource_watermarks WHERE tenant_id=$1 AND namespace_uid=$2`, e.tenant, e.nsUID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := map[string]kubernetesWatermarkRow{}
	for rows.Next() {
		var kind string
		var row kubernetesWatermarkRow
		if err := rows.Scan(&kind, &row.Status, &row.RunSequence, &row.CompleteSequence, &row.CompleteAt, &row.ReportID); err != nil {
			t.Fatal(err)
		}
		result[kind] = row
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(result) != len(kubernetesTrackedResources) {
		t.Fatalf("watermark rows = %d, want %d: %+v", len(result), len(kubernetesTrackedResources), result)
	}
	return result
}

func (e kubernetesIngestITEnv) deploymentProjection(t *testing.T, ctx context.Context, db *pgxpool.Pool) (string, int) {
	t.Helper()
	var name string
	var refs int
	nativeID := kubernetesNativeID("apps/v1", "Deployment", "deploy-uid-"+e.nsUID)
	if err := db.QueryRow(ctx, `SELECT MIN(a.display_name),COUNT(*) FROM agent_asset_source_refs s
		JOIN agent_unified_assets a ON a.tenant_id=s.tenant_id AND a.id=s.asset_id
		WHERE s.tenant_id=$1 AND s.source_type=$2 AND s.native_id=$3`, e.tenant, kubernetesSourceType, nativeID).Scan(&name, &refs); err != nil {
		t.Fatalf("lookup projected deployment: %v", err)
	}
	return name, refs
}

func mustIngestProjected(t *testing.T, ctx context.Context, e kubernetesIngestITEnv, report KubernetesObservationReport, sequence int64, duplicate bool) {
	t.Helper()
	result, err := e.repo.IngestSnapshot(ctx, e.endpoint, report)
	if err != nil {
		t.Fatalf("IngestSnapshot(seq=%d duplicate=%t): %v", sequence, duplicate, err)
	}
	if result.ProjectionStatus != "projected" || result.Sequence != sequence || result.Duplicate != duplicate || result.ReportID != report.ReportID {
		t.Fatalf("IngestSnapshot result = %+v, want projected seq=%d duplicate=%t", result, sequence, duplicate)
	}
}

// TestKubernetesSnapshotIngestFullChainRealPG drives the real repository chain
// cluster -> namespace registration -> run -> projected ingest against the
// full migrated schema and checks watermarks and the unified-asset projection.
func TestKubernetesSnapshotIngestFullChainRealPG(t *testing.T) {
	ctx, db := kubernetesIngestRealPG(t)
	e := newKubernetesIngestITEnv(t, ctx, db)

	run, err := e.repo.BeginSnapshotRun(ctx, e.endpoint, KubernetesSnapshotRunRequest{RequestID: uuid.NewString()})
	if err != nil {
		t.Fatalf("BeginSnapshotRun: %v", err)
	}
	if run.Sequence != 1 || run.NamespaceUID != e.nsUID || run.ClusterID != "cluster-a" {
		t.Fatalf("first run = %+v", run)
	}
	for kind, row := range e.watermarks(t, ctx, db) {
		if row.Status != "pending" || row.RunSequence != 1 || row.CompleteSequence != 0 || row.CompleteAt != nil {
			t.Fatalf("pending watermark %s = %+v", kind, row)
		}
	}

	report := e.report(t, run.RunID, "api")
	mustIngestProjected(t, ctx, e, report, 1, false)

	coverage, _, _, _ := normalizedKubernetesCoverage(report.Snapshot, e.nsUID)
	marks := e.watermarks(t, ctx, db)
	for _, status := range coverage {
		row := marks[status.Resource]
		if row.Status != status.Status || row.RunSequence != 1 || row.ReportID != report.ReportID {
			t.Fatalf("watermark %s = %+v, want status=%s seq=1 report=%s", status.Resource, row, status.Status, report.ReportID)
		}
		if status.Status == "complete" && (row.CompleteSequence != 1 || row.CompleteAt == nil) {
			t.Fatalf("complete watermark %s did not advance: %+v", status.Resource, row)
		}
		if status.Status != "complete" && (row.CompleteSequence != 0 || row.CompleteAt != nil) {
			t.Fatalf("non-complete watermark %s advanced: %+v", status.Resource, row)
		}
	}
	if marks["deployments"].Status != "complete" || marks["namespaces"].Status != "complete" {
		t.Fatalf("fixture expected complete deployments/namespaces: %+v", marks)
	}
	if name, refs := e.deploymentProjection(t, ctx, db); refs != 1 || name != "api" {
		t.Fatalf("projected deployment = %q refs=%d, want api/1", name, refs)
	}
	var receipts int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_kubernetes_snapshot_receipts WHERE tenant_id=$1 AND run_id=$2 AND projection_status='projected'`,
		e.tenant, run.RunID).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("projected receipts = %d err=%v, want 1", receipts, err)
	}
	cov, err := e.repo.GetCoverage(ctx, e.tenant, e.clusterID)
	if err != nil {
		t.Fatalf("GetCoverage: %v", err)
	}
	if len(cov.Namespaces) != 1 || cov.Namespaces[0].LatestSequence != 1 || cov.Namespaces[0].LatestProjectionStatus != "projected" ||
		len(cov.Namespaces[0].Resources) != len(kubernetesTrackedResources) {
		t.Fatalf("coverage = %+v", cov)
	}
}

// TestKubernetesSnapshotIngestIdempotentReplayRealPG replays the same run and
// report: the run request and the receipt are idempotent, watermarks and the
// projection do not move, and a different report for the same run conflicts.
func TestKubernetesSnapshotIngestIdempotentReplayRealPG(t *testing.T) {
	ctx, db := kubernetesIngestRealPG(t)
	e := newKubernetesIngestITEnv(t, ctx, db)
	requestID := uuid.NewString()
	run, err := e.repo.BeginSnapshotRun(ctx, e.endpoint, KubernetesSnapshotRunRequest{RequestID: requestID})
	if err != nil {
		t.Fatalf("BeginSnapshotRun: %v", err)
	}
	again, err := e.repo.BeginSnapshotRun(ctx, e.endpoint, KubernetesSnapshotRunRequest{RequestID: requestID})
	if err != nil || again.RunID != run.RunID || again.Sequence != 1 {
		t.Fatalf("replayed BeginSnapshotRun = %+v err=%v, want run %s seq 1", again, err, run.RunID)
	}
	report := e.report(t, run.RunID, "api")
	mustIngestProjected(t, ctx, e, report, 1, false)
	before := e.watermarks(t, ctx, db)

	mustIngestProjected(t, ctx, e, report, 1, true)
	after := e.watermarks(t, ctx, db)
	for kind, row := range before {
		got := after[kind]
		if got.Status != row.Status || got.RunSequence != row.RunSequence || got.CompleteSequence != row.CompleteSequence ||
			got.ReportID != row.ReportID || (got.CompleteAt == nil) != (row.CompleteAt == nil) ||
			(got.CompleteAt != nil && !got.CompleteAt.Equal(*row.CompleteAt)) {
			t.Fatalf("replay moved watermark %s: %+v -> %+v", kind, row, got)
		}
	}
	var receipts int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_kubernetes_snapshot_receipts WHERE tenant_id=$1 AND run_id=$2`, e.tenant, run.RunID).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("receipts after replay = %d err=%v, want 1", receipts, err)
	}
	if name, refs := e.deploymentProjection(t, ctx, db); refs != 1 || name != "api" {
		t.Fatalf("projected deployment after replay = %q refs=%d", name, refs)
	}

	different := e.report(t, run.RunID, "api-renamed")
	if _, err := e.repo.IngestSnapshot(ctx, e.endpoint, different); !errors.Is(err, ErrKubernetesConflict) {
		t.Fatalf("different report for same run: err=%v, want ErrKubernetesConflict", err)
	}
}

// TestKubernetesSnapshotIngestSecondRunSequenceRealPG issues a second run: the
// sequence increments, the new run resets watermarks to pending without losing
// last_complete_sequence, and a partial report advances only complete kinds.
func TestKubernetesSnapshotIngestSecondRunSequenceRealPG(t *testing.T) {
	ctx, db := kubernetesIngestRealPG(t)
	e := newKubernetesIngestITEnv(t, ctx, db)
	run1, err := e.repo.BeginSnapshotRun(ctx, e.endpoint, KubernetesSnapshotRunRequest{RequestID: uuid.NewString()})
	if err != nil {
		t.Fatalf("BeginSnapshotRun 1: %v", err)
	}
	report1 := e.report(t, run1.RunID, "api")
	mustIngestProjected(t, ctx, e, report1, 1, false)

	run2, err := e.repo.BeginSnapshotRun(ctx, e.endpoint, KubernetesSnapshotRunRequest{RequestID: uuid.NewString()})
	if err != nil {
		t.Fatalf("BeginSnapshotRun 2: %v", err)
	}
	if run2.Sequence != 2 || run2.RunID == run1.RunID {
		t.Fatalf("second run = %+v, want sequence 2 and a new run ID", run2)
	}
	for kind, row := range e.watermarks(t, ctx, db) {
		if row.Status != "pending" || row.RunSequence != 2 || row.CompleteSequence != 1 {
			t.Fatalf("watermark %s after second run issue = %+v, want pending seq=2 complete=1", kind, row)
		}
	}

	report2 := e.report(t, run2.RunID, "api-v2", "deployments")
	mustIngestProjected(t, ctx, e, report2, 2, false)
	coverage, _, _, _ := normalizedKubernetesCoverage(report2.Snapshot, e.nsUID)
	marks := e.watermarks(t, ctx, db)
	for _, status := range coverage {
		row := marks[status.Resource]
		want := int64(1)
		if status.Status == "complete" {
			want = 2
		}
		if row.Status != status.Status || row.RunSequence != 2 || row.CompleteSequence != want || row.ReportID != report2.ReportID {
			t.Fatalf("watermark %s after run 2 = %+v, want status=%s seq=2 complete=%d", status.Resource, row, status.Status, want)
		}
	}
	if marks["deployments"].Status != "partial" || marks["deployments"].CompleteSequence != 1 || marks["pods"].CompleteSequence != 2 {
		t.Fatalf("run 2 partial deployments / complete pods watermarks = %+v / %+v", marks["deployments"], marks["pods"])
	}

	// The first run is now stale; replaying its receipt stays a duplicate of seq 1.
	mustIngestProjected(t, ctx, e, report1, 1, true)
}

// TestKubernetesRepositorySQLPrepareRealPG parses every non-test
// kubernetes_*.go file in this package, collects every SQL literal passed to
// Exec/Query/QueryRow, and prepares each one on the real migrated schema with
// the extended protocol (the same path pgx uses at runtime). It fails on any
// statement Postgres refuses (for example 42P08 inconsistent parameter types)
// and on any call whose SQL is not a literal and therefore escaped the check.
func TestKubernetesRepositorySQLPrepareRealPG(t *testing.T) {
	ctx, db := kubernetesIngestRealPG(t)
	files, err := filepath.Glob("kubernetes_*.go")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	type statement struct {
		pos string
		sql string
	}
	var statements []statement
	fset := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Exec" && sel.Sel.Name != "Query" && sel.Sel.Name != "QueryRow") || len(call.Args) < 2 {
				return true
			}
			pos := fset.Position(call.Pos())
			where := filepath.Base(pos.Filename) + ":" + strconv.Itoa(pos.Line)
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("%s: SQL argument is not a string literal; it cannot be prepared by this check", where)
				return true
			}
			sql, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("%s: %v", where, err)
			}
			statements = append(statements, statement{pos: where, sql: sql})
			return true
		})
	}
	if len(statements) == 0 {
		t.Fatal("no Kubernetes SQL statements found")
	}
	conn, err := db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	typeName := func(oid uint32) string {
		var name string
		if err := conn.QueryRow(ctx, `SELECT format_type($1::oid,NULL)`, oid).Scan(&name); err != nil {
			return strconv.FormatUint(uint64(oid), 10)
		}
		return name
	}
	failed := 0
	for i, stmt := range statements {
		desc, err := conn.Conn().PgConn().Prepare(ctx, "", stmt.sql, nil)
		if err != nil {
			failed++
			t.Errorf("PREPARE %02d %s: FAIL %v", i+1, stmt.pos, err)
			continue
		}
		params := make([]string, 0, len(desc.ParamOIDs))
		for j, oid := range desc.ParamOIDs {
			params = append(params, "$"+strconv.Itoa(j+1)+"="+typeName(oid))
		}
		t.Logf("PREPARE %02d %s: OK params[%s]", i+1, stmt.pos, strings.Join(params, " "))
	}
	t.Logf("PREPARE summary: statements=%d ok=%d failed=%d", len(statements), len(statements)-failed, failed)
}

// TestKubernetesSnapshotRunAfterRevokeAndReregisterRealPG revokes the only
// registration of a collector endpoint and registers the same endpoint again.
// The partial unique index only covers active rows, so the endpoint then has
// one revoked and one active registration; BeginSnapshotRun must pick the
// active one instead of failing closed on whichever row the plan returns first.
func TestKubernetesSnapshotRunAfterRevokeAndReregisterRealPG(t *testing.T) {
	ctx, db := kubernetesIngestRealPG(t)
	e := newKubernetesIngestITEnv(t, ctx, db)
	run1, err := e.repo.BeginSnapshotRun(ctx, e.endpoint, KubernetesSnapshotRunRequest{RequestID: uuid.NewString()})
	if err != nil {
		t.Fatalf("BeginSnapshotRun before revoke: %v", err)
	}
	mustIngestProjected(t, ctx, e, e.report(t, run1.RunID, "api"), 1, false)

	ok, err := e.repo.RevokeNamespace(ctx, e.tenant, "admin-it", run1.RegistrationID)
	if err != nil || !ok {
		t.Fatalf("RevokeNamespace = %t, %v", ok, err)
	}
	if _, err := e.repo.BeginSnapshotRun(ctx, e.endpoint, KubernetesSnapshotRunRequest{RequestID: uuid.NewString()}); !errors.Is(err, ErrKubernetesUnauthorized) {
		t.Fatalf("BeginSnapshotRun on revoked-only endpoint: err=%v, want ErrKubernetesUnauthorized", err)
	}

	registration, err := e.repo.RegisterNamespace(ctx, e.tenant, "admin-it", e.clusterID,
		KubernetesNamespaceRegister{EndpointID: e.endpoint.EndpointID, Name: "prod", UID: e.nsUID})
	if err != nil {
		t.Fatalf("re-register endpoint: %v", err)
	}
	var total, active int
	if err := db.QueryRow(ctx, `SELECT COUNT(*),COUNT(*) FILTER (WHERE active) FROM agent_kubernetes_namespace_registrations
		WHERE tenant_id=$1 AND endpoint_id=$2`, e.tenant, e.endpoint.EndpointID).Scan(&total, &active); err != nil || total != 2 || active != 1 {
		t.Fatalf("registrations for endpoint = %d (active %d) err=%v, want 2 (active 1)", total, active, err)
	}

	for i := 0; i < 3; i++ {
		run, err := e.repo.BeginSnapshotRun(ctx, e.endpoint, KubernetesSnapshotRunRequest{RequestID: uuid.NewString()})
		if err != nil {
			t.Fatalf("BeginSnapshotRun after re-register (attempt %d): %v", i+1, err)
		}
		if run.RegistrationID != registration.ID || run.Sequence != int64(i+1) {
			t.Fatalf("run after re-register = %+v, want registration %s sequence %d", run, registration.ID, i+1)
		}
		if i == 0 {
			mustIngestProjected(t, ctx, e, e.report(t, run.RunID, "api-reregistered"), 1, false)
		}
	}
	// Projection sources are keyed by registration, so the new registration
	// projects into its own source ref; the revoked registration's ref is kept.
	var name string
	nativeID := kubernetesNativeID("apps/v1", "Deployment", "deploy-uid-"+e.nsUID)
	if err := db.QueryRow(ctx, `SELECT a.display_name FROM agent_asset_source_refs s
		JOIN agent_unified_assets a ON a.tenant_id=s.tenant_id AND a.id=s.asset_id
		WHERE s.tenant_id=$1 AND s.source_type=$2 AND s.source_namespace=$3 AND s.native_id=$4`,
		e.tenant, kubernetesSourceType, kubernetesSourceNamespace(registration.ID, e.nsUID), nativeID).Scan(&name); err != nil || name != "api-reregistered" {
		t.Fatalf("deployment projected under re-registered source = %q err=%v, want api-reregistered", name, err)
	}
}
