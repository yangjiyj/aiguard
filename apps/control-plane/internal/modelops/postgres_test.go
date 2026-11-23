package modelops

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func fixture(t *testing.T) (context.Context, *PostgresStore, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("MODEL_OPS_TEST_DSN")
	}
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL / MODEL_OPS_TEST_DSN 未配置")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "modelops_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	// Each test owns a fresh schema in the dedicated fixture. Evidence is kept.
	_, err = pool.Exec(ctx, `CREATE TABLE tenants(id TEXT PRIMARY KEY);
CREATE TABLE providers(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL REFERENCES tenants(id),name TEXT NOT NULL,provider_type TEXT NOT NULL,base_url TEXT,auth_mode TEXT,status TEXT NOT NULL);
CREATE TABLE provider_credentials(id TEXT PRIMARY KEY,provider_id TEXT NOT NULL REFERENCES providers(id),secret_ciphertext TEXT,status TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
CREATE TABLE models(id TEXT PRIMARY KEY,provider_id TEXT REFERENCES providers(id),model_name TEXT NOT NULL,upstream_model_id TEXT,status TEXT NOT NULL);
CREATE TABLE model_endpoint_capability_effective(model_id TEXT,endpoint_type TEXT,state TEXT);
CREATE TABLE request_logs(id TEXT PRIMARY KEY,request_id TEXT,tenant_id TEXT,model_id TEXT,provider_id TEXT,endpoint_type TEXT,request_status TEXT,upstream_status_code INT,latency_ms INT,upstream_ttft_ms BIGINT,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),output_audit_result JSONB,input_tokens BIGINT,output_tokens BIGINT);
CREATE INDEX ON request_logs(tenant_id,created_at);`)
	if err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("MODEL_OPS_MIGRATION")
	if path == "" {
		path = filepath.Join("..", "..", "..", "..", "deploy", "migrations", "943_model_operations.sql")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(b)); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO tenants(id) VALUES('tenant-a'),('tenant-b');
INSERT INTO providers VALUES('pa','tenant-a','Provider A','openai','https://provider.invalid','api_key','active'),('pb','tenant-b','Provider B','openai','https://other.invalid','api_key','active'),('disabled','tenant-a','Disabled','openai','https://disabled.invalid','api_key','disabled'),('native','tenant-a','Claude','anthropic','https://native.invalid','api_key','active');
INSERT INTO provider_credentials(id,provider_id,secret_ciphertext,status) VALUES('ca','pa','cipher-a','active'),('cb','pb','cipher-b','active'),('cd','disabled','cipher-disabled','active'),('cn','native','cipher-native','active');
INSERT INTO models VALUES('ma','pa','public-a','deployment-a','active'),('mb','pb','public-b','deployment-b','active'),('md','disabled','public-disabled','deployment-d','active'),('deleted','pa','deleted','deployment-deleted','deleted'),('mc','native','claude','claude-deployment','active');
INSERT INTO model_endpoint_capability_effective VALUES('ma','responses','supported'),('mc','messages','supported');`)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, NewPostgresStore(pool), pool
}
func configOn(t *testing.T, ctx context.Context, s *PostgresStore, tenant string) Config {
	t.Helper()
	c, err := s.GetConfig(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	c.Enabled = true
	c.FailureThreshold = 2
	c.Protocols = []string{"chat"}
	c, err = s.UpdateConfig(ctx, tenant, "actor", c.Version, c, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(ctx, `UPDATE model_endpoint_capability_effective SET endpoint_type='chat' WHERE model_id='ma'`); err != nil {
		t.Fatal(err)
	}
	return c
}
func targetFor(t *testing.T, ctx context.Context, s *PostgresStore, tenant, id string) Target {
	t.Helper()
	targets, err := s.ListTargets(ctx, tenant, []string{"chat"})
	if err != nil {
		t.Fatal(err)
	}
	for _, t := range targets {
		if t.ModelID == id {
			return t
		}
	}
	t.Fatal("target not found")
	return Target{}
}
func TestPostgresConfigCASCostAuditTenantIsolation(t *testing.T) {
	ctx, s, p := fixture(t)
	c, err := s.GetConfig(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled || c.MaxOutputTokens != 128 || c.Version != 1 {
		t.Fatalf("unsafe default: %+v", c)
	}
	c.Enabled = true
	if _, err = s.UpdateConfig(ctx, "tenant-a", "actor", 1, c, false); !errors.Is(err, ErrCostConfirmation) {
		t.Fatal(err)
	}
	c, err = s.UpdateConfig(ctx, "tenant-a", "actor", 1, c, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 2 || c.CostConfirmedAt == nil || c.CostConfirmedBy != "actor" {
		t.Fatal(c)
	}
	if _, err = s.UpdateConfig(ctx, "tenant-a", "actor", 1, c, true); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	b, err := s.GetConfig(ctx, "tenant-b")
	if err != nil || b.Enabled || b.Version != 1 {
		t.Fatalf("tenant isolation: %+v %v", b, err)
	}
	var count int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM model_ops_config_audit WHERE tenant_id='tenant-a' AND actor='actor' AND version=2`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("audit: %d %v", count, err)
	}
}
func TestPostgresLeaseClaimsCompletionCancellationAndFencing(t *testing.T) {
	ctx, s, p := fixture(t)
	configOn(t, ctx, s, "tenant-a")
	var wg sync.WaitGroup
	var mu sync.Mutex
	leases := []*Lease{}
	errs := []error{}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := s.AcquireLease(ctx, "tenant-a", uuid.NewString())
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
			if l != nil {
				leases = append(leases, l)
			}
		}()
	}
	wg.Wait()
	if len(errs) != 0 || len(leases) != 1 {
		t.Fatalf("lease writers=%d errors=%v", len(leases), errs)
	}
	l := leases[0]
	if err := s.RenewLease(ctx, l); err != nil {
		t.Fatal(err)
	}
	target := targetFor(t, ctx, s, "tenant-a", "ma")
	claimed, err := s.ClaimTarget(ctx, l, target)
	if err != nil || !claimed {
		t.Fatalf("claim: %t %v", claimed, err)
	}
	if claimed, err = s.ClaimTarget(ctx, l, target); err != nil || claimed {
		t.Fatalf("duplicate claim: %t %v", claimed, err)
	}
	r, err := s.Complete(ctx, l, target, Outcome{Success: true, HTTPStatus: 200, BodyValidated: true, LatencyMS: 55})
	if err != nil || r.Epoch != l.Epoch || r.Source != "scheduled" {
		t.Fatalf("complete: %+v %v", r, err)
	}
	if _, err = s.Complete(ctx, l, target, Outcome{Success: true, HTTPStatus: 200, BodyValidated: true}); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("duplicate completion: %v", err)
	}
	if err = s.ReleaseLease(ctx, l, target.Key()); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, `UPDATE model_ops_configs SET next_batch_at=clock_timestamp() WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal(err)
	}
	next, err := s.AcquireLease(ctx, "tenant-a", "replacement")
	if err != nil || next == nil || next.Epoch <= l.Epoch {
		t.Fatalf("next lease %+v %v", next, err)
	}
	if err = s.RenewLease(ctx, l); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("old epoch renewed: %v", err)
	}
	c, err := s.GetConfig(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	c.Enabled = false
	if _, err = s.UpdateConfig(ctx, "tenant-a", "disable", c.Version, c, false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimTarget(ctx, next, target); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("disabled config claim: %v", err)
	}
	if _, err = s.Complete(ctx, next, target, Outcome{}); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("disabled config completion: %v", err)
	}
	if err = s.ReleaseLease(ctx, next, ""); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("invalid epoch release: %v", err)
	}
	var count int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM model_ops_probe_history`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("stale write history count=%d %v", count, err)
	}
}
func TestPostgresTargetCredentialMappingDriftAndTenantIsolation(t *testing.T) {
	ctx, s, p := fixture(t)
	if _, err := s.GetConfig(ctx, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	targets, err := s.ListTargets(ctx, "tenant-a", nil)
	if err != nil || len(targets) != 2 {
		t.Fatalf("targets %+v %v", targets, err)
	}
	for _, x := range targets {
		if x.ModelID == "ma" && x.Protocol != "responses" {
			t.Fatal("registered protocol not selected")
		}
		if x.ModelID == "mc" && x.Protocol != "messages" {
			t.Fatal("Claude messages not selected")
		}
	}
	target := targetFor(t, ctx, s, "tenant-a", "ma")
	if _, err = s.RecordManual(ctx, "tenant-b", "actor", target, Outcome{}); err == nil {
		t.Fatal("cross-tenant accepted")
	}
	if _, err = p.Exec(ctx, `UPDATE provider_credentials SET secret_ciphertext='rotated-same-id' WHERE id='ca'`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RecordManual(ctx, "tenant-a", "actor", target, Outcome{}); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("credential drift: %v", err)
	}
	target = targetFor(t, ctx, s, "tenant-a", "ma")
	if _, err = p.Exec(ctx, `UPDATE models SET upstream_model_id='deployment-changed' WHERE id='ma'`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RecordManual(ctx, "tenant-a", "actor", target, Outcome{}); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("mapping drift: %v", err)
	}
	var n int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM model_ops_probe_history`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("unsafe records: %d %v", n, err)
	}
}
func TestPostgresInventoryAndOverviewRetainUnsupportedAndManualMessages(t *testing.T) {
	ctx, s, p := fixture(t)
	configOn(t, ctx, s, "tenant-a")
	if _, err := p.Exec(ctx, `UPDATE providers SET provider_type=' Anthropic ' WHERE id='native'; INSERT INTO providers VALUES('native-gemini','tenant-a','Gemini','gemini','https://gemini.invalid','api_key','active'); INSERT INTO provider_credentials(id,provider_id,secret_ciphertext,status) VALUES('cg','native-gemini','cipher-g','active'); INSERT INTO models VALUES('mg','native-gemini','gemini','gemini-deployment','active');`); err != nil {
		t.Fatal(err)
	}
	targets, err := s.ListTargets(ctx, "tenant-a", nil)
	if err != nil || len(targets) != 3 {
		t.Fatalf("inventory omitted active native models %+v %v", targets, err)
	}
	var gemini Target
	for _, target := range targets {
		if target.ModelID == "mc" && (target.Protocol != "messages" || !target.Supported) {
			t.Fatalf("native messages wrong inventory %+v", target)
		}
		if target.ModelID == "mg" {
			gemini = target
			if !target.Supported || target.Protocol != "chat" {
				t.Fatal("Gemini native chat probe missing")
			}
		}
	}
	o, err := s.GetOverview(ctx, "tenant-a", ReadFilter{ModelID: "mg"})
	if err != nil || len(o.Targets) != 1 || o.Targets[0].State != "unknown" || o.Targets[0].Samples != 0 {
		t.Fatalf("unsupported health fabricated %+v %v", o, err)
	}
	if _, err = s.RecordManual(ctx, "tenant-a", "actor", gemini, Outcome{Success: true, HTTPStatus: 200, BodyValidated: true}); err != nil {
		t.Fatalf("native chat evidence failed %v", err)
	}
	var n int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM model_ops_probe_history`).Scan(&n); err != nil || n != 1 {
		t.Fatal("native chat evidence not persisted")
	}
}
func TestPostgresHistoryStatsAlertsAcknowledgementAndRecovery(t *testing.T) {
	ctx, s, p := fixture(t)
	configOn(t, ctx, s, "tenant-a")
	target := targetFor(t, ctx, s, "tenant-a", "ma")
	for i := 0; i < 2; i++ {
		if _, err := s.RecordManual(ctx, "tenant-a", "actor", target, Outcome{HTTPStatus: 503, LatencyMS: 80, ErrorKind: "upstream_error"}); err != nil {
			t.Fatal(err)
		}
	}
	alerts, err := s.ListAlerts(ctx, "tenant-a", AlertFilter{State: "open"})
	if err != nil || len(alerts.Items) != 1 {
		t.Fatalf("alerts %+v %v", alerts, err)
	}
	id := alerts.Items[0].ID
	if _, err = s.AcknowledgeAlert(ctx, "tenant-b", id, "intruder"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ack crossed tenant: %v", err)
	}
	a, err := s.AcknowledgeAlert(ctx, "tenant-a", id, "reviewer")
	if err != nil || a.State != "open" || a.ResolvedAt != nil || a.AcknowledgedAt == nil {
		t.Fatalf("ack resolved incident: %+v %v", a, err)
	}
	for _, ms := range []int64{10, 30} {
		if _, err = s.RecordManual(ctx, "tenant-a", "actor", target, Outcome{Success: true, HTTPStatus: 200, BodyValidated: true, LatencyMS: ms}); err != nil {
			t.Fatal(err)
		}
	}
	alerts, err = s.ListAlerts(ctx, "tenant-a", AlertFilter{State: "resolved"})
	if err != nil || len(alerts.Items) != 1 || alerts.Items[0].AcknowledgedAt == nil {
		t.Fatalf("recovery %+v %v", alerts, err)
	}
	o, err := s.GetOverview(ctx, "tenant-a", ReadFilter{WindowHours: 24, ModelID: "ma"})
	if err != nil || len(o.Targets) != 1 {
		t.Fatalf("overview %+v %v", o, err)
	}
	summary := o.Targets[0]
	if summary.State != "healthy" || summary.Samples != 4 || summary.Successes != 2 || summary.Availability == nil || *summary.Availability != .5 || summary.P50MS == nil || *summary.P50MS != 20 || summary.P95MS == nil || *summary.P95MS != 29 || len(summary.Hourly) != 24 {
		t.Fatalf("stats: %+v", summary)
	}
	first, err := s.ListHistory(ctx, "tenant-a", HistoryFilter{Limit: 2})
	if err != nil || len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("history first %+v %v", first, err)
	}
	if !first.Items[0].Supported || !alerts.Items[0].Supported {
		t.Fatal("implemented probe history/alerts mislabelled unsupported")
	}
	second, err := s.ListHistory(ctx, "tenant-a", HistoryFilter{Limit: 2, Cursor: first.NextCursor})
	if err != nil || len(second.Items) != 2 || second.NextCursor != "" || first.Items[0].ID == second.Items[0].ID {
		t.Fatalf("history second %+v %v", second, err)
	}
	other, err := s.ListHistory(ctx, "tenant-b", HistoryFilter{})
	if err != nil || len(other.Items) != 0 {
		t.Fatalf("history crossed tenant %+v %v", other, err)
	}
	data, _ := json.Marshal(first)
	if strings.Contains(string(data), "cipher") || strings.Contains(string(data), "provider.invalid") || strings.Contains(string(data), `"credential_id"`) || strings.Contains(string(data), `"identity_digest"`) {
		t.Fatal("history leaked private inputs")
	}
	if _, err = p.Exec(ctx, `UPDATE provider_credentials SET secret_ciphertext='new-credential' WHERE id='ca'`); err != nil {
		t.Fatal(err)
	}
	o, err = s.GetOverview(ctx, "tenant-a", ReadFilter{ModelID: "ma"})
	if err != nil || o.Targets[0].State != "unknown" || o.Targets[0].Samples != 0 || o.Targets[0].P50MS != nil {
		t.Fatalf("stale identity misreported %+v %v", o, err)
	}
}
func TestPostgresWindowsQualityClassificationAndBusinessDownsampling(t *testing.T) {
	ctx, s, p := fixture(t)
	configOn(t, ctx, s, "tenant-a")
	target := targetFor(t, ctx, s, "tenant-a", "ma")
	_, err := p.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,model_id,provider_id,endpoint_type,request_status,upstream_status_code,latency_ms,upstream_ttft_ms,created_at) VALUES('rq1','request1','tenant-a','ma','pa','chat','success',200,100,25,clock_timestamp()),('rq2','request2','tenant-a','ma','pa','chat','failed',429,40,NULL,clock_timestamp()),('rq3','request3','tenant-a','ma','pa','chat','failed',503,50,NULL,clock_timestamp()),('rq4','request4','tenant-a','ma','pa','chat','failed',401,60,NULL,clock_timestamp()),('rq5','request5','tenant-a','ma','pa','chat','cancelled',NULL,NULL,NULL,clock_timestamp()),('rq6','request6','tenant-a','ma','pa','chat','success',200,300,80,clock_timestamp()-interval '30 hours'),('rqb','private-b','tenant-b','mb','pb','chat','success',200,20,5,clock_timestamp());`)
	if err != nil {
		t.Fatal(err)
	}
	q, err := s.GetQuality(ctx, "tenant-a", ReadFilter{WindowHours: 24, ProviderID: "pa", ModelID: "ma"})
	if err != nil || len(q.Items) != 1 {
		t.Fatalf("quality %+v %v", q, err)
	}
	x := q.Items[0]
	if x.Samples != 5 || x.Successes != 1 || x.Failures != 3 || x.HTTP5xx != 1 || x.HTTP429 != 1 || x.HTTP4xx != 1 || x.Cancelled != 1 || x.AuthFailures != 1 || x.P50MS == nil || *x.P50MS != 100 || x.AvgFirstEventMS == nil || *x.AvgFirstEventMS != 25 {
		t.Fatalf("quality classification %+v", x)
	}
	q, err = s.GetQuality(ctx, "tenant-a", ReadFilter{WindowHours: 72})
	if err != nil || q.Items[0].Samples != 6 {
		t.Fatalf("window ignored %+v %v", q, err)
	}
	l, err := s.AcquireLease(ctx, "tenant-a", "writer")
	if err != nil || l == nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimTarget(ctx, l, target)
	if err != nil || !claimed {
		t.Fatalf("first claim %+v %v", claimed, err)
	}
	if _, err = s.Complete(ctx, l, target, Outcome{Success: true, HTTPStatus: 200, BodyValidated: true}); err != nil {
		t.Fatal(err)
	}
	_, err = p.Exec(ctx, `UPDATE model_ops_target_schedule SET next_probe_at=clock_timestamp()-interval '1 second',last_probe_at=clock_timestamp()-interval '1 minute' WHERE tenant_id='tenant-a'; UPDATE request_logs SET created_at=clock_timestamp() WHERE id='rq1'`)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = s.ClaimTarget(ctx, l, target)
	if err != nil || claimed {
		t.Fatalf("recent business failed to reduce probes: %t %v", claimed, err)
	}
	if _, err = p.Exec(ctx, `UPDATE model_ops_target_schedule SET last_probe_at=clock_timestamp()-interval '21 minutes' WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal(err)
	}
	claimed, err = s.ClaimTarget(ctx, l, target)
	if err != nil || !claimed {
		t.Fatalf("periodic coverage skipped: %t %v", claimed, err)
	}
}
func TestPostgresExpiredLeaseRejectsResultAndRenewal(t *testing.T) {
	ctx, s, p := fixture(t)
	configOn(t, ctx, s, "tenant-a")
	l, err := s.AcquireLease(ctx, "tenant-a", "writer")
	if err != nil || l == nil {
		t.Fatal(err)
	}
	target := targetFor(t, ctx, s, "tenant-a", "ma")
	if _, err = s.ClaimTarget(ctx, l, target); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, `UPDATE model_ops_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal(err)
	}
	if err = s.RenewLease(ctx, l); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired lease renewed %v", err)
	}
	if _, err = s.Complete(ctx, l, target, Outcome{Success: true, HTTPStatus: 200, BodyValidated: true}); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired lease result %v", err)
	}
	newLease, err := s.AcquireLease(ctx, "tenant-a", "new")
	if err != nil || newLease == nil || newLease.Epoch <= l.Epoch {
		t.Fatalf("expired lease not reclaimed %+v %v", newLease, err)
	}
	claimed, err := s.ClaimTarget(ctx, newLease, target)
	if err != nil || claimed {
		t.Fatalf("crash caused repeat billing: %t %v", claimed, err)
	}
}

func TestPostgresManualJobOwnershipCancellationAndSchedulerExclusion(t *testing.T) {
	ctx, s, p := fixture(t)
	configOn(t, ctx, s, "tenant-a")
	target := targetFor(t, ctx, s, "tenant-a", "ma")
	if _, err := p.Exec(ctx, `INSERT INTO model_operations_jobs(id,tenant_id,actor,request_key,request_sha256,request_json,state,owner_token,lease_until) VALUES('job-a','tenant-a','actor','key-a','sha','{}','queued','owner-a',clock_timestamp()+interval '1 minute')`); err != nil {
		t.Fatal(err)
	}
	if lease, err := s.AcquireLease(ctx, "tenant-a", "scheduler"); err != nil || lease != nil {
		t.Fatalf("scheduler overlapped queued job: %+v %v", lease, err)
	}
	if _, err := p.Exec(ctx, `UPDATE model_operations_jobs SET state='running' WHERE id='job-a'`); err != nil {
		t.Fatal(err)
	}
	outcome := Outcome{Success: true, HTTPStatus: 200, BodyValidated: true}
	if _, err := s.RecordManual(WithJobOwner(ctx, "job-a", "old-owner"), "tenant-a", "actor", target, outcome); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("wrong worker wrote result %v", err)
	}
	if _, err := s.RecordManual(WithJobOwner(ctx, "job-a", "owner-a"), "tenant-a", "other-actor", target, outcome); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("wrong actor wrote result %v", err)
	}
	owned := WithJobOwner(ctx, "job-a", "owner-a")
	if _, err := p.Exec(ctx, `UPDATE model_operations_jobs SET cancel_requested=true WHERE id='job-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordManual(owned, "tenant-a", "actor", target, outcome); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("cancelled job wrote result %v", err)
	}
	if _, err := p.Exec(ctx, `UPDATE model_operations_jobs SET cancel_requested=false,lease_until=clock_timestamp()-interval '1 second' WHERE id='job-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordManual(owned, "tenant-a", "actor", target, outcome); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired job wrote result %v", err)
	}
	if _, err := p.Exec(ctx, `UPDATE model_operations_jobs SET lease_until=clock_timestamp()+interval '1 minute' WHERE id='job-a'`); err != nil {
		t.Fatal(err)
	}
	claimed, err := s.BeginManualTarget(owned, "tenant-a", "actor", target)
	if err != nil || !claimed {
		t.Fatalf("valid claim: %t %v", claimed, err)
	}
	claimed, err = s.BeginManualTarget(owned, "tenant-a", "actor", target)
	if err != nil || claimed {
		t.Fatalf("repeat manual claim: %t %v", claimed, err)
	}
	r, err := s.RecordManual(owned, "tenant-a", "actor", target, outcome)
	if err != nil || r.InvocationID != "job-a" {
		t.Fatalf("valid job %+v %v", r, err)
	}
	if _, err := s.RecordManual(owned, "tenant-a", "actor", target, outcome); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate manual completion: %v", err)
	}
	if _, err = p.Exec(ctx, `UPDATE model_ops_probe_history SET created_at=clock_timestamp()-interval '8 days' WHERE invocation_id='job-a'`); err != nil {
		t.Fatal(err)
	}
	page, err := s.ListHistory(ctx, "tenant-a", HistoryFilter{InvocationID: "job-a"})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("retained invocation evidence lost: %+v %v", page, err)
	}
	other, err := s.ListHistory(ctx, "tenant-b", HistoryFilter{InvocationID: "job-a"})
	if err != nil || len(other.Items) != 0 {
		t.Fatalf("invocation evidence crossed tenant: %+v %v", other, err)
	}
}
func TestPostgresLeaseRechecksJobAfterConfigLockWait(t *testing.T) {
	ctx, s, p := fixture(t)
	configOn(t, ctx, s, "tenant-a")
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT tenant_id FROM model_ops_configs WHERE tenant_id='tenant-a' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	result := make(chan *Lease, 1)
	errs := make(chan error, 1)
	go func() { l, err := s.AcquireLease(ctx, "tenant-a", "scheduler"); result <- l; errs <- err }()
	deadline := time.Now().Add(time.Second)
	for {
		var waiting bool
		err = p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%model_ops_configs%' AND query LIKE '%FOR UPDATE%')`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scheduler did not reach real row lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO model_operations_jobs(id,tenant_id,actor,request_key,request_sha256,request_json,state) VALUES('racing-job','tenant-a','actor','racing','sha','{}','queued')`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if l, err := <-result, <-errs; err != nil || l != nil {
		t.Fatalf("snapshot race started scheduler after manual submit: %+v %v", l, err)
	}
}
func TestPostgresUnknownTrafficAndBlockedCancelledAreNotUpstreamFailures(t *testing.T) {
	ctx, s, p := fixture(t)
	_, err := p.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,model_id,provider_id,request_status,upstream_status_code,created_at) VALUES('unknown1','unknown1','tenant-a','ma','pa','success',NULL,clock_timestamp()),('unknown2','unknown2','tenant-a','ma','pa','failed',NULL,clock_timestamp()),('blocked','blocked','tenant-a','ma','pa','blocked',403,clock_timestamp()),('cancelled','cancelled','tenant-a','ma','pa','cancelled',503,clock_timestamp());`)
	if err != nil {
		t.Fatal(err)
	}
	q, err := s.GetQuality(ctx, "tenant-a", ReadFilter{})
	if err != nil || len(q.Items) != 1 {
		t.Fatalf("quality %+v %v", q, err)
	}
	x := q.Items[0]
	if x.UpstreamSamples != 0 || x.Availability != nil || x.P50MS != nil || x.P95MS != nil || x.Failures != 0 || x.HTTP5xx != 0 || x.HTTP4xx != 0 || x.AuthFailures != 0 || x.Blocked != 1 || x.Cancelled != 1 {
		t.Fatalf("unknown/blocked traffic fabricated upstream evidence %+v", x)
	}
}
func TestPostgresEmptyAndStaleOverviewHonorsWindowAndNullableHourly(t *testing.T) {
	ctx, s, p := fixture(t)
	configOn(t, ctx, s, "tenant-a")
	o, err := s.GetOverview(ctx, "tenant-a", ReadFilter{WindowHours: 6, ModelID: "ma"})
	if err != nil || len(o.Targets) != 1 {
		t.Fatalf("overview %+v %v", o, err)
	}
	x := o.Targets[0]
	if x.State != "unknown" || x.Availability != nil || x.P50MS != nil || x.LastProbeAt != nil || len(x.Hourly) != 24 {
		t.Fatalf("empty target fabricated health %+v", x)
	}
	for _, hour := range x.Hourly {
		if hour.Availability != nil || hour.P50MS != nil || hour.P95MS != nil {
			t.Fatal("empty hour is not unknown")
		}
	}
	target := targetFor(t, ctx, s, "tenant-a", "ma")
	r, err := s.RecordManual(ctx, "tenant-a", "actor", target, Outcome{Success: true, HTTPStatus: 200, BodyValidated: true, LatencyMS: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, `UPDATE model_ops_probe_history SET created_at=clock_timestamp()-interval '8 hours' WHERE id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	o, err = s.GetOverview(ctx, "tenant-a", ReadFilter{WindowHours: 6, ModelID: "ma"})
	if err != nil || o.Targets[0].State != "stale" || o.Targets[0].Samples != 0 || o.Targets[0].Availability != nil {
		t.Fatalf("window/staleness ignored %+v %v", o, err)
	}
	page, err := s.ListHistory(ctx, "tenant-a", HistoryFilter{WindowHours: 6})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("history window ignored %+v %v", page, err)
	}
	page, err = s.ListHistory(ctx, "tenant-a", HistoryFilter{WindowHours: 24})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("24h evidence not preserved %+v %v", page, err)
	}
	for _, window := range []int{6, 24, 72, 168} {
		o, err = s.GetOverview(ctx, "tenant-a", ReadFilter{WindowHours: window, ModelID: "ma"})
		if err != nil {
			t.Fatal(err)
		}
		x = o.Targets[0]
		var n int64
		for _, bucket := range x.Hourly {
			n += bucket.Samples
		}
		if len(x.Hourly) != 24 || n != x.Samples || x.Hourly[0].Hour.Sub(o.GeneratedAt) != -time.Duration(window)*time.Hour {
			t.Fatalf("curve/count window mismatch window=%d samples=%d curve=%d", window, x.Samples, n)
		}
	}
}
func TestPostgresExpiredWriterInFlightDeadlineFencesNewDispatch(t *testing.T) {
	ctx, s, p := fixture(t)
	configOn(t, ctx, s, "tenant-a")
	target := targetFor(t, ctx, s, "tenant-a", "ma")
	l, err := s.AcquireLease(ctx, "tenant-a", "old-scheduler")
	if err != nil || l == nil {
		t.Fatal(err)
	}
	if claimed, err := s.ClaimTarget(ctx, l, target); err != nil || !claimed {
		t.Fatalf("claim: %t %v", claimed, err)
	}
	if err = s.BeginScheduledDispatch(ctx, l, target); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, `UPDATE model_ops_leases SET expires_at=clock_timestamp()-interval '1 second'; INSERT INTO model_operations_jobs(id,tenant_id,actor,request_key,request_sha256,request_json,state,owner_token,lease_until) VALUES('new-manual','tenant-a','actor','new-request','sha','{}','running','new-owner',clock_timestamp()+interval '1 minute')`); err != nil {
		t.Fatal(err)
	}
	manualCtx := WithJobOwner(ctx, "new-manual", "new-owner")
	if _, err = s.BeginManualTarget(manualCtx, "tenant-a", "actor", target); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired scheduler HTTP overlapped manual: %v", err)
	}
	if _, err = p.Exec(ctx, `UPDATE model_ops_target_schedule SET dispatch_deadline=clock_timestamp()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if claimed, err := s.BeginManualTarget(manualCtx, "tenant-a", "actor", target); err != nil || !claimed {
		t.Fatalf("manual after old deadline: %t %v", claimed, err)
	}
	if _, err = p.Exec(ctx, `UPDATE model_operations_jobs SET state='interrupted',completed_at=clock_timestamp(),lease_until=clock_timestamp()-interval '1 second'; UPDATE model_ops_target_schedule SET next_probe_at=clock_timestamp()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	newLease, err := s.AcquireLease(ctx, "tenant-a", "new-scheduler")
	if err != nil || newLease == nil {
		t.Fatalf("acquire %+v %v", newLease, err)
	}
	if claimed, err := s.ClaimTarget(ctx, newLease, target); err != nil || !claimed {
		t.Fatalf("scheduled claim: %t %v", claimed, err)
	}
	if err = s.BeginScheduledDispatch(ctx, newLease, target); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired manual HTTP overlapped scheduler: %v", err)
	}
	if _, err = p.Exec(ctx, `UPDATE model_ops_manual_claims SET dispatch_deadline=clock_timestamp()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if err = s.BeginScheduledDispatch(ctx, newLease, target); err != nil {
		t.Fatalf("dispatch after real deadline: %v", err)
	}
	var n int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM model_ops_probe_history`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("fencing forged observations: %d %v", n, err)
	}
}

type pendingAdmissionExecutor struct{ calls int }

func (e *pendingAdmissionExecutor) Execute(_ context.Context, _ string, t Target) Outcome {
	e.calls++
	return Outcome{Success: true, HTTPStatus: 200, BodyValidated: true, LatencyMS: 2}
}

func TestPostgresPendingManualProbeDoesNotActivateOrSchedule(t *testing.T) {
	ctx, store, pool := fixture(t)
	_, err := pool.Exec(ctx, `INSERT INTO models VALUES('pending-native','native','pending-claude','upstream-pending','pending'),('hidden-pending','pb','foreign-pending','foreign','pending'),('disabled-model','pa','disabled','disabled','disabled')`)
	if err != nil {
		t.Fatal(err)
	}
	executor := &pendingAdmissionExecutor{}
	svc := NewService(store, executor)
	targets, err := svc.Targets(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, target := range targets {
		if target.ModelID == "hidden-pending" || target.ModelID == "disabled-model" || target.ModelID == "deleted" {
			t.Fatal("manual target scope escaped", target)
		}
		if target.ModelID == "pending-native" {
			found = true
			if target.Protocol != "messages" {
				t.Fatal(target)
			}
		}
	}
	if !found {
		t.Fatal("pending model cannot be manually verified")
	}
	cfg, err := svc.Config(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Test(ctx, "tenant-a", "actor", TestRequest{ModelIDs: []string{"pending-native"}, ConfirmCost: true, ExpectedConfigVersion: cfg.Version})
	if err != nil || len(result.Items) != 1 || !result.Items[0].Success || executor.calls != 1 {
		t.Fatalf("pending probe did not execute: %+v %v calls=%d", result, err, executor.calls)
	}
	overview, err := svc.OverviewFiltered(ctx, "tenant-a", ReadFilter{ProviderID: "native", ModelID: "pending-native"})
	if err != nil || len(overview.Targets) != 1 || overview.Targets[0].State != "healthy" || overview.Targets[0].Samples != 1 {
		t.Fatalf("pending manual result missing from overview: %+v %v", overview, err)
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM models WHERE id='pending-native'`).Scan(&status); err != nil || status != "pending" {
		t.Fatal("probe activated business traffic", status, err)
	}
	scheduled, err := store.ListTargets(ctx, "tenant-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range scheduled {
		if target.ModelID == "pending-native" {
			t.Fatal("pending model scheduled automatically")
		}
	}
	if _, err = svc.Test(ctx, "tenant-a", "actor", TestRequest{ModelIDs: []string{"hidden-pending"}, ConfirmCost: true, ExpectedConfigVersion: cfg.Version}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cross tenant pending probe accepted", err)
	}
}

// 真库 fixture 使用独立 schema，覆盖控制台实际质量接口的数据来源。
func TestPostgresQualityTimingMetrics(t *testing.T) {
	ctx, store, pool := fixture(t)
	_, err := pool.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,model_id,provider_id,request_status,upstream_status_code,latency_ms,upstream_ttft_ms,output_audit_result,input_tokens,output_tokens,created_at) VALUES
 ('timing-a','timing-a','tenant-a','ma','pa','success',200,1000,100,'{"response_metadata":{"timing":{"input_security_ms":10,"output_security_ms":20,"pre_upstream_ms":40,"generation_ms":500}}}',20,50,clock_timestamp()-interval '1 minute'),
 ('timing-old','timing-old','tenant-a','ma','pa','success',200,1100,100,'{}',30,100,clock_timestamp()-interval '1 minute'),
 ('timing-short','timing-short','tenant-a','ma','pa','success',200,300,100,'{"response_metadata":{"timing":{"generation_ms":199}}}',1,1,clock_timestamp()-interval '1 minute'),
 ('timing-failed','timing-failed','tenant-a','ma','pa','failed',500,500,100,'{"response_metadata":{"timing":{"input_security_ms":999,"pre_upstream_ms":999,"generation_ms":300}}}',5,5,clock_timestamp()-interval '1 minute'),
 ('timing-foreign','timing-foreign','tenant-b','mb','pb','success',200,500,100,'{}',9000,9000,clock_timestamp()-interval '1 minute'),
 ('timing-future','timing-future','tenant-a','ma','pa','success',200,500,100,'{}',9000,9000,clock_timestamp()+interval '1 hour'),
 ('timing-outside','timing-outside','tenant-a','ma','pa','success',200,500,100,'{}',9000,9000,clock_timestamp()-interval '7 hours')`)
	if err != nil {
		t.Fatal(err)
	}
	quality, err := store.GetQuality(ctx, "tenant-a", ReadFilter{WindowHours: 6, ProviderID: "pa", ModelID: "ma"})
	if err != nil || len(quality.Items) != 1 {
		t.Fatalf("质量接口聚合失败: %+v %v", quality, err)
	}
	item := quality.Items[0]
	for name, pair := range map[string]struct {
		actual   *float64
		expected float64
	}{
		"首字中位数": {item.FirstEventP50MS, 100}, "首字九五分位": {item.FirstEventP95MS, 100},
		"输出速度": {item.OutputTokensPerSecP50, 100}, "安全中位数": {item.SecurityP50MS, 30}, "安全九五分位": {item.SecurityP95MS, 30},
		"处理时间中位数": {item.PreUpstreamP50MS, 40}, "处理时间九五分位": {item.PreUpstreamP95MS, 40},
		"每分钟请求数": {item.RPM, 4.0 / 360}, "每分钟词元数": {item.TPM, 212.0 / 360},
	} {
		if pair.actual == nil || math.Abs(*pair.actual-pair.expected) > 1e-9 {
			t.Errorf("%s 错误: %v，预期 %v", name, pair.actual, pair.expected)
		}
	}
	if item.Samples != 4 || !strings.Contains(quality.Note, "无流量分钟") {
		t.Fatalf("窗口或统计口径丢失: %+v", quality)
	}
	encoded, err := json.Marshal(quality)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"first_event_p50_ms", "first_event_p95_ms", "output_tokens_per_sec_p50", "security_p50_ms", "security_p95_ms", "pre_upstream_p50_ms", "pre_upstream_p95_ms", "rpm", "tpm"} {
		if !strings.Contains(string(encoded), `"`+field+`":`) {
			t.Errorf("前端约定字段缺失: %s", field)
		}
	}
	rows, err := pool.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) "+modelOperationsQualitySQL, "tenant-a", 6, "pa", "ma")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var line string
		if err = rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		t.Log(line)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Log("观察点：租户及时间窗口索引扫描、JSON 提取前行数、排序内存及磁盘、共享缓冲区；小 fixture 顺序扫描正常。")
}
