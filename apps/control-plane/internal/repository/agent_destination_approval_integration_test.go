package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/probereports"
)

// w27RunNonce makes every tenant/endpoint/rule id in this file unique across
// repeated `go test` invocations against the same persistent container: the
// integration DB is not torn down between runs (only between fresh
// containers), so fixed fixture ids would collide with rows a prior run left
// behind. This has no bearing on the behavior under test — only on this
// test file's own re-run hygiene.
var w27RunNonce = w27NewRunNonce()

func w27NewRunNonce() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// T07/T08 real-Postgres integration test. This runs against W27's own
// isolated postgres:16-alpine container (port 28491, per the wave3 contract)
// with the full migration chain applied through 869 — never against the
// shared jjdguard_dev database used by agent_endpoints_test.go's
// agentEndpointTestDB helper, hence a distinct env var and a distinct safety
// check on current_database().
//
// It exercises exactly the six contract-mandated scenarios end to end
// through AcceptAiprobeReport: approved hit, forged rule_id, disabled rule,
// not_listed, an other-status-with-fields wire violation, cross-tenant
// isolation, and duplicate-report idempotency (the last one folded into the
// approved-hit scenario, since idempotency is about the same report being
// submitted twice, not a distinct destination outcome).
func w27DestinationApprovalTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("W27_DESTINATION_APPROVAL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("W27_DESTINATION_APPROVAL_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var name string
	if err = db.QueryRow(ctx, `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "w27_t07" {
		t.Fatalf("refusing non-w27-isolated database %q", name)
	}
	return db
}

// w27SeedEndpoint inserts the minimal agent_endpoints row AcceptAiprobeReport
// requires (its UPDATE agent_endpoints ... WHERE tenant_id=$1 AND id=$2 step
// is a no-op, not an error, if the row is missing — but a real deployment
// always has one, so the test fixture matches that).
func w27SeedEndpoint(t *testing.T, db *pgxpool.Pool, tenant, endpoint string) {
	t.Helper()
	_, err := db.Exec(context.Background(), `INSERT INTO agent_endpoints
		(id,tenant_id,machine_id,hostname,os,arch,agent_product,token_hash)
		VALUES($1,$2,'m','h','linux','amd64','aiprobe',$3)
		ON CONFLICT (id) DO NOTHING`, endpoint, tenant, "w27-token-hash-"+endpoint)
	if err != nil {
		t.Fatal(err)
	}
}

// w27MinimalReport builds the smallest report that satisfies
// probereports.Report.Validate(): exactly one cli_agent asset, all ten
// collectors marked complete, one destination attached via
// Evidence.Destinations. reportSuffix keeps ReportID/EndpointID/SourceID
// distinct across subtests sharing the same database.
func w27MinimalReport(endpoint string, destinations []probereports.Destination) probereports.Report {
	collectorNames := []string{"homes", "host", "process", "netsock", "agents", "apps", "browser_extensions", "container", "schedule", "modelsvc"}
	collectors := make([]probereports.CollectorResult, 0, len(collectorNames))
	for _, name := range collectorNames {
		collectors = append(collectors, probereports.CollectorResult{Name: name, Status: "complete"})
	}
	scannedAt := "2026-01-02T03:04:05Z"
	sourceID := strings.Repeat("a", 64)
	asset := probereports.Asset{
		SourceID: sourceID, Kind: "cli_agent", Name: "asset", DisplayName: "Asset",
		ContentHash: "sha256:" + strings.Repeat("b", 64), ObservedAt: scannedAt, CollectionStatus: "current",
		Confidence: 80, EvidenceLabels: []string{}, RiskFlags: []string{},
		Evidence: probereports.Evidence{
			Destinations: destinations, MCPServers: []probereports.MCPServer{}, Skills: []probereports.Skill{},
			Config:              probereports.AssetConfig{InstructionFiles: []probereports.HashedFile{}, ConfigFiles: []probereports.HashedFile{}},
			ProcessPIDs:         []int32{},
			SocketAttributions:  []probereports.SocketObservation{},
		},
	}
	report := probereports.Report{
		SchemaVersion: probereports.SchemaVersion, EndpointID: endpoint, ProbeVersion: "0.1.0",
		ScannedAt: scannedAt, Status: "complete", Collectors: collectors, Assets: []probereports.Asset{asset},
		SocketObservations: []probereports.SocketObservation{},
	}
	report.ReportID = probereports.ReportID(report.EndpointID, report.ScannedAt)
	return report
}

func w27InsertRule(t *testing.T, db *pgxpool.Pool, tenant, ruleID, matchType, matchValue, category string, enabled bool) string {
	t.Helper()
	id := "dar_test_" + ruleID + "_" + tenant
	_, err := db.Exec(context.Background(), `INSERT INTO agent_destination_approval_rules
		(id,tenant_id,rule_id,match_type,match_value,category,enabled,created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,'test')`, id, tenant, ruleID, matchType, matchValue, category, enabled)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestAcceptAiprobeReportDestinationApprovalScenarios covers the approved
// hit, forged rule_id, disabled rule, and not_listed scenarios: four
// destinations on one report, one tenant, one enabled and one disabled
// catalog rule.
func TestAcceptAiprobeReportDestinationApprovalScenarios(t *testing.T) {
	db := w27DestinationApprovalTestDB(t)
	tenant := "w27-tenant-scenarios-" + w27RunNonce
	endpoint := "w27-endpoint-scenarios-" + w27RunNonce
	w27SeedEndpoint(t, db, tenant, endpoint)

	// Catalog: one enabled host rule for the "approved hit" destination, one
	// disabled rule whose match the "disabled rule" destination will hit.
	w27InsertRule(t, db, tenant, "official-anthropic-1", "host", "api.anthropic.com", "official", true)
	w27InsertRule(t, db, tenant, "relay-disabled-1", "base_url_prefix", "https://disabled.relay.test", "relay", false)

	destinations := []probereports.Destination{
		// approved hit: matches the enabled host rule. Client also claims
		// approved with a *different*, non-existent rule id — the server
		// must verify by its own catalog lookup, not by trusting this string.
		{Origin: "https://api.anthropic.com", Classification: "official", Source: "env", Models: []string{"claude-sonnet-5"}, ApprovalStatus: "approved", ApprovalBasis: "approved_destination_catalog", ApprovalRuleID: "client-claimed-official-1"},
		// forged rule_id: client claims approved with a rule id that does
		// not exist in this tenant's catalog at all, and the origin itself
		// does not match any enabled rule either.
		{Origin: "https://forged.relay.test", Provider: "forged.relay.test", Classification: "relay", Source: "config_file", Models: []string{}, ApprovalStatus: "approved", ApprovalBasis: "approved_destination_catalog", ApprovalRuleID: "totally-made-up-rule"},
		// disabled rule: origin matches relay-disabled-1's match_value
		// exactly, but that rule is disabled, so it must not count as a
		// catalog hit — verification must fall through to not_listed.
		{Origin: "https://disabled.relay.test", Provider: "disabled.relay.test", Classification: "relay", Source: "config_file", Models: []string{}, ApprovalStatus: "not_listed", ApprovalBasis: "approved_destination_catalog"},
		// not_listed: an origin that matches nothing in a non-empty catalog.
		{Origin: "https://unknown.relay.test", Provider: "unknown.relay.test", Classification: "relay", Source: "config_file", Models: []string{}, ApprovalStatus: "not_listed", ApprovalBasis: "approved_destination_catalog"},
	}
	report := w27MinimalReport(endpoint, destinations)
	if err := report.Validate(); err != nil {
		t.Fatalf("fixture report should validate: %v", err)
	}

	repo := NewAgentEndpointRepository(db)
	receipt, err := repo.AcceptAiprobeReport(context.Background(), tenant, endpoint, &report)
	if err != nil {
		t.Fatalf("AcceptAiprobeReport: %v", err)
	}
	if !receipt.Accepted || receipt.Duplicate {
		t.Fatalf("expected a fresh accepted receipt, got %#v", receipt)
	}

	rows, err := db.Query(context.Background(), `SELECT origin,client_claimed_status,client_claimed_rule_id,server_verified_status,server_verified_rule_id
		FROM agent_destination_approval_observations WHERE tenant_id=$1 AND report_id=$2 ORDER BY destination_index`, tenant, report.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type obs struct {
		origin, clientStatus, clientRuleID, serverStatus, serverRuleID string
	}
	var got []obs
	for rows.Next() {
		var o obs
		if err = rows.Scan(&o.origin, &o.clientStatus, &o.clientRuleID, &o.serverStatus, &o.serverRuleID); err != nil {
			t.Fatal(err)
		}
		got = append(got, o)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 observation rows, got %d: %#v", len(got), got)
	}

	// approved hit
	if got[0].origin != "https://api.anthropic.com" || got[0].serverStatus != "approved" || got[0].serverRuleID != "official-anthropic-1" {
		t.Fatalf("approved-hit destination: %#v", got[0])
	}
	if got[0].clientRuleID != "client-claimed-official-1" {
		t.Fatalf("client_claimed_rule_id must be preserved verbatim, got %#v", got[0])
	}

	// forged rule_id: client claimed approved, server must not agree.
	if got[1].origin != "https://forged.relay.test" || got[1].clientStatus != "approved" || got[1].clientRuleID != "totally-made-up-rule" {
		t.Fatalf("forged destination client-claimed fields not preserved: %#v", got[1])
	}
	if got[1].serverStatus == "approved" {
		t.Fatalf("forged rule_id must never verify as approved: %#v", got[1])
	}
	if got[1].serverStatus != "not_listed" {
		t.Fatalf("forged rule_id with non-matching origin should resolve not_listed, got %#v", got[1])
	}

	// disabled rule: origin matches match_value exactly, but the rule is
	// disabled, so this must not verify as approved either.
	if got[2].origin != "https://disabled.relay.test" {
		t.Fatalf("unexpected destination at index 2: %#v", got[2])
	}
	if got[2].serverStatus == "approved" {
		t.Fatalf("a disabled rule's match must never verify as approved: %#v", got[2])
	}
	if got[2].serverStatus != "not_listed" {
		t.Fatalf("disabled-rule match should resolve not_listed (catalog non-empty, no enabled match), got %#v", got[2])
	}

	// not_listed: no match in a non-empty catalog.
	if got[3].origin != "https://unknown.relay.test" || got[3].serverStatus != "not_listed" {
		t.Fatalf("not_listed destination: %#v", got[3])
	}

	// Evidence projection must also carry both client_claimed and
	// server_verified for every destination — never dropped at the
	// evidence-blob layer either.
	var evidenceJSON []byte
	if err = db.QueryRow(context.Background(), `SELECT evidence FROM agent_endpoint_assets WHERE tenant_id=$1 AND endpoint_id=$2`, tenant, endpoint).Scan(&evidenceJSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(evidenceJSON), `"destination_approvals"`) || !strings.Contains(string(evidenceJSON), `"server_verified"`) {
		t.Fatalf("evidence blob missing destination_approvals/server_verified projection: %s", evidenceJSON)
	}

	// Duplicate-report idempotency: submitting the byte-identical report
	// again must not create a second set of observation rows, and must be
	// reported as a duplicate, not a fresh accept.
	receipt2, err := repo.AcceptAiprobeReport(context.Background(), tenant, endpoint, &report)
	if err != nil {
		t.Fatalf("duplicate AcceptAiprobeReport: %v", err)
	}
	if !receipt2.Duplicate {
		t.Fatalf("expected duplicate=true on identical resubmission, got %#v", receipt2)
	}
	var countAfter int
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM agent_destination_approval_observations WHERE tenant_id=$1 AND report_id=$2`, tenant, report.ReportID).Scan(&countAfter); err != nil {
		t.Fatal(err)
	}
	if countAfter != 4 {
		t.Fatalf("duplicate report must not create extra observation rows, got count=%d", countAfter)
	}
}

// TestDestinationApprovalCrossTenantIsolation asserts that tenant B's report
// cannot be verified against tenant A's catalog: a rule that would match
// tenant B's destination if the tenant boundary were ignored must have no
// effect, and tenant B's own catalog (empty) must resolve to unreviewed, not
// a false not_listed or a false approved leaked from tenant A.
func TestDestinationApprovalCrossTenantIsolation(t *testing.T) {
	db := w27DestinationApprovalTestDB(t)
	tenantA := "w27-tenant-a-isolation-" + w27RunNonce
	tenantB := "w27-tenant-b-isolation-" + w27RunNonce
	endpointA := "w27-endpoint-a-isolation-" + w27RunNonce
	endpointB := "w27-endpoint-b-isolation-" + w27RunNonce
	w27SeedEndpoint(t, db, tenantA, endpointA)
	w27SeedEndpoint(t, db, tenantB, endpointB)

	// Tenant A approves this exact host. Tenant B must never benefit from it.
	w27InsertRule(t, db, tenantA, "shared-host-rule", "host", "shared.example.test", "relay", true)

	destinations := []probereports.Destination{
		{Origin: "https://shared.example.test", Provider: "shared.example.test", Classification: "relay", Source: "config_file", Models: []string{}, ApprovalStatus: "not_listed", ApprovalBasis: "approved_destination_catalog"},
	}
	reportB := w27MinimalReport(endpointB, destinations)
	if err := reportB.Validate(); err != nil {
		t.Fatalf("fixture report should validate: %v", err)
	}

	repo := NewAgentEndpointRepository(db)
	if _, err := repo.AcceptAiprobeReport(context.Background(), tenantB, endpointB, &reportB); err != nil {
		t.Fatalf("AcceptAiprobeReport for tenant B: %v", err)
	}

	var serverStatus string
	if err := db.QueryRow(context.Background(), `SELECT server_verified_status FROM agent_destination_approval_observations
		WHERE tenant_id=$1 AND report_id=$2`, tenantB, reportB.ReportID).Scan(&serverStatus); err != nil {
		t.Fatal(err)
	}
	if serverStatus == "approved" {
		t.Fatalf("tenant B must never be approved by tenant A's catalog rule, got %q", serverStatus)
	}
	// Tenant B's own catalog is completely empty: per the "no basis
	// configured yet" semantics, this must resolve to unreviewed, not a
	// fabricated not_listed shadow-AI finding.
	if serverStatus != "unreviewed" {
		t.Fatalf("tenant B with an empty catalog should resolve unreviewed, got %q", serverStatus)
	}

	// Also assert the repository-level List() never returns tenant A's rule
	// under tenant B's filter.
	repoApproval := NewAgentDestinationApprovalRepository(db)
	page, err := repoApproval.List(context.Background(), tenantB, DestinationApprovalRuleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		if item.RuleID == "shared-host-rule" {
			t.Fatalf("tenant B's catalog listing leaked tenant A's rule: %#v", item)
		}
	}
	if page.Total != 0 {
		t.Fatalf("tenant B's catalog should be empty, got total=%d", page.Total)
	}
}

// TestAcceptAiprobeReportRejectsApprovalBasisWireViolation covers the
// "other-status-with-fields" scenario: a destination whose approval_status
// is neither approved nor not_listed but which still carries
// approval_basis/approval_rule_id violates the wire contract
// (contracts/model-destination-approval.v1.schema.json's conditional
// requirement), and the whole report must be rejected up front — never
// silently dropped, never partially accepted with the bad destination
// quietly stripped.
func TestAcceptAiprobeReportRejectsApprovalBasisWireViolation(t *testing.T) {
	db := w27DestinationApprovalTestDB(t)
	tenant := "w27-tenant-violation-" + w27RunNonce
	endpoint := "w27-endpoint-violation-" + w27RunNonce
	w27SeedEndpoint(t, db, tenant, endpoint)

	destinations := []probereports.Destination{
		{Origin: "https://relay.example.test", Provider: "relay.example.test", Classification: "relay", Source: "config_file", Models: []string{}, ApprovalStatus: "unreviewed", ApprovalBasis: "approved_destination_catalog", ApprovalRuleID: "should-not-be-here"},
	}
	report := w27MinimalReport(endpoint, destinations)
	if err := report.Validate(); err == nil {
		t.Fatal("fixture is supposed to violate the conditional contract at the wire-format layer")
	}

	repo := NewAgentEndpointRepository(db)
	_, err := repo.AcceptAiprobeReport(context.Background(), tenant, endpoint, &report)
	if err != ErrAiprobeReportInvalid {
		t.Fatalf("expected ErrAiprobeReportInvalid for a wire-contract violation, got %v", err)
	}

	var count int
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND id=$2`, tenant, report.ReportID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("a rejected report must never be partially persisted to agent_events")
	}
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM agent_destination_approval_observations WHERE tenant_id=$1`, tenant).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("a rejected report must never produce partial destination approval observations")
	}
}

// TestDestinationApprovalRepositoryAdminLifecycle exercises the admin-facing
// Create/List/Deactivate surface directly (not through report ingestion):
// create is idempotent-safe against duplicate match values, deactivate never
// deletes history, and a deactivated rule's match_value can be reused by a
// fresh rule.
func TestDestinationApprovalRepositoryAdminLifecycle(t *testing.T) {
	db := w27DestinationApprovalTestDB(t)
	tenant := "w27-tenant-admin-lifecycle-" + w27RunNonce
	repo := NewAgentDestinationApprovalRepository(db)
	ctx := context.Background()

	created, err := repo.Create(ctx, tenant, DestinationApprovalRuleCreate{
		RuleID: "lifecycle-rule-1", MatchType: "host", MatchValue: "lifecycle.example.test", Category: "relay", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !created.Enabled {
		t.Fatal("a newly created rule must start enabled")
	}

	_, err = repo.Create(ctx, tenant, DestinationApprovalRuleCreate{
		RuleID: "lifecycle-rule-2", MatchType: "host", MatchValue: "lifecycle.example.test", Category: "relay", CreatedBy: "tester",
	})
	if err != ErrDestinationApprovalRuleConflict {
		t.Fatalf("expected ErrDestinationApprovalRuleConflict for a duplicate enabled match, got %v", err)
	}

	ok, err := repo.Deactivate(ctx, tenant, created.ID, "tester")
	if err != nil || !ok {
		t.Fatalf("Deactivate: ok=%v err=%v", ok, err)
	}
	// Idempotent: deactivating an already-disabled rule is a no-op, not an
	// error, and history is never deleted.
	ok, err = repo.Deactivate(ctx, tenant, created.ID, "tester")
	if err != nil || !ok {
		t.Fatalf("second Deactivate should be an idempotent no-op: ok=%v err=%v", ok, err)
	}
	page, err := repo.List(ctx, tenant, DestinationApprovalRuleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range page.Items {
		if item.ID == created.ID {
			found = true
			if item.Enabled {
				t.Fatal("deactivated rule must show enabled=false, not be deleted")
			}
			if item.DisabledAt == nil || item.DisabledBy != "tester" {
				t.Fatalf("deactivated rule missing disabled_at/disabled_by: %#v", item)
			}
		}
	}
	if !found {
		t.Fatal("deactivated rule must still be listed (history, not deletion)")
	}

	// The match_value is now free again since the earlier rule is disabled.
	if _, err = repo.Create(ctx, tenant, DestinationApprovalRuleCreate{
		RuleID: "lifecycle-rule-3", MatchType: "host", MatchValue: "lifecycle.example.test", Category: "relay", CreatedBy: "tester",
	}); err != nil {
		t.Fatalf("expected match_value reuse after deactivation to succeed: %v", err)
	}

	if _, err = repo.Deactivate(ctx, tenant, "does-not-exist", "tester"); err != ErrDestinationApprovalRuleNotFound {
		t.Fatalf("expected ErrDestinationApprovalRuleNotFound, got %v", err)
	}
}
