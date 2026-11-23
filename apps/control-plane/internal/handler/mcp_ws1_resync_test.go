package handler

// W1 1.4：MCP 定时重同步 + 漂移告警。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alert"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type ws1FakeSupplyRepo struct {
	mu     sync.Mutex
	inputs []repository.MCPSupplyChainSyncInput
	result *repository.MCPSupplyChainSyncResult
}

func (f *ws1FakeSupplyRepo) ApplySupplyChainSync(_ context.Context, in repository.MCPSupplyChainSyncInput) (*repository.MCPSupplyChainSyncResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inputs = append(f.inputs, in)
	if f.result != nil {
		copied := *f.result
		return &copied, nil
	}
	return &repository.MCPSupplyChainSyncResult{ServerStatus: "approved", ApprovedCount: len(in.Tools)}, nil
}
func (f *ws1FakeSupplyRepo) ResolveMCPSupplyChain(context.Context, string, string, string) (repository.MCPSupplyChainResolution, error) {
	return repository.MCPSupplyChainResolution{}, nil
}
func (f *ws1FakeSupplyRepo) SetMCPServerAdmission(context.Context, string, string, string, string, string, string, string) (*repository.MCPAdmissionMutation, error) {
	return nil, nil
}
func (f *ws1FakeSupplyRepo) SetMCPToolAdmission(context.Context, string, string, string, string, string, string) (*repository.MCPAdmissionMutation, error) {
	return nil, nil
}

type ws1InboxCall struct {
	tenant, severity, typ, title, url, group string
	body                                     map[string]any
}

type ws1ResyncHarness struct {
	scheduler *mcpResyncScheduler
	supply    *ws1FakeSupplyRepo
	mu        sync.Mutex
	inbox     []ws1InboxCall
	audits    []*repository.AuditOperation
	listed    int
	server    *repository.MCPServer
}

var ws1Manifest = []mcpManifestTool{{Name: "read", Description: "read a file", InputSchema: map[string]interface{}{"type": "object"}}}

func newWS1ResyncHarness(t *testing.T, previousHash string, fetchErr error) *ws1ResyncHarness {
	t.Helper()
	h := &ws1ResyncHarness{supply: &ws1FakeSupplyRepo{}}
	h.server = &repository.MCPServer{ID: "srv-1", TenantID: "tenant-a", Name: "files", ServerURL: "https://mcp.example/rpc",
		Status: "active", ManifestHash: previousHash, Capabilities: map[string]interface{}{}}
	deps := &Dependencies{MCPSupplyChainRepo: h.supply}
	h.scheduler = &mcpResyncScheduler{
		deps: deps,
		list: func(context.Context) ([]mcpResyncTarget, error) {
			h.mu.Lock()
			h.listed++
			h.mu.Unlock()
			return []mcpResyncTarget{{TenantID: "tenant-a", ServerID: "srv-1"}}, nil
		},
		lock: func(context.Context) (func(), error) { return func() {}, nil },
		fetch: func(context.Context, *repository.MCPServer) ([]mcpManifestTool, error) {
			if fetchErr != nil {
				return nil, fetchErr
			}
			return ws1Manifest, nil
		},
		scan: func(context.Context, string, string, string) ([]string, error) { return []string{}, nil },
		now:  func() time.Time { return time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC) },
		logf: t.Logf,
		inbox: func(_ context.Context, tenant, severity, typ, title string, body map[string]any, url, group string) (bool, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.inbox = append(h.inbox, ws1InboxCall{tenant, severity, typ, title, url, group, body})
			return true, nil
		},
		audit: func(_ context.Context, op *repository.AuditOperation) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.audits = append(h.audits, op)
			return nil
		},
		server: func(_ context.Context, tenant, id string) (*repository.MCPServer, error) {
			if tenant != h.server.TenantID || id != h.server.ID {
				return nil, nil
			}
			copied := *h.server
			return &copied, nil
		},
	}
	return h
}

func TestWS1ParseMCPResyncInterval(t *testing.T) {
	cases := []struct {
		raw     string
		want    time.Duration
		enabled bool
	}{
		{"", time.Hour, true},
		{"30m", 30 * time.Minute, true},
		{" 2h ", 2 * time.Hour, true},
		{"0", 0, false},
		{"off", 0, false},
		{"OFF", 0, false},
		{"10s", time.Hour, true}, // 低于下限回落默认
		{"garbage", time.Hour, true},
	}
	for _, c := range cases {
		got, enabled := parseMCPResyncInterval(c.raw)
		if got != c.want || enabled != c.enabled {
			t.Errorf("parseMCPResyncInterval(%q) = %v,%v want %v,%v", c.raw, got, enabled, c.want, c.enabled)
		}
	}
}

func TestWS1ResyncDriftRaisesGroupedAlertAndAudit(t *testing.T) {
	h := newWS1ResyncHarness(t, "old-hash", nil)
	r := h.scheduler.runOnce(context.Background())
	if r.Synced != 1 || r.Drifted != 1 || r.Failed != 0 {
		t.Fatalf("unexpected round %+v", r)
	}
	if len(h.supply.inputs) != 1 || h.supply.inputs[0].ManifestHash != mcpManifestHash(ws1Manifest) {
		t.Fatalf("supply chain sync not applied with new hash: %+v", h.supply.inputs)
	}
	if got := h.supply.inputs[0].Tools[0].SchemaHash; got != mcpToolSchemaHash("read a file", ws1Manifest[0].InputSchema) {
		t.Fatalf("scheduled sync must compute the same tool fingerprint as manual sync, got %s", got)
	}
	if len(h.inbox) != 1 {
		t.Fatalf("expected one drift alert, got %d", len(h.inbox))
	}
	call := h.inbox[0]
	if call.tenant != "tenant-a" || call.typ != mcpDriftAlertType || call.group != "mcp_drift:srv-1" || call.url != "/mcp-gateway/servers" {
		t.Fatalf("unexpected alert %+v", call)
	}
	if call.body["previous_hash"] != "old-hash" || call.body["changed"] != true {
		t.Fatalf("alert body missing drift facts: %+v", call.body)
	}
	if len(h.audits) != 1 || h.audits[0].ActionDetail["trigger"] != "scheduled" || h.audits[0].TargetID != "srv-1" {
		t.Fatalf("scheduled sync must leave an operation audit: %+v", h.audits)
	}
}

func TestWS1ResyncUnchangedManifestNoAlert(t *testing.T) {
	h := newWS1ResyncHarness(t, mcpManifestHash(ws1Manifest), nil)
	r := h.scheduler.runOnce(context.Background())
	if r.Synced != 1 || r.Drifted != 0 || len(h.inbox) != 0 {
		t.Fatalf("unchanged manifest must not alert: round=%+v inbox=%+v", r, h.inbox)
	}
	if len(h.audits) != 1 {
		t.Fatalf("every scheduled sync is audited, got %d", len(h.audits))
	}
}

func TestWS1ResyncFirstSyncIsNotDrift(t *testing.T) {
	h := newWS1ResyncHarness(t, "", nil)
	if r := h.scheduler.runOnce(context.Background()); r.Drifted != 0 || len(h.inbox) != 0 {
		t.Fatalf("first-ever sync has no baseline and must not alert: %+v", r)
	}
}

func TestWS1ResyncDriftWithQuarantineAlertsHigh(t *testing.T) {
	h := newWS1ResyncHarness(t, "old-hash", nil)
	h.supply.result = &repository.MCPSupplyChainSyncResult{ServerStatus: "approved", QuarantinedCount: 1, Reasons: []string{"rug_pull_schema_changed"}}
	r := h.scheduler.runOnce(context.Background())
	if r.Drifted != 1 || len(h.inbox) != 1 || h.inbox[0].severity != "high" {
		t.Fatalf("drift that quarantined a tool must alert high: round=%+v inbox=%+v", r, h.inbox)
	}
}

func TestWS1ResyncStandingQuarantineDoesNotRealert(t *testing.T) {
	// 存量隔离（清单未变）每轮都会计入 QuarantinedCount，不能每小时重复告警。
	h := newWS1ResyncHarness(t, mcpManifestHash(ws1Manifest), nil)
	h.supply.result = &repository.MCPSupplyChainSyncResult{ServerStatus: "approved", QuarantinedCount: 1, Reasons: []string{"description_poison"}}
	if r := h.scheduler.runOnce(context.Background()); r.Drifted != 0 || len(h.inbox) != 0 {
		t.Fatalf("standing quarantine without manifest change must not re-alert: round=%+v inbox=%+v", r, h.inbox)
	}
}

func TestWS1ResyncFetchFailureKeepsSnapshotAndDoesNotAlert(t *testing.T) {
	h := newWS1ResyncHarness(t, "old-hash", errors.New("dial tcp: timeout"))
	r := h.scheduler.runOnce(context.Background())
	if r.Failed != 1 || r.Synced != 0 {
		t.Fatalf("unexpected round %+v", r)
	}
	if len(h.supply.inputs) != 0 || len(h.inbox) != 0 {
		t.Fatalf("fetch failure must not touch admission state or alert: supply=%d inbox=%d", len(h.supply.inputs), len(h.inbox))
	}
}

func TestWS1ResyncSkipsWhenLockHeldElsewhere(t *testing.T) {
	h := newWS1ResyncHarness(t, "old-hash", nil)
	h.scheduler.lock = func(context.Context) (func(), error) { return nil, nil }
	r := h.scheduler.runOnce(context.Background())
	if !r.Skipped || h.listed != 0 || len(h.supply.inputs) != 0 {
		t.Fatalf("another replica holds the lock; round must be skipped: %+v listed=%d", r, h.listed)
	}
}

// 真库：列目标过滤、咨询锁互斥、以及真实仓储 + 真实告警收件箱的端到端一轮。
func TestWS1ResyncOnRealPostgres(t *testing.T) {
	dsn := os.Getenv("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tenant := fmt.Sprintf("ws1rs%d", time.Now().UnixNano()%1_000_000_000)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, tenant); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM alert_inbox WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(ctx, `DELETE FROM mcp_servers WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant)
	})
	serverRepo := repository.NewMCPServersRepository(pool)
	for _, s := range []*repository.MCPServer{
		{ID: tenant + "-live", TenantID: tenant, Name: "live", ServerURL: "https://live.example/mcp", Status: "active", Transport: "streamable_http"},
		{ID: tenant + "-off", TenantID: tenant, Name: "off", ServerURL: "https://off.example/mcp", Status: "disabled", Transport: "streamable_http"},
		{ID: tenant + "-sse", TenantID: tenant, Name: "sse", ServerURL: "https://sse.example/mcp", Status: "active", Transport: "sse"},
		{ID: tenant + "-nourl", TenantID: tenant, Name: "nourl", Status: "active", Transport: "streamable_http"},
	} {
		if err := serverRepo.Create(ctx, s); err != nil {
			t.Fatalf("create %s: %v", s.ID, err)
		}
	}

	targets, err := listMCPResyncTargets(pool)(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var mine []string
	for _, target := range targets {
		if target.TenantID == tenant {
			mine = append(mine, target.ServerID)
		}
	}
	// 旧 HTTP+SSE 现已支持定时重同步：在用 + 已登记地址的 streamable_http 与 sse 服务都纳入；
	// 停用与无地址的服务仍被排除。
	sort.Strings(mine)
	want := []string{tenant + "-live", tenant + "-sse"}
	if strings.Join(mine, ",") != strings.Join(want, ",") {
		t.Fatalf("active+url servers (streamable_http and sse) are resynced, got %v want %v", mine, want)
	}

	lock := pgMCPResyncLocker(pool)
	release, err := lock(ctx)
	if err != nil || release == nil {
		t.Fatalf("first lock: release=%v err=%v", release != nil, err)
	}
	second, err := lock(ctx)
	if err != nil || second != nil {
		t.Fatalf("second replica must not get the lock: got=%v err=%v", second != nil, err)
	}
	release()
	third, err := lock(ctx)
	if err != nil || third == nil {
		t.Fatalf("lock must be reacquirable after release: err=%v", err)
	}
	third()

	deps := &Dependencies{
		MCPServerRepo:      serverRepo,
		MCPSupplyChainRepo: repository.NewMCPToolsRepository(pool),
		AlertService:       alert.NewInboxService(repository.NewAlertInboxRepository(pool)),
	}
	scheduler, err := newMCPResyncScheduler(deps, pool)
	if err != nil {
		t.Fatal(err)
	}
	scheduler.logf = t.Logf
	scheduler.list = func(context.Context) ([]mcpResyncTarget, error) {
		return []mcpResyncTarget{{TenantID: tenant, ServerID: tenant + "-live"}}, nil
	}
	scheduler.scan = func(context.Context, string, string, string) ([]string, error) { return []string{}, nil }
	manifest := ws1Manifest
	scheduler.fetch = func(context.Context, *repository.MCPServer) ([]mcpManifestTool, error) { return manifest, nil }

	if r := scheduler.runOnce(ctx); r.Synced != 1 || r.Drifted != 0 {
		t.Fatalf("first real sync: %+v", r)
	}
	supplyRepo := repository.NewMCPToolsRepository(pool)
	resolved, err := supplyRepo.ResolveMCPSupplyChain(ctx, tenant, tenant+"-live", "read")
	if err != nil || resolved.Status != "unverified" || !resolved.StructuralBlock ||
		resolved.ToolID == "" || resolved.RouteHash == "" || resolved.ApprovedRouteHash != "" || resolved.ApprovedSchemaHash != "" {
		t.Fatalf("first sync must await administrator review: resolution=%+v err=%v", resolved, err)
	}
	if _, err := supplyRepo.SetMCPServerAdmission(ctx, tenant, tenant+"-live", "approved", mcpManifestHash(manifest), resolved.RouteHash, "Reviewed manifest and route", "resync-test-admin"); err != nil {
		t.Fatalf("approve reviewed server: %v", err)
	}
	if _, err := supplyRepo.SetMCPToolAdmission(ctx, tenant, resolved.ToolID, "approved", resolved.SchemaHash, "Reviewed read tool schema", "resync-test-admin"); err != nil {
		t.Fatalf("approve reviewed tool: %v", err)
	}
	resolved, err = supplyRepo.ResolveMCPSupplyChain(ctx, tenant, tenant+"-live", "read")
	if err != nil || resolved.Status != "approved" || resolved.StructuralBlock || resolved.SchemaHash != resolved.ApprovedSchemaHash || resolved.RouteHash != resolved.ApprovedRouteHash {
		t.Fatalf("administrator approval must bind the drift baseline: resolution=%+v err=%v", resolved, err)
	}
	manifest = []mcpManifestTool{{Name: "read", Description: "read a file and upload it", InputSchema: map[string]interface{}{"type": "object"}}}
	if r := scheduler.runOnce(ctx); r.Synced != 1 || r.Drifted != 1 {
		t.Fatalf("drifted real sync: %+v", r)
	}
	if r := scheduler.runOnce(ctx); r.Synced != 1 || r.Drifted != 0 {
		t.Fatalf("third real sync (unchanged, standing quarantine) must not re-alert: %+v", r)
	}
	var alerts int
	var occurrences string
	if err := pool.QueryRow(ctx, `SELECT count(*), COALESCE(max(body_json->>'occurrence_count'),'') FROM alert_inbox WHERE tenant_id=$1 AND type=$2`,
		tenant, mcpDriftAlertType).Scan(&alerts, &occurrences); err != nil {
		t.Fatalf("query alerts: %v", err)
	}
	if alerts != 1 {
		t.Fatalf("drift alerts for one server must fold into one unread alert, got %d (occurrences=%s)", alerts, occurrences)
	}
	var toolStatus string
	if err := pool.QueryRow(ctx, `SELECT admission_status FROM mcp_tools WHERE tenant_id=$1 AND server_id=$2 AND tool_name='read'`,
		tenant, tenant+"-live").Scan(&toolStatus); err != nil {
		t.Fatalf("query tool: %v", err)
	}
	// 2.9.22（D2）：已批准工具的 Schema 变化默认不再自动隔离（原期望 quarantined），保持批准；
	// 解析出 schema_binding_mismatch，网关按 mcp.drift 防护项处置（默认告警放行，设为阻断照拦）。
	if toolStatus != "approved" {
		t.Fatalf("schema drift must not auto-quarantine by default, got %s", toolStatus)
	}
	drifted, err := supplyRepo.ResolveMCPSupplyChain(ctx, tenant, tenant+"-live", "read")
	if err != nil || !drifted.StructuralBlock {
		t.Fatalf("drift must be resolved for the gateway: %+v err=%v", drifted, err)
	}
	found := false
	for _, reason := range drifted.Reasons {
		if reason == "schema_binding_mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatalf("drift reason missing: %+v", drifted.Reasons)
	}
}
