package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setupMCPToolAssetTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("MCP_TOOL_ASSET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("MCP_TOOL_ASSET_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	schema := fmt.Sprintf("mcp_asset_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect schema: %v", err)
	}
	_, err = db.Exec(ctx, `
		CREATE TABLE mcp_tools (
			id text PRIMARY KEY, server_id text NOT NULL, tenant_id text NOT NULL,
			tool_name text NOT NULL, schema_hash text NOT NULL DEFAULT '', removed boolean NOT NULL DEFAULT false
		);
		CREATE TABLE mcp_policies (
			id text PRIMARY KEY, tenant_id text NOT NULL, scope_type text NOT NULL,
			scope_ref text NOT NULL DEFAULT '', server_id text NOT NULL DEFAULT '',
			tool_pattern text NOT NULL DEFAULT '', mode text NOT NULL DEFAULT 'audit',
			default_action text NOT NULL DEFAULT 'audit', priority integer NOT NULL DEFAULT 0,
			enabled boolean NOT NULL DEFAULT true, note text NOT NULL DEFAULT '',
			created_by text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			target_kind text NOT NULL DEFAULT 'tool',
			arg_conditions jsonb NOT NULL DEFAULT '[]'::jsonb
		);
		INSERT INTO mcp_tools (id, server_id, tenant_id, tool_name, schema_hash, removed) VALUES
			('mcpt-known','server-1','tenant-a','known.tool','hash-known',false),
			('mcpt-no-policy','server-1','tenant-a','no.policy','hash-no-policy',false),
			('mcpt-removed','server-1','tenant-a','removed.tool','hash-removed',true);
		INSERT INTO mcp_policies (id, tenant_id, scope_type, scope_ref, server_id, tool_pattern, mode, default_action, priority, enabled)
		VALUES ('mcppol-known','tenant-a','tenant','tenant-a','server-1','known.tool','strict','allow',10,true);
	`)
	if err != nil {
		t.Fatalf("seed schema: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	return db
}

// mcpStubSupplyChainRepo resolves the effective tool asset through the active MCP
// tool catalog so the effective-policy endpoint returns the same tool_id the data
// plane uses for tenant-scoped asset lookup. It is a minimal in-test double of the
// production MCPSupplyChainRepo, sufficient for the effective-policy contract test.
type mcpStubSupplyChainRepo struct {
	tools *repository.MCPToolsRepository
}

func (s *mcpStubSupplyChainRepo) ResolveMCPSupplyChain(ctx context.Context, tenantID, serverID, toolName string) (repository.MCPSupplyChainResolution, error) {
	id, err := s.tools.FindActiveToolID(ctx, tenantID, serverID, toolName)
	if err != nil {
		return repository.MCPSupplyChainResolution{}, err
	}
	return repository.MCPSupplyChainResolution{
		ToolID:       id,
		Status:       "approved",
		ServerStatus: "approved",
		ToolStatus:   "approved",
	}, nil
}

func (s *mcpStubSupplyChainRepo) ApplySupplyChainSync(context.Context, repository.MCPSupplyChainSyncInput) (*repository.MCPSupplyChainSyncResult, error) {
	return nil, nil
}

func (s *mcpStubSupplyChainRepo) SetMCPServerAdmission(context.Context, string, string, string, string, string, string, string) (*repository.MCPAdmissionMutation, error) {
	return nil, nil
}

func (s *mcpStubSupplyChainRepo) SetMCPToolAdmission(context.Context, string, string, string, string, string, string) (*repository.MCPAdmissionMutation, error) {
	return nil, nil
}

func TestInternalMCPEffectivePolicyReturnsTenantScopedToolAsset(t *testing.T) {
	db := setupMCPToolAssetTestDB(t)
	toolRepo := repository.NewMCPToolsRepository(db)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		tenant string
		tool   string
		want   string
	}{
		"active":       {tenant: "tenant-a", tool: "known.tool", want: "mcpt-known"},
		"unknown":      {tenant: "tenant-a", tool: "unknown.tool", want: ""},
		"removed":      {tenant: "tenant-a", tool: "removed.tool", want: ""},
		"cross-tenant": {tenant: "tenant-b", tool: "known.tool", want: ""},
	} {
		got, err := toolRepo.FindActiveToolID(ctx, tc.tenant, "server-1", tc.tool)
		if err != nil || got != tc.want {
			t.Fatalf("%s FindActiveToolID=(%q,%v), want %q", name, got, err, tc.want)
		}
	}
	deps := &Dependencies{
		MCPToolRepo:        toolRepo,
		MCPPolicyRepo:      repository.NewMCPPoliciesRepository(db),
		MCPSupplyChainRepo: &mcpStubSupplyChainRepo{tools: toolRepo},
	}
	call := func(tenantID, toolName string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/mcp/effective-policy?server_id=server-1&tool_name="+toolName, nil)
		req.Header.Set("X-Tenant-ID", tenantID)
		rr := httptest.NewRecorder()
		GetInternalMCPEffectivePolicy(deps)(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("tenant=%s tool=%s status=%d body=%s", tenantID, toolName, rr.Code, rr.Body.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		return payload
	}

	known := call("tenant-a", "known.tool")
	if known["matched"] != true || known["tool_id"] != "mcpt-known" {
		t.Fatalf("known tool response=%#v", known)
	}
	miss := call("tenant-a", "no.policy")
	if miss["matched"] != false || miss["tool_id"] != "mcpt-no-policy" {
		t.Fatalf("policy miss response=%#v", miss)
	}
	for name, payload := range map[string]map[string]any{
		"unknown":      call("tenant-a", "unknown.tool"),
		"removed":      call("tenant-a", "removed.tool"),
		"cross-tenant": call("tenant-b", "known.tool"),
	} {
		if payload["tool_id"] != "" {
			t.Fatalf("%s leaked tool id: %#v", name, payload)
		}
	}
}
