package handler

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMCPAllowedDomainsUseTenantWhitelistOnPostgres(t *testing.T) {
	dsn := os.Getenv("MCP_ANALYSIS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("MCP_ANALYSIS_TEST_DATABASE_URL is required; run with disposable PostgreSQL")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	cleanup := func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM proxy_whitelist WHERE tenant_id IN ('mcp_analysis_a','mcp_analysis_b')`)
	}
	cleanup()
	t.Cleanup(cleanup)
	_, err = pool.Exec(ctx, `INSERT INTO proxy_whitelist(id,tenant_id,host_pattern,port) VALUES
		('pw_mcp_analysis_exact','mcp_analysis_a','api.approved.example',443),
		('pw_mcp_analysis_wild','mcp_analysis_a','*.approved-sub.example',443),
		('pw_mcp_analysis_other','mcp_analysis_b','other.example',443)`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		args map[string]any
		want []string
	}{
		{"exact host", map[string]any{"url": "https://api.approved.example/upload"}, []string{"api.approved.example"}},
		{"wildcard child", map[string]any{"url": "https://one.approved-sub.example/upload"}, []string{"one.approved-sub.example"}},
		{"wildcard apex excluded", map[string]any{"url": "https://approved-sub.example/upload"}, nil},
		{"port restricted", map[string]any{"url": "https://api.approved.example:8443/upload"}, nil},
		{"tenant isolation", map[string]any{"url": "https://other.example/upload"}, nil},
		{"mixed unlisted subdomain", map[string]any{"url": "https://api.approved.example/upload", "extra": "https://unlisted.api.approved.example/upload"}, nil},
		{"nested target", map[string]any{"request": map[string]any{"url": "https://api.approved.example/upload"}}, []string{"api.approved.example"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, gap := toolAllowedDomains(ctx, pool, "mcp_analysis_a", tt.args)
			if len(gap) != 0 || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("domains=%v want=%v gap=%v", got, tt.want, gap)
			}
		})
	}
}

func TestMCPAllowedDomainLookupMissingStoreRecordsGap(t *testing.T) {
	domains, evidence := toolAllowedDomains(context.Background(), nil, "tenant-a", map[string]any{"url": "https://outside.example/upload"})
	if len(domains) != 0 || len(evidence) != 1 || evidence[0].Category != "coverage_gap" {
		t.Fatalf("missing store silently created trusted domains: domains=%v evidence=%v", domains, evidence)
	}
}
