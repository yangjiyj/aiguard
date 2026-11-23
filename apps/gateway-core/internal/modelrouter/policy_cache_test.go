package modelrouter

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPolicyCacheWithDB tests GetPolicy against a real database.
// Skipped unless CONTENT_LOGS_TEST_DATABASE_URL is set.
func TestPolicyCacheWithDB(t *testing.T) {
	dbURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set; skipping DB test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect to DB: %v", err)
	}
	defer pool.Close()

	// Insert a test routing policy
	tenantID := fmt.Sprintf("test-tenant-%d", time.Now().UnixNano())
	scopeRef := fmt.Sprintf("test-project-%d", time.Now().UnixNano())
	if _, err = pool.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $1, 'enterprise', 'active', TRUE)`, tenantID); err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO routing_policies (id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled)
		VALUES (gen_random_uuid(), $1, 'project', $2, 'model', 'conditional',
		        '{"default_model":"gpt-4","rules":[]}'::jsonb, true)
	`, tenantID, scopeRef)
	if err != nil {
		t.Fatalf("insert test policy: %v", err)
	}

	// Cleanup
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM routing_policies WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	cache := NewPolicyCache(pool, time.Minute)

	// First call: DB hit
	policy, err := cache.GetPolicy(ctx, tenantID, "project", scopeRef, "model")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if policy == nil {
		t.Fatal("expected policy, got nil")
	}
	if policy.Strategy != "conditional" {
		t.Errorf("strategy: expected conditional, got %s", policy.Strategy)
	}
	if policy.Config["default_model"] != "gpt-4" {
		t.Errorf("config default_model: expected gpt-4, got %v", policy.Config["default_model"])
	}

	// Second call: cache hit (same result, no DB query)
	policy2, err := cache.GetPolicy(ctx, tenantID, "project", scopeRef, "model")
	if err != nil {
		t.Fatalf("GetPolicy (cache): %v", err)
	}
	if policy2 == nil {
		t.Fatal("expected cached policy, got nil")
	}
	if policy2.Strategy != "conditional" {
		t.Errorf("cached strategy: expected conditional, got %s", policy2.Strategy)
	}
}

// TestPolicyCacheMiss verifies that GetPolicy returns nil (fail-open) when no policy exists.
func TestPolicyCacheMiss(t *testing.T) {
	dbURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set; skipping DB test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect to DB: %v", err)
	}
	defer pool.Close()

	cache := NewPolicyCache(pool, time.Minute)

	// No policy for this tenant
	policy, err := cache.GetPolicy(ctx, "no-such-tenant", "project", "no-such-project", "model")
	if err != nil {
		t.Fatalf("GetPolicy on miss: %v", err)
	}
	if policy != nil {
		t.Errorf("expected nil on miss, got %+v", policy)
	}
}

// TestPolicyCacheBuildOnly ensures the package compiles even without DB env.
func TestPolicyCacheBuildOnly(t *testing.T) {
	// This test just ensures all types and functions compile.
	_ = NewPolicyCache(nil, time.Minute)
}
