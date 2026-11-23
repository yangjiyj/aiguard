package repository

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupRoutingPoliciesTestDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()

	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}

	// Create a unique test tenant.
	tenantID := "tenant_rp_test_" + rpRandomSuffix()
	_, err = db.Exec(ctx, `
		INSERT INTO tenants (id, name, edition, status, is_test)
		VALUES ($1, $1, 'cloud', 'active', TRUE)
	`, tenantID)
	if err != nil {
		db.Close()
		t.Fatalf("create tenant: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx := context.Background()
		_, _ = db.Exec(cleanupCtx, `DELETE FROM routing_policies WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(cleanupCtx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})

	return db, tenantID
}

func TestRoutingPolicyRepository_UpsertAndList(t *testing.T) {
	db, tenantID := setupRoutingPoliciesTestDB(t)
	ctx := context.Background()
	repo := NewRoutingPolicyRepository(db)

	p := &RoutingPolicy{
		ID:        "rp_" + rpRandomSuffix(),
		TenantID:  tenantID,
		ScopeType: "model",
		ScopeRef:  "gpt-4",
		Layer:     "model",
		Strategy:  "prompt_aware",
		ConfigJSON: map[string]any{
			"low_threshold":  0.3,
			"high_threshold": 0.7,
		},
		Enabled: true,
	}

	if err := repo.Upsert(ctx, p); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := repo.ListByScope(ctx, tenantID, "model", "gpt-4")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(got))
	}
	if got[0].Strategy != "prompt_aware" {
		t.Errorf("strategy mismatch: got %s", got[0].Strategy)
	}
}

func TestRoutingPolicyRepository_TestTenantIsHidden(t *testing.T) {
	db, tenantID := setupRoutingPoliciesTestDB(t)
	ctx := context.Background()

	var isTest bool
	if err := db.QueryRow(ctx, `SELECT is_test FROM tenants WHERE id = $1`, tenantID).Scan(&isTest); err != nil {
		t.Fatalf("query is_test: %v", err)
	}
	if !isTest {
		t.Fatal("routing policy repository test tenant should be marked is_test")
	}
}

func TestRoutingPolicyRepository_GetByID(t *testing.T) {
	db, tenantID := setupRoutingPoliciesTestDB(t)
	ctx := context.Background()
	repo := NewRoutingPolicyRepository(db)

	p := &RoutingPolicy{
		ID:        "rp_" + rpRandomSuffix(),
		TenantID:  tenantID,
		ScopeType: "project",
		ScopeRef:  "proj_abc",
		Layer:     "provider",
		Strategy:  "lb",
		ConfigJSON: map[string]any{
			"weighted_providers": []any{
				map[string]any{"id": "prov1", "weight": 80},
				map[string]any{"id": "prov2", "weight": 20},
			},
		},
		Enabled: true,
	}

	if err := repo.Upsert(ctx, p); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := repo.GetByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil policy")
	}
	if got.Layer != "provider" {
		t.Errorf("layer mismatch: got %s", got.Layer)
	}
}

func TestRoutingPolicyRepository_Delete(t *testing.T) {
	db, tenantID := setupRoutingPoliciesTestDB(t)
	ctx := context.Background()
	repo := NewRoutingPolicyRepository(db)

	p := &RoutingPolicy{
		ID:        "rp_" + rpRandomSuffix(),
		TenantID:  tenantID,
		ScopeType: "model",
		ScopeRef:  "claude-3",
		Layer:     "model",
		Strategy:  "single",
		Enabled:   true,
	}

	if err := repo.Upsert(ctx, p); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := repo.Delete(ctx, p.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	got, err := repo.GetByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if got != nil {
		t.Error("expected nil after delete")
	}
}

func TestRoutingPolicyRepository_UpsertUpdate(t *testing.T) {
	db, tenantID := setupRoutingPoliciesTestDB(t)
	ctx := context.Background()
	repo := NewRoutingPolicyRepository(db)

	id := "rp_" + rpRandomSuffix()
	p := &RoutingPolicy{
		ID:        id,
		TenantID:  tenantID,
		ScopeType: "tenant",
		ScopeRef:  tenantID,
		Layer:     "model",
		Strategy:  "conditional",
		Enabled:   true,
	}

	if err := repo.Upsert(ctx, p); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	// Update strategy
	p.Strategy = "prompt_aware"
	p.Enabled = false
	if err := repo.Upsert(ctx, p); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	got, err := repo.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Strategy != "prompt_aware" {
		t.Errorf("strategy not updated: got %s", got.Strategy)
	}
	if got.Enabled {
		t.Error("enabled should be false after update")
	}
}

// rpRandomSuffix returns a short random hex string.
func rpRandomSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
