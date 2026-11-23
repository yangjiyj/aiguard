package org

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// setupServiceTestDB opens a pool to the test database.
func setupServiceTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func svcSuffix() string { return fmt.Sprintf("%d", time.Now().UnixNano()) }

// TestEffectiveQuotaFunnel verifies that EffectiveQuota picks the minimum
// MonthlyTokenLimit across tenant / team / project scopes.
//
// Setup:
//   tenant  → 10 000 000
//   team_a  →  1 000 000   (root)
//   team_b  →    500 000   (child of team_a)
//   project →    300 000
//
// Expected: MonthlyTokenLimit = 300 000, TriggeredScope = "project"
func TestEffectiveQuotaFunnel(t *testing.T) {
	pool := setupServiceTestDB(t)
	ctx := context.Background()

	sfx := svcSuffix()
	tenantID  := "ten_svc_" + sfx
	teamAID   := "tea_a_" + sfx
	teamBID   := "tea_b_" + sfx
	projectID := "proj_" + sfx

	// --- fixtures ---
	mustExec(t, pool, ctx,
		`INSERT INTO tenants (id, name, edition, status) VALUES ($1, $2, $3, $4)`,
		tenantID, tenantID, "enterprise", "active")

	teamRepo   := repository.NewTeamRepository(pool)
	memberRepo := repository.NewTeamMemberRepository(pool)
	quotaRepo  := repository.NewQuotaPolicyRepository(pool)

	teamA := &repository.Team{ID: teamAID, TenantID: tenantID, Name: "研发部"}
	if err := teamRepo.Create(ctx, teamA, ""); err != nil {
		t.Fatalf("create team_a: %v", err)
	}
	teamB := &repository.Team{ID: teamBID, TenantID: tenantID, Name: "后端组", ParentTeamID: teamAID}
	if err := teamRepo.Create(ctx, teamB, teamA.Path); err != nil {
		t.Fatalf("create team_b: %v", err)
	}

	mustExec(t, pool, ctx,
		`INSERT INTO projects (id, tenant_id, name, status) VALUES ($1, $2, $3, $4)`,
		projectID, tenantID, "proj-"+sfx, "active")

	// cleanup
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM quota_policies WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM teams WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	// --- quota policies ---
	mustCreateQuota(t, quotaRepo, ctx, &repository.QuotaPolicy{
		ID: "qp_tn_" + sfx, TenantID: tenantID, ScopeType: "tenant",
		MonthlyTokenLimit: 10_000_000, EnforcementMode: "soft", Status: "active",
	})
	mustCreateQuota(t, quotaRepo, ctx, &repository.QuotaPolicy{
		ID: "qp_ta_" + sfx, TenantID: tenantID, ScopeType: "team", ScopeRef: teamAID,
		MonthlyTokenLimit: 1_000_000, EnforcementMode: "soft", Status: "active",
	})
	mustCreateQuota(t, quotaRepo, ctx, &repository.QuotaPolicy{
		ID: "qp_tb_" + sfx, TenantID: tenantID, ScopeType: "team", ScopeRef: teamBID,
		MonthlyTokenLimit: 500_000, EnforcementMode: "soft", Status: "active",
	})
	mustCreateQuota(t, quotaRepo, ctx, &repository.QuotaPolicy{
		ID: "qp_pr_" + sfx, TenantID: tenantID, ScopeType: "project", ProjectID: projectID,
		MonthlyTokenLimit: 300_000, EnforcementMode: "enforce", Status: "active",
	})

	svc := NewService(teamRepo, memberRepo, quotaRepo)

	eq, err := svc.EffectiveQuota(ctx, ScopeRef{
		TenantID:  tenantID,
		TeamID:    teamBID,
		ProjectID: projectID,
	})
	if err != nil {
		t.Fatalf("EffectiveQuota error: %v", err)
	}
	if eq.MonthlyTokenLimit != 300_000 {
		t.Errorf("MonthlyTokenLimit: want 300000, got %d", eq.MonthlyTokenLimit)
	}
	if eq.TriggeredScope != "project" {
		t.Errorf("TriggeredScope: want project, got %s", eq.TriggeredScope)
	}
}

// TestEffectiveQuotaNoPolicy verifies empty result when no policies exist.
func TestEffectiveQuotaNoPolicy(t *testing.T) {
	pool := setupServiceTestDB(t)
	ctx := context.Background()

	sfx       := svcSuffix()
	tenantID  := "ten_empty_" + sfx

	mustExec(t, pool, ctx,
		`INSERT INTO tenants (id, name, edition, status) VALUES ($1, $2, $3, $4)`,
		tenantID, tenantID, "enterprise", "active")
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	svc := NewService(
		repository.NewTeamRepository(pool),
		repository.NewTeamMemberRepository(pool),
		repository.NewQuotaPolicyRepository(pool),
	)

	eq, err := svc.EffectiveQuota(ctx, ScopeRef{TenantID: tenantID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eq.MonthlyTokenLimit != 0 || eq.TriggeredScope != "" {
		t.Errorf("expected empty EffectiveQuota, got %+v", eq)
	}
}

// TestValidateTeamDepth checks depth enforcement.
func TestValidateTeamDepth(t *testing.T) {
	svc := &Service{}
	cases := []struct {
		path    string
		wantErr bool
	}{
		{"", false},
		{"/a", false},
		{"/a/b/c/d/e", false},   // depth 5, OK
		{"/a/b/c/d/e/f", true},  // depth 6, error
	}
	for _, c := range cases {
		err := svc.ValidateTeamDepth(c.path)
		if (err != nil) != c.wantErr {
			t.Errorf("path=%q wantErr=%v got err=%v", c.path, c.wantErr, err)
		}
	}
}

// --- helpers ---

func mustExec(t *testing.T, pool *pgxpool.Pool, ctx context.Context, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(ctx, query, args...); err != nil {
		t.Fatalf("mustExec %q: %v", query, err)
	}
}

func mustCreateQuota(t *testing.T, repo *repository.QuotaPolicyRepository, ctx context.Context, p *repository.QuotaPolicy) {
	t.Helper()
	if err := repo.CreateOrUpdate(ctx, p); err != nil {
		t.Fatalf("CreateOrUpdate %+v: %v", p, err)
	}
}
