package repository

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setupQuotaTestDB opens a connection to the test database and creates a
// tenant + user fixture. Cleanup removes all created rows on test exit.
func setupQuotaTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		if os.Getenv("JJD_REQUIRE_QUOTA_DB_TESTS") == "1" {
			t.Fatal("CONTENT_LOGS_TEST_DATABASE_URL is required when JJD_REQUIRE_QUOTA_DB_TESTS=1")
		}
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func uniqSuffix(t *testing.T) string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// TestQuotaPolicyMultiScope exercises the multi-scope CreateOrUpdate + GetByScope path.
func TestQuotaPolicyMultiScope(t *testing.T) {
	pool := setupQuotaTestDB(t)
	repo := NewQuotaPolicyRepository(pool)
	ctx := context.Background()

	tenantID := "tenant_q_" + uniqSuffix(t)
	userID := "user_q_" + uniqSuffix(t)

	// Insert tenant fixture
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, $3, $4, TRUE)`,
		tenantID, tenantID, "enterprise", "active",
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	// Insert user fixture
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		userID, tenantID, userID, userID+"@test.com", "x", "admin", "active",
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM quota_policies WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	// --- tenant scope ---
	tenantTPM := int64(12_000)
	tnPolicy := &QuotaPolicy{
		ID: "qpol_tn_" + uniqSuffix(t), TenantID: tenantID, ScopeType: "tenant",
		EnforcementMode: "enforce", MonthlyBudgetLimit: 10000, TPMLimit: &tenantTPM, Status: "active",
	}
	if err := repo.CreateOrUpdate(ctx, tnPolicy); err != nil {
		t.Fatalf("create tenant-scope policy: %v", err)
	}

	got, err := repo.GetByScope(ctx, tenantID, "tenant", "", "", "", "")
	if err != nil {
		t.Fatalf("GetByScope tenant: %v", err)
	}
	if got == nil || got.MonthlyBudgetLimit != 10000 {
		t.Fatalf("tenant scope: expected MonthlyBudgetLimit=10000, got %+v", got)
	}
	if got.EnforcementMode != "enforce" {
		t.Errorf("tenant enforcement_mode: want enforce, got %s", got.EnforcementMode)
	}
	if got.TPMLimit == nil || *got.TPMLimit != 12_000 || got.TPMBlocked {
		t.Fatalf("tenant TPM round-trip: %+v", got)
	}

	// --- user scope ---
	usPolicy := &QuotaPolicy{
		ID: "qpol_us_" + uniqSuffix(t), TenantID: tenantID, ScopeType: "user", UserID: userID,
		EnforcementMode: "enforce", MonthlyTokenLimit: 100_000, TPMBlocked: true, Status: "active",
	}
	if err := repo.CreateOrUpdate(ctx, usPolicy); err != nil {
		t.Fatalf("create user-scope policy: %v", err)
	}

	got2, err := repo.GetByScope(ctx, tenantID, "user", "", "", userID, "")
	if err != nil {
		t.Fatalf("GetByScope user: %v", err)
	}
	if got2 == nil || got2.MonthlyTokenLimit != 100_000 {
		t.Fatalf("user scope: expected MonthlyTokenLimit=100000, got %+v", got2)
	}
	if got2.EnforcementMode != "enforce" {
		t.Errorf("user enforcement_mode: want enforce, got %s", got2.EnforcementMode)
	}
	if got2.UserID != userID {
		t.Errorf("user_id: want %s, got %s", userID, got2.UserID)
	}
	if !got2.TPMBlocked || got2.TPMLimit != nil {
		t.Fatalf("explicit TPM block round-trip: %+v", got2)
	}

	// --- DailyBudgetLimit round-trip ---
	budgPolicy := &QuotaPolicy{
		ID: "qpol_bd_" + uniqSuffix(t), TenantID: tenantID, ScopeType: "tenant",
		DailyBudgetLimit: 500.0, EnforcementMode: "soft", Status: "active",
	}
	if err := repo.CreateOrUpdate(ctx, budgPolicy); err != nil {
		t.Fatalf("create budget policy: %v", err)
	}
	// CreateOrUpdate should update the existing tenant-scope row
	got3, err := repo.GetByScope(ctx, tenantID, "tenant", "", "", "", "")
	if err != nil {
		t.Fatalf("GetByScope after budget update: %v", err)
	}
	if got3 == nil || got3.DailyBudgetLimit != 500.0 {
		t.Fatalf("daily_budget_limit: want 500.0, got %+v", got3)
	}
	if got3.TPMLimit != nil || got3.TPMBlocked {
		t.Fatalf("unset TPM must round-trip as inherited: %+v", got3)
	}

	// --- invalid scope_type ---
	_, err = repo.GetByScope(ctx, tenantID, "invalid_scope", "", "", "", "")
	if err == nil {
		t.Error("expected error for invalid scope_type, got nil")
	}

	// --- List includes new scopes ---
	list, err := repo.List(ctx, tenantID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) < 2 {
		t.Fatalf("List: expected >=2 policies, got %d", len(list))
	}
}

func TestQuotaPolicyGetByStableKeyIDFindsUniqueLegacyPrefix(t *testing.T) {
	pool := setupQuotaTestDB(t)
	repo := NewQuotaPolicyRepository(pool)
	ctx := context.Background()
	suffix := uniqSuffix(t)
	tenantID, projectID, keyID := "tenant_qk_"+suffix, "project_qk_"+suffix, "key_qk_"+suffix
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id,name,edition,status,is_test) VALUES ($1,$1,'enterprise','active',TRUE)`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id,tenant_id,name,status) VALUES ($1,$2,$1,'active')`, projectID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO internal_keys (id,tenant_id,project_id,key_hash,key_prefix,status) VALUES ($1,$2,$3,$1,'sk-legacy','active')`, keyID, tenantID, projectID); err != nil {
		t.Fatal(err)
	}
	legacyPolicyID := "qpol_qk_" + suffix
	if _, err := pool.Exec(ctx, `INSERT INTO quota_policies (id,tenant_id,scope_type,key_prefix,status) VALUES ($1,$2,'key','sk-legacy','active')`, legacyPolicyID, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM quota_policies WHERE tenant_id=$1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM internal_keys WHERE tenant_id=$1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
	})

	got, err := repo.GetByScope(ctx, tenantID, "key", "", "", "", keyID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.KeyPrefix != "sk-legacy" {
		t.Fatalf("stable key lookup did not resolve unique legacy row: %+v", got)
	}
	resolved, err := NewInternalKeyRepository(pool).GetUniqueByPrefix(ctx, tenantID, "sk-legacy")
	if err != nil || resolved == nil || resolved.ID != keyID {
		t.Fatalf("unique legacy prefix did not resolve to stable key: key=%+v err=%v", resolved, err)
	}

	incoming := &QuotaPolicy{
		TenantID: tenantID, ScopeType: "key", KeyID: keyID, KeyPrefix: "sk-legacy",
		MonthlyTokenLimit: 42, EnforcementMode: "enforce", Status: "active",
	}
	if err := repo.CreateOrUpdate(ctx, incoming); err != nil {
		t.Fatal(err)
	}
	if incoming.ID != legacyPolicyID {
		t.Fatalf("legacy row was not upgraded in place: id=%q want=%q", incoming.ID, legacyPolicyID)
	}
	var count int
	var persistedKeyID string
	if err := pool.QueryRow(ctx, `SELECT COUNT(*), COALESCE(MAX(key_id),'') FROM quota_policies WHERE tenant_id=$1 AND scope_type='key'`, tenantID).Scan(&count, &persistedKeyID); err != nil {
		t.Fatal(err)
	}
	if count != 1 || persistedKeyID != keyID {
		t.Fatalf("CreateOrUpdate duplicated key policy: count=%d key_id=%q", count, persistedKeyID)
	}
	siblingKeyID := "key_qk_sibling_" + suffix
	if _, err := pool.Exec(ctx, `INSERT INTO internal_keys (id,tenant_id,project_id,key_hash,key_prefix,status) VALUES ($1,$2,$3,$1,'sk-legacy','active')`, siblingKeyID, tenantID, projectID); err != nil {
		t.Fatal(err)
	}
	resolved, err = NewInternalKeyRepository(pool).GetUniqueByPrefix(ctx, tenantID, "sk-legacy")
	if err != nil || resolved != nil {
		t.Fatalf("ambiguous legacy prefix must look absent: key=%+v err=%v", resolved, err)
	}
}

func TestQuotaPolicyCreateOrUpdateStableKeyIsConcurrentAndIdempotent(t *testing.T) {
	pool := setupQuotaTestDB(t)
	repo := NewQuotaPolicyRepository(pool)
	ctx := context.Background()
	suffix := uniqSuffix(t)
	tenantID, projectID, keyID := "tenant_qc_"+suffix, "project_qc_"+suffix, "key_qc_"+suffix
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id,name,edition,status,is_test) VALUES ($1,$1,'enterprise','active',TRUE)`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id,tenant_id,name,status) VALUES ($1,$2,$1,'active')`, projectID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO internal_keys (id,tenant_id,project_id,key_hash,key_prefix,status) VALUES ($1,$2,$3,$1,'sk-concurrent','active')`, keyID, tenantID, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION quota_policy_concurrency_delay() RETURNS trigger AS $$
		BEGIN
			IF NEW.key_prefix = 'sk-concurrent' THEN
				PERFORM pg_sleep(0.2);
			END IF;
			RETURN NEW;
		END
		$$ LANGUAGE plpgsql;
		DROP TRIGGER IF EXISTS quota_policy_concurrency_delay_trigger ON quota_policies;
		CREATE TRIGGER quota_policy_concurrency_delay_trigger BEFORE INSERT ON quota_policies
		FOR EACH ROW EXECUTE FUNCTION quota_policy_concurrency_delay();
	`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS quota_policy_concurrency_delay_trigger ON quota_policies`)
		_, _ = pool.Exec(ctx, `DROP FUNCTION IF EXISTS quota_policy_concurrency_delay()`)
		_, _ = pool.Exec(ctx, `DELETE FROM quota_policies WHERE tenant_id=$1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM internal_keys WHERE tenant_id=$1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
	})

	policies := []*QuotaPolicy{
		{TenantID: tenantID, ScopeType: "key", KeyID: keyID, KeyPrefix: "sk-concurrent", MonthlyTokenLimit: 10, Status: "active"},
		{TenantID: tenantID, ScopeType: "key", KeyID: keyID, KeyPrefix: "sk-concurrent", MonthlyTokenLimit: 20, Status: "active"},
	}
	start := make(chan struct{})
	errCh := make(chan error, len(policies))
	var wg sync.WaitGroup
	for _, policy := range policies {
		wg.Add(1)
		go func(policy *QuotaPolicy) {
			defer wg.Done()
			<-start
			errCh <- repo.CreateOrUpdate(ctx, policy)
		}(policy)
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent CreateOrUpdate failed: %v", err)
		}
	}
	if policies[0].ID == "" || policies[0].ID != policies[1].ID {
		t.Fatalf("concurrent calls did not converge on one policy: %q %q", policies[0].ID, policies[1].ID)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM quota_policies WHERE tenant_id=$1 AND key_id=$2`, tenantID, keyID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("stable key policy count=%d, want 1", count)
	}
}

func TestQuotaPolicyCreateOrUpdateDoesNotChooseAmbiguousLegacyPolicy(t *testing.T) {
	pool := setupQuotaTestDB(t)
	repo := NewQuotaPolicyRepository(pool)
	ctx := context.Background()
	suffix := uniqSuffix(t)
	tenantID, projectID, keyID := "tenant_qa_"+suffix, "project_qa_"+suffix, "key_qa_"+suffix
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id,name,edition,status,is_test) VALUES ($1,$1,'enterprise','active',TRUE)`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id,tenant_id,name,status) VALUES ($1,$2,$1,'active')`, projectID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO internal_keys (id,tenant_id,project_id,key_hash,key_prefix,status) VALUES ($1,$2,$3,$1,'sk-ambig-pol','active')`, keyID, tenantID, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO quota_policies (id,tenant_id,scope_type,key_prefix,status) VALUES ($1,$3,'key','sk-ambig-pol','active'),($2,$3,'key','sk-ambig-pol','active')`, "qpol_a_"+suffix, "qpol_b_"+suffix, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM quota_policies WHERE tenant_id=$1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM internal_keys WHERE tenant_id=$1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
	})

	incoming := &QuotaPolicy{TenantID: tenantID, ScopeType: "key", KeyID: keyID, KeyPrefix: "sk-ambig-pol", MonthlyTokenLimit: 30, Status: "active"}
	if err := repo.CreateOrUpdate(ctx, incoming); err != nil {
		t.Fatal(err)
	}
	var legacyCount, stableCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FILTER (WHERE key_id IS NULL), COUNT(*) FILTER (WHERE key_id=$2) FROM quota_policies WHERE tenant_id=$1 AND scope_type='key'`, tenantID, keyID).Scan(&legacyCount, &stableCount); err != nil {
		t.Fatal(err)
	}
	if legacyCount != 2 || stableCount != 1 {
		t.Fatalf("ambiguous legacy rows were modified: legacy=%d stable=%d", legacyCount, stableCount)
	}
}

func TestQuotaPolicyCreateOrUpdateRejectsMismatchedStableKeyIdentity(t *testing.T) {
	pool := setupQuotaTestDB(t)
	repo := NewQuotaPolicyRepository(pool)
	ctx := context.Background()
	suffix := uniqSuffix(t)
	tenantA, tenantB := "tenant_qta_"+suffix, "tenant_qtb_"+suffix
	projectB, keyB := "project_qtb_"+suffix, "key_qtb_"+suffix
	for _, tenantID := range []string{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id,name,edition,status,is_test) VALUES ($1,$1,'enterprise','active',TRUE)`, tenantID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id,tenant_id,name,status) VALUES ($1,$2,$1,'active')`, projectB, tenantB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO internal_keys (id,tenant_id,project_id,key_hash,key_prefix,status) VALUES ($1,$2,$3,$1,'sk-tenant-b','active')`, keyB, tenantB, projectB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM quota_policies WHERE tenant_id IN ($1,$2)`, tenantA, tenantB)
		_, _ = pool.Exec(ctx, `DELETE FROM internal_keys WHERE tenant_id=$1`, tenantB)
		_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE tenant_id=$1`, tenantB)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenantA, tenantB)
	})

	err := repo.CreateOrUpdate(ctx, &QuotaPolicy{TenantID: tenantA, ScopeType: "key", KeyID: keyB, KeyPrefix: "sk-tenant-b", Status: "active"})
	if err == nil {
		t.Fatal("cross-tenant stable key identity unexpectedly accepted")
	}
	err = repo.CreateOrUpdate(ctx, &QuotaPolicy{TenantID: tenantB, ScopeType: "key", KeyID: keyB, KeyPrefix: "sk-wrong", Status: "active"})
	if err == nil {
		t.Fatal("mismatched stable key prefix unexpectedly accepted")
	}
}
