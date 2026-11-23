package repository

import (
	"context"
	"os"
	"testing"
)

func TestQuotaPolicyRepositoryCanonicalRoundTrip(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	const schemaSQL = "CREATE TABLE internal_keys (" +
		"id varchar(64) PRIMARY KEY, tenant_id varchar(64) NOT NULL, key_prefix varchar(64), agent_instance_id varchar(128));" +
		"CREATE TABLE quota_policies (" +
		"id varchar(64) PRIMARY KEY, tenant_id varchar(64) NOT NULL REFERENCES tenants(id), " +
		"project_id varchar(64), scope_type varchar(32) NOT NULL, scope_ref varchar(64), " +
		"user_id varchar(64), key_id varchar(64), key_prefix varchar(64), " +
		"daily_token_limit bigint, monthly_token_limit bigint, " +
		"daily_budget_limit numeric, monthly_budget_limit numeric, " +
		"rpm_limit integer, tpm_limit bigint, tpm_blocked boolean NOT NULL DEFAULT false, " +
		"concurrency_limit integer, overage_action varchar(32) NOT NULL DEFAULT 'notify', " +
		"enforcement_mode varchar(16) NOT NULL DEFAULT 'soft', " +
		"downgrade_model varchar(128) NOT NULL DEFAULT '', " +
		"status varchar(32) NOT NULL DEFAULT 'active', created_at timestamptz NOT NULL DEFAULT now());"
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../../../deploy/migrations/827_quota_policy_money_micros.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("apply migration 827: %v", err)
	}
	if _, err := db.Exec(ctx, "INSERT INTO tenants(id) VALUES('tenant-quota-canonical')"); err != nil {
		t.Fatal(err)
	}

	repo := NewQuotaPolicyRepository(db)
	policy := &QuotaPolicy{
		ID:                         "quota-canonical",
		TenantID:                   "tenant-quota-canonical",
		ScopeType:                  "tenant",
		DailyTokenCanonical:        true,
		MonthlyTokenCanonical:      true,
		MonthlyTokenLimitCanonical: quotaMicros(0),
		DailyBudgetCanonical:       true,
		DailyBudgetBlocked:         true,
		MonthlyBudgetCanonical:     true,
		MonthlyBudgetMicros:        quotaMicros(1_234_567),
		RPMCanonical:               true,
		RPMLimitCanonical:          quotaInt(50),
		ConcurrencyCanonical:       true,
		ConcurrencyBlocked:         true,
		TPMLimit:                   quotaMicros(900),
		OverageAction:              "notify",
		EnforcementMode:            "enforce",
		QuotaTimezone:              "UTC",
		QuotaTimezoneCanonical:     true,
		Status:                     "active",
	}
	if err := repo.CreateOrUpdate(ctx, policy); err != nil {
		t.Fatalf("insert canonical policy: %v", err)
	}
	got, err := repo.GetByScope(ctx, policy.TenantID, "tenant", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("inserted policy not found")
	}
	if got.DailyTokenLimitCanonical != nil || got.DailyTokenLimit != 0 {
		t.Fatalf("daily token inherit mismatch: %+v", got)
	}
	assertQuotaMicros(t, got.MonthlyTokenLimitCanonical, quotaMicros(0))
	if !got.DailyBudgetBlocked || got.DailyBudgetMicros != nil || got.DailyBudgetLimit != 0 {
		t.Fatalf("daily amount block mismatch: %+v", got)
	}
	assertQuotaMicros(t, got.MonthlyBudgetMicros, quotaMicros(1_234_567))
	if got.RPMLimitCanonical == nil || *got.RPMLimitCanonical != 50 || got.RPMLimit != 50 {
		t.Fatalf("RPM mismatch: %+v", got)
	}
	if !got.ConcurrencyBlocked || got.ConcurrencyLimitCanonical != nil || got.ConcurrencyLimit != 0 {
		t.Fatalf("concurrency block mismatch: %+v", got)
	}
	if got.QuotaTimezone != "UTC" {
		t.Fatalf("metadata mismatch: %+v", got)
	}

	policy.DailyTokenLimitCanonical = quotaMicros(25)
	policy.MonthlyTokenLimitCanonical = nil
	policy.MonthlyTokenBlocked = true
	policy.DailyBudgetMicros = nil
	policy.DailyBudgetBlocked = false
	policy.MonthlyBudgetMicros = quotaMicros(0)
	policy.RPMLimitCanonical = nil
	policy.ConcurrencyLimitCanonical = quotaInt(2)
	policy.ConcurrencyBlocked = false
	policy.OverageAction = "notify"
	policy.QuotaTimezone = ""
	policy.QuotaTimezoneCanonical = false
	if err := repo.CreateOrUpdate(ctx, policy); err != nil {
		t.Fatalf("update canonical policy: %v", err)
	}
	updated, err := repo.GetByScope(ctx, policy.TenantID, "tenant", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	assertQuotaMicros(t, updated.DailyTokenLimitCanonical, quotaMicros(25))
	if !updated.MonthlyTokenBlocked || updated.MonthlyTokenLimitCanonical != nil {
		t.Fatalf("monthly token block mismatch: %+v", updated)
	}
	if updated.DailyBudgetMicros != nil || updated.DailyBudgetBlocked {
		t.Fatalf("daily amount inherit mismatch: %+v", updated)
	}
	assertQuotaMicros(t, updated.MonthlyBudgetMicros, quotaMicros(0))
	if updated.RPMLimitCanonical != nil || updated.RPMLimit != 0 {
		t.Fatalf("RPM inherit mismatch: %+v", updated)
	}
	if updated.ConcurrencyLimitCanonical == nil || *updated.ConcurrencyLimitCanonical != 2 ||
		updated.ConcurrencyLimit != 2 {
		t.Fatalf("concurrency mismatch: %+v", updated)
	}
	if updated.QuotaTimezone != "UTC" {
		t.Fatalf("updated metadata mismatch: %+v", updated)
	}
}
