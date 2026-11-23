package providers

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/jackc/pgx/v5/pgxpool"
)

func quotaInt64(value int64) *int64 { return &value }

func TestComputeScopedQuotasPreservesPolicyScopeAndAction(t *testing.T) {
	policies := []rawPolicy{
		{scopeType: "tenant", monthlyTokenLimit: 1_000_000, tpmLimit: quotaInt64(12_000), enforcementMode: "enforce", overageAction: "rate_limit"},
		{scopeType: "user", monthlyTokenLimit: 10_000, dailyBudgetMicros: 25_000_000, enforcementMode: "soft", overageAction: "notify", quotaTimezone: "UTC"},
	}
	got := computeScopedQuotas(policies, governor.ScopeRef{TenantID: "tenant-1", UserID: "user-1"})

	if len(got) != 2 {
		t.Fatalf("scoped quotas = %d, want 2", len(got))
	}
	if got[0].Key() != "tenant:tenant-1" || got[0].Limits.MonthlyTokenLimit != 1_000_000 || got[0].EnforcementMode != "enforce" {
		t.Fatalf("unexpected tenant quota: %+v", got[0])
	}
	if !got[0].Limits.TPMConfigured || got[0].Limits.TPMLimit != 12_000 {
		t.Fatalf("tenant TPM limit = %d, want 12000", got[0].Limits.TPMLimit)
	}
	if got[1].Key() != "user:user-1" || got[1].Limits.MonthlyTokenLimit != 10_000 || got[1].Limits.DailyBudgetMicros != 25_000_000 || got[1].Limits.QuotaTimezone != "UTC" {
		t.Fatalf("unexpected user quota: %+v", got[1])
	}
}

func TestComputeScopedQuotasKeepsApplicationTeamAncestorsDistinct(t *testing.T) {
	got := computeScopedQuotas([]rawPolicy{
		{scopeType: "team", scopeRef: "team-root", enforcementMode: "enforce", dailyTokenLimit: 100},
		{scopeType: "team", scopeRef: "team-child", enforcementMode: "accounting"},
	}, governor.ScopeRef{TenantID: "tenant-1", TeamID: "team-child"})
	if len(got) != 2 || got[0].Key() != "team:team-root" || got[1].Key() != "team:team-child" || got[1].EnforcementMode != "accounting" {
		t.Fatalf("team ancestor scopes collapsed: %+v", got)
	}
}

func TestComputeScopedQuotasCarriesCanonicalBlockedAndMoneyState(t *testing.T) {
	got := computeScopedQuotas([]rawPolicy{{
		scopeType: "tenant", enforcementMode: "enforce", quotaTimezone: "Europe/London",
		dailyTokenBlocked: true, monthlyTokenBlocked: true,
		monthlyBudgetMicros: 456,
		dailyBudgetBlocked:  true,
		rpmBlocked:          true, tpmBlocked: true, concurrencyBlocked: true,
	}}, governor.ScopeRef{TenantID: "tenant-1"})
	if len(got) != 1 {
		t.Fatalf("scoped quotas=%+v", got)
	}
	limits := got[0].Limits
	if !limits.DailyTokenBlocked || !limits.MonthlyTokenBlocked ||
		!limits.DailyBudgetBlocked || limits.MonthlyBudgetBlocked ||
		!limits.RPMBlocked || !limits.TPMBlocked || !limits.ConcurrencyBlocked ||
		limits.DailyBudgetMicros != 0 || limits.MonthlyBudgetMicros != 456 ||
		limits.QuotaTimezone != "Europe/London" {
		t.Fatalf("canonical quota state lost: %+v", limits)
	}
}

func TestQuotaCacheLoadsApplicationTeamAncestorsTenantSafely(t *testing.T) {
	dsn := os.Getenv("KEY_QUOTA_BOOTSTRAP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("quota PostgreSQL test service is not configured")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	suffix := time.Now().Format("150405.000000000")
	tenantID := "tenant_ancestor_" + suffix
	rootID := "team_root_" + suffix
	childID := "team_child_" + suffix
	projectID := "project_ancestor_" + suffix
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id,name,edition,status,is_test) VALUES ($1,$1,'enterprise','active',TRUE)`, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM quota_policies WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM teams WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
	})
	if _, err := db.Exec(ctx, `INSERT INTO teams (id,tenant_id,name,parent_team_id,path) VALUES
		($1::varchar,$3::varchar,'root',NULL,('/'||$1::varchar)::varchar),
		($2::varchar,$3::varchar,'child',$1::varchar,('/'||$1::varchar||'/'||$2::varchar)::varchar)`, rootID, childID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id,tenant_id,name,status,team_id) VALUES ($1,$2,'ancestor-project','active',$3)`, projectID, tenantID, childID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO quota_policies (id,tenant_id,scope_type,scope_ref,daily_token_limit,overage_action,enforcement_mode,status)
		VALUES ($1,$2,'team',$3,100,'rate_limit','enforce','active')`, "qpol_ancestor_"+suffix, tenantID, rootID); err != nil {
		t.Fatal(err)
	}
	got, err := NewQuotaCache(db, time.Minute).ScopedQuotas(ctx, governor.ScopeRef{TenantID: tenantID, TeamID: childID, ProjectID: projectID})
	if err != nil {
		t.Fatal(err)
	}
	byKey := make(map[string]governor.ScopedQuota, len(got))
	for _, quota := range got {
		byKey[quota.Key()] = quota
	}
	if byKey["team:"+rootID].Limits.DailyTokenLimit != 100 || byKey["team:"+rootID].EnforcementMode != "enforce" {
		t.Fatalf("parent policy missing: %+v", got)
	}
	if byKey["team:"+childID].EnforcementMode != "accounting" {
		t.Fatalf("direct team accounting scope missing: %+v", got)
	}
}

func TestQuotaCacheQueryIgnoresAmbiguousLegacyPolicies(t *testing.T) {
	dsn := os.Getenv("KEY_QUOTA_BOOTSTRAP_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("JJD_REQUIRE_KEY_QUOTA_BOOTSTRAP_TESTS") == "1" {
			t.Fatal("PostgreSQL test URL is required")
		}
		t.Skip("key quota PostgreSQL test service is not configured")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	suffix := time.Now().Format("150405.000000000")
	tenantID, projectID, keyID := "tenant_gw_"+suffix, "project_gw_"+suffix, "key_gw_"+suffix
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id,name,edition,status,is_test) VALUES ($1,$1,'enterprise','active',TRUE)`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id,tenant_id,name,status) VALUES ($1,$2,$1,'active')`, projectID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO internal_keys (id,tenant_id,project_id,key_hash,key_prefix,status) VALUES ($1,$2,$3,$1,'sk-ambiguous','active')`, keyID, tenantID, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO quota_policies (id,tenant_id,scope_type,key_prefix,status) VALUES ($1,$3,'key','sk-ambiguous','active'),($2,$3,'key','sk-ambiguous','active')`, "qpol_gwa_"+suffix, "qpol_gwb_"+suffix, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM quota_policies WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM internal_keys WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
	})

	ref := governor.ScopeRef{TenantID: tenantID, ProjectID: projectID, KeyID: keyID}
	got, err := NewQuotaCache(db, time.Minute).ScopedQuotas(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, quota := range got {
		if quota.Scope == "key" {
			t.Fatalf("legacy key policy unexpectedly matched at runtime: %+v", quota)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO quota_policies (id,tenant_id,scope_type,key_id,key_prefix,status) VALUES ($1,$2,'key',$3,'sk-ambiguous','active')`, "qpol_gws_"+suffix, tenantID, keyID); err != nil {
		t.Fatal(err)
	}
	got, err = NewQuotaCache(db, time.Minute).ScopedQuotas(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	keyPolicies := 0
	for _, quota := range got {
		if quota.Scope == "key" {
			keyPolicies++
			if quota.ID != keyID {
				t.Fatalf("stable key policy used wrong bucket: %+v", quota)
			}
		}
	}
	if keyPolicies != 1 {
		t.Fatalf("stable key policy count=%d, want 1; quotas=%+v", keyPolicies, got)
	}
}

func TestComputeScopedQuotasSkipsMissingIdentityDimension(t *testing.T) {
	got := computeScopedQuotas(
		[]rawPolicy{{scopeType: "user", monthlyTokenLimit: 10}},
		governor.ScopeRef{TenantID: "tenant-1"},
	)
	if len(got) != 0 {
		t.Fatalf("untrusted or absent user identity must not create a user quota bucket: %+v", got)
	}
}

func TestComputeScopedQuotasUsesStableKeyAndIgnoresLegacyRows(t *testing.T) {
	ref := governor.ScopeRef{TenantID: "tenant-1", KeyID: "key-id-1"}
	stable := computeScopedQuotas([]rawPolicy{{scopeType: "key", keyID: "key-id-1", monthlyTokenLimit: 10}}, ref)
	if len(stable) != 1 || stable[0].Key() != "key:key-id-1" {
		t.Fatalf("stable policy paired with wrong bucket: %+v", stable)
	}
	legacy := computeScopedQuotas([]rawPolicy{{scopeType: "key", monthlyTokenLimit: 10}}, ref)
	if len(legacy) != 0 {
		t.Fatalf("legacy policy must remain inert until cleanup: %+v", legacy)
	}
}
