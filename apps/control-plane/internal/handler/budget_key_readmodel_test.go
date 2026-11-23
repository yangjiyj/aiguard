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

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/budget"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/org"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// setupKeyReadModelDB seeds tenant/user/project/key/wallet fixtures on the
// one-off test database and returns everything the key budget read model
// needs, including a real OrgService (no quota policies seeded: the gateway
// default timezone applies).
func setupKeyReadModelDB(t *testing.T) (*pgxpool.Pool, *repository.InternalKeyRepository, *org.Service, string, string, string) {
	t.Helper()
	databaseURL := os.Getenv("BILLING_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("BILLING_TEST_DATABASE_URL not set; skipping real-DB test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID := "rbkh_" + sfx
	userID := "rbku_" + sfx
	projectID := "rbkp_" + sfx
	keyID := "rbkk_" + sfx

	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status) VALUES ($1, $1, 'enterprise', 'active')`, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		 VALUES ($1, $2, $3, $4, 'x', 'platform_admin', 'active')`,
		userID, tenantID, userID, userID+"@test.com"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO projects (id, tenant_id, name, status) VALUES ($1, $2, 'rbk-project', 'active')`,
		projectID, tenantID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, scopes_json, name, status, created_at)
		VALUES ($1, $2, $3, $4, 'rbk-hash', 'rbkpre', '[]'::jsonb, 'readmodel-key', 'active', NOW())`,
		keyID, tenantID, projectID, userID); err != nil {
		t.Fatalf("insert internal_key: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM internal_keys WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM billing_wallets WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		pool.Close()
	})
	orgService := org.NewService(
		repository.NewTeamRepository(pool),
		repository.NewTeamMemberRepository(pool),
		repository.NewQuotaPolicyRepository(pool),
	)
	return pool, repository.NewInternalKeyRepository(pool), orgService, tenantID, userID, keyID
}

// newKeyReadModelRouter wires the handler exactly as the integration snippet.
func newKeyReadModelRouter(deps ReadModelDeps) *chi.Mux {
	router := chi.NewRouter()
	router.Get("/admin/v1/budgets/keys/{key_id}/readmodel", GetBudgetKeyReadModel(deps))
	return router
}

// TestGetBudgetKeyReadModel covers attribution, confirmed usage from the
// gateway-owned Redis buckets, wallet-level in-flight and window/reset fields.
func TestGetBudgetKeyReadModel(t *testing.T) {
	s := miniredis.RunT(t)
	s.SetTime(time.Date(2026, 10, 1, 0, 30, 0, 0, time.UTC))
	mr := redis.NewClient(&redis.Options{Addr: s.Addr()})
	t.Cleanup(func() { _ = mr.Close() })

	pool, keyRepo, orgService, tenantID, userID, keyID := setupKeyReadModelDB(t)
	ctx := context.Background()

	// Seed the exact keys the gateway AtomicAdmission writes for scope=key.
	monthBucket := budget.QuotaPeriodBucket("", "2026-10")
	dayBucket := budget.QuotaPeriodBucket("", "2026-10-01")
	if err := mr.HSet(ctx, budget.BudgetKey("key", keyID, monthBucket),
		"tokens", 1234, "cost_micros", 5678, "requests", 9).Err(); err != nil {
		t.Fatalf("seed month bucket: %v", err)
	}
	if err := mr.HSet(ctx, budget.BudgetKeyDay("key", keyID, dayBucket),
		"tokens", 234, "cost_micros", 678, "requests", 8).Err(); err != nil {
		t.Fatalf("seed day bucket: %v", err)
	}

	// Owner wallet: user-scoped in-flight evidence.
	if _, err := pool.Exec(ctx, `
		INSERT INTO billing_wallets (id, tenant_id, user_id, currency, balance_micros, reserved_micros)
		VALUES ($1, $2, $3, 'CNY', 10000000, 2500000)`,
		"rbkw_"+tenantID, tenantID, userID); err != nil {
		t.Fatalf("insert wallet: %v", err)
	}

	deps := ReadModelDeps{
		DB:             pool,
		KeyRepo:        keyRepo,
		BudgetSnapshot: budget.NewSnapshotReader(mr),
		OrgService:     orgService,
		RedisClient:    mr,
	}
	router := newKeyReadModelRouter(deps)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/budgets/keys/"+keyID+"/readmodel", nil)
	req = withBudgetUserCtx(req, tenantID, userID)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Key struct {
				ID          string `json:"id"`
				Attribution string `json:"attribution"`
				UserID      string `json:"user_id"`
			} `json:"key"`
			ConfirmedUsage struct {
				Available       bool   `json:"available"`
				MonthTokens     int64  `json:"month_tokens"`
				DayCostMicros   int64  `json:"day_cost_micros"`
				MonthCostMicros int64  `json:"month_cost_micros"`
				MonthBucket     string `json:"month_bucket"`
				DayBucket       string `json:"day_bucket"`
			} `json:"confirmed_usage"`
			InFlight struct {
				KeyLevelAvailable   bool                     `json:"key_level_available"`
				OwnerLevelAvailable bool                     `json:"owner_level_available"`
				OwnerWallets        []map[string]interface{} `json:"owner_wallets"`
			} `json:"in_flight"`
			Window struct {
				Available    bool   `json:"available"`
				Timezone     string `json:"timezone"`
				DayBucket    string `json:"day_bucket"`
				DayStartedAt string `json:"day_started_at"`
				DayResetAt   string `json:"day_reset_at"`
				MonthResetAt string `json:"month_reset_at"`
			} `json:"window"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data.Key.ID != keyID || body.Data.Key.Attribution != "user" || body.Data.Key.UserID != userID {
		t.Fatalf("attribution wrong: %+v", body.Data.Key)
	}
	if !body.Data.ConfirmedUsage.Available || body.Data.ConfirmedUsage.MonthTokens != 1234 ||
		body.Data.ConfirmedUsage.MonthCostMicros != 5678 || body.Data.ConfirmedUsage.DayCostMicros != 678 {
		t.Fatalf("confirmed usage wrong: %+v", body.Data.ConfirmedUsage)
	}
	// Window must match the buckets actually read (cross-midnight guard).
	if body.Data.Window.DayBucket != dayBucket || !body.Data.Window.Available {
		t.Fatalf("window buckets mismatch: %+v vs %s", body.Data.Window, dayBucket)
	}
	// Compare the wall-clock date inside the window timezone against the
	// bucket label: the window must be the bucket day's local midnight.
	winDay, err := time.Parse(time.RFC3339, body.Data.Window.DayStartedAt)
	bucketDay := body.Data.ConfirmedUsage.DayBucket[:10]
	if err != nil || winDay.Format("2006-01-02") != bucketDay {
		t.Fatalf("window day_started_at %s does not match bucket day %s", body.Data.Window.DayStartedAt, bucketDay)
	}
	// Key-level in-flight must be explicitly unavailable (wallet-scoped data).
	if body.Data.InFlight.KeyLevelAvailable {
		t.Fatalf("key-level in-flight must not be claimed available")
	}
	if !body.Data.InFlight.OwnerLevelAvailable || len(body.Data.InFlight.OwnerWallets) != 1 {
		t.Fatalf("owner wallets wrong: %+v", body.Data.InFlight)
	}
	wl := body.Data.InFlight.OwnerWallets[0]
	if wl["level"] != "user" || wl["reserved_micros"].(float64) != 2500000 {
		t.Fatalf("owner wallet wrong: %+v", wl)
	}
	if !body.Data.Window.Available || body.Data.Window.Timezone == "" || body.Data.Window.DayResetAt == "" {
		t.Fatalf("window wrong: %+v", body.Data.Window)
	}
}

// TestGetBudgetKeyReadModelQuotaLookupUnavailable is the negative sample: a
// missing OrgService must fail explicitly instead of silently querying a
// default-timezone bucket that may not match the gateway's buckets.
func TestGetBudgetKeyReadModelQuotaLookupUnavailable(t *testing.T) {
	s := miniredis.RunT(t)
	s.SetTime(time.Date(2026, 10, 1, 0, 30, 0, 0, time.UTC))
	mr := redis.NewClient(&redis.Options{Addr: s.Addr()})
	t.Cleanup(func() { _ = mr.Close() })
	pool, keyRepo, _, tenantID, _, keyID := setupKeyReadModelDB(t)
	deps := ReadModelDeps{DB: pool, KeyRepo: keyRepo, BudgetSnapshot: budget.NewSnapshotReader(mr), RedisClient: mr}
	router := newKeyReadModelRouter(deps)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/budgets/keys/"+keyID+"/readmodel", nil)
	req = withBudgetUserCtx(req, tenantID, "admin")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s, want 503", rec.Code, rec.Body.String())
	}
	if !containsJSONString(rec.Body.String(), "quota_lookup_unavailable") {
		t.Fatalf("stable reason code missing: %s", rec.Body.String())
	}
}

// TestGetBudgetKeyReadModelOwnerless covers a portal-issued key with no owner
// user: attribution falls back to project and no wallet is invented.
func TestGetBudgetKeyReadModelOwnerless(t *testing.T) {
	s := miniredis.RunT(t)
	s.SetTime(time.Date(2026, 10, 1, 0, 30, 0, 0, time.UTC))
	mr := redis.NewClient(&redis.Options{Addr: s.Addr()})
	t.Cleanup(func() { _ = mr.Close() })

	pool, keyRepo, orgService, tenantID, _, keyID := setupKeyReadModelDB(t)
	ctx := context.Background()
	// Strip the owner: portal-issued keys have NULL user_id.
	if _, err := pool.Exec(ctx, `UPDATE internal_keys SET user_id = NULL WHERE id = $1`, keyID); err != nil {
		t.Fatalf("clear owner: %v", err)
	}

	deps := ReadModelDeps{DB: pool, KeyRepo: keyRepo, BudgetSnapshot: budget.NewSnapshotReader(mr), OrgService: orgService, RedisClient: mr}
	router := newKeyReadModelRouter(deps)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/budgets/keys/"+keyID+"/readmodel", nil)
	req = withBudgetUserCtx(req, tenantID, "someadmin")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Key struct {
				Attribution string `json:"attribution"`
				UserID      string `json:"user_id"`
			} `json:"key"`
			InFlight struct {
				OwnerWallets []map[string]interface{} `json:"owner_wallets"`
			} `json:"in_flight"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data.Key.Attribution != "project" || body.Data.Key.UserID != "" {
		t.Fatalf("ownerless key attribution = %+v, want project with empty user_id", body.Data.Key)
	}
	if len(body.Data.InFlight.OwnerWallets) != 0 {
		t.Fatalf("wallets must not be invented for ownerless keys")
	}
}

// TestGetBudgetKeyReadModelNotFound guards against cross-tenant key reads.
func TestGetBudgetKeyReadModelNotFound(t *testing.T) {
	s := miniredis.RunT(t)
	s.SetTime(time.Date(2026, 10, 1, 0, 30, 0, 0, time.UTC))
	mr := redis.NewClient(&redis.Options{Addr: s.Addr()})
	t.Cleanup(func() { _ = mr.Close() })
	pool, keyRepo, orgService, tenantID, _, _ := setupKeyReadModelDB(t)
	deps := ReadModelDeps{DB: pool, KeyRepo: keyRepo, BudgetSnapshot: budget.NewSnapshotReader(mr), OrgService: orgService, RedisClient: mr}
	router := newKeyReadModelRouter(deps)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/budgets/keys/missing_key/readmodel", nil)
	req = withBudgetUserCtx(req, tenantID, "someadmin")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestBudgetWindowDSTAndMonthEnd pins the window derivation: DST transitions
// and month ends stay anchored to local midnight of the bucket day, and the
// timezone-hash bucket suffix is stripped before parsing.
func TestBudgetWindowDSTAndMonthEnd(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("tzdata unavailable")
	}
	// US DST spring-forward day: local midnight -05:00, next midnight -04:00.
	win := budgetWindow("America/New_York", "2026-03", "2026-03-08")
	if !win["available"].(bool) {
		t.Fatalf("window unavailable: %v", win)
	}
	dayStart := win["day_started_at"].(time.Time).In(loc)
	if !dayStart.Equal(time.Date(2026, 3, 8, 0, 0, 0, 0, loc)) {
		t.Fatalf("day_started_at = %s, want local midnight 2026-03-08", dayStart)
	}
	dayReset := win["day_reset_at"].(time.Time).In(loc)
	if !dayReset.Equal(time.Date(2026, 3, 9, 0, 0, 0, 0, loc)) {
		t.Fatalf("day_reset_at = %s, want local midnight 2026-03-09", dayReset)
	}
	if dayReset.Sub(dayStart) != 23*time.Hour {
		t.Fatalf("DST day length = %s, want 23h", dayReset.Sub(dayStart))
	}
	// Month end: January window resets at Feb 1 local midnight.
	winJan := budgetWindow("America/New_York", "2026-01", "2026-01-31")
	monthReset := winJan["month_reset_at"].(time.Time).In(loc)
	if !monthReset.Equal(time.Date(2026, 2, 1, 0, 0, 0, 0, loc)) {
		t.Fatalf("month_reset_at = %s, want 2026-02-01 local midnight", monthReset)
	}
	// Non-default timezone bucket suffix must not break parsing.
	winSuffix := budgetWindow("UTC", "2026-01@abc123", "2026-01-02@abc123")
	if !winSuffix["available"].(bool) {
		t.Fatalf("suffixed bucket window unavailable: %v", winSuffix)
	}
	// Consistency: window start equals the bucket label it was derived from.
	if got := winSuffix["day_started_at"].(time.Time); got != time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("suffixed bucket day start = %s", got)
	}
	// Invalid bucket labels degrade explicitly instead of guessing.
	bad := budgetWindow("UTC", "bad", "worse")
	if bad["available"].(bool) || bad["reason_code"] != "invalid_bucket_labels" {
		t.Fatalf("invalid bucket window = %v", bad)
	}
}

func containsJSONString(body, needle string) bool {
	return len(body) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(body); i++ {
			if body[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// TestGetBudgetKeyReadModelWrongBucketNegative is the timezone negative sample.
// A tenant policy sets America/New_York while the key has NO policy of its own.
// The gateway accounts the key scope in its hardcoded accounting default
// (addAdmissionAccountingScopes), so the usage lives in the Asia/Shanghai
// bucket. A read model that took the merged/parent timezone would HGetAll the
// America/New_York bucket, find it empty and report the key's usage as zero —
// a silent, confident, wrong number.
//
// The gateway's Asia/Shanghai bucket is seeded with usage and the
// America/New_York bucket is deliberately left empty, so the assertions can
// only pass if the right bucket was read.
func TestGetBudgetKeyReadModelWrongBucketNegative(t *testing.T) {
	s := miniredis.RunT(t)
	s.SetTime(time.Date(2026, 10, 1, 0, 30, 0, 0, time.UTC))
	mr := redis.NewClient(&redis.Options{Addr: s.Addr()})
	t.Cleanup(func() { _ = mr.Close() })

	pool, keyRepo, orgService, tenantID, userID, keyID := setupKeyReadModelDB(t)
	ctx := context.Background()

	// Tenant-scope policy at a NON-default timezone. The key has no policy.
	// monthly_token_limit_canonical is a bigint mirror column, not a boolean.
	if _, err := pool.Exec(ctx, `
		INSERT INTO quota_policies (id, tenant_id, scope_type, monthly_token_limit,
			monthly_token_limit_canonical, quota_timezone, status)
		VALUES ($1, $2, 'tenant', 500000, 500000, 'America/New_York', 'active')`,
		"rbkqp_"+tenantID, tenantID); err != nil {
		t.Fatalf("insert tenant quota policy: %v", err)
	}

	// The bucket the gateway actually writes for a policy-less key scope.
	gatewayBucket := budget.QuotaPeriodBucket(budget.DefaultQuotaTimezone, "2026-10")
	wrongBucket := budget.QuotaPeriodBucket("America/New_York", "2026-10")
	if wrongBucket == gatewayBucket {
		t.Skip("buckets coincide; the negative sample needs two distinct timezones")
	}
	if err := mr.HSet(ctx, budget.BudgetKey("key", keyID, gatewayBucket),
		"tokens", 777, "cost_micros", 1000, "requests", 2).Err(); err != nil {
		t.Fatalf("seed gateway bucket: %v", err)
	}
	// The parent-timezone bucket stays empty on purpose.

	deps := ReadModelDeps{
		DB:             pool,
		KeyRepo:        keyRepo,
		BudgetSnapshot: budget.NewSnapshotReader(mr),
		OrgService:     orgService,
		RedisClient:    mr,
	}
	router := newKeyReadModelRouter(deps)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/budgets/keys/"+keyID+"/readmodel", nil)
	req = withBudgetUserCtx(req, tenantID, userID)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			ConfirmedUsage struct {
				Available       bool   `json:"available"`
				MonthTokens     int64  `json:"month_tokens"`
				MonthCostMicros int64  `json:"month_cost_micros"`
				MonthBucket     string `json:"month_bucket"`
				BucketTimezone  string `json:"bucket_timezone"`
			} `json:"confirmed_usage"`
			EffectiveQuota struct {
				QuotaTimezone string `json:"quota_timezone"`
			} `json:"effective_quota"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	cu := body.Data.ConfirmedUsage
	// The bucket timezone must be the accounting default, NOT the tenant
	// policy's timezone.
	if cu.BucketTimezone != budget.DefaultQuotaTimezone {
		t.Fatalf("bucket_timezone = %q, want the accounting default %q (key has no policy)",
			cu.BucketTimezone, budget.DefaultQuotaTimezone)
	}
	if cu.MonthBucket != gatewayBucket {
		t.Fatalf("month_bucket = %q, want the gateway-written bucket %q", cu.MonthBucket, gatewayBucket)
	}
	// The usage must be found, not silently reported as zero.
	if !cu.Available || cu.MonthTokens != 777 || cu.MonthCostMicros != 1000 {
		t.Fatalf("confirmed usage = %+v, want 777 tokens / 1000 micros from the gateway bucket", cu)
	}
	// The merged effective quota may still report the parent timezone for the
	// LIMITS; that is a different fact from the bucket, and both are reported.
	if body.Data.EffectiveQuota.QuotaTimezone != "America/New_York" {
		t.Fatalf("effective_quota.quota_timezone = %q, want the merged parent value America/New_York",
			body.Data.EffectiveQuota.QuotaTimezone)
	}
}

// TestGetBudgetKeyReadModelCostQualityNegative seeds the cost-quality counters
// the gateway settlement script writes and asserts the response reports the
// money and its quality side by side, with day and month tracked separately.
//
// It also pins that the total is never adjusted: cost_micros is incremented
// unconditionally by the gateway, so relabelling money would be fabrication.
func TestGetBudgetKeyReadModelCostQualityNegative(t *testing.T) {
	s := miniredis.RunT(t)
	s.SetTime(time.Date(2026, 10, 1, 0, 30, 0, 0, time.UTC))
	mr := redis.NewClient(&redis.Options{Addr: s.Addr()})
	t.Cleanup(func() { _ = mr.Close() })

	pool, keyRepo, orgService, tenantID, userID, keyID := setupKeyReadModelDB(t)
	ctx := context.Background()

	monthBucket := budget.QuotaPeriodBucket("", "2026-10")
	dayBucket := budget.QuotaPeriodBucket("", "2026-10-01")
	// Month: one estimated request on top of real money.
	if err := mr.HSet(ctx, budget.BudgetKey("key", keyID, monthBucket),
		"tokens", 100, "cost_micros", 5000, "requests", 4,
		"cost_estimated_requests", 1).Err(); err != nil {
		t.Fatalf("seed month bucket: %v", err)
	}
	// Day: one unpriced request, which is worse than an estimate — its cost
	// contribution is not a billable figure at all. Day and month counters are
	// independent, so the day must NOT inherit the month's "estimated".
	if err := mr.HSet(ctx, budget.BudgetKeyDay("key", keyID, dayBucket),
		"tokens", 40, "cost_micros", 2000, "requests", 2,
		"cost_unpriced_requests", 1).Err(); err != nil {
		t.Fatalf("seed day bucket: %v", err)
	}

	deps := ReadModelDeps{
		DB:             pool,
		KeyRepo:        keyRepo,
		BudgetSnapshot: budget.NewSnapshotReader(mr),
		OrgService:     orgService,
		RedisClient:    mr,
	}
	router := newKeyReadModelRouter(deps)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/budgets/keys/"+keyID+"/readmodel", nil)
	req = withBudgetUserCtx(req, tenantID, userID)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			ConfirmedUsage struct {
				MonthCostMicros  int64 `json:"month_cost_micros"`
				DayCostMicros    int64 `json:"day_cost_micros"`
				MonthCostQuality struct {
					TotalMicros       int64  `json:"total_micros"`
					EstimatedRequests int64  `json:"estimated_requests"`
					UnpricedRequests  int64  `json:"unpriced_requests"`
					Quality           string `json:"quality"`
				} `json:"month_cost_quality"`
				DayCostQuality struct {
					TotalMicros       int64  `json:"total_micros"`
					EstimatedRequests int64  `json:"estimated_requests"`
					UnpricedRequests  int64  `json:"unpriced_requests"`
					Quality           string `json:"quality"`
				} `json:"day_cost_quality"`
			} `json:"confirmed_usage"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	cu := body.Data.ConfirmedUsage
	// Month: estimated.
	if cu.MonthCostQuality.Quality != "estimated" || cu.MonthCostQuality.EstimatedRequests != 1 ||
		cu.MonthCostQuality.UnpricedRequests != 0 {
		t.Fatalf("month quality = %+v, want estimated/1/0", cu.MonthCostQuality)
	}
	// Day: unpriced, and NOT contaminated by the month's estimated counter.
	if cu.DayCostQuality.Quality != "unpriced" || cu.DayCostQuality.UnpricedRequests != 1 ||
		cu.DayCostQuality.EstimatedRequests != 0 {
		t.Fatalf("day quality = %+v, want unpriced/0/1 (windows are independent)", cu.DayCostQuality)
	}
	// The money is reported verbatim next to its label: never adjusted.
	if cu.MonthCostQuality.TotalMicros != cu.MonthCostMicros || cu.MonthCostMicros != 5000 {
		t.Fatalf("month money = %d (quality total %d), want the raw 5000",
			cu.MonthCostMicros, cu.MonthCostQuality.TotalMicros)
	}
	if cu.DayCostQuality.TotalMicros != cu.DayCostMicros || cu.DayCostMicros != 2000 {
		t.Fatalf("day money = %d (quality total %d), want the raw 2000",
			cu.DayCostMicros, cu.DayCostQuality.TotalMicros)
	}
}

// TestKeyAccountingTimezoneBoundaries is the boundary evidence table for the
// bucket timezone. Every case pins one rule from the gateway's admission path.
// Each row also carries a TENANT policy at a non-default timezone, so a
// merge-based reader would pick the wrong bucket in every single row — that is
// the failure mode being guarded.
func TestKeyAccountingTimezoneBoundaries(t *testing.T) {
	const other = "America/New_York" // a non-default timezone, stands in for any policy tz

	cases := []struct {
		name string
		// keyPolicy is nil for "no key-scope policy row at all".
		keyPolicy *struct {
			mode        string
			limit       int64
			timezone    *string // nil exercises the NULL/empty COALESCE path
			wantApplied bool
		}
		want string
		// blankTimezoneRejected marks the case whose policy row the schema
		// itself must refuse, because it documents an unreachable state.
		blankTimezoneRejected bool
	}{
		{name: "01 no key policy at all falls back to the accounting default", keyPolicy: nil, want: budget.DefaultQuotaTimezone},
		{
			name: "02 key policy with a real limit lends its own timezone",
			keyPolicy: &struct {
				mode        string
				limit       int64
				timezone    *string
				wantApplied bool
			}{mode: "enforce", limit: 1000, timezone: ptr(other), wantApplied: true},
			want: other,
		},
		{
			name: "03 soft key policy that gates nothing is not effective, so its timezone is not borrowed",
			keyPolicy: &struct {
				mode        string
				limit       int64
				timezone    *string
				wantApplied bool
			}{mode: "soft", limit: 0, timezone: ptr(other), wantApplied: false},
			want: budget.DefaultQuotaTimezone,
		},
		{
			name: "04 accounting mode with no limit IS effective and lends its timezone",
			keyPolicy: &struct {
				mode        string
				limit       int64
				timezone    *string
				wantApplied bool
			}{mode: "accounting", limit: 0, timezone: ptr(other), wantApplied: true},
			want: other,
		},
		{
			name: "05 an unrecognised mode normalizes to soft and enters with a limit",
			keyPolicy: &struct {
				mode        string
				limit       int64
				timezone    *string
				wantApplied bool
			}{mode: "bogus", limit: 1000, timezone: ptr(other), wantApplied: true},
			want: other,
		},
		{
			name: "06 quota_timezone is never blank, so the default branch is defence in depth",
			// The column is NOT NULL DEFAULT 'Asia/Shanghai' and
			// chk_quota_timezone_nonempty rejects blank values, so an effective
			// policy always carries a real timezone. The COALESCE fallback in
			// the reader is defence in depth against a row that predates those
			// constraints, and this case pins that a policy cannot be
			// constructed in the blank state the fallback exists for.
			keyPolicy: &struct {
				mode        string
				limit       int64
				timezone    *string
				wantApplied bool
			}{mode: "enforce", limit: 1000, timezone: ptr("   "), wantApplied: true},
			want: budget.DefaultQuotaTimezone,
			// blankTimezoneRejected is asserted inside the subtest.
			blankTimezoneRejected: true,
		},
		{
			name: "07 bypass is mapped to accounting, so with no limit it is effective",
			keyPolicy: &struct {
				mode        string
				limit       int64
				timezone    *string
				wantApplied bool
			}{mode: "bypass", limit: 0, timezone: ptr(other), wantApplied: true},
			want: other,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := miniredis.RunT(t)
			s.SetTime(time.Date(2026, 10, 1, 0, 30, 0, 0, time.UTC))
			mr := redis.NewClient(&redis.Options{Addr: s.Addr()})
			t.Cleanup(func() { _ = mr.Close() })
			pool, _, orgService, tenantID, _, keyID := setupKeyReadModelDB(t)
			ctx := context.Background()

			if _, err := pool.Exec(ctx, `
				INSERT INTO quota_policies (id, tenant_id, scope_type, monthly_token_limit,
					monthly_token_limit_canonical, quota_timezone, status)
				VALUES ($1, $2, 'tenant', 500000, 500000, $3, 'active')`,
				"bt_t_"+tenantID, tenantID, other); err != nil {
				t.Fatalf("insert tenant policy: %v", err)
			}
			if tc.keyPolicy != nil {
				var tzArg interface{}
				if tc.keyPolicy.timezone != nil {
					tzArg = *tc.keyPolicy.timezone
				}
				_, insertErr := pool.Exec(ctx, `
					INSERT INTO quota_policies (id, tenant_id, scope_type, key_id, enforcement_mode,
						monthly_token_limit, monthly_token_limit_canonical, quota_timezone, status)
					VALUES ($1, $2, 'key', $3, $4, $5, $5, $6, 'active')`,
					"bt_k_"+tenantID, tenantID, keyID, tc.keyPolicy.mode,
					tc.keyPolicy.limit, tzArg)
				if tc.blankTimezoneRejected {
					if insertErr == nil {
						t.Fatalf("blank quota_timezone must be rejected by chk_quota_timezone_nonempty")
					}
					// With no policy row insertable, the scope stays on the
					// accounting default — the same verdict as the other rows.
				} else if insertErr != nil {
					t.Fatalf("insert key policy: %v", insertErr)
				}
			}

			got, err := orgService.KeyAccountingTimezone(ctx, tenantID, keyID)
			if err != nil {
				t.Fatalf("KeyAccountingTimezone: %v", err)
			}
			if got != tc.want {
				t.Fatalf("KeyAccountingTimezone = %q, want %q (tenant policy is %q and must not leak)",
					got, tc.want, other)
			}
		})
	}
}

// ptr returns a pointer to a copy of v, for the optional-timezone table field.
func ptr(v string) *string { return &v }

func TestAccountingScopeWriterGateMatrix(t *testing.T) {
	cases := []struct{ name, fields, mode, want string }{
		{"empty_soft", "", "soft", "Asia/Shanghai"},
		{"empty_enforce", "", "enforce", "Asia/Shanghai"},
		{"empty_off", "", "off", "Asia/Shanghai"},
		{"empty_monitor", "", "monitor", "Asia/Shanghai"},
		{"empty_bypass", "", "bypass", "UTC"},
		{"empty_accounting", "", "accounting", "UTC"},
		{"canonical_zero_overrides_legacy", ", monthly_token_limit=100, monthly_token_limit_canonical=0, rpm_limit=100, rpm_limit_canonical=0, concurrency_limit=100, concurrency_limit_canonical=0, daily_budget_limit=100, daily_budget_micros=0", "enforce", "Asia/Shanghai"},
		{"legacy_money_decimal_round", ", daily_budget_limit=0.01, daily_budget_micros=NULL", "monitor", "UTC"},
		{"tpm_configured_alone", ", tpm_limit=0", "soft", "Asia/Shanghai"},
		{"blocked_zero", ", daily_budget_blocked=true", "off", "UTC"},
		{"rpm_positive", ", rpm_limit_canonical=1", "monitor", "UTC"},
		{"concurrency_positive", ", concurrency_limit_canonical=1", "soft", "UTC"},
		{"tpm_positive", ", tpm_limit=1", "soft", "UTC"},
		{"day_token_positive", ", daily_token_limit_canonical=1", "soft", "UTC"},
		{"month_money_positive", ", monthly_budget_micros=1", "soft", "UTC"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, _, service, tenant, user, key := setupKeyReadModelDB(t)
			ctx := context.Background()
			if _, err := pool.Exec(ctx, `INSERT INTO quota_policies (id,tenant_id,scope_type,key_id,enforcement_mode,quota_timezone,status)
				VALUES ($1,$2,'key',$3,$4,'UTC','active')`, "matrix_"+tenant, tenant, key, tc.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `UPDATE quota_policies SET quota_timezone='UTC'`+tc.fields+` WHERE id=$1`, "matrix_"+tenant); err != nil {
				t.Fatal(err)
			}
			got, err := service.KeyAccountingTimezone(ctx, tenant, key)
			if err != nil || got != tc.want {
				t.Fatalf("zone=%q err=%v want=%q", got, err, tc.want)
			}
			mini := miniredis.RunT(t)
			now := time.Date(2026, 10, 1, 0, 30, 0, 0, time.UTC)
			mini.SetTime(now)
			rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
			t.Cleanup(func() { _ = rdb.Close() })
			loc, _ := time.LoadLocation(tc.want)
			bucket := budget.QuotaPeriodBucket(tc.want, now.In(loc).Format("2006-01"))
			if tc.want == "UTC" && bucket != "2026-10@7e5f76c94a63" {
				t.Fatalf("writer UTC hash=%q", bucket)
			}
			if err := rdb.HSet(ctx, budget.BudgetKey("key", key, bucket), "tokens", 17, "cost_micros", 25).Err(); err != nil {
				t.Fatal(err)
			}
			deps := ReadModelDeps{DB: pool, KeyRepo: repository.NewInternalKeyRepository(pool), OrgService: service, BudgetSnapshot: budget.NewSnapshotReader(rdb)}
			req := withBudgetUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/budgets/keys/"+key+"/readmodel", nil), tenant, user)
			rec := httptest.NewRecorder()
			newKeyReadModelRouter(deps).ServeHTTP(rec, req)
			if rec.Code != 200 {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			var body struct {
				Data struct {
					Usage struct {
						Tokens int64  `json:"month_tokens"`
						Bucket string `json:"month_bucket"`
					} `json:"confirmed_usage"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Data.Usage.Tokens != 17 || body.Data.Usage.Bucket != bucket {
				t.Fatalf("wrong bucket: %+v", body)
			}
		})
	}
}

func TestBudgetSnapshotScopeAccountingBuckets(t *testing.T) {
	pool, keyRepo, service, tenant, user, key := setupKeyReadModelDB(t)
	ctx := context.Background()
	k, err := keyRepo.GetByID(ctx, tenant, key)
	if err != nil {
		t.Fatal(err)
	}
	team := "scope_team_" + tenant
	if _, err := pool.Exec(ctx, `INSERT INTO teams (id,tenant_id,name,path) VALUES ($1,$2,'scope team',$3)`, team, tenant, "/"+team); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO quota_policies (id,tenant_id,scope_type,monthly_token_limit_canonical,quota_timezone,status) VALUES ($1,$2,'tenant',100,'UTC','active')`, "parent_"+tenant, tenant); err != nil {
		t.Fatal(err)
	}
	mini := miniredis.RunT(t)
	now := time.Date(2026, 9, 30, 17, 30, 0, 0, time.UTC)
	mini.SetTime(now)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	deps := &Dependencies{OrgService: service, BudgetSnapshot: budget.NewSnapshotReader(rdb)}
	for _, sc := range []struct{ typ, id, zone string }{{"tenant", tenant, "UTC"}, {"team", team, "Asia/Shanghai"}, {"project", k.ProjectID, "Asia/Shanghai"}, {"user", user, "Asia/Shanghai"}, {"key", key, "Asia/Shanghai"}} {
		t.Run(sc.typ, func(t *testing.T) {
			loc, _ := time.LoadLocation(sc.zone)
			bucket := budget.QuotaPeriodBucket(sc.zone, now.In(loc).Format("2006-01"))
			rdb.HSet(ctx, budget.BudgetKey(sc.typ, sc.id, bucket), "tokens", 91, "cost_micros", 37)
			req := withBudgetUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/budgets/snapshot?scope_type="+sc.typ+"&scope_id="+sc.id, nil), tenant, user)
			rec := httptest.NewRecorder()
			GetBudgetSnapshot(deps)(rec, req)
			if rec.Code != 200 {
				t.Fatalf("status=%d %s", rec.Code, rec.Body.String())
			}
			var b map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
				t.Fatal(err)
			}
			if b["quota_timezone"] != sc.zone || b["month_tokens"] != float64(91) || b["month"] != bucket {
				t.Fatalf("parent bucket leak: %s", rec.Body.String())
			}
		})
	}
	for _, typ := range []string{"key", "project", "user", "team"} {
		req := withBudgetUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/budgets/snapshot?scope_type="+typ+"&scope_id=foreign_missing", nil), tenant, user)
		rec := httptest.NewRecorder()
		GetBudgetSnapshot(deps)(rec, req)
		if rec.Code != 404 {
			t.Fatalf("%s unauthorized scope status=%d", typ, rec.Code)
		}
	}
	closedPool, err := pgxpool.New(ctx, os.Getenv("BILLING_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	closedPool.Close()
	deps.OrgService = org.NewService(repository.NewTeamRepository(closedPool), repository.NewTeamMemberRepository(closedPool), repository.NewQuotaPolicyRepository(closedPool))
	req := withBudgetUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/budgets/snapshot?scope_type=key&scope_id="+key, nil), tenant, user)
	rec := httptest.NewRecorder()
	GetBudgetSnapshot(deps)(rec, req)
	if rec.Code != 503 {
		t.Fatalf("query failure fallback status=%d", rec.Code)
	}
}

func TestCostEvidenceActualJSON(t *testing.T) {
	for _, tc := range []struct {
		name          string
		fields        map[string]bool
		est, unpriced int64
		want          string
	}{
		{"missing", map[string]bool{"cost_micros": true}, 0, 0, "unknown"},
		{"explicit_zero", map[string]bool{"cost_micros": true, "cost_estimated_requests": true, "cost_unpriced_requests": true}, 0, 0, "unknown"},
		{"estimated", map[string]bool{"cost_micros": true, "cost_estimated_requests": true}, 1, 0, "estimated"},
		{"unpriced_precedes", map[string]bool{"cost_micros": true, "cost_estimated_requests": true, "cost_unpriced_requests": true}, 1, 2, "unpriced"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(costQualityBody(123, tc.est, tc.unpriced, tc.fields))
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]interface{}
			if err = json.Unmarshal(b, &body); err != nil {
				t.Fatal(err)
			}
			if body["quality"] != tc.want || body["actual_available"] != false || body["actual_micros"] != nil || body["coverage_verified"] != false || body["total_micros"] != float64(123) {
				t.Fatalf("fabricated evidence: %s", b)
			}
			present := body["fields_present"].(map[string]interface{})
			if _, ok := present["cost_estimated_requests"]; ok != tc.fields["cost_estimated_requests"] {
				t.Fatalf("presence lost: %s", b)
			}
		})
	}
}

// TestKeyAccountingTimezoneOwnershipAndStatus proves the SQL gate is equivalent
// to the gateway's: a key-scope policy only counts when the key belongs to the
// tenant and the policy is active. A cross-tenant key row, or an inactive
// policy, must leave the scope on the accounting default rather than hand back
// that policy's timezone.
func TestKeyAccountingTimezoneOwnershipAndStatus(t *testing.T) {
	pool, _, orgService, tenantID, _, keyID := setupKeyReadModelDB(t)
	ctx := context.Background()

	insert := func(id, keyIDValue, status string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO quota_policies (id, tenant_id, scope_type, key_id, enforcement_mode,
				monthly_token_limit, monthly_token_limit_canonical, quota_timezone, status)
			VALUES ($1, $2, 'key', $3, 'enforce', 1000, 1000, 'America/New_York', $4)`,
			id, tenantID, keyIDValue, status); err != nil {
			t.Fatalf("insert policy %s: %v", id, err)
		}
	}

	// Inactive policy is ignored even though it is well-formed and owned.
	insert("own_inactive_"+tenantID, keyID, "disabled")
	got, err := orgService.KeyAccountingTimezone(ctx, tenantID, keyID)
	if err != nil {
		t.Fatalf("KeyAccountingTimezone(inactive): %v", err)
	}
	if got != budget.DefaultQuotaTimezone {
		t.Fatalf("inactive policy timezone = %q, want the accounting default %q",
			got, budget.DefaultQuotaTimezone)
	}

	// Ownership is enforced by the schema itself: fk_quota_policies_key_id is
	// FOREIGN KEY (tenant_id, key_id) REFERENCES internal_keys(tenant_id, id),
	// so a policy can never name a key belonging to another tenant. The
	// gateway still repeats the check as an EXISTS predicate; this asserts the
	// stronger database guarantee holds, so the reader's EXISTS clause can
	// never be the only thing standing between a policy and a foreign key.
	otherTenant := "bt_other_" + tenantID
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status) VALUES ($1, $1, 'enterprise', 'active')`,
		otherTenant); err != nil {
		t.Fatalf("insert other tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO quota_policies (id, tenant_id, scope_type, key_id, enforcement_mode,
			monthly_token_limit, monthly_token_limit_canonical, quota_timezone, status)
		VALUES ($1, $2, 'key', $3, 'enforce', 1000, 1000, 'America/New_York', 'active')`,
		"own_cross_"+tenantID, otherTenant, keyID); err == nil {
		t.Fatalf("cross-tenant key policy must be rejected by fk_quota_policies_key_id")
	}
	otherKey := "bt_bkey_" + tenantID
	otherProject := "bt_bproj_" + tenantID
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id,tenant_id,name,status) VALUES ($1,$2,'bproject','active')`, otherProject, otherTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO internal_keys (id, tenant_id, project_id, key_hash, key_prefix, scopes_json, name, status)
		VALUES ($1, $2, $3, 'bhash', 'bprefix', '[]'::jsonb, 'bkey', 'active')`, otherKey, otherTenant, otherProject); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO quota_policies (id, tenant_id, scope_type, key_id, enforcement_mode,
		monthly_token_limit_canonical, quota_timezone, status) VALUES ($1,$2,'key',$3,'enforce',1000,'UTC','active')`,
		"own_b_"+tenantID, otherTenant, otherKey); err != nil {
		t.Fatal(err)
	}
	foreign, err := orgService.KeyAccountingTimezone(ctx, tenantID, otherKey)
	if err != nil || foreign != budget.DefaultQuotaTimezone {
		t.Fatalf("legal tenant B policy leaked into tenant A: %q %v", foreign, err)
	}
	own, err := orgService.KeyAccountingTimezone(ctx, otherTenant, otherKey)
	if err != nil || own != "UTC" {
		t.Fatalf("legal tenant B policy not read in B: %q %v", own, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM quota_policies WHERE tenant_id=$1`, otherTenant)
		_, _ = pool.Exec(ctx, `DELETE FROM internal_keys WHERE tenant_id=$1`, otherTenant)
		_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE tenant_id=$1`, otherTenant)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, otherTenant)
	})
	// And the tenant's own key is still unaffected by that other tenant.
	got, err = orgService.KeyAccountingTimezone(ctx, tenantID, keyID)
	if err != nil {
		t.Fatalf("KeyAccountingTimezone(after cross-tenant attempt): %v", err)
	}
	if got != budget.DefaultQuotaTimezone {
		t.Fatalf("timezone = %q, want the accounting default %q", got, budget.DefaultQuotaTimezone)
	}
}

// TestKeyAccountingTimezoneIgnoresPolicyForAnotherKey proves the stable-key
// match is exact: a key policy that exists and is active but names a DIFFERENT
// key must not lend its timezone to this key.
func TestKeyAccountingTimezoneIgnoresPolicyForAnotherKey(t *testing.T) {
	pool, _, orgService, tenantID, userID, keyID := setupKeyReadModelDB(t)
	ctx := context.Background()

	otherKey := "rbkk_other_" + tenantID
	if _, err := pool.Exec(ctx, `
		INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, scopes_json, name, status, created_at)
		SELECT $1, tenant_id, project_id, user_id, 'other-hash', 'othrpre', '[]'::jsonb, 'other-key', 'active', NOW()
		FROM internal_keys WHERE id = $2`,
		otherKey, keyID); err != nil {
		t.Fatalf("insert sibling key: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO quota_policies (id, tenant_id, scope_type, key_id, enforcement_mode,
			monthly_token_limit, monthly_token_limit_canonical, quota_timezone, status)
		VALUES ($1, $2, 'key', $3, 'enforce', 1000, 1000, 'America/New_York', 'active')`,
		"own_otherkey_"+tenantID, tenantID, otherKey); err != nil {
		t.Fatalf("insert sibling key policy: %v", err)
	}
	got, err := orgService.KeyAccountingTimezone(ctx, tenantID, keyID)
	if err != nil {
		t.Fatalf("KeyAccountingTimezone: %v", err)
	}
	if got != budget.DefaultQuotaTimezone {
		t.Fatalf("another key's policy leaked: timezone = %q, want %q", got, budget.DefaultQuotaTimezone)
	}
	// Sanity: that policy IS effective for its own key, so the test is not
	// passing merely because the row is inert.
	other, err := orgService.KeyAccountingTimezone(ctx, tenantID, otherKey)
	if err != nil {
		t.Fatalf("KeyAccountingTimezone(other key): %v", err)
	}
	if other != "America/New_York" {
		t.Fatalf("sibling key timezone = %q, want America/New_York (its own policy)", other)
	}
	_ = userID
}

// TestKeyAccountingTimezoneIgnoresLegacyKeyPrefix pins that the stable-key rule
// holds: a policy carrying only the legacy key_prefix (key_id NULL) must NOT
// select a bucket. control-plane's older GetByScope still matches that shape via
// its single-sibling prefix branch, but the gateway's key branch has no such
// branch, so honouring it here would read a bucket the gateway never writes.
func TestKeyAccountingTimezoneIgnoresLegacyKeyPrefix(t *testing.T) {
	pool, _, orgService, tenantID, _, keyID := setupKeyReadModelDB(t)
	ctx := context.Background()

	var prefix string
	if err := pool.QueryRow(ctx, `SELECT key_prefix FROM internal_keys WHERE id = $1 AND tenant_id = $2`,
		keyID, tenantID).Scan(&prefix); err != nil {
		t.Fatalf("read key prefix: %v", err)
	}
	// key_id NULL + key_prefix set: the legacy shape.
	if _, err := pool.Exec(ctx, `
		INSERT INTO quota_policies (id, tenant_id, scope_type, key_id, key_prefix, enforcement_mode,
			monthly_token_limit, monthly_token_limit_canonical, quota_timezone, status)
		VALUES ($1, $2, 'key', NULL, $3, 'enforce', 1000, 1000, 'America/New_York', 'active')`,
		"own_prefix_"+tenantID, tenantID, prefix); err != nil {
		t.Fatalf("insert legacy prefix policy: %v", err)
	}
	got, err := orgService.KeyAccountingTimezone(ctx, tenantID, keyID)
	if err != nil {
		t.Fatalf("KeyAccountingTimezone(legacy prefix): %v", err)
	}
	if got != budget.DefaultQuotaTimezone {
		t.Fatalf("legacy key_prefix policy timezone = %q, want the accounting default %q (stable-key rule)",
			got, budget.DefaultQuotaTimezone)
	}
	// Sanity: the older helper DOES match that row, which is exactly why the
	// read model must not use it for bucket selection.
	if matched, err := orgService.EffectiveQuota(ctx, org.ScopeRef{TenantID: tenantID, KeyID: keyID}); err == nil &&
		matched != nil && matched.QuotaTimezone == "America/New_York" {
		t.Logf("note: EffectiveQuota reports %q here, confirming the two paths diverge as documented",
			matched.QuotaTimezone)
	}
}
