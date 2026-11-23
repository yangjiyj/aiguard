package providers

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func TestBootstrapUsageFromDBRestoresStableKeyDailyAndMonthlyBuckets(t *testing.T) {
	dsn := os.Getenv("KEY_QUOTA_BOOTSTRAP_TEST_DATABASE_URL")
	redisURL := os.Getenv("KEY_QUOTA_BOOTSTRAP_TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		if os.Getenv("JJD_REQUIRE_KEY_QUOTA_BOOTSTRAP_TESTS") == "1" {
			t.Fatal("PostgreSQL and Redis test URLs are required")
		}
		t.Skip("key quota bootstrap integration services are not configured")
	}
	ctx := context.Background()
	dbConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	// TEMP tables must stay on one PostgreSQL session while BootstrapUsageFromDB
	// acquires and releases connections for each scope query.
	dbConfig.MaxConns = 1
	db, err := pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	if err := rdb.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `CREATE TEMP TABLE request_logs (
		tenant_id text, project_id text, user_id text, actor_user_id text, client_id text,
		input_tokens integer, output_tokens integer, total_cost numeric(18,6), created_at timestamptz,
		request_id text DEFAULT '', request_status text DEFAULT 'success', output_audit_result jsonb DEFAULT '{}'::jsonb
	); CREATE TEMP TABLE projects (id text, tenant_id text, team_id text);
	CREATE TEMP TABLE teams (id text, tenant_id text, path text);
	CREATE TEMP TABLE quota_policies (
		tenant_id text, scope_type text, scope_ref text, project_id text, user_id text, key_id text,
		quota_timezone text, status text
	);
	CREATE TEMP TABLE billing_usage_facts (tenant_id text, request_id text, billable_amount_micros bigint, status text);
	INSERT INTO quota_policies (tenant_id,scope_type,quota_timezone,status)
	VALUES ('tenant-cost','tenant','UTC','active')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO teams VALUES
		('team-root', 'tenant-a', '/team-root'),
		('team-a', 'tenant-a', '/team-root/team-a'),
		('team-b', 'tenant-b', '/team-b')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects VALUES
		('project-a', 'tenant-a', 'team-a'),
		('project-a', 'tenant-b', 'team-b'),
		('project-without-team', 'tenant-a', NULL)`); err != nil {
		t.Fatal(err)
	}

	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc)
	olderThisMonth := monthStart.Add(time.Minute)
	rows := []struct {
		at     time.Time
		tokens int
		cost   float64
	}{
		{now.Add(-time.Minute), 10, 1.25},
		{olderThisMonth, 20, 2.50},
		{monthStart.Add(-time.Minute), 100, 100},
	}
	for i, row := range rows {
		if _, err := db.Exec(ctx, `INSERT INTO request_logs VALUES ('tenant-a','project-a','owner-a','', 'key-stable', $1, 0, $2, $3)`, row.tokens, row.cost, row.at); err != nil {
			t.Fatalf("insert row %d: %v", i, err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO request_logs VALUES
		('tenant-b','project-a','owner-b','', 'key-b',40,0,4.00,$1),
		('tenant-a','project-without-team','owner-a','', 'key-no-team',50,0,5.00,$1)`, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects VALUES ('project-cost','tenant-cost',NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs
			(tenant_id,project_id,user_id,actor_user_id,client_id,input_tokens,output_tokens,total_cost,created_at,request_id,request_status,output_audit_result)
		VALUES
			('tenant-cost','project-cost','owner-cost','actor-cost','key-cost',7,3,0.25,$1,'request-priced','success','{"response_metadata":{"usage_source":"estimated_reservation"}}'),
			('tenant-cost','project-cost','owner-cost','actor-cost','key-cost',2,1,0.10,$1,'request-unpriced','success','{}')
	`, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts VALUES ('tenant-cost','request-priced',77,'settled')`); err != nil {
		t.Fatal(err)
	}
	legacyKey := BudgetKey("key", "sk-legacy", now.Format("2006-01"))
	if err := rdb.HSet(ctx, legacyKey, "tokens", 999).Err(); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		if err := BootstrapUsageFromDB(ctx, db, rdb); err != nil {
			t.Fatalf("bootstrap run %d: %v", i+1, err)
		}
	}
	month := readBudgetHash(t, ctx, rdb, BudgetKey("key", "key-stable", now.Format("2006-01")))
	if month["requests"] != 2 || month["tokens"] != 30 || month["cost"] != 3.75 {
		t.Fatalf("unexpected monthly stable key bucket: %+v", month)
	}
	expectedDayRequests, expectedDayTokens, expectedDayCost := float64(1), float64(10), 1.25
	if !olderThisMonth.Before(todayStart) {
		expectedDayRequests, expectedDayTokens, expectedDayCost = 2, 30, 3.75
	}
	day := readBudgetHash(t, ctx, rdb, BudgetKeyDay("key", "key-stable", now.Format("2006-01-02")))
	if day["requests"] != expectedDayRequests || day["tokens"] != expectedDayTokens || day["cost"] != expectedDayCost {
		t.Fatalf("unexpected daily stable key bucket: %+v", day)
	}
	if got := rdb.HGet(ctx, legacyKey, "tokens").Val(); got != "999" {
		t.Fatalf("bootstrap touched legacy prefix bucket: %q", got)
	}
	costBucket := readBudgetHash(t, ctx, rdb, BudgetKey("tenant", "tenant-cost", now.Format("2006-01")))
	if costBucket["cost_micros"] != 77 || costBucket["cost_estimated_requests"] != 1 || costBucket["cost_unpriced_requests"] != 1 {
		t.Fatalf("billable cost bootstrap=%+v", costBucket)
	}
	utcNow := now.In(time.UTC)
	utcCostKey := BudgetKey("tenant", "tenant-cost", quotaPeriodBucket("UTC", utcNow.Format("2006-01")))
	if got := readBudgetHash(t, ctx, rdb, utcCostKey)["cost_micros"]; got != 77 {
		t.Fatalf("UTC billable cost bootstrap=%v", got)
	}
	utcUnrelatedKey := BudgetKey("tenant", "tenant-a", quotaPeriodBucket("UTC", utcNow.Format("2006-01")))
	if exists, err := rdb.Exists(ctx, utcUnrelatedKey).Result(); err != nil || exists != 0 {
		t.Fatalf("unrelated scope was copied into UTC bucket: exists=%d err=%v", exists, err)
	}

	teamMonth := readBudgetHash(t, ctx, rdb, BudgetKey("team", "team-a", now.Format("2006-01")))
	if teamMonth["requests"] != 2 || teamMonth["tokens"] != 30 || teamMonth["cost"] != 3.75 {
		t.Fatalf("unexpected tenant-safe team-a monthly bucket: %+v", teamMonth)
	}
	teamDay := readBudgetHash(t, ctx, rdb, BudgetKeyDay("team", "team-a", now.Format("2006-01-02")))
	if teamDay["requests"] != expectedDayRequests || teamDay["tokens"] != expectedDayTokens || teamDay["cost"] != expectedDayCost {
		t.Fatalf("unexpected team-a daily bucket: %+v", teamDay)
	}
	teamBMonth := readBudgetHash(t, ctx, rdb, BudgetKey("team", "team-b", now.Format("2006-01")))
	if teamBMonth["requests"] != 1 || teamBMonth["tokens"] != 40 || teamBMonth["cost"] != 4 {
		t.Fatalf("cross-tenant project join polluted team-b bucket: %+v", teamBMonth)
	}
	rootMonth := readBudgetHash(t, ctx, rdb, BudgetKey("team", "team-root", now.Format("2006-01")))
	if rootMonth["requests"] != 2 || rootMonth["tokens"] != 30 || rootMonth["cost"] != 3.75 {
		t.Fatalf("parent team monthly bucket was not restored: %+v", rootMonth)
	}
	rootDay := readBudgetHash(t, ctx, rdb, BudgetKeyDay("team", "team-root", now.Format("2006-01-02")))
	if rootDay["requests"] != expectedDayRequests || rootDay["tokens"] != expectedDayTokens || rootDay["cost"] != expectedDayCost {
		t.Fatalf("parent team daily bucket was not restored: %+v", rootDay)
	}
	if keys, err := rdb.Keys(ctx, "budget:team:*").Result(); err != nil {
		t.Fatal(err)
	} else if len(keys) != 6 {
		t.Fatalf("expected only Shanghai direct/parent team daily and monthly keys; custom timezone copied unrelated scopes: %v", keys)
	}
}

func TestBootstrapBudgetMaxIsAtomicMonotonicAcrossRuntimeIncrement(t *testing.T) {
	client := atomicAdmissionRedis(t)
	ctx := context.Background()
	key := "budget:test:rolling"
	if err := client.HSet(ctx, key,
		"requests", "9007199254740993",
		"tokens", 205,
		"cost", "3.5",
	).Err(); err != nil {
		t.Fatal(err)
	}
	pipe := client.Pipeline()
	// This represents a DB snapshot selected before another gateway performed
	// HINCRBY. The Lua write must retain the newer Redis value.
	queueBootstrapBudgetMax(ctx, pipe, key, 9007199254740992, 200, 3, 0, 0, 0)
	if _, err := pipe.Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if got := client.HGet(ctx, key, "requests").Val(); got != "9007199254740993" {
		t.Fatalf("large integer counter regressed through float comparison: %q", got)
	}
	if got := client.HGet(ctx, key, "tokens").Val(); got != "205" {
		t.Fatalf("runtime HINCR was overwritten by stale DB snapshot: %q", got)
	}
	if got := client.HGet(ctx, key, "cost").Val(); got != "3.5" {
		t.Fatalf("higher runtime cost was overwritten: %q", got)
	}

	pipe = client.Pipeline()
	queueBootstrapBudgetMax(ctx, pipe, key, 9007199254740994, 210, 4.25, 7, 2, 1)
	if _, err := pipe.Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if got := client.HGet(ctx, key, "requests").Val(); got != "9007199254740994" {
		t.Fatalf("newer DB request floor was not restored: %q", got)
	}
	if got := client.HGet(ctx, key, "tokens").Val(); got != "210" {
		t.Fatalf("newer DB token floor was not restored: %q", got)
	}
	if got := client.HGet(ctx, key, "cost").Val(); got != "4.25" {
		t.Fatalf("newer DB cost floor was not restored: %q", got)
	}
	if got := client.HGet(ctx, key, "cost_micros").Val(); got != "7" {
		t.Fatalf("billable micros floor was not restored: %q", got)
	}
	if got := client.HGet(ctx, key, "cost_estimated_requests").Val(); got != "2" {
		t.Fatalf("estimated cost quality floor was not restored: %q", got)
	}
	if got := client.HGet(ctx, key, "cost_unpriced_requests").Val(); got != "1" {
		t.Fatalf("unpriced cost quality floor was not restored: %q", got)
	}
}

func TestBootstrapUsageFromDBFailsWhenOneScopeQueryFails(t *testing.T) {
	dsn := os.Getenv("KEY_QUOTA_BOOTSTRAP_TEST_DATABASE_URL")
	redisURL := os.Getenv("KEY_QUOTA_BOOTSTRAP_TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		if os.Getenv("JJD_REQUIRE_KEY_QUOTA_BOOTSTRAP_TESTS") == "1" {
			t.Fatal("PostgreSQL and Redis test URLs are required")
		}
		t.Skip("key quota bootstrap integration services are not configured")
	}
	ctx := context.Background()
	dbConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	dbConfig.MaxConns = 1
	db, err := pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	defer client.Close()
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	// Tenant scope succeeds, then team scope fails because projects/teams are
	// deliberately absent. A partial bootstrap must never be reported as safe.
	if _, err := db.Exec(ctx, `CREATE TEMP TABLE request_logs (
		tenant_id text, project_id text, actor_user_id text, client_id text,
		input_tokens integer, output_tokens integer, total_cost numeric(18,6), created_at timestamptz,
		request_id text DEFAULT '', request_status text DEFAULT 'success', output_audit_result jsonb DEFAULT '{}'::jsonb
		); CREATE TEMP TABLE projects (id text, tenant_id text);
		CREATE TEMP TABLE quota_policies (
			tenant_id text, scope_type text, scope_ref text, project_id text, user_id text, key_id text,
			quota_timezone text, status text
		);
	CREATE TEMP TABLE billing_usage_facts (tenant_id text, request_id text, billable_amount_micros bigint, status text);
	INSERT INTO request_logs VALUES ('tenant-a','project-a','actor-a','key-a',10,2,1.25,NOW())`); err != nil {
		t.Fatal(err)
	}
	err = BootstrapUsageFromDB(ctx, db, client)
	if err == nil || !strings.Contains(err.Error(), "query team") {
		t.Fatalf("single-scope query failure was swallowed: %v", err)
	}
	if keys, err := client.Keys(ctx, "budget:*").Result(); err != nil {
		t.Fatal(err)
	} else if len(keys) != 0 {
		t.Fatalf("partial bootstrap wrote Redis before all scopes succeeded: %v", keys)
	}
}

func readBudgetHash(t *testing.T, ctx context.Context, rdb *redis.Client, key string) map[string]float64 {
	t.Helper()
	raw, err := rdb.HGetAll(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]float64, len(raw))
	for field, value := range raw {
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			t.Fatalf("parse %s=%q: %v", field, value, err)
		}
		out[field] = parsed
	}
	return out
}
