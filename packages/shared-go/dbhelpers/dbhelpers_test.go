package dbhelpers

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// 预算：四个连主库的进程默认最大连接数之和，加网关池外 1 条 LISTEN，必须给 PostgreSQL
// max_connections=100（保留 3 条超级用户）留出至少 30 条余量给 psql/备份/迁移/一次性工具。
func TestDefaultPoolBudgetLeavesHeadroomUnderPostgresDefault(t *testing.T) {
	total := 1 // gateway-core 池外常驻 LISTEN 连接
	minTotal := 1
	for _, svc := range []string{ServiceGateway, ServiceControlPlane, ServiceProxy, ServiceWorker} {
		cfg, warnings := ConfigFromEnv(svc, "postgres://x/y", env(nil))
		if len(warnings) != 0 {
			t.Fatalf("%s default warnings: %v", svc, warnings)
		}
		total += int(cfg.MaxConns)
		minTotal += int(cfg.MinConns)
	}
	if total > 100-3-30 {
		t.Fatalf("default max connections sum=%d, want <= 67 (100 - 3 reserved - 30 headroom)", total)
	}
	if minTotal > 15 {
		t.Fatalf("default idle floor=%d, want <= 15", minTotal)
	}
}

// 钉住具体数值：预算表（注释、报告、compose 说明）都按这组数字写，改默认值时必须同步更新它们。
func TestDefaultPoolSizesMatchDocumentedBudget(t *testing.T) {
	want := map[string][2]int32{
		ServiceGateway: {24, 4}, ServiceControlPlane: {22, 3}, ServiceProxy: {12, 2}, ServiceWorker: {6, 1},
	}
	sum := int32(1) // gateway LISTEN
	for svc, w := range want {
		cfg, _ := ConfigFromEnv(svc, "u", env(nil))
		if cfg.MaxConns != w[0] || cfg.MinConns != w[1] {
			t.Fatalf("%s default=%d/%d want %d/%d", svc, cfg.MaxConns, cfg.MinConns, w[0], w[1])
		}
		sum += cfg.MaxConns
	}
	if sum != 65 {
		t.Fatalf("documented total is 65, got %d", sum)
	}
	// proxy-server-vm 同时启用（第二个 PROXY 池）后仍要给一次性工具留 15 条以上。
	if withVM := sum + want[ServiceProxy][0]; withVM > 100-3-15 {
		t.Fatalf("with proxy-server-vm total=%d leaves too little headroom", withVM)
	}
}

func TestGatewayKeepsTheLargestDefaultPool(t *testing.T) {
	gw, _ := ConfigFromEnv(ServiceGateway, "u", env(nil))
	for _, svc := range []string{ServiceControlPlane, ServiceProxy, ServiceWorker} {
		other, _ := ConfigFromEnv(svc, "u", env(nil))
		if other.MaxConns > gw.MaxConns {
			t.Fatalf("%s default (%d) larger than gateway (%d)", svc, other.MaxConns, gw.MaxConns)
		}
	}
}

func TestServiceSpecificEnvBeatsGenericBeatsDefault(t *testing.T) {
	cfg, warnings := ConfigFromEnv(ServiceControlPlane, "u", env(map[string]string{
		"DB_POOL_MAX_CONNS":               "12",
		"CONTROL_PLANE_DB_POOL_MAX_CONNS": "20",
		"DB_POOL_MIN_CONNS":               "3",
	}))
	if len(warnings) != 0 {
		t.Fatal(warnings)
	}
	if cfg.MaxConns != 20 {
		t.Fatalf("service-specific should win: %d", cfg.MaxConns)
	}
	if cfg.MinConns != 3 {
		t.Fatalf("generic should apply when no service-specific: %d", cfg.MinConns)
	}
	// 另一服务不受 control-plane 专属变量影响，但受通用变量影响。
	gw, _ := ConfigFromEnv(ServiceGateway, "u", env(map[string]string{"CONTROL_PLANE_DB_POOL_MAX_CONNS": "20", "DB_POOL_MAX_CONNS": "12"}))
	if gw.MaxConns != 12 {
		t.Fatalf("gateway=%d want generic 12", gw.MaxConns)
	}
}

func TestEmptyEnvValuesMeanUnsetBecauseComposePassesEmptyStrings(t *testing.T) {
	want, _ := ConfigFromEnv(ServiceWorker, "u", env(nil))
	got, warnings := ConfigFromEnv(ServiceWorker, "u", env(map[string]string{
		"WORKER_DB_POOL_MAX_CONNS": "", "WORKER_DB_POOL_MIN_CONNS": "  ", "DB_POOL_MAX_CONN_IDLE_TIME": "",
	}))
	if len(warnings) != 0 || got.MaxConns != want.MaxConns || got.MinConns != want.MinConns || got.MaxConnIdleTime != want.MaxConnIdleTime {
		t.Fatalf("empty values changed config: %+v warnings=%v", got, warnings)
	}
}

func TestInvalidValuesFallBackToDefaultWithWarningAndNeverLeakValueOrURL(t *testing.T) {
	want, _ := ConfigFromEnv(ServiceGateway, "u", env(nil))
	for _, bad := range []string{"abc", "0", "-3", "100000", "1.5", "12; DROP"} {
		cfg, warnings := ConfigFromEnv(ServiceGateway, "postgres://leaky_user:leaky_pw@db.internal/leaky_db", env(map[string]string{"GATEWAY_DB_POOL_MAX_CONNS": bad}))
		if cfg.MaxConns != want.MaxConns {
			t.Fatalf("bad=%q MaxConns=%d want default %d", bad, cfg.MaxConns, want.MaxConns)
		}
		if len(warnings) != 1 || !strings.Contains(warnings[0], "GATEWAY_DB_POOL_MAX_CONNS") {
			t.Fatalf("bad=%q warnings=%v", bad, warnings)
		}
		for _, leaked := range []string{"leaky_user", "leaky_pw", "db.internal", "leaky_db"} {
			if strings.Contains(warnings[0], leaked) {
				t.Fatalf("warning leaks %q: %s", leaked, warnings[0])
			}
		}
	}
}

func TestMinConnsIsClampedToMaxConns(t *testing.T) {
	cfg, warnings := ConfigFromEnv(ServiceWorker, "u", env(map[string]string{"WORKER_DB_POOL_MAX_CONNS": "3", "WORKER_DB_POOL_MIN_CONNS": "9"}))
	if cfg.MaxConns != 3 || cfg.MinConns != 3 {
		t.Fatalf("max=%d min=%d", cfg.MaxConns, cfg.MinConns)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "MIN_CONNS") {
		t.Fatalf("warnings=%v", warnings)
	}
}

func TestMinConnsZeroIsAllowed(t *testing.T) {
	cfg, warnings := ConfigFromEnv(ServiceProxy, "u", env(map[string]string{"PROXY_DB_POOL_MIN_CONNS": "0"}))
	if cfg.MinConns != 0 || len(warnings) != 0 {
		t.Fatalf("min=%d warnings=%v", cfg.MinConns, warnings)
	}
}

func TestDurationsParseAndRejectNonPositive(t *testing.T) {
	cfg, warnings := ConfigFromEnv(ServiceGateway, "u", env(map[string]string{
		"GATEWAY_DB_POOL_MAX_CONN_IDLE_TIME": "5m",
		"GATEWAY_DB_POOL_MAX_CONN_LIFETIME":  "30m",
		"GATEWAY_DB_POOL_CONNECT_TIMEOUT":    "7s",
	}))
	if len(warnings) != 0 || cfg.MaxConnIdleTime != 5*time.Minute || cfg.MaxConnLifetime != 30*time.Minute || cfg.ConnectTimeout != 7*time.Second {
		t.Fatalf("cfg=%+v warnings=%v", cfg, warnings)
	}
	want, _ := ConfigFromEnv(ServiceGateway, "u", env(nil))
	cfg, warnings = ConfigFromEnv(ServiceGateway, "u", env(map[string]string{"GATEWAY_DB_POOL_MAX_CONN_IDLE_TIME": "-1s", "GATEWAY_DB_POOL_CONNECT_TIMEOUT": "soon"}))
	if len(warnings) != 2 || cfg.MaxConnIdleTime != want.MaxConnIdleTime || cfg.ConnectTimeout != want.ConnectTimeout {
		t.Fatalf("cfg=%+v warnings=%v", cfg, warnings)
	}
}

func TestUnknownServiceGetsConservativeDefaults(t *testing.T) {
	cfg, _ := ConfigFromEnv("some-cli-tool", "u", env(nil))
	if cfg.MaxConns > 10 || cfg.MinConns > 2 {
		t.Fatalf("one-shot tools must not default to a large pool: %+v", cfg)
	}
	if got := DefaultConfig("u"); got.MaxConns != cfg.MaxConns {
		t.Fatalf("DefaultConfig=%d, want same conservative default %d", got.MaxConns, cfg.MaxConns)
	}
}

// 连接超时：DSN 自带 connect_timeout 时尊重它；没带时用本包默认（原来是 pgxpool 兜底的 2 分钟）。
func TestApplyPoolConfigDefaultsConnectTimeoutButHonoursDSN(t *testing.T) {
	cfg, _ := ConfigFromEnv(ServiceGateway, "u", env(nil))

	pc, err := pgxpool.ParseConfig("postgres://u:p@h/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	applyPoolConfig(pc, cfg)
	if pc.ConnConfig.ConnectTimeout != cfg.ConnectTimeout || cfg.ConnectTimeout <= 0 || cfg.ConnectTimeout > time.Minute {
		t.Fatalf("connect timeout=%s cfg=%s", pc.ConnConfig.ConnectTimeout, cfg.ConnectTimeout)
	}

	pc, err = pgxpool.ParseConfig("postgres://u:p@h/db?sslmode=disable&connect_timeout=3")
	if err != nil {
		t.Fatal(err)
	}
	applyPoolConfig(pc, cfg)
	if pc.ConnConfig.ConnectTimeout != 3*time.Second {
		t.Fatalf("DSN connect_timeout overridden: %s", pc.ConnConfig.ConnectTimeout)
	}
}

func TestApplyPoolConfigSetsEveryField(t *testing.T) {
	cfg := &Config{MaxConns: 11, MinConns: 2, MaxConnLifetime: 20 * time.Minute, MaxConnIdleTime: 4 * time.Minute,
		HealthCheckPeriod: 45 * time.Second, ConnectTimeout: 9 * time.Second}
	pc, _ := pgxpool.ParseConfig("postgres://u:p@h/db")
	applyPoolConfig(pc, cfg)
	if pc.MaxConns != 11 || pc.MinConns != 2 || pc.MaxConnLifetime != 20*time.Minute || pc.MaxConnIdleTime != 4*time.Minute ||
		pc.HealthCheckPeriod != 45*time.Second || pc.ConnConfig.ConnectTimeout != 9*time.Second {
		t.Fatalf("pool config not applied: %+v", pc)
	}
	if pc.MaxConnLifetimeJitter <= 0 {
		t.Fatal("lifetime jitter must be set so pooled connections do not all recycle at the same instant")
	}
}

func TestSummaryContainsOnlyNumbers(t *testing.T) {
	cfg, _ := ConfigFromEnv(ServiceGateway, "postgres://leaky_user:leaky_pw@db.internal/leaky_db", env(nil))
	s := Summary(ServiceGateway, cfg)
	for _, want := range []string{"service=gateway", "max_conns=", "min_conns="} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary %q missing %q", s, want)
		}
	}
	for _, leaked := range []string{"leaky", "db.internal", "postgres://"} {
		if strings.Contains(s, leaked) {
			t.Fatalf("summary leaks %q: %s", leaked, s)
		}
	}
}
