package dbhelpers

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 服务名：决定默认池大小与服务专属环境变量前缀（gateway -> GATEWAY_DB_POOL_*）。
const (
	ServiceGateway      = "gateway"
	ServiceControlPlane = "control-plane"
	ServiceProxy        = "proxy"
	ServiceWorker       = "worker"
)

// 连接数预算（PostgreSQL 默认 max_connections=100，其中 3 条留给超级用户）：
//
//	gateway-core   24  +1 条池外常驻 LISTEN 连接（mcp_server_cache_invalidate）
//	control-plane  22
//	proxy-server   12
//	worker          6
//	合计           64 + 1 = 65，剩余约 32 条给 psql、备份、迁移、jjdctl backfill run-once 等一次性工具。
//
// 启用 proxy-server-vm profile（compose 里与 proxy-server 并存的第二个代理实例，同样走 PROXY 池）时再 +12：
// 合计 77，剩余约 20 条。启用前先确认现场没有把其他池调大，必要时下调 PROXY_DB_POOL_MAX_CONNS。
//
// 旧实现四个进程都硬编码 25/5：纸面峰值 101 > 100，常驻下限 21，且没有任何环境变量可调。
// 调大任一服务前先算总和；用 <SERVICE>_DB_POOL_MAX_CONNS 覆盖，不用改镜像。
// 本包不设置 application_name（避免改动连接参数带来意外）；排查连接归属时请按来源 IP / 用户名区分。
type serviceDefaults struct{ max, min int32 }

var defaultsByService = map[string]serviceDefaults{
	ServiceGateway:      {24, 4},
	ServiceControlPlane: {22, 3},
	ServiceProxy:        {12, 2},
	ServiceWorker:       {6, 1},
}

// 未登记的进程（一次性 CLI、迁移工具）取保守值，避免一个临时工具占满名额。
var unknownServiceDefaults = serviceDefaults{8, 1}

const (
	defaultMaxConnLifetime   = time.Hour
	defaultMaxConnIdleTime   = 10 * time.Minute // 旧值 30 分钟；空闲连接早点还给库
	defaultHealthCheckPeriod = time.Minute
	defaultConnectTimeout    = 15 * time.Second // 旧值是 pgxpool 兜底的 2 分钟：卡住的建连会长时间占着池名额
	maxAllowedConns          = 500
)

// Config holds database connection configuration
type Config struct {
	URL               string
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	// ConnectTimeout 是单次建连超时。DSN 里自带 connect_timeout（或 PGCONNECT_TIMEOUT）时以 DSN 为准。
	ConnectTimeout time.Duration
}

// DefaultConfig 返回保守默认值（用于未按服务调参的调用方，如一次性工具）。
func DefaultConfig(url string) *Config {
	return configWithDefaults(url, unknownServiceDefaults)
}

func configWithDefaults(url string, d serviceDefaults) *Config {
	return &Config{
		URL:               url,
		MaxConns:          d.max,
		MinConns:          d.min,
		MaxConnLifetime:   defaultMaxConnLifetime,
		MaxConnIdleTime:   defaultMaxConnIdleTime,
		HealthCheckPeriod: defaultHealthCheckPeriod,
		ConnectTimeout:    defaultConnectTimeout,
	}
}

func envPrefix(service string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(service))
}

// ConfigFromEnv 解析某服务的连接池配置。优先级：<PREFIX>_DB_POOL_* > DB_POOL_* > 内置默认值。
// 空串视为未设置（compose 用 ${VAR:-} 透传时会得到空串）。非法值回退到下一级并产生警告；
// 警告里只有变量名，不回显取值或连接串。
//
// 变量（<PREFIX> 为 GATEWAY / CONTROL_PLANE / PROXY / WORKER）：
//
//	<PREFIX>_DB_POOL_MAX_CONNS        最大连接数，1..500
//	<PREFIX>_DB_POOL_MIN_CONNS        常驻最小连接数，0..MAX
//	<PREFIX>_DB_POOL_MAX_CONN_IDLE_TIME   Go duration，如 10m
//	<PREFIX>_DB_POOL_MAX_CONN_LIFETIME    Go duration，如 1h
//	<PREFIX>_DB_POOL_CONNECT_TIMEOUT      Go duration，如 15s
func ConfigFromEnv(service, url string, getenv func(string) string) (*Config, []string) {
	d, ok := defaultsByService[service]
	if !ok {
		d = unknownServiceDefaults
	}
	cfg := configWithDefaults(url, d)
	var warnings []string
	prefix := envPrefix(service)

	// 依次尝试服务专属、通用两级；某一级非法就警告并试下一级。
	resolve := func(suffix string, parse func(string) bool) {
		for _, key := range []string{prefix + "_DB_POOL_" + suffix, "DB_POOL_" + suffix} {
			v := strings.TrimSpace(getenv(key))
			if v == "" {
				continue
			}
			if parse(v) {
				return
			}
			warnings = append(warnings, key+" 取值无效，已忽略（回退到下一级配置或内置默认值）")
		}
	}
	minExplicit := false
	resolve("MAX_CONNS", func(v string) bool {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxAllowedConns {
			return false
		}
		cfg.MaxConns = int32(n)
		return true
	})
	resolve("MIN_CONNS", func(v string) bool {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > maxAllowedConns {
			return false
		}
		cfg.MinConns, minExplicit = int32(n), true
		return true
	})
	duration := func(dst *time.Duration) func(string) bool {
		return func(v string) bool {
			parsed, err := time.ParseDuration(v)
			if err != nil || parsed <= 0 {
				return false
			}
			*dst = parsed
			return true
		}
	}
	resolve("MAX_CONN_IDLE_TIME", duration(&cfg.MaxConnIdleTime))
	resolve("MAX_CONN_LIFETIME", duration(&cfg.MaxConnLifetime))
	resolve("CONNECT_TIMEOUT", duration(&cfg.ConnectTimeout))

	if cfg.MinConns > cfg.MaxConns {
		// 只调低了 MAX、没动 MIN 时，默认 MIN 静默收敛，不算配置错误；显式设置的 MIN 过大才警告。
		if minExplicit {
			warnings = append(warnings, prefix+"_DB_POOL_MIN_CONNS 大于最大连接数，已收敛为最大连接数")
		}
		cfg.MinConns = cfg.MaxConns
	}
	return cfg, warnings
}

// applyPoolConfig 把配置写进 pgxpool.Config。
func applyPoolConfig(pc *pgxpool.Config, cfg *Config) {
	pc.MaxConns = cfg.MaxConns
	pc.MinConns = cfg.MinConns
	pc.MaxConnLifetime = cfg.MaxConnLifetime
	// 抖动：所有连接在同一时刻到期会造成「整池同时重建」，磁盘卡顿时尤其糟。让到期时间在 10% 区间内散开。
	pc.MaxConnLifetimeJitter = cfg.MaxConnLifetime / 10
	pc.MaxConnIdleTime = cfg.MaxConnIdleTime
	pc.HealthCheckPeriod = cfg.HealthCheckPeriod
	if pc.ConnConfig.ConnectTimeout <= 0 { // DSN / PGCONNECT_TIMEOUT 明确给了就尊重
		pc.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	}
}

// Summary 返回只含数字的配置摘要，用于启动日志（不含连接串）。
func Summary(service string, cfg *Config) string {
	return fmt.Sprintf("service=%s max_conns=%d min_conns=%d max_conn_idle_time=%s max_conn_lifetime=%s connect_timeout=%s",
		service, cfg.MaxConns, cfg.MinConns, cfg.MaxConnIdleTime, cfg.MaxConnLifetime, cfg.ConnectTimeout)
}

// NewPool creates a new connection pool
func NewPool(ctx context.Context, cfg *Config) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}
	applyPoolConfig(poolConfig, cfg)

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return pool, nil
}

// NewPoolForService 按服务名取默认值、读环境变量覆盖，并在启动日志里打印生效的池参数。
func NewPoolForService(ctx context.Context, service, url string) (*pgxpool.Pool, error) {
	cfg, warnings := ConfigFromEnv(service, url, os.Getenv)
	for _, w := range warnings {
		log.Printf("db pool config warning: %s", w)
	}
	log.Printf("db pool config: %s", Summary(service, cfg))
	return NewPool(ctx, cfg)
}

// NewPoolFromURL creates a connection pool from a URL string with conservative defaults.
// 长驻服务应改用 NewPoolForService。
func NewPoolFromURL(ctx context.Context, url string) (*pgxpool.Pool, error) {
	return NewPool(ctx, DefaultConfig(url))
}
