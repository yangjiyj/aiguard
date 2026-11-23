package config

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

type Config struct {
	ListenAddr                    string
	DatabaseURL                   string
	RedisURL                      string
	EventStream                   string
	ConsumerGroup                 string
	ConsumerName                  string
	RollupRefreshInterval         time.Duration
	RollupLookback                time.Duration
	OutboxEnabled                 bool
	OutboxPollInterval            time.Duration
	OutboxBatchSize               int
	OutboxMaxAttempts             int
	EnvironmentScope              string
	ScanFPCleanInterval           time.Duration
	ScanFPRetention               time.Duration
	MigrationBackfillEnabled      bool
	MigrationBackfillPollInterval time.Duration
	MigrationBackfillLease        time.Duration
	// NAS 脱敏事件导出（设计§13）：默认关；开启时 worker 把安全事件写到挂载目录。
	NASExportEnabled bool
	NASExportDir     string
}

func LoadFromEnv() (Config, error) {
	cfg := Config{
		ListenAddr:            envOrDefault("LISTEN_ADDR", ":8090"),
		DatabaseURL:           strings.TrimSpace(os.Getenv("DATABASE_URL")),
		RedisURL:              strings.TrimSpace(os.Getenv("REDIS_URL")),
		EventStream:           envOrDefault("EVENT_STREAM", eventbus.DefaultStreamName),
		RollupRefreshInterval: 0,
		RollupLookback:        0,
		ConsumerGroup:         envOrDefault("EVENT_CONSUMER_GROUP", "jjdguard-worker"),
		ConsumerName:          envOrDefault("EVENT_CONSUMER_NAME", "worker-1"),
		OutboxEnabled:         parseBoolEnv("OUTBOX_CONSUMER_ENABLED", true),
		EnvironmentScope:      retentionartifact.NormalizeEnvironmentScope(os.Getenv("GATEWAY_ENVIRONMENT_SCOPE")),
	}
	rollupInterval, err := parseDurationEnv("ROLLUP_REFRESH_INTERVAL", 5*time.Minute)
	if err != nil {
		return Config{}, err
	}
	rollupLookbackHours, err := parsePositiveIntEnv("ROLLUP_LOOKBACK_HOURS", 2)
	if err != nil {
		return Config{}, err
	}
	outboxPollInterval, err := parseDurationEnv("OUTBOX_POLL_INTERVAL", time.Second)
	if err != nil {
		return Config{}, err
	}
	outboxBatchSize, err := parsePositiveIntEnv("OUTBOX_BATCH_SIZE", 100)
	if err != nil {
		return Config{}, err
	}
	outboxMaxAttempts, err := parsePositiveIntEnv("OUTBOX_MAX_ATTEMPTS", 8)
	if err != nil {
		return Config{}, err
	}
	fpCleanInterval, err := parseDurationEnv("SCAN_FP_CLEAN_INTERVAL", time.Hour)
	if err != nil {
		return Config{}, err
	}
	fpRetentionDays, err := parsePositiveIntEnv("SCAN_FP_RETENTION_DAYS", 30)
	if err != nil {
		return Config{}, err
	}
	backfillPoll, err := parseDurationEnv("MIGRATION_BACKFILL_POLL_INTERVAL", 5*time.Second)
	if err != nil {
		return Config{}, err
	}
	if backfillPoll <= 0 {
		return Config{}, errors.New("MIGRATION_BACKFILL_POLL_INTERVAL must be positive")
	}
	backfillLease, err := parseDurationEnv("MIGRATION_BACKFILL_LEASE", time.Minute)
	if err != nil {
		return Config{}, err
	}
	if backfillLease < 15*time.Second {
		return Config{}, errors.New("MIGRATION_BACKFILL_LEASE must be at least 15s")
	}
	cfg.RollupRefreshInterval = rollupInterval
	cfg.RollupLookback = time.Duration(rollupLookbackHours) * time.Hour
	cfg.OutboxPollInterval = outboxPollInterval
	cfg.OutboxBatchSize = outboxBatchSize
	cfg.OutboxMaxAttempts = outboxMaxAttempts
	cfg.ScanFPCleanInterval = fpCleanInterval
	cfg.ScanFPRetention = time.Duration(fpRetentionDays) * 24 * time.Hour
	cfg.MigrationBackfillEnabled = parseBoolEnv("MIGRATION_BACKFILL_ENABLED", true)
	cfg.MigrationBackfillPollInterval = backfillPoll
	cfg.MigrationBackfillLease = backfillLease

	// NAS 脱敏事件导出：默认关；目录必须是绝对路径（管理员固定配置）。
	cfg.NASExportEnabled = parseBoolEnv("NAS_EXPORT_ENABLED", false)
	cfg.NASExportDir = strings.TrimSpace(os.Getenv("NAS_EXPORT_DIR"))
	if cfg.NASExportEnabled && (cfg.NASExportDir == "" || !filepath.IsAbs(cfg.NASExportDir)) {
		return Config{}, errors.New("NAS_EXPORT_ENABLED requires absolute NAS_EXPORT_DIR")
	}

	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if cfg.RedisURL == "" {
		return Config{}, errors.New("REDIS_URL is required")
	}
	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func parseDurationEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, errors.New(key + " must be non-negative")
	}
	return value, nil
}

func parseBoolEnv(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

func parsePositiveIntEnv(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if value <= 0 {
		return 0, errors.New(key + " must be positive")
	}
	return value, nil
}
