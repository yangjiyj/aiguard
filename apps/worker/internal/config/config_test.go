package config

import (
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
)

const (
	expectedDefaultEventStream   = "jjdguard.events"
	expectedDefaultConsumerGroup = "jjdguard-worker"
)

func TestLoadFromEnvDefaults(t *testing.T) {
	for _, key := range []string{
		"LISTEN_ADDR", "EVENT_STREAM", "EVENT_CONSUMER_GROUP", "EVENT_CONSUMER_NAME",
		"ROLLUP_REFRESH_INTERVAL", "ROLLUP_LOOKBACK_HOURS", "OUTBOX_CONSUMER_ENABLED",
		"OUTBOX_POLL_INTERVAL", "OUTBOX_BATCH_SIZE", "OUTBOX_MAX_ATTEMPTS",
		"GATEWAY_ENVIRONMENT_SCOPE", "MIGRATION_BACKFILL_ENABLED",
		"MIGRATION_BACKFILL_POLL_INTERVAL", "MIGRATION_BACKFILL_LEASE",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/newapi")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if cfg.ListenAddr != ":8090" {
		t.Fatalf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.DatabaseURL != "postgres://user:pass@localhost:5432/newapi" {
		t.Fatalf("DatabaseURL = %q", cfg.DatabaseURL)
	}
	if cfg.RedisURL != "redis://localhost:6379/0" {
		t.Fatalf("RedisURL = %q", cfg.RedisURL)
	}
	if eventbus.DefaultStreamName != expectedDefaultEventStream {
		t.Fatalf("DefaultStreamName = %q, want %q", eventbus.DefaultStreamName, expectedDefaultEventStream)
	}
	if cfg.EventStream != eventbus.DefaultStreamName {
		t.Fatalf("EventStream = %q", cfg.EventStream)
	}
	if cfg.RollupRefreshInterval != 5*time.Minute {
		t.Fatalf("RollupRefreshInterval = %s", cfg.RollupRefreshInterval)
	}
	if cfg.RollupLookback != 2*time.Hour {
		t.Fatalf("RollupLookback = %s", cfg.RollupLookback)
	}
	if cfg.ConsumerGroup != expectedDefaultConsumerGroup {
		t.Fatalf("ConsumerGroup = %q", cfg.ConsumerGroup)
	}
	if cfg.ConsumerName != "worker-1" {
		t.Fatalf("ConsumerName = %q", cfg.ConsumerName)
	}
	if !cfg.OutboxEnabled {
		t.Fatal("OutboxEnabled should default to true")
	}
	if cfg.OutboxPollInterval != time.Second {
		t.Fatalf("OutboxPollInterval = %s", cfg.OutboxPollInterval)
	}
	if cfg.OutboxBatchSize != 100 {
		t.Fatalf("OutboxBatchSize = %d", cfg.OutboxBatchSize)
	}
	if cfg.OutboxMaxAttempts != 8 {
		t.Fatalf("OutboxMaxAttempts = %d", cfg.OutboxMaxAttempts)
	}
	if cfg.EnvironmentScope != "legacy-unclassified" {
		t.Fatalf("EnvironmentScope = %q, want legacy-unclassified", cfg.EnvironmentScope)
	}
	if !cfg.MigrationBackfillEnabled || cfg.MigrationBackfillPollInterval != 5*time.Second || cfg.MigrationBackfillLease != time.Minute {
		t.Fatalf("unexpected migration backfill defaults: %#v", cfg)
	}
}

func TestLoadFromEnvNormalizesTrustedEnvironmentScope(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/newapi")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	t.Setenv("GATEWAY_ENVIRONMENT_SCOPE", " CUSTOMER ")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if cfg.EnvironmentScope != "customer" {
		t.Fatalf("EnvironmentScope = %q, want customer", cfg.EnvironmentScope)
	}
}

func TestLoadFromEnvOverrides(t *testing.T) {
	t.Setenv("ROLLUP_REFRESH_INTERVAL", "30s")
	t.Setenv("ROLLUP_LOOKBACK_HOURS", "4")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/newapi")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	t.Setenv("LISTEN_ADDR", ":19090")
	t.Setenv("EVENT_STREAM", "custom.events")
	t.Setenv("EVENT_CONSUMER_GROUP", "custom-group")
	t.Setenv("EVENT_CONSUMER_NAME", "worker-a")
	t.Setenv("OUTBOX_CONSUMER_ENABLED", "false")
	t.Setenv("OUTBOX_POLL_INTERVAL", "250ms")
	t.Setenv("OUTBOX_BATCH_SIZE", "17")
	t.Setenv("OUTBOX_MAX_ATTEMPTS", "5")
	t.Setenv("MIGRATION_BACKFILL_ENABLED", "false")
	t.Setenv("MIGRATION_BACKFILL_POLL_INTERVAL", "3s")
	t.Setenv("MIGRATION_BACKFILL_LEASE", "45s")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if cfg.RollupRefreshInterval != 30*time.Second || cfg.RollupLookback != 4*time.Hour {
		t.Fatalf("unexpected rollup config: %#v", cfg)
	}
	if cfg.ListenAddr != ":19090" || cfg.EventStream != "custom.events" || cfg.ConsumerGroup != "custom-group" || cfg.ConsumerName != "worker-a" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	if cfg.OutboxEnabled {
		t.Fatal("OutboxEnabled should be overridden to false")
	}
	if cfg.OutboxPollInterval != 250*time.Millisecond {
		t.Fatalf("OutboxPollInterval = %s", cfg.OutboxPollInterval)
	}
	if cfg.OutboxBatchSize != 17 || cfg.OutboxMaxAttempts != 5 {
		t.Fatalf("unexpected outbox config: %#v", cfg)
	}
	if cfg.MigrationBackfillEnabled || cfg.MigrationBackfillPollInterval != 3*time.Second || cfg.MigrationBackfillLease != 45*time.Second {
		t.Fatalf("unexpected migration backfill overrides: %#v", cfg)
	}
}

func TestLoadFromEnvRequiresDatabaseAndRedis(t *testing.T) {
	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("LoadFromEnv should require DATABASE_URL and REDIS_URL")
	}
}

func TestLoadFromEnvRequiresRedis(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/newapi")
	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("LoadFromEnv should require REDIS_URL")
	}
}

func TestLoadFromEnvAllowsDisablingRollup(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/newapi")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	t.Setenv("ROLLUP_REFRESH_INTERVAL", "0")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if cfg.RollupRefreshInterval != 0 {
		t.Fatalf("RollupRefreshInterval = %s", cfg.RollupRefreshInterval)
	}
}
