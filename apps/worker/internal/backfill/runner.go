package backfill

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

const CustomerContentProjectionTask = "customer_content_projection_v1"
const RequestLogCompatibilityTask = "request_log_compatibility_v1"
const CustomerEnvironmentScopeTask = "customer_environment_scope_v1"
const EvidenceAgentProjectionTask = "evidence_agent_projection_v1"
const SecurityEventDeliveryTask = "security_event_delivery_v1"
const EvidenceTitleNoiseTask = "evidence_title_noise_v1"
const WorkBuddyIdentityTask = "workbuddy_identity_v1"
const UsageRollupDimensionsTask = "usage_rollup_dimensions_v1"
const AgentUAIdentityTask = "agent_ua_identity_v1"
const AgentUAIdentityCodexTask = "agent_ua_identity_v2"

type Task struct {
	Name                   string
	Version                int
	BatchSize              int
	RateLimitRowsPerSecond int
	LockTimeout            time.Duration
	StatementTimeout       time.Duration
	MaxRetries             int
	EstimatedRows          int64
	CheckpointCreatedAt    *time.Time
	CheckpointID           string
	UpperCreatedAt         *time.Time
	UpperID                string
}

type BatchResult struct {
	Scanned int64
	Updated int64
	Skipped int64
	Failed  int64
	Done    bool
}

type Store interface {
	Claim(context.Context, string, time.Duration) (*Task, error)
	RunBatch(context.Context, *Task, string, time.Duration) (BatchResult, error)
	Complete(context.Context, *Task, string, BatchResult) error
	Release(context.Context, *Task, string, BatchResult, error) error
}

type Config struct {
	Owner        string
	PollInterval time.Duration
	Lease        time.Duration
	Logger       *slog.Logger
}

type Runner struct {
	store Store
	cfg   Config
}

func NewRunner(store Store, cfg Config) *Runner {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.Lease <= 0 {
		cfg.Lease = time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Runner{store: store, cfg: cfg}
}

func (r *Runner) Run(ctx context.Context) {
	if r == nil || r.store == nil || r.cfg.Owner == "" {
		return
	}
	for {
		didWork, err := r.RunOnce(ctx)
		if err != nil && ctx.Err() == nil {
			r.cfg.Logger.Error("migration backfill batch failed", "error", err)
		}
		if ctx.Err() != nil {
			return
		}
		if !didWork || err != nil {
			if !sleepContext(ctx, r.cfg.PollInterval) {
				return
			}
		}
	}
}

func (r *Runner) RunOnce(ctx context.Context) (bool, error) {
	task, err := r.store.Claim(ctx, r.cfg.Owner, r.cfg.Lease)
	if err != nil || task == nil {
		return false, err
	}
	if task.Name != CustomerContentProjectionTask &&
		task.Name != RequestLogCompatibilityTask &&
		task.Name != CustomerEnvironmentScopeTask &&
		task.Name != EvidenceAgentProjectionTask &&
		task.Name != SecurityEventDeliveryTask &&
		task.Name != EvidenceTitleNoiseTask &&
		task.Name != WorkBuddyIdentityTask &&
		task.Name != UsageRollupDimensionsTask &&
		task.Name != AgentUAIdentityTask &&
		task.Name != AgentUAIdentityCodexTask {
		err = errors.New("no registered implementation for migration backfill task " + task.Name)
		_ = r.store.Release(ctx, task, r.cfg.Owner, BatchResult{Failed: 1}, err)
		return true, err
	}

	started := time.Now()
	result, err := r.store.RunBatch(ctx, task, r.cfg.Owner, r.cfg.Lease)
	if err != nil {
		_ = r.store.Release(ctx, task, r.cfg.Owner, result, err)
		return true, err
	}
	if result.Done {
		if err = r.store.Complete(ctx, task, r.cfg.Owner, result); err != nil {
			return true, err
		}
	}
	r.cfg.Logger.Info("migration backfill progress",
		"task", task.Name, "version", task.Version, "scanned", result.Scanned,
		"updated", result.Updated, "skipped", result.Skipped, "completed", result.Done)

	if task.RateLimitRowsPerSecond > 0 && result.Scanned > 0 {
		target := time.Duration(float64(time.Second) * float64(result.Scanned) / float64(task.RateLimitRowsPerSecond))
		if remaining := target - time.Since(started); remaining > 0 {
			sleepContext(ctx, remaining)
		}
	}
	return true, nil
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
