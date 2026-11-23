package auditpipe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/outbox"
)

type Store interface {
	Claim(ctx context.Context, consumer string, limit int) ([]outbox.Event, error)
	MarkProcessed(ctx context.Context, id string) error
	MarkFailed(ctx context.Context, id string, cause error, maxAttempts int, nextAvailableAt time.Time) error
}

type Processor interface {
	Process(ctx context.Context, event outbox.Event) error
}

type Config struct {
	ConsumerName   string
	BatchSize      int
	PollInterval   time.Duration
	MaxAttempts    int
	RetryBaseDelay time.Duration
	Now            func() time.Time
	Logger         *slog.Logger
}

type Runner struct {
	store          Store
	processor      Processor
	consumerName   string
	batchSize      int
	pollInterval   time.Duration
	maxAttempts    int
	retryBaseDelay time.Duration
	now            func() time.Time
	logger         *slog.Logger
}

func NewRunner(store Store, processor Processor, cfg Config) *Runner {
	consumerName := cfg.ConsumerName
	if consumerName == "" {
		consumerName = "worker-1"
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = outbox.DefaultClaimLimit
	}
	maxAttempts := cfg.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = outbox.DefaultMaxAttempts
	}
	retryBaseDelay := cfg.RetryBaseDelay
	if retryBaseDelay <= 0 {
		retryBaseDelay = outbox.DefaultRetryBaseDelay
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Runner{
		store:          store,
		processor:      processor,
		consumerName:   consumerName,
		batchSize:      batchSize,
		pollInterval:   cfg.PollInterval,
		maxAttempts:    maxAttempts,
		retryBaseDelay: retryBaseDelay,
		now:            now,
		logger:         cfg.Logger,
	}
}

func (r *Runner) Run(ctx context.Context) {
	if r == nil || r.pollInterval <= 0 {
		return
	}
	r.runAndLog(ctx)
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runAndLog(ctx)
		}
	}
}

func (r *Runner) RunOnce(ctx context.Context) (int, error) {
	if r == nil || r.store == nil || r.processor == nil {
		return 0, errors.New("auditpipe runner dependencies are required")
	}
	events, err := r.store.Claim(ctx, r.consumerName, r.batchSize)
	if err != nil {
		return 0, err
	}
	var errs []error
	processed := 0
	for _, event := range events {
		if err := r.processor.Process(ctx, event); err != nil {
			next := r.nextAvailableAt(event.Attempts)
			if markErr := r.store.MarkFailed(ctx, event.ID, err, r.maxAttempts, next); markErr != nil {
				errs = append(errs, fmt.Errorf("mark failed %s: %w", event.ID, markErr))
			} else {
				errs = append(errs, fmt.Errorf("process %s: %w", event.ID, err))
			}
			continue
		}
		if err := r.store.MarkProcessed(ctx, event.ID); err != nil {
			errs = append(errs, fmt.Errorf("mark processed %s: %w", event.ID, err))
			continue
		}
		processed++
	}
	return processed, errors.Join(errs...)
}

func (r *Runner) runAndLog(ctx context.Context) {
	processed, err := r.RunOnce(ctx)
	if err != nil && r.logger != nil {
		r.logger.Error("audit outbox drain failed", "error", err)
	}
	if processed > 0 && r.logger != nil {
		r.logger.Info("audit outbox drained", "processed", processed)
	}
}

func (r *Runner) nextAvailableAt(attempts int) time.Time {
	return outbox.NextAvailableAt(r.now(), r.retryBaseDelay, attempts)
}
