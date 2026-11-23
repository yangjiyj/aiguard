package identitybinding

import (
	"context"
	"fmt"
	"time"
)

const (
	WorkerErrorStageCleanup = "cleanup_processed_invalidations"
	WorkerErrorStageProcess = "process_invalidation"
)

type ErrorObserver func(stage string, err error)

type ProcessedInvalidationCleaner interface {
	CleanupProcessedInvalidations(ctx context.Context, before time.Time, limit int) (int64, error)
}

type WorkerConfig struct {
	ErrorObserver   ErrorObserver
	EmptyBackoff    time.Duration
	FailureBackoff  time.Duration
	CleanupInterval time.Duration
	ProcessedTTL    time.Duration
	CleanupBatch    int
}

func (c WorkerConfig) withDefaults() WorkerConfig {
	if c.EmptyBackoff <= 0 {
		c.EmptyBackoff = time.Second
	}
	if c.FailureBackoff <= 0 {
		c.FailureBackoff = 5 * time.Second
	}
	if c.CleanupInterval <= 0 {
		c.CleanupInterval = time.Hour
	}
	if c.ProcessedTTL <= 0 {
		c.ProcessedTTL = 30 * 24 * time.Hour
	}
	if c.CleanupBatch <= 0 {
		c.CleanupBatch = 500
	}
	return c
}

func (r *Reconciler) Run(ctx context.Context, config WorkerConfig) error {
	if r == nil {
		return fmt.Errorf("%w: nil reconciler", ErrCacheInvalidation)
	}
	cleaner, ok := r.outbox.(ProcessedInvalidationCleaner)
	if !ok {
		return fmt.Errorf("%w: outbox cleanup unavailable", ErrCacheInvalidation)
	}
	config = config.withDefaults()
	nextCleanup := time.Now()

	for {
		if err := ctx.Err(); err != nil {
			if err == context.Canceled {
				return nil
			}
			return err
		}

		now := time.Now()
		if !now.Before(nextCleanup) {
			if _, err := cleaner.CleanupProcessedInvalidations(
				ctx, now.Add(-config.ProcessedTTL), config.CleanupBatch,
			); err != nil {
				observeWorkerError(config.ErrorObserver, WorkerErrorStageCleanup)
				if !waitForWorker(ctx, config.FailureBackoff) {
					return nil
				}
				continue
			}
			nextCleanup = now.Add(config.CleanupInterval)
		}

		processed, err := r.ProcessOne(ctx)
		switch {
		case err != nil:
			observeWorkerError(config.ErrorObserver, WorkerErrorStageProcess)
			if !waitForWorker(ctx, config.FailureBackoff) {
				return nil
			}
		case processed:
			continue
		default:
			if !waitForWorker(ctx, config.EmptyBackoff) {
				return nil
			}
		}
	}
}

func observeWorkerError(observer ErrorObserver, stage string) {
	if observer == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	var err error
	switch stage {
	case WorkerErrorStageCleanup:
		err = fmt.Errorf("%w: processed invalidation cleanup failed", ErrCacheInvalidation)
	default:
		err = fmt.Errorf("%w: invalidation processing failed", ErrCacheInvalidation)
	}
	observer(stage, err)
}

func waitForWorker(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
