package rollup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

type TenantSource interface {
	ActiveTenantIDs(ctx context.Context) ([]string, error)
}

type Refresher interface {
	Refresh(ctx context.Context, tenantID string, from, to time.Time) error
}

type Config struct {
	Interval time.Duration
	Lookback time.Duration
	Now      func() time.Time
	Logger   *slog.Logger
}

type Runner struct {
	tenants   TenantSource
	refresher Refresher
	interval  time.Duration
	lookback  time.Duration
	now       func() time.Time
	logger    *slog.Logger
}

func NewRunner(tenants TenantSource, refresher Refresher, cfg Config) *Runner {
	lookback := cfg.Lookback
	if lookback <= 0 {
		lookback = 2 * time.Hour
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Runner{
		tenants:   tenants,
		refresher: refresher,
		interval:  cfg.Interval,
		lookback:  lookback,
		now:       now,
		logger:    cfg.Logger,
	}
}

func (r *Runner) Run(ctx context.Context) {
	if r == nil || r.interval <= 0 || r.tenants == nil || r.refresher == nil {
		return
	}
	r.runAndLog(ctx)
	ticker := time.NewTicker(r.interval)
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

func (r *Runner) RunOnce(ctx context.Context) error {
	if r == nil || r.tenants == nil || r.refresher == nil {
		return errors.New("rollup runner dependencies are required")
	}
	tenantIDs, err := r.tenants.ActiveTenantIDs(ctx)
	if err != nil {
		return err
	}
	from, to := refreshWindow(r.now(), r.lookback)
	var errs []error
	for _, tenantID := range tenantIDs {
		if err := r.refresher.Refresh(ctx, tenantID, from, to); err != nil {
			errs = append(errs, fmt.Errorf("refresh tenant %s: %w", tenantID, err))
		}
	}
	return errors.Join(errs...)
}

func (r *Runner) runAndLog(ctx context.Context) {
	if err := r.RunOnce(ctx); err != nil && r.logger != nil {
		r.logger.Error("rollup refresh failed", "error", err)
	}
}

func refreshWindow(now time.Time, lookback time.Duration) (time.Time, time.Time) {
	if lookback <= 0 {
		lookback = 2 * time.Hour
	}
	to := now.UTC().Truncate(time.Hour).Add(time.Hour)
	return to.Add(-lookback), to
}
