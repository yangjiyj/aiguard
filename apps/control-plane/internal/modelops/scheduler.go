package modelops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

func rotateTargets(targets []Target, cursor string) []Target {
	targets = append([]Target(nil), targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].Key() < targets[j].Key() })
	i := sort.Search(len(targets), func(i int) bool { return targets[i].Key() > cursor })
	return append(targets[i:], targets[:i]...)
}

// Run may execute on every replica; the database lease fences each tenant batch.
func (s *Service) Run(ctx context.Context, owner string) error {
	if owner == "" || s.executor == nil {
		return ErrInvalid
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if err := s.Tick(ctx, owner); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Error("model operations scheduler batch failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (s *Service) Tick(ctx context.Context, owner string) error {
	ids, err := s.store.ListEnabledTenants(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, tenant := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		lease, err := s.store.AcquireLease(ctx, tenant, owner)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if lease == nil {
			continue
		}
		if err = s.RunLease(ctx, lease); err != nil && first == nil {
			first = err
		}
	}
	return first
}
func (s *Service) RunLease(ctx context.Context, l *Lease) error {
	batchCtx, cancel := context.WithCancel(WithInvocation(ctx, l.Token))
	defer cancel()
	stop := make(chan struct{})
	renewed := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				renewed <- nil
				return
			case <-batchCtx.Done():
				renewed <- batchCtx.Err()
				return
			case <-ticker.C:
				renewCtx, done := context.WithTimeout(batchCtx, 2*time.Second)
				err := s.store.RenewLease(renewCtx, l)
				done()
				if err != nil {
					cancel()
					renewed <- err
					return
				}
			}
		}
	}()
	targets, err := s.store.ListTargets(batchCtx, l.TenantID, l.Config.Protocols)
	targets = preferredTargets(targets)
	cursor := l.Cursor
	selected := []Target{}
	if err == nil {
		for _, t := range rotateTargets(targets, l.Cursor) {
			if !ProtocolSupported(t.ProviderType, t.Protocol) {
				continue
			}
			if len(selected) >= l.Config.MaxTargets {
				break
			}
			if batchCtx.Err() != nil {
				err = batchCtx.Err()
				break
			}
			cursor = t.Key()
			var claimed bool
			claimed, err = s.store.ClaimTarget(batchCtx, l, t)
			if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrIdentityChanged) {
				err = nil
				continue
			}
			if err != nil {
				break
			}
			if claimed {
				t.MaxOutputTokens = l.Config.MaxOutputTokens
				t.TimeoutSeconds = l.Config.TimeoutSeconds
				selected = append(selected, t)
			}
		}
	}
	if err == nil {
		var mu sync.Mutex
		blocked := map[string]bool{}
		err = runGroups(batchCtx, l.Config.Concurrency, groupTargets(selected), func(workCtx context.Context, group []Target) error {
			for _, t := range group {
				if err := workCtx.Err(); err != nil {
					return err
				}
				mu.Lock()
				skip := blocked[t.ProviderID]
				mu.Unlock()
				if skip {
					continue
				}
				if err := s.store.BeginScheduledDispatch(workCtx, l, t); err != nil {
					if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrIdentityChanged) {
						continue
					}
					return err
				}
				probeCtx, done := context.WithTimeout(workCtx, time.Duration(l.Config.TimeoutSeconds)*time.Second)
				o := s.executor.Execute(probeCtx, l.TenantID, t).sanitized()
				done()
				if o.ErrorKind == "config_changed" {
					continue
				}
				if o.ErrorKind == "unsupported" {
					continue
				}
				if _, err := s.store.Complete(workCtx, l, t, o); err != nil {
					if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrIdentityChanged) {
						continue
					}
					cancel()
					return err
				}
				if o.ErrorKind == "unauthorized" {
					mu.Lock()
					blocked[t.ProviderID] = true
					mu.Unlock()
				}
			}
			return nil
		})
	}
	close(stop)
	renewErr := <-renewed
	if renewErr != nil {
		err = renewErr
	}
	// An expired/replaced epoch is never released on behalf of the new owner.
	cleanupCtx, done := context.WithTimeout(context.Background(), 3*time.Second)
	defer done()
	releaseErr := s.store.ReleaseLease(cleanupCtx, l, cursor)
	if err != nil {
		return err
	}
	if releaseErr != nil {
		return fmt.Errorf("release model operations batch: %w", releaseErr)
	}
	return nil
}
