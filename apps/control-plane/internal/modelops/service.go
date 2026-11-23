package modelops

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"sort"
	"sync"
	"time"
)

type Service struct {
	store    Store
	executor Executor
	now      func() time.Time
	perfMu   sync.Mutex
	perf     map[string]portalPerfEntry
}

func NewService(store Store, executor Executor) *Service {
	return &Service{store: store, executor: executor}
}
func (s *Service) Config(ctx context.Context, tenant string) (Config, error) {
	return s.store.GetConfig(ctx, tenant)
}
func (s *Service) UpdateConfig(ctx context.Context, tenant, actor string, version int64, cfg Config, confirm bool) (Config, error) {
	if tenant == "" || actor == "" || version < 1 {
		return Config{}, ErrInvalid
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	if cfg.Enabled && !confirm {
		return Config{}, ErrCostConfirmation
	}
	return s.store.UpdateConfig(ctx, tenant, actor, version, cfg, confirm)
}
func (s *Service) Targets(ctx context.Context, tenant string) ([]Target, error) {
	return s.store.ListManualTargets(ctx, tenant, nil)
}
func (s *Service) Overview(ctx context.Context, tenant string) (Overview, error) {
	return s.OverviewFiltered(ctx, tenant, ReadFilter{})
}
func (s *Service) OverviewFiltered(ctx context.Context, tenant string, f ReadFilter) (Overview, error) {
	f, err := f.validated()
	if err != nil {
		return Overview{}, err
	}
	return s.store.GetOverview(ctx, tenant, f)
}
func (s *Service) History(ctx context.Context, tenant string, f HistoryFilter) (HistoryPage, error) {
	return s.store.ListHistory(ctx, tenant, f)
}
func (s *Service) Quality(ctx context.Context, tenant string) (Quality, error) {
	return s.QualityFiltered(ctx, tenant, ReadFilter{})
}
func (s *Service) QualityFiltered(ctx context.Context, tenant string, f ReadFilter) (Quality, error) {
	f, err := f.validated()
	if err != nil {
		return Quality{}, err
	}
	return s.store.GetQuality(ctx, tenant, f)
}
func (s *Service) Alerts(ctx context.Context, tenant string, f AlertFilter) (AlertPage, error) {
	return s.store.ListAlerts(ctx, tenant, f)
}
func (s *Service) AcknowledgeAlert(ctx context.Context, tenant, id, actor string) (Alert, error) {
	if actor == "" || id == "" {
		return Alert{}, ErrInvalid
	}
	return s.store.AcknowledgeAlert(ctx, tenant, id, actor)
}

func (s *Service) Test(ctx context.Context, tenant, actor string, req TestRequest) (TestResult, error) {
	if !req.ConfirmCost {
		return TestResult{}, ErrCostConfirmation
	}
	if tenant == "" || actor == "" || len(req.ModelIDs) == 0 || len(req.ModelIDs) > 50 {
		return TestResult{}, ErrInvalid
	}
	if len(req.Protocols) > 0 {
		if err := ValidateProtocols(req.Protocols); err != nil {
			return TestResult{}, err
		}
	}
	cfg, err := s.Config(ctx, tenant)
	if err != nil {
		return TestResult{}, err
	}
	if req.ExpectedConfigVersion != cfg.Version {
		return TestResult{}, ErrConflict
	}
	if invocationID(ctx) == "" {
		ctx = WithInvocation(ctx, uuid.NewString())
	}
	all, err := s.store.ListManualTargets(ctx, tenant, req.Protocols)
	if err != nil {
		return TestResult{}, err
	}
	wanted := map[string]bool{}
	for _, id := range req.ModelIDs {
		if id == "" || wanted[id] {
			return TestResult{}, ErrInvalid
		}
		wanted[id] = true
	}
	targets := make([]Target, 0)
	seen := map[string]bool{}
	for _, t := range all {
		if wanted[t.ModelID] {
			if identities := targetIdentities(ctx); identities != nil && identities[t.ModelID] != t.IdentityDigest {
				return TestResult{}, ErrIdentityChanged
			}
			t.MaxOutputTokens = cfg.MaxOutputTokens
			t.TimeoutSeconds = cfg.TimeoutSeconds
			t.ConfigVersion = cfg.Version
			targets = append(targets, t)
			seen[t.ModelID] = true
		}
	}
	if len(seen) != len(wanted) {
		return TestResult{}, ErrUnavailable
	}
	if len(targets) > 50 {
		return TestResult{}, fmt.Errorf("%w: maximum 50 protocol requests", ErrInvalid)
	}
	if s.executor == nil {
		return TestResult{}, ErrUnavailable
	}
	items := make([]ProbeRecord, 0, len(targets))
	skipped := []SkippedTarget{}
	var mu sync.Mutex
	blocked := map[string]bool{}
	started := map[string]bool{}
	// One worker owns a provider so an auth failure cannot race its next probe.
	groups := groupTargets(targets)
	err = runGroups(ctx, 2, groups, func(workCtx context.Context, group []Target) error {
		for _, t := range group {
			if !ProtocolSupported(t.ProviderType, t.Protocol) {
				mu.Lock()
				skipped = append(skipped, SkippedTarget{Target: t, Reason: "unsupported"})
				mu.Unlock()
				continue
			}
			mu.Lock()
			skip := blocked[t.ProviderID]
			if skip {
				skipped = append(skipped, SkippedTarget{Target: t, Reason: "provider_auth_failed"})
			}
			mu.Unlock()
			if skip {
				continue
			}
			if err := workCtx.Err(); err != nil {
				return err
			}
			current, err := s.Config(workCtx, tenant)
			if err != nil {
				return err
			}
			if current.Version != cfg.Version {
				return ErrConflict
			}
			claimed, err := s.store.BeginManualTarget(workCtx, tenant, actor, t)
			if err != nil {
				return err
			}
			if !claimed {
				return ErrConflict
			}
			if err := workCtx.Err(); err != nil {
				return err
			}
			mu.Lock()
			started[t.Key()] = true
			mu.Unlock()
			probeCtx, cancel := context.WithTimeout(workCtx, time.Duration(cfg.TimeoutSeconds)*time.Second)
			o := s.executor.Execute(probeCtx, tenant, t).sanitized()
			cancel()
			if o.ErrorKind == "unsupported" {
				mu.Lock()
				skipped = append(skipped, SkippedTarget{Target: t, Reason: "unsupported"})
				mu.Unlock()
				continue
			}
			if o.ErrorKind == "config_changed" {
				return ErrIdentityChanged
			}
			record, err := s.store.RecordManual(workCtx, tenant, actor, t, o)
			if err != nil {
				return err
			}
			mu.Lock()
			items = append(items, record)
			if o.ErrorKind == "unauthorized" {
				blocked[t.ProviderID] = true
			}
			mu.Unlock()
		}
		return nil
	})
	if err != nil {
		known := map[string]bool{}
		for _, r := range items {
			known[r.Key()] = true
		}
		for _, r := range skipped {
			known[r.Key()] = true
		}
		for _, t := range targets {
			if known[t.Key()] {
				continue
			}
			reason := "worker_interrupted"
			if errors.Is(err, ErrConflict) || errors.Is(err, ErrIdentityChanged) {
				reason = "configuration_changed"
			} else if errors.Is(err, context.Canceled) {
				reason = "cancelled"
			}
			if started[t.Key()] {
				reason = "unknown_after_interruption"
			}
			skipped = append(skipped, SkippedTarget{Target: t, Reason: reason})
		}
		return TestResult{Items: items, Skipped: skipped}, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Key() < items[j].Key() })
	return TestResult{Items: items, Skipped: skipped}, nil
}

func groupTargets(targets []Target) [][]Target {
	groups := [][]Target{}
	idx := map[string]int{}
	for _, t := range targets {
		i, ok := idx[t.ProviderID]
		if !ok {
			i = len(groups)
			idx[t.ProviderID] = i
			groups = append(groups, []Target{})
		}
		groups[i] = append(groups[i], t)
	}
	return groups
}

func preferredTargets(targets []Target) []Target {
	out := []Target{}
	index := map[string]int{}
	for _, t := range targets {
		key := t.ModelID + "/" + t.ProviderID
		i, ok := index[key]
		if !ok {
			index[key] = len(out)
			out = append(out, t)
		} else if t.Protocol == t.PreferredProtocol {
			out[i] = t
		}
	}
	return out
}
func runGroups(ctx context.Context, n int, groups [][]Target, fn func(context.Context, []Target) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan []Target)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for g := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := fn(ctx, g); err != nil {
					select {
					case errs <- err:
					default:
					}
					cancel()
					return
				}
			}
		}()
	}
loop:
	for _, g := range groups {
		select {
		case jobs <- g:
		case <-ctx.Done():
			break loop
		}
	}
	close(jobs)
	wg.Wait()
	select {
	case err := <-errs:
		return err
	default:
		return ctx.Err()
	}
}
