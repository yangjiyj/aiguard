package org

import (
	"context"
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// Service provides org-level business logic: EffectiveQuota funnel and team depth validation.
type Service struct {
	teams       *repository.TeamRepository
	members     *repository.TeamMemberRepository
	quotaPolicy *repository.QuotaPolicyRepository
}

// NewService creates a new org.Service.
func NewService(
	teams *repository.TeamRepository,
	members *repository.TeamMemberRepository,
	qp *repository.QuotaPolicyRepository,
) *Service {
	return &Service{teams: teams, members: members, quotaPolicy: qp}
}

// EffectiveQuota collects all quota_policies along the scope path and returns
// the minimum (most-restrictive) value per dimension.
//
// Scope resolution order (lowest → tightest):
//
//	tenant → team ancestors (root first) → project → user → key
//
// TriggeredScope is set to the scope_type of the policy that imposed the
// tightest MonthlyTokenLimit. If MonthlyTokenLimit is unconstrained across
// all scopes, TriggeredScope reflects the last dimension that set any limit.
func (s *Service) EffectiveQuota(ctx context.Context, ref ScopeRef) (*EffectiveQuota, error) {
	var policies []*repository.QuotaPolicy

	// 1. Tenant-level
	if p, err := s.quotaPolicy.GetByScope(ctx, ref.TenantID, "tenant", "", "", "", ""); err != nil {
		return nil, fmt.Errorf("tenant quota: %w", err)
	} else if p != nil {
		policies = append(policies, p)
	}

	// 2. Team path — walk ancestors root-first so the deepest team wins on ties
	if ref.TeamID != "" {
		team, err := s.teams.GetByID(ctx, ref.TeamID)
		if err != nil {
			return nil, fmt.Errorf("get team: %w", err)
		}
		if team != nil {
			// Path looks like "/root_id/child_id/leaf_id"; split and skip empty segments
			for _, tid := range strings.Split(strings.Trim(team.Path, "/"), "/") {
				if tid == "" {
					continue
				}
				if p, err := s.quotaPolicy.GetByScope(ctx, ref.TenantID, "team", "", tid, "", ""); err != nil {
					return nil, fmt.Errorf("team quota (%s): %w", tid, err)
				} else if p != nil {
					policies = append(policies, p)
				}
			}
		}
	}

	// 3. Project
	if ref.ProjectID != "" {
		if p, err := s.quotaPolicy.GetByScope(ctx, ref.TenantID, "project", ref.ProjectID, "", "", ""); err != nil {
			return nil, fmt.Errorf("project quota: %w", err)
		} else if p != nil {
			policies = append(policies, p)
		}
	}

	// 4. User
	if ref.UserID != "" {
		if p, err := s.quotaPolicy.GetByScope(ctx, ref.TenantID, "user", "", "", ref.UserID, ""); err != nil {
			return nil, fmt.Errorf("user quota: %w", err)
		} else if p != nil {
			policies = append(policies, p)
		}
	}

	// 5. Stable key identity
	if ref.KeyID != "" {
		if p, err := s.quotaPolicy.GetByScope(ctx, ref.TenantID, "key", "", "", "", ref.KeyID); err != nil {
			return nil, fmt.Errorf("key quota: %w", err)
		} else if p != nil {
			policies = append(policies, p)
		}
	}

	eq := &EffectiveQuota{}
	for _, p := range policies {
		if p.MonthlyTokenLimit > 0 && (eq.MonthlyTokenLimit == 0 || p.MonthlyTokenLimit < eq.MonthlyTokenLimit) {
			eq.MonthlyTokenLimit = p.MonthlyTokenLimit
			eq.TriggeredScope = p.ScopeType
		}
		if p.DailyTokenLimit > 0 && (eq.DailyTokenLimit == 0 || p.DailyTokenLimit < eq.DailyTokenLimit) {
			eq.DailyTokenLimit = p.DailyTokenLimit
		}
		if monthly := policyBudgetMicros(p.MonthlyBudgetMicros); monthly > 0 && (eq.MonthlyBudgetMicros == 0 || monthly < eq.MonthlyBudgetMicros) {
			eq.MonthlyBudgetMicros = monthly
		}
		if daily := policyBudgetMicros(p.DailyBudgetMicros); daily > 0 && (eq.DailyBudgetMicros == 0 || daily < eq.DailyBudgetMicros) {
			eq.DailyBudgetMicros = daily
		}
		// Policies are appended from least to most specific scope.
		eq.QuotaTimezone = p.QuotaTimezone
		if p.RPMLimit > 0 && (eq.RPMLimit == 0 || p.RPMLimit < eq.RPMLimit) {
			eq.RPMLimit = p.RPMLimit
		}
		if p.ConcurrencyLimit > 0 && (eq.ConcurrencyLimit == 0 || p.ConcurrencyLimit < eq.ConcurrencyLimit) {
			eq.ConcurrencyLimit = p.ConcurrencyLimit
		}
	}
	return eq, nil
}

// ValidateTeamDepth returns an error when the materialised path exceeds 5 levels.
// Path is expected in the form "/id1/id2/id3", empty or root paths are depth 1.
func (s *Service) ValidateTeamDepth(path string) error {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil // root
	}
	depth := strings.Count(trimmed, "/") + 1
	if depth > 5 {
		return fmt.Errorf("team depth exceeds maximum of 5 (got %d): %s", depth, path)
	}
	return nil
}

// KeyAccountingTimezone returns the timezone the gateway accounts a key scope
// in, which is what selects the Redis budget bucket holding that key's usage.
//
// It is deliberately NOT derived from EffectiveQuota. EffectiveQuota merges the
// whole scope path and keeps only the most specific policy's timezone, but the
// gateway accounts each scope independently: atomicAdmissionScopes gives a
// scope the quota_timezone of a policy on THAT scope, and
// addAdmissionAccountingScopes falls back to DefaultAccountingTimezone for every
// scope with no effective policy. So with a tenant policy at
// America/New_York and no key policy, EffectiveQuota reports America/New_York
// while the gateway books the key into the Asia/Shanghai bucket — a reader
// trusting the merge queries a bucket the gateway never writes and reports the
// key's usage as a confident zero.
//
// The policy lookup mirrors gateway-core quota_cache.go key for a key scope, so
// the two cannot drift:
//
//   - stable key identity only: key_id = the key, never the legacy key_prefix
//     fallback that control-plane's GetByScope still carries (the gateway has
//     no such branch, so a prefix-matched policy would select a bucket the
//     gateway does not write);
//   - ownership: the key row must belong to the same tenant;
//   - only status = 'active' rows;
//   - canonical limit columns win over the legacy float columns, matching the
//     gateway's COALESCE(canonical, GREATEST(legacy, 0));
//   - a key policy only takes effect when it can actually gate something
//     (enforcement mode accounting, or any limit/blocked flag set), and the
//     last such policy by created_at wins its timezone — the same order and
//     the same effective-scope test as atomicAdmissionScopes.
//
// A key with no effective policy is not an error: that is the accounting
// default. The returned string is never empty.
func (s *Service) KeyAccountingTimezone(ctx context.Context, tenantID, keyID string) (string, error) {
	if tenantID == "" || keyID == "" {
		return DefaultAccountingTimezone, nil
	}
	return s.AccountingScopeTimezone(ctx, tenantID, "key", keyID)
}

// AccountingScopeTimezone selects the bucket for this scope only; no parent
// timezone is inherited. Policies use the same normalization as quota_cache.
func (s *Service) AccountingScopeOwned(ctx context.Context, tenantID, scopeType, scopeID string) (bool, error) {
	return s.quotaPolicy.AccountingScopeOwned(ctx, tenantID, scopeType, scopeID)
}

func (s *Service) AccountingScopeTimezone(ctx context.Context, tenantID, scopeType, scopeID string) (string, error) {
	policies, err := s.quotaPolicy.ListAccountingScopePolicies(ctx, tenantID, scopeType, scopeID)
	if err != nil {
		return "", err
	}
	// Merge gates by created_at like atomic admission. A later empty policy
	// changes timezone if earlier gates survive; accounting is not inherited.
	timezone := DefaultAccountingTimezone
	hasGate := false
	for _, p := range policies {
		gate := *p
		gate.EnforcementMode = "soft"
		hasGate = hasGate || keyPolicyIsEffective(&gate)
		if !hasGate && !keyPolicyIsEffective(p) {
			continue
		}
		timezone = strings.TrimSpace(p.QuotaTimezone)
		if timezone == "" {
			timezone = DefaultAccountingTimezone
		}
	}
	return timezone, nil
}

// keyPolicyIsEffective mirrors the entry test in atomicAdmissionScopes: a
// bypass is accounting, and quota_cache normalizes all other modes to soft,
// and a policy that neither gates nor is accounting leaves the scope on the
// accounting default (its timezone must not be borrowed).
func keyPolicyIsEffective(p *repository.QuotaPolicy) bool {
	mode := p.EnforcementMode
	if mode == "bypass" {
		mode = "accounting"
	}
	if mode != "enforce" && mode != "accounting" {
		mode = "soft"
	}
	if p.RPMLimit > 0 || p.RPMBlocked ||
		p.TPMLimit != nil && *p.TPMLimit > 0 || p.TPMBlocked ||
		p.ConcurrencyLimit > 0 || p.ConcurrencyBlocked ||
		p.DailyTokenLimit > 0 || p.DailyTokenBlocked ||
		p.MonthlyTokenLimit > 0 || p.MonthlyTokenBlocked ||
		p.DailyBudgetMicros != nil && *p.DailyBudgetMicros > 0 || p.DailyBudgetBlocked ||
		p.MonthlyBudgetMicros != nil && *p.MonthlyBudgetMicros > 0 || p.MonthlyBudgetBlocked {
		return true
	}
	return mode == "accounting"
}

// policyBudgetMicros reads the canonical integer budget column (migration 827).
// NULL means unconstrained; the legacy float column is never consulted.
func policyBudgetMicros(value *int64) int64 {
	if value == nil || *value < 0 {
		return 0
	}
	return *value
}
