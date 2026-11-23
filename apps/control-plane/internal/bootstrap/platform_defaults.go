package bootstrap

import (
	"context"
	"fmt"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const (
	defaultTenantID  = "tenant_default"
	defaultUserID    = "user_admin"
	defaultRuleSetID = "ruleset_default"
)

type RuleSetRepo interface {
	Ensure(ctx context.Context, tenantID string, ruleSet *repository.RuleSet) (*repository.RuleSet, bool, error)
}

type RuleRepo interface {
	SeedDefaultSubRules(ctx context.Context, tenantID, ruleSetID string) (int, error)
}

type TenantLister interface {
	ListSecurityPolicyTenantIDs(ctx context.Context) ([]string, error)
}

func EnsureTenantPolicyDefaults(ctx context.Context, tenantID, createdBy string, ruleSetRepo RuleSetRepo, ruleRepo RuleRepo) error {
	ruleSetID := repository.DefaultSecurityRuleSetID(tenantID)
	ruleSet := &repository.RuleSet{
		ID: ruleSetID, TenantID: tenantID, Name: "默认安全策略", Version: "1.0.0",
		SourceType: "system", Published: true, CreatedBy: createdBy,
	}
	if _, _, err := ruleSetRepo.Ensure(ctx, tenantID, ruleSet); err != nil {
		return fmt.Errorf("ensure tenant policy rule set: %w", err)
	}
	if _, err := ruleRepo.SeedDefaultSubRules(ctx, tenantID, ruleSetID); err != nil {
		return fmt.Errorf("seed tenant policy catalog: %w", err)
	}
	return nil
}

func EnsureAllTenantPolicyDefaults(ctx context.Context, tenants TenantLister, ruleSetRepo RuleSetRepo, ruleRepo RuleRepo) error {
	tenantIDs, err := tenants.ListSecurityPolicyTenantIDs(ctx)
	if err != nil {
		return fmt.Errorf("list tenants for policy backfill: %w", err)
	}
	for _, tenantID := range tenantIDs {
		if err := EnsureTenantPolicyDefaults(ctx, tenantID, "system", ruleSetRepo, ruleRepo); err != nil {
			return fmt.Errorf("backfill security policies for tenant %s: %w", tenantID, err)
		}
	}
	return nil
}

func EnsurePlatformDefaults(ctx context.Context, ruleSetRepo RuleSetRepo, ruleRepo RuleRepo) error {
	defaultRuleSet := &repository.RuleSet{
		ID:         defaultRuleSetID,
		TenantID:   defaultTenantID,
		Name:       "默认安全策略",
		Version:    "1.0.0",
		SourceType: "system",
		Published:  true,
		CreatedBy:  defaultUserID,
	}
	if _, _, err := ruleSetRepo.Ensure(ctx, defaultTenantID, defaultRuleSet); err != nil {
		return fmt.Errorf("ensure default rule set: %w", err)
	}

	if _, err := ruleRepo.SeedDefaultSubRules(ctx, defaultTenantID, defaultRuleSetID); err != nil {
		return fmt.Errorf("seed default rules: %w", err)
	}

	return nil
}
