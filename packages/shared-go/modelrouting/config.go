package modelrouting

import (
	"fmt"
	"math"
	"strings"
)

const SchemaVersion = 2

type Scope string

const (
	ScopeDefault  Scope = "default"
	ScopeOverride Scope = "override"
)

type Strategy string

const (
	StrategyPriority Strategy = "priority"
	StrategyWeighted Strategy = "weighted"
	StrategySmart    Strategy = "smart"
	StrategyFixed    Strategy = "fixed"
)

type Objective string

const (
	ObjectiveStability Objective = "stability"
	ObjectiveLatency   Objective = "latency"
	ObjectiveCost      Objective = "cost"
	ObjectiveBalanced  Objective = "balanced"
	ObjectiveCustom    Objective = "custom"
)

type CostBasis string

const (
	CostNone     CostBasis = "none"
	CostRelative CostBasis = "relative"
	CostActual   CostBasis = "actual"
)

type CostLevel string

const (
	CostLow    CostLevel = "low"
	CostMedium CostLevel = "medium"
	CostHigh   CostLevel = "high"
)

type TokenPrice struct {
	Currency         string  `json:"currency"`
	InputPerMillion  float64 `json:"input_per_million"`
	OutputPerMillion float64 `json:"output_per_million"`
}

type ProviderRule struct {
	ProviderID   string      `json:"provider_id"`
	Enabled      bool        `json:"enabled"`
	Priority     int         `json:"priority"`
	Weight       int         `json:"weight"`
	RelativeCost CostLevel   `json:"relative_cost,omitempty"`
	ActualCost   *TokenPrice `json:"actual_cost,omitempty"`
}

type Config struct {
	Strategy        Strategy       `json:"strategy"`
	Objective       Objective      `json:"objective,omitempty"`
	CustomOrder     []Objective    `json:"custom_order,omitempty"`
	CostBasis       CostBasis      `json:"cost_basis"`
	FixedProviderID string         `json:"fixed_provider_id,omitempty"`
	Providers       []ProviderRule `json:"providers"`
}

const ExplicitSchemaVersion int16 = 3

type Mode string

const (
	ModeFailover Mode = "failover"
	ModeWeighted Mode = "weighted"
	ModeDynamic  Mode = "dynamic"
)

type FailureCategory string

const (
	FailureTimeout          FailureCategory = "timeout"
	FailureRateLimited      FailureCategory = "rate_limited"
	FailureUpstream5xx      FailureCategory = "upstream_5xx"
	FailureTemporaryNetwork FailureCategory = "temporary_network"
	FailureSecurityRejected FailureCategory = "security_rejected"
)

type RouteRule struct {
	ProviderID    string      `json:"provider_id"`
	Enabled       bool        `json:"enabled"`
	Priority      int         `json:"priority,omitempty"`
	Weight        int         `json:"weight,omitempty"`
	AdminPriority int         `json:"admin_priority,omitempty"`
	RelativeCost  CostLevel   `json:"relative_cost,omitempty"`
	ActualCost    *TokenPrice `json:"actual_cost,omitempty"`
}

type FactorWeights struct {
	Stability     int `json:"stability"`
	Latency       int `json:"latency"`
	Cost          int `json:"cost"`
	AdminPriority int `json:"admin_priority"`
}

type FailurePolicy struct {
	RetryOn          []FailureCategory `json:"retry_on"`
	RejoinOnRecovery bool              `json:"rejoin_on_recovery"`
	RestorePrimary   bool              `json:"restore_primary"`
}

type ExplicitConfig struct {
	Mode          Mode          `json:"mode"`
	Routes        []RouteRule   `json:"routes"`
	Factors       FactorWeights `json:"factors,omitempty"`
	FailurePolicy FailurePolicy `json:"failure_policy"`
}

func (c Config) Validate(scope Scope) error {
	if !validScope(scope) {
		return fmt.Errorf("modelrouting: unknown scope %q", scope)
	}
	if !validStrategy(c.Strategy) {
		return fmt.Errorf("modelrouting: unknown strategy %q", c.Strategy)
	}
	if c.Objective != "" && !validObjective(c.Objective) {
		return fmt.Errorf("modelrouting: unknown objective %q", c.Objective)
	}
	if c.Strategy == StrategySmart && c.Objective == "" {
		return fmt.Errorf("modelrouting: smart strategy requires objective")
	}
	if c.CostBasis != "" && !validCostBasis(c.CostBasis) {
		return fmt.Errorf("modelrouting: unknown cost basis %q", c.CostBasis)
	}
	if scope == ScopeDefault && c.Strategy == StrategyFixed {
		return fmt.Errorf("modelrouting: default scope cannot use fixed strategy")
	}
	if err := validateCustomOrder(c.Strategy, c.Objective, c.CustomOrder); err != nil {
		return err
	}

	enabledByID := make(map[string]ProviderRule)
	enabledProviders := make([]ProviderRule, 0, len(c.Providers))
	seen := make(map[string]struct{}, len(c.Providers))
	for i, provider := range c.Providers {
		trimmedProviderID := strings.TrimSpace(provider.ProviderID)
		if trimmedProviderID == "" {
			return fmt.Errorf("modelrouting: provider at index %d has empty provider_id", i)
		}
		if provider.ProviderID != trimmedProviderID {
			return fmt.Errorf("modelrouting: provider_id %q has surrounding whitespace", provider.ProviderID)
		}
		if _, exists := seen[provider.ProviderID]; exists {
			return fmt.Errorf("modelrouting: duplicate provider_id %q", provider.ProviderID)
		}
		seen[provider.ProviderID] = struct{}{}

		if provider.RelativeCost != "" && !validCostLevel(provider.RelativeCost) {
			return fmt.Errorf("modelrouting: provider %q has unknown relative_cost %q", provider.ProviderID, provider.RelativeCost)
		}
		if provider.ActualCost != nil {
			if err := validateTokenPrice(provider.ProviderID, provider.ActualCost); err != nil {
				return err
			}
		}
		if provider.Enabled {
			enabledByID[provider.ProviderID] = provider
			enabledProviders = append(enabledProviders, provider)
		}
	}

	switch c.Strategy {
	case StrategyPriority:
		if len(enabledProviders) == 0 {
			return fmt.Errorf("modelrouting: priority strategy requires an enabled provider")
		}
		for _, provider := range enabledProviders {
			if provider.Priority <= 0 {
				return fmt.Errorf("modelrouting: enabled provider %q must have positive priority", provider.ProviderID)
			}
		}
	case StrategyWeighted:
		if len(enabledProviders) == 0 {
			return fmt.Errorf("modelrouting: weighted strategy requires an enabled provider")
		}
		for _, provider := range enabledProviders {
			if provider.Weight <= 0 {
				return fmt.Errorf("modelrouting: enabled provider %q must have positive weight", provider.ProviderID)
			}
		}
	case StrategySmart:
		if len(enabledProviders) == 0 {
			return fmt.Errorf("modelrouting: smart strategy requires an enabled provider")
		}
	case StrategyFixed:
		trimmedFixedProviderID := strings.TrimSpace(c.FixedProviderID)
		if trimmedFixedProviderID == "" {
			return fmt.Errorf("modelrouting: fixed strategy requires fixed_provider_id")
		}
		if c.FixedProviderID != trimmedFixedProviderID {
			return fmt.Errorf("modelrouting: fixed_provider_id %q has surrounding whitespace", c.FixedProviderID)
		}
		if len(c.Providers) > 0 {
			if _, ok := enabledByID[c.FixedProviderID]; !ok {
				return fmt.Errorf("modelrouting: fixed provider %q is not enabled", c.FixedProviderID)
			}
		}
	}

	if c.Strategy == StrategySmart && c.Objective == ObjectiveCost {
		if c.CostBasis == "" || c.CostBasis == CostNone {
			return fmt.Errorf("modelrouting: cost objective requires a cost basis")
		}
		if err := validateComparableCosts(c.CostBasis, enabledProviders); err != nil {
			return err
		}
	}

	return nil
}

func (c ExplicitConfig) Validate() error {
	if !validMode(c.Mode) {
		return fmt.Errorf("modelrouting: unknown explicit mode %q", c.Mode)
	}

	enabledRoutes := make([]RouteRule, 0, len(c.Routes))
	seenProviders := make(map[string]struct{}, len(c.Routes))
	for i, route := range c.Routes {
		providerID := strings.TrimSpace(route.ProviderID)
		if providerID == "" {
			return fmt.Errorf("modelrouting: explicit route at index %d has empty provider_id", i)
		}
		if route.ProviderID != providerID {
			return fmt.Errorf("modelrouting: explicit provider_id %q has surrounding whitespace", route.ProviderID)
		}
		if _, exists := seenProviders[route.ProviderID]; exists {
			return fmt.Errorf("modelrouting: duplicate explicit provider_id %q", route.ProviderID)
		}
		seenProviders[route.ProviderID] = struct{}{}
		if route.Enabled {
			enabledRoutes = append(enabledRoutes, route)
		}
	}
	if len(enabledRoutes) < 2 {
		return fmt.Errorf("modelrouting: explicit config requires at least two enabled routes")
	}

	switch c.Mode {
	case ModeFailover:
		seenPriorities := make(map[int]struct{}, len(enabledRoutes))
		for _, route := range enabledRoutes {
			if route.Priority <= 0 {
				return fmt.Errorf("modelrouting: enabled explicit route %q must have positive priority", route.ProviderID)
			}
			if _, exists := seenPriorities[route.Priority]; exists {
				return fmt.Errorf("modelrouting: enabled explicit routes have duplicate priority %d", route.Priority)
			}
			seenPriorities[route.Priority] = struct{}{}
		}
	case ModeWeighted:
		totalWeight := 0
		for _, route := range enabledRoutes {
			if route.Weight < 0 {
				return fmt.Errorf("modelrouting: enabled explicit route %q weight cannot be negative", route.ProviderID)
			}
			if route.Weight == 0 {
				return fmt.Errorf("modelrouting: enabled explicit route %q must have positive weight", route.ProviderID)
			}
			if route.Weight > 100 {
				return fmt.Errorf("modelrouting: enabled explicit route %q weight cannot exceed 100", route.ProviderID)
			}
			totalWeight += route.Weight
		}
		if totalWeight != 100 {
			return fmt.Errorf("modelrouting: enabled explicit route weights must total 100, got %d", totalWeight)
		}
	case ModeDynamic:
		factors := []struct {
			name  string
			value int
		}{
			{"stability", c.Factors.Stability}, {"latency", c.Factors.Latency},
			{"cost", c.Factors.Cost}, {"admin_priority", c.Factors.AdminPriority},
		}
		for _, factor := range factors {
			if factor.value < 0 {
				return fmt.Errorf("modelrouting: explicit dynamic factor %s cannot be negative", factor.name)
			}
			if factor.value > 100 {
				return fmt.Errorf("modelrouting: explicit dynamic factor %s cannot exceed 100", factor.name)
			}
		}
		totalFactors := c.Factors.Stability + c.Factors.Latency + c.Factors.Cost + c.Factors.AdminPriority
		if totalFactors != 100 {
			return fmt.Errorf("modelrouting: explicit dynamic factor weights must total 100, got %d", totalFactors)
		}
		if c.Factors.Cost > 0 {
			if err := validateExplicitComparableCosts(enabledRoutes); err != nil {
				return err
			}
		}
		if c.Factors.AdminPriority > 0 {
			seenPriorities := make(map[int]struct{}, len(enabledRoutes))
			for _, route := range enabledRoutes {
				if route.AdminPriority <= 0 {
					return fmt.Errorf("modelrouting: enabled explicit route %q must have positive admin_priority", route.ProviderID)
				}
				if _, exists := seenPriorities[route.AdminPriority]; exists {
					return fmt.Errorf("modelrouting: enabled explicit routes have duplicate admin_priority %d", route.AdminPriority)
				}
				seenPriorities[route.AdminPriority] = struct{}{}
			}
		}
	}

	seenRetryCategories := make(map[FailureCategory]struct{}, len(c.FailurePolicy.RetryOn))
	for _, category := range c.FailurePolicy.RetryOn {
		if !isRetryableFailureCategory(category) {
			return fmt.Errorf("modelrouting: failure category %q is not retryable", category)
		}
		if _, exists := seenRetryCategories[category]; exists {
			return fmt.Errorf("modelrouting: duplicate retry failure category %q", category)
		}
		seenRetryCategories[category] = struct{}{}
	}
	return nil
}

func validateExplicitComparableCosts(routes []RouteRule) error {
	allRelative := true
	allActual := true
	var currency string
	for _, route := range routes {
		if route.RelativeCost != "" && !validCostLevel(route.RelativeCost) {
			return fmt.Errorf("modelrouting: enabled explicit route %q has unknown relative cost %q", route.ProviderID, route.RelativeCost)
		}
		if route.ActualCost != nil {
			if err := validateTokenPrice(route.ProviderID, route.ActualCost); err != nil {
				return err
			}
			if math.IsNaN(route.ActualCost.InputPerMillion) || math.IsInf(route.ActualCost.InputPerMillion, 0) ||
				math.IsNaN(route.ActualCost.OutputPerMillion) || math.IsInf(route.ActualCost.OutputPerMillion, 0) {
				return fmt.Errorf("modelrouting: provider %q actual cost must be finite", route.ProviderID)
			}
		}
		if !validCostLevel(route.RelativeCost) {
			allRelative = false
		}
		if route.ActualCost == nil {
			allActual = false
			continue
		}
		if currency == "" {
			currency = route.ActualCost.Currency
		} else if route.ActualCost.Currency != currency {
			return fmt.Errorf("modelrouting: enabled explicit routes have an actual cost currency mismatch")
		}
	}
	if !allRelative && !allActual {
		return fmt.Errorf("modelrouting: every enabled explicit route requires comparable cost information")
	}
	return nil
}

func validMode(mode Mode) bool {
	switch mode {
	case ModeFailover, ModeWeighted, ModeDynamic:
		return true
	default:
		return false
	}
}

func isRetryableFailureCategory(category FailureCategory) bool {
	switch category {
	case FailureTimeout, FailureRateLimited, FailureUpstream5xx, FailureTemporaryNetwork:
		return true
	default:
		return false
	}
}

func validateCustomOrder(strategy Strategy, objective Objective, order []Objective) error {
	if strategy != StrategySmart || objective != ObjectiveCustom {
		return nil
	}
	if len(order) != 3 {
		return fmt.Errorf("modelrouting: custom objective requires exactly three ordering entries")
	}
	want := map[Objective]struct{}{
		ObjectiveStability: {},
		ObjectiveLatency:   {},
		ObjectiveCost:      {},
	}
	for _, item := range order {
		if _, ok := want[item]; !ok {
			return fmt.Errorf("modelrouting: invalid or duplicate custom objective %q", item)
		}
		delete(want, item)
	}
	return nil
}

func validateTokenPrice(providerID string, price *TokenPrice) error {
	if strings.TrimSpace(price.Currency) == "" {
		return fmt.Errorf("modelrouting: provider %q actual cost requires currency", providerID)
	}
	if price.InputPerMillion < 0 || price.OutputPerMillion < 0 {
		return fmt.Errorf("modelrouting: provider %q actual cost cannot be negative", providerID)
	}
	return nil
}

func validateComparableCosts(basis CostBasis, enabledProviders []ProviderRule) error {
	var currency string
	for _, provider := range enabledProviders {
		switch basis {
		case CostRelative:
			if !validCostLevel(provider.RelativeCost) {
				return fmt.Errorf("modelrouting: enabled provider %q requires relative_cost", provider.ProviderID)
			}
		case CostActual:
			if provider.ActualCost == nil {
				return fmt.Errorf("modelrouting: enabled provider %q requires actual_cost", provider.ProviderID)
			}
			if currency == "" {
				currency = provider.ActualCost.Currency
			} else if provider.ActualCost.Currency != currency {
				return fmt.Errorf("modelrouting: enabled providers use mixed actual cost currencies")
			}
		}
	}
	return nil
}

func validScope(scope Scope) bool {
	return scope == ScopeDefault || scope == ScopeOverride
}

func validStrategy(strategy Strategy) bool {
	switch strategy {
	case StrategyPriority, StrategyWeighted, StrategySmart, StrategyFixed:
		return true
	default:
		return false
	}
}

func validObjective(objective Objective) bool {
	switch objective {
	case ObjectiveStability, ObjectiveLatency, ObjectiveCost, ObjectiveBalanced, ObjectiveCustom:
		return true
	default:
		return false
	}
}

func validCostBasis(basis CostBasis) bool {
	return basis == CostNone || basis == CostRelative || basis == CostActual
}

func validCostLevel(level CostLevel) bool {
	return level == CostLow || level == CostMedium || level == CostHigh
}
