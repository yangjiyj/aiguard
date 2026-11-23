package modelrouting

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestValidateRejectsFixedAndUnknownCostBasisForDefaultRule(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "fixed strategy",
			cfg: Config{
				Strategy:        StrategyFixed,
				Objective:       ObjectiveStability,
				CostBasis:       CostNone,
				FixedProviderID: "provider-a",
				Providers:       []ProviderRule{{ProviderID: "provider-a", Enabled: true}},
			},
		},
		{
			name: "unknown cost basis",
			cfg: Config{
				Strategy:  StrategyPriority,
				Objective: ObjectiveStability,
				CostBasis: CostBasis("estimated"),
				Providers: []ProviderRule{{ProviderID: "provider-a", Enabled: true, Priority: 1}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(ScopeDefault); err == nil {
				t.Fatal("Validate() error = nil, want rejection")
			}
		})
	}
}

func TestValidateAllowsFixedProviderForOverride(t *testing.T) {
	cfg := Config{
		Strategy:        StrategyFixed,
		FixedProviderID: "provider_a",
	}

	if err := cfg.Validate(ScopeOverride); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateFixedProviderAllowsEnabledConfiguredProvider(t *testing.T) {
	cfg := Config{
		Strategy:        StrategyFixed,
		FixedProviderID: "provider-a",
		Providers:       []ProviderRule{{ProviderID: "provider-a", Enabled: true}},
	}

	if err := cfg.Validate(ScopeOverride); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateFixedProviderRejectsMissingConfiguredProvider(t *testing.T) {
	cfg := Config{
		Strategy:        StrategyFixed,
		FixedProviderID: "provider-a",
		Providers:       []ProviderRule{{ProviderID: "provider-b", Enabled: true}},
	}

	requireValidateErrorContains(t, cfg, ScopeOverride, "provider-a", "enabled")
}

func TestValidateFixedProviderRejectsDisabledConfiguredProvider(t *testing.T) {
	cfg := Config{
		Strategy:        StrategyFixed,
		FixedProviderID: "provider-a",
		Providers:       []ProviderRule{{ProviderID: "provider-a", Enabled: false}},
	}

	requireValidateErrorContains(t, cfg, ScopeOverride, "provider-a", "enabled")
}

func TestValidateRejectsProviderIDWithSurroundingWhitespace(t *testing.T) {
	cfg := Config{
		Strategy: StrategyPriority,
		Providers: []ProviderRule{
			{ProviderID: "provider-a", Enabled: true, Priority: 1},
			{ProviderID: " provider-a ", Enabled: true, Priority: 2},
		},
	}

	requireValidateErrorContains(t, cfg, ScopeDefault, "provider_id", "whitespace")
}

func TestValidateRejectsFixedProviderIDWithSurroundingWhitespace(t *testing.T) {
	cfg := Config{
		Strategy:        StrategyFixed,
		FixedProviderID: " provider-a ",
	}

	requireValidateErrorContains(t, cfg, ScopeOverride, "fixed_provider_id", "whitespace")
}

func TestValidateReportsEnabledProviderErrorsInInputOrder(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		wantField string
	}{
		{
			name: "priority",
			cfg: Config{
				Strategy: StrategyPriority,
				Providers: []ProviderRule{
					{ProviderID: "provider-first", Enabled: true},
					{ProviderID: "provider-second", Enabled: true},
				},
			},
			wantField: "priority",
		},
		{
			name: "weighted",
			cfg: Config{
				Strategy: StrategyWeighted,
				Providers: []ProviderRule{
					{ProviderID: "provider-first", Enabled: true},
					{ProviderID: "provider-second", Enabled: true},
				},
			},
			wantField: "weight",
		},
		{
			name: "relative cost",
			cfg: Config{
				Strategy:  StrategySmart,
				Objective: ObjectiveCost,
				CostBasis: CostRelative,
				Providers: []ProviderRule{
					{ProviderID: "provider-first", Enabled: true},
					{ProviderID: "provider-second", Enabled: true},
				},
			},
			wantField: "relative_cost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for range 100 {
				requireValidateErrorContains(t, tt.cfg, ScopeDefault, "provider-first", tt.wantField)
			}
		})
	}
}

func TestValidateSmartRequiresObjective(t *testing.T) {
	cfg := Config{
		Strategy:  StrategySmart,
		Providers: []ProviderRule{{ProviderID: "provider-a", Enabled: true}},
	}

	if err := cfg.Validate(ScopeDefault); err == nil {
		t.Fatal("Validate() error = nil, want missing smart objective rejection")
	}

	cfg.Objective = ObjectiveStability
	if err := cfg.Validate(ScopeDefault); err != nil {
		t.Fatalf("Validate() error = %v, want empty cost basis accepted", err)
	}
}

func TestValidateNonSmartAllowsEmptyOrKnownObjective(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "priority ignores cost objective",
			cfg: Config{
				Strategy:  StrategyPriority,
				Objective: ObjectiveCost,
				Providers: []ProviderRule{{ProviderID: "provider-a", Enabled: true, Priority: 1}},
			},
		},
		{
			name: "weighted ignores custom objective",
			cfg: Config{
				Strategy:  StrategyWeighted,
				Objective: ObjectiveCustom,
				Providers: []ProviderRule{{ProviderID: "provider-a", Enabled: true, Weight: 1}},
			},
		},
		{
			name: "fixed ignores cost objective",
			cfg: Config{
				Strategy:        StrategyFixed,
				Objective:       ObjectiveCost,
				FixedProviderID: "provider-a",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(ScopeOverride); err != nil {
				t.Fatalf("known non-smart objective rejected: %v", err)
			}
		})
	}

	empty := Config{
		Strategy:  StrategyPriority,
		Providers: []ProviderRule{{ProviderID: "provider-a", Enabled: true, Priority: 1}},
	}
	if err := empty.Validate(ScopeDefault); err != nil {
		t.Fatalf("empty objective and cost basis rejected: %v", err)
	}

	empty.Objective = Objective("throughput")
	if err := empty.Validate(ScopeDefault); err == nil {
		t.Fatal("Validate() error = nil, want unknown non-empty objective rejection")
	}
}

func TestValidateCostPriorityRelativeRequiresEveryEnabledProviderCost(t *testing.T) {
	for _, missing := range []CostLevel{CostLow, CostMedium, CostHigh} {
		t.Run(string(missing), func(t *testing.T) {
			cfg := Config{
				Strategy:  StrategySmart,
				Objective: ObjectiveCost,
				CostBasis: CostRelative,
				Providers: []ProviderRule{
					{ProviderID: "provider-low", Enabled: true, Priority: 1, RelativeCost: CostLow},
					{ProviderID: "provider-medium", Enabled: true, Priority: 2, RelativeCost: CostMedium},
					{ProviderID: "provider-high", Enabled: true, Priority: 3, RelativeCost: CostHigh},
				},
			}
			for i := range cfg.Providers {
				if cfg.Providers[i].RelativeCost == missing {
					cfg.Providers[i].RelativeCost = ""
				}
			}

			requireValidateErrorContains(t, cfg, ScopeDefault, "provider-"+string(missing), "relative_cost")
		})
	}
}

func TestValidateActualCostAllowsCompleteSameCurrencyPrices(t *testing.T) {
	cfg := Config{
		Strategy:  StrategySmart,
		Objective: ObjectiveCost,
		CostBasis: CostActual,
		Providers: []ProviderRule{
			{
				ProviderID: "provider-a",
				Enabled:    true,
				Priority:   1,
				ActualCost: &TokenPrice{Currency: "CNY", InputPerMillion: 1.25, OutputPerMillion: 5},
			},
			{
				ProviderID: "provider-b",
				Enabled:    true,
				Priority:   2,
				ActualCost: &TokenPrice{Currency: "CNY", InputPerMillion: 2, OutputPerMillion: 8},
			},
			{
				ProviderID: "disabled-without-price",
				Enabled:    false,
				Priority:   3,
			},
		},
	}

	if err := cfg.Validate(ScopeDefault); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateRejectsInvalidContractValues(t *testing.T) {
	valid := func() Config {
		return Config{
			Strategy:  StrategyPriority,
			Objective: ObjectiveStability,
			CostBasis: CostNone,
			Providers: []ProviderRule{{ProviderID: "provider-a", Enabled: true, Priority: 1}},
		}
	}

	tests := []struct {
		name  string
		scope Scope
		edit  func(*Config)
	}{
		{name: "unknown scope", scope: Scope("tenant"), edit: func(*Config) {}},
		{name: "unknown strategy", scope: ScopeDefault, edit: func(c *Config) { c.Strategy = Strategy("random") }},
		{name: "unknown objective", scope: ScopeDefault, edit: func(c *Config) { c.Objective = Objective("throughput") }},
		{name: "empty provider id", scope: ScopeDefault, edit: func(c *Config) { c.Providers[0].ProviderID = "" }},
		{name: "duplicate provider id", scope: ScopeDefault, edit: func(c *Config) { c.Providers = append(c.Providers, c.Providers[0]) }},
		{name: "fixed missing provider id", scope: ScopeOverride, edit: func(c *Config) { c.Strategy = StrategyFixed }},
		{name: "weighted non-positive weight", scope: ScopeDefault, edit: func(c *Config) { c.Strategy = StrategyWeighted; c.Providers[0].Weight = 0 }},
		{name: "priority non-positive priority", scope: ScopeDefault, edit: func(c *Config) { c.Providers[0].Priority = 0 }},
		{name: "smart without enabled provider", scope: ScopeDefault, edit: func(c *Config) { c.Strategy = StrategySmart; c.Providers[0].Enabled = false }},
		{name: "unknown cost level", scope: ScopeDefault, edit: func(c *Config) { c.Providers[0].RelativeCost = CostLevel("very-low") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			tt.edit(&cfg)
			if err := cfg.Validate(tt.scope); err == nil {
				t.Fatal("Validate() error = nil, want rejection")
			}
		})
	}
}

func TestValidateRejectsInvalidActualCosts(t *testing.T) {
	valid := func() Config {
		return Config{
			Strategy:  StrategySmart,
			Objective: ObjectiveCost,
			CostBasis: CostActual,
			Providers: []ProviderRule{
				{ProviderID: "provider-a", Enabled: true, Priority: 1, ActualCost: &TokenPrice{Currency: "USD", InputPerMillion: 1, OutputPerMillion: 2}},
				{ProviderID: "provider-b", Enabled: true, Priority: 2, ActualCost: &TokenPrice{Currency: "USD", InputPerMillion: 2, OutputPerMillion: 4}},
			},
		}
	}

	tests := []struct {
		name string
		edit func(*Config)
	}{
		{name: "missing enabled provider price", edit: func(c *Config) { c.Providers[1].ActualCost = nil }},
		{name: "empty currency", edit: func(c *Config) { c.Providers[0].ActualCost.Currency = "" }},
		{name: "negative input price", edit: func(c *Config) { c.Providers[0].ActualCost.InputPerMillion = -1 }},
		{name: "negative output price", edit: func(c *Config) { c.Providers[0].ActualCost.OutputPerMillion = -1 }},
		{name: "mixed currencies", edit: func(c *Config) { c.Providers[1].ActualCost.Currency = "CNY" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			tt.edit(&cfg)
			if err := cfg.Validate(ScopeDefault); err == nil {
				t.Fatal("Validate() error = nil, want rejection")
			}
		})
	}
}

func TestValidateV2PreservesNonFiniteActualCostCompatibility(t *testing.T) {
	tests := []struct {
		name  string
		value float64
	}{
		{name: "NaN", value: math.NaN()},
		{name: "positive infinity", value: math.Inf(1)},
	}

	for _, field := range []string{"input", "output"} {
		for _, tt := range tests {
			t.Run(field+"/"+tt.name, func(t *testing.T) {
				cfg := Config{
					Strategy:  StrategySmart,
					Objective: ObjectiveCost,
					CostBasis: CostActual,
					Providers: []ProviderRule{
						{ProviderID: "provider-a", Enabled: true, ActualCost: &TokenPrice{
							Currency: "USD", InputPerMillion: 1, OutputPerMillion: 2,
						}},
						{ProviderID: "provider-b", Enabled: true, ActualCost: &TokenPrice{
							Currency: "USD", InputPerMillion: 2, OutputPerMillion: 4,
						}},
					},
				}
				if field == "input" {
					cfg.Providers[0].ActualCost.InputPerMillion = tt.value
				} else {
					cfg.Providers[0].ActualCost.OutputPerMillion = tt.value
				}
				if err := cfg.Validate(ScopeDefault); err != nil {
					t.Fatalf("v2 Validate() error = %v, want legacy acceptance", err)
				}
			})
		}
	}
}

func TestValidateCostObjectiveRequiresUsableCostBasis(t *testing.T) {
	cfg := Config{
		Strategy:  StrategySmart,
		Objective: ObjectiveCost,
		CostBasis: CostNone,
		Providers: []ProviderRule{{ProviderID: "provider-a", Enabled: true, Priority: 1}},
	}

	if err := cfg.Validate(ScopeDefault); err == nil {
		t.Fatal("Validate() error = nil, want cost basis rejection")
	}
}

func TestValidateCustomObjectiveRequiresExactUniqueOrder(t *testing.T) {
	base := Config{
		Strategy:  StrategySmart,
		Objective: ObjectiveCustom,
		CostBasis: CostRelative,
		Providers: []ProviderRule{{ProviderID: "provider-a", Enabled: true, Priority: 1, RelativeCost: CostLow}},
	}

	valid := base
	valid.CustomOrder = []Objective{ObjectiveLatency, ObjectiveCost, ObjectiveStability}
	if err := valid.Validate(ScopeDefault); err != nil {
		t.Fatalf("valid custom order rejected: %v", err)
	}

	invalidOrders := [][]Objective{
		nil,
		{ObjectiveStability, ObjectiveLatency},
		{ObjectiveStability, ObjectiveLatency, ObjectiveLatency},
		{ObjectiveStability, ObjectiveLatency, ObjectiveBalanced},
	}
	for _, order := range invalidOrders {
		cfg := base
		cfg.CustomOrder = order
		if err := cfg.Validate(ScopeDefault); err == nil {
			t.Fatalf("Validate() error = nil for custom_order %v, want rejection", order)
		}
	}
}

func TestValidateDoesNotRequireCostOutsideCostObjective(t *testing.T) {
	cfg := Config{
		Strategy:  StrategySmart,
		Objective: ObjectiveBalanced,
		CostBasis: CostActual,
		Providers: []ProviderRule{{ProviderID: "provider-a", Enabled: true}},
	}

	if err := cfg.Validate(ScopeDefault); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestConfigJSONUsesSnakeCaseContract(t *testing.T) {
	cfg := Config{
		Strategy:        StrategyFixed,
		Objective:       ObjectiveCustom,
		CustomOrder:     []Objective{ObjectiveStability, ObjectiveLatency, ObjectiveCost},
		CostBasis:       CostActual,
		FixedProviderID: "provider-a",
		Providers: []ProviderRule{{
			ProviderID:   "provider-a",
			Enabled:      true,
			Priority:     1,
			Weight:       1,
			RelativeCost: CostLow,
			ActualCost:   &TokenPrice{Currency: "CNY", InputPerMillion: 1, OutputPerMillion: 2},
		}},
	}

	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	encoded := string(raw)
	for _, field := range []string{
		`"custom_order"`, `"cost_basis"`, `"fixed_provider_id"`, `"provider_id"`,
		`"relative_cost"`, `"actual_cost"`, `"currency"`, `"input_per_million"`, `"output_per_million"`,
	} {
		if !strings.Contains(encoded, field) {
			t.Errorf("JSON %s missing field %s", encoded, field)
		}
	}
}

func TestExplicitConfigJSONContractUsesSchemaV3AndSnakeCase(t *testing.T) {
	if ExplicitSchemaVersion != 3 {
		t.Fatalf("ExplicitSchemaVersion = %d, want 3", ExplicitSchemaVersion)
	}

	cfg := ExplicitConfig{
		Mode: ModeDynamic,
		Routes: []RouteRule{{
			ProviderID:    "provider-a",
			Enabled:       true,
			Priority:      1,
			Weight:        100,
			AdminPriority: 1,
			RelativeCost:  CostLow,
			ActualCost:    &TokenPrice{Currency: "USD", InputPerMillion: 1, OutputPerMillion: 2},
		}},
		Factors: FactorWeights{
			Stability:     25,
			Latency:       25,
			Cost:          25,
			AdminPriority: 25,
		},
		FailurePolicy: FailurePolicy{
			RetryOn:          []FailureCategory{FailureTimeout},
			RejoinOnRecovery: true,
			RestorePrimary:   true,
		},
	}

	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var encoded map[string]any
	if err := json.Unmarshal(raw, &encoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	requireExactJSONKeys(t, encoded, "mode", "routes", "factors", "failure_policy")

	routes, ok := encoded["routes"].([]any)
	if !ok || len(routes) != 1 {
		t.Fatalf("routes = %#v, want one JSON object", encoded["routes"])
	}
	route, ok := routes[0].(map[string]any)
	if !ok {
		t.Fatalf("route = %#v, want JSON object", routes[0])
	}
	requireExactJSONKeys(t, route,
		"provider_id", "enabled", "priority", "weight", "admin_priority", "relative_cost", "actual_cost",
	)

	actualCost, ok := route["actual_cost"].(map[string]any)
	if !ok {
		t.Fatalf("actual_cost = %#v, want JSON object", route["actual_cost"])
	}
	requireExactJSONKeys(t, actualCost, "currency", "input_per_million", "output_per_million")

	factors, ok := encoded["factors"].(map[string]any)
	if !ok {
		t.Fatalf("factors = %#v, want JSON object", encoded["factors"])
	}
	requireExactJSONKeys(t, factors, "stability", "latency", "cost", "admin_priority")

	failurePolicy, ok := encoded["failure_policy"].(map[string]any)
	if !ok {
		t.Fatalf("failure_policy = %#v, want JSON object", encoded["failure_policy"])
	}
	requireExactJSONKeys(t, failurePolicy, "retry_on", "rejoin_on_recovery", "restore_primary")
}

func TestExplicitValidateRequiresAtLeastTwoEnabledRoutes(t *testing.T) {
	cfg := validExplicitFailoverConfig()
	cfg.Routes[1].Enabled = false

	requireExplicitValidateErrorContains(t, cfg, "two", "enabled")
}

func TestExplicitValidateRejectsDuplicateProviders(t *testing.T) {
	cfg := validExplicitFailoverConfig()
	cfg.Routes[1].ProviderID = cfg.Routes[0].ProviderID

	requireExplicitValidateErrorContains(t, cfg, "duplicate", "provider-a")
}

func TestExplicitValidateRejectsUnknownMode(t *testing.T) {
	cfg := validExplicitFailoverConfig()
	cfg.Mode = Mode("random")

	requireExplicitValidateErrorContains(t, cfg, "unknown", "mode")
}

func TestExplicitValidateModeFieldsDoNotLeakAcrossModes(t *testing.T) {
	tests := []struct {
		name string
		cfg  ExplicitConfig
	}{
		{
			name: "failover ignores weights and factors",
			cfg: func() ExplicitConfig {
				cfg := validExplicitFailoverConfig()
				cfg.Factors = FactorWeights{Stability: -1, Latency: -2, Cost: -3, AdminPriority: -4}
				for i := range cfg.Routes {
					cfg.Routes[i].Weight = -1
				}
				return cfg
			}(),
		},
		{
			name: "weighted ignores priorities costs and factors",
			cfg: func() ExplicitConfig {
				cfg := validExplicitWeightedConfig()
				cfg.Factors = FactorWeights{Stability: -1, Latency: -2, Cost: -3, AdminPriority: -4}
				for i := range cfg.Routes {
					cfg.Routes[i].Priority = -1
					cfg.Routes[i].AdminPriority = -1
					cfg.Routes[i].RelativeCost = CostLevel("not-applicable")
				}
				return cfg
			}(),
		},
		{
			name: "dynamic ignores failover priority and weight",
			cfg: func() ExplicitConfig {
				cfg := validExplicitDynamicConfig()
				for i := range cfg.Routes {
					cfg.Routes[i].Priority = -1
					cfg.Routes[i].Weight = -1
				}
				return cfg
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); err != nil {
				t.Fatalf("Validate() error = %v, want unrelated mode fields ignored", err)
			}
		})
	}
}

func TestExplicitValidateIgnoresModeFieldsOnDisabledRoutes(t *testing.T) {
	cfg := validExplicitDynamicConfig()
	cfg.Routes = append(cfg.Routes, RouteRule{
		ProviderID:    "provider-disabled",
		Enabled:       false,
		Priority:      -1,
		Weight:        -1,
		AdminPriority: -1,
		RelativeCost:  CostLevel("not-applicable"),
		ActualCost:    &TokenPrice{Currency: "", InputPerMillion: -1, OutputPerMillion: -1},
	})

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want disabled route mode fields ignored", err)
	}
}

func TestExplicitValidateRejectsEmptyOrWhitespaceProviderID(t *testing.T) {
	for _, providerID := range []string{"", " provider-a ", "   "} {
		t.Run(providerID, func(t *testing.T) {
			cfg := validExplicitFailoverConfig()
			cfg.Routes[0].ProviderID = providerID
			requireExplicitValidateErrorContains(t, cfg, "provider")
		})
	}
}

func TestExplicitValidateDuplicatePrioritiesReportConflictValue(t *testing.T) {
	failover := validExplicitFailoverConfig()
	failover.Routes[1].Priority = failover.Routes[0].Priority
	requireExplicitValidateErrorContains(t, failover, "priority", "1")

	dynamic := validExplicitDynamicConfig()
	dynamic.Routes[1].AdminPriority = dynamic.Routes[0].AdminPriority
	requireExplicitValidateErrorContains(t, dynamic, "admin_priority", "1")
}

func TestExplicitValidateFailoverRequiresPositiveUniquePriorities(t *testing.T) {
	tests := []struct {
		name string
		edit func(*ExplicitConfig)
	}{
		{name: "zero", edit: func(c *ExplicitConfig) { c.Routes[0].Priority = 0 }},
		{name: "negative", edit: func(c *ExplicitConfig) { c.Routes[0].Priority = -1 }},
		{name: "duplicate", edit: func(c *ExplicitConfig) { c.Routes[1].Priority = c.Routes[0].Priority }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validExplicitFailoverConfig()
			tt.edit(&cfg)
			requireExplicitValidateErrorContains(t, cfg, "priority")
		})
	}
}

func TestExplicitValidateWeightedRequiresEnabledWeightsTotal100(t *testing.T) {
	cfg := validExplicitWeightedConfig()
	cfg.Routes[1].Weight = 49

	requireExplicitValidateErrorContains(t, cfg, "weight", "100")
}

func TestExplicitValidateWeightedRejectsZeroWeightOnEnabledRoute(t *testing.T) {
	cfg := validExplicitWeightedConfig()
	cfg.Routes[0].Weight = 0
	cfg.Routes[1].Weight = 100

	requireExplicitValidateErrorContains(t, cfg, "provider-a", "weight")
}

func TestExplicitValidateRejectsFactorOrWeightAbove100(t *testing.T) {
	t.Run("weight", func(t *testing.T) {
		weighted := validExplicitWeightedConfig()
		weighted.Routes[0].Weight = 101
		requireExplicitValidateErrorContains(t, weighted, "provider-a", "weight", "100")
	})

	factorTests := []struct {
		name string
		edit func(*FactorWeights)
	}{
		{name: "stability", edit: func(f *FactorWeights) { f.Stability = 101 }},
		{name: "latency", edit: func(f *FactorWeights) { f.Latency = 101 }},
		{name: "cost", edit: func(f *FactorWeights) { f.Cost = 101 }},
		{name: "admin_priority", edit: func(f *FactorWeights) { f.AdminPriority = 101 }},
	}
	for _, tt := range factorTests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validExplicitDynamicConfig()
			tt.edit(&cfg.Factors)
			requireExplicitValidateErrorContains(t, cfg, tt.name, "100")
		})
	}
}

func TestExplicitValidateRejectsExtremeIntsBeforeSumming(t *testing.T) {
	maxInt := int(^uint(0) >> 1)

	t.Run("weight", func(t *testing.T) {
		weighted := ExplicitConfig{
			Mode: ModeWeighted,
			Routes: []RouteRule{
				{ProviderID: "provider-a", Enabled: true, Weight: maxInt},
				{ProviderID: "provider-b", Enabled: true, Weight: maxInt},
				{ProviderID: "provider-c", Enabled: true, Weight: 102},
			},
		}
		requireExplicitValidateErrorContains(t, weighted, "weight", "100")
	})

	t.Run("factor", func(t *testing.T) {
		dynamic := ExplicitConfig{
			Mode: ModeDynamic,
			Routes: []RouteRule{
				{ProviderID: "provider-a", Enabled: true, RelativeCost: CostLow},
				{ProviderID: "provider-b", Enabled: true, RelativeCost: CostHigh},
			},
			Factors: FactorWeights{
				Stability: maxInt,
				Latency:   maxInt,
				Cost:      102,
			},
		}
		requireExplicitValidateErrorContains(t, dynamic, "factor", "100")
	})
}

func TestExplicitValidateRejectsNegativeWeightsAndFactors(t *testing.T) {
	tests := []struct {
		name string
		edit func(*ExplicitConfig)
	}{
		{name: "route weight", edit: func(c *ExplicitConfig) {
			c.Mode = ModeWeighted
			c.Routes[0].Weight = -1
			c.Routes[1].Weight = 101
		}},
		{name: "stability factor", edit: func(c *ExplicitConfig) { c.Factors.Stability = -1 }},
		{name: "latency factor", edit: func(c *ExplicitConfig) { c.Factors.Latency = -1 }},
		{name: "cost factor", edit: func(c *ExplicitConfig) { c.Factors.Cost = -1 }},
		{name: "admin priority factor", edit: func(c *ExplicitConfig) { c.Factors.AdminPriority = -1 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validExplicitDynamicConfig()
			tt.edit(&cfg)
			requireExplicitValidateErrorContains(t, cfg, "negative")
		})
	}
}

func TestExplicitValidateDynamicRequiresFactorsTotal100(t *testing.T) {
	cfg := validExplicitDynamicConfig()
	cfg.Factors.Latency--

	requireExplicitValidateErrorContains(t, cfg, "factor", "100")
}

func TestExplicitValidateDynamicCostFactorRequiresComparableCostForEveryRoute(t *testing.T) {
	tests := []struct {
		name string
		edit func(*ExplicitConfig)
	}{
		{name: "missing cost", edit: func(c *ExplicitConfig) { c.Routes[1].RelativeCost = "" }},
		{name: "unknown relative cost", edit: func(c *ExplicitConfig) { c.Routes[1].RelativeCost = CostLevel("tiny") }},
		{name: "mixed cost representations", edit: func(c *ExplicitConfig) {
			c.Routes[1].RelativeCost = ""
			c.Routes[1].ActualCost = &TokenPrice{Currency: "USD", InputPerMillion: 1, OutputPerMillion: 2}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validExplicitDynamicConfig()
			tt.edit(&cfg)
			requireExplicitValidateErrorContains(t, cfg, "cost")
		})
	}
}

func TestExplicitValidateDynamicAllowsComparableActualCosts(t *testing.T) {
	cfg := validExplicitDynamicConfig()
	for i := range cfg.Routes {
		cfg.Routes[i].RelativeCost = ""
		cfg.Routes[i].ActualCost = &TokenPrice{
			Currency:         "USD",
			InputPerMillion:  float64(i + 1),
			OutputPerMillion: float64(i + 2),
		}
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}

	cfg.Routes[1].ActualCost.Currency = "CNY"
	requireExplicitValidateErrorContains(t, cfg, "cost", "currency")
}

func TestExplicitValidateRejectsNonFiniteOrNegativeActualCosts(t *testing.T) {
	tests := []struct {
		name  string
		value float64
	}{
		{name: "NaN", value: math.NaN()},
		{name: "positive infinity", value: math.Inf(1)},
		{name: "negative infinity", value: math.Inf(-1)},
		{name: "negative", value: -0.01},
	}

	for _, field := range []string{"input", "output"} {
		for _, tt := range tests {
			t.Run(field+"/"+tt.name, func(t *testing.T) {
				cfg := validExplicitDynamicConfig()
				for i := range cfg.Routes {
					cfg.Routes[i].RelativeCost = ""
					cfg.Routes[i].ActualCost = &TokenPrice{
						Currency:         "USD",
						InputPerMillion:  1,
						OutputPerMillion: 2,
					}
				}
				if field == "input" {
					cfg.Routes[0].ActualCost.InputPerMillion = tt.value
				} else {
					cfg.Routes[0].ActualCost.OutputPerMillion = tt.value
				}

				requireExplicitValidateErrorContains(t, cfg, "provider-a", "cost")
			})
		}
	}
}

func TestExplicitValidateDynamicAllowsMissingCostWhenCostFactorIsZero(t *testing.T) {
	cfg := validExplicitDynamicConfig()
	cfg.Factors.Stability += cfg.Factors.Cost
	cfg.Factors.Cost = 0
	for i := range cfg.Routes {
		cfg.Routes[i].RelativeCost = ""
		cfg.Routes[i].ActualCost = nil
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil when cost factor is zero", err)
	}
}

func TestExplicitValidateDynamicAllowsZeroOrDuplicateAdminPriorityWhenFactorIsZero(t *testing.T) {
	cfg := validExplicitDynamicConfig()
	cfg.Factors.Stability += cfg.Factors.AdminPriority
	cfg.Factors.AdminPriority = 0
	cfg.Routes[0].AdminPriority = 0
	cfg.Routes[1].AdminPriority = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil when admin priority factor is zero", err)
	}
}

func TestExplicitValidateDynamicAdminPriorityRequiresPositiveUniqueValues(t *testing.T) {
	tests := []struct {
		name string
		edit func(*ExplicitConfig)
	}{
		{name: "zero", edit: func(c *ExplicitConfig) { c.Routes[0].AdminPriority = 0 }},
		{name: "negative", edit: func(c *ExplicitConfig) { c.Routes[0].AdminPriority = -1 }},
		{name: "duplicate", edit: func(c *ExplicitConfig) { c.Routes[1].AdminPriority = c.Routes[0].AdminPriority }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validExplicitDynamicConfig()
			tt.edit(&cfg)
			requireExplicitValidateErrorContains(t, cfg, "admin_priority")
		})
	}
}

func TestExplicitValidateRejectsNonRetryableAndUnknownFailureCategories(t *testing.T) {
	tests := []FailureCategory{
		FailureSecurityRejected,
		FailureCategory("authentication_failed"),
		FailureCategory("mystery"),
	}

	for _, category := range tests {
		t.Run(string(category), func(t *testing.T) {
			cfg := validExplicitFailoverConfig()
			cfg.FailurePolicy.RetryOn = []FailureCategory{category}
			requireExplicitValidateErrorContains(t, cfg, "retry", string(category))
		})
	}
}

func TestExplicitValidateRejectsDuplicateRetryCategories(t *testing.T) {
	cfg := validExplicitFailoverConfig()
	cfg.FailurePolicy.RetryOn = []FailureCategory{
		FailureTimeout, FailureRateLimited, FailureTimeout,
	}
	requireExplicitValidateErrorContains(t, cfg, "duplicate", string(FailureTimeout))
}

func TestExplicitValidateAcceptsSupportedModes(t *testing.T) {
	configs := []ExplicitConfig{
		validExplicitFailoverConfig(),
		validExplicitWeightedConfig(),
		validExplicitDynamicConfig(),
	}
	for _, cfg := range configs {
		t.Run(string(cfg.Mode), func(t *testing.T) {
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
		})
	}
}

func validExplicitFailoverConfig() ExplicitConfig {
	return ExplicitConfig{
		Mode: ModeFailover,
		Routes: []RouteRule{
			{ProviderID: "provider-a", Enabled: true, Priority: 1},
			{ProviderID: "provider-b", Enabled: true, Priority: 2},
		},
		FailurePolicy: FailurePolicy{
			RetryOn: []FailureCategory{FailureTimeout, FailureRateLimited, FailureUpstream5xx, FailureTemporaryNetwork},
		},
	}
}

func validExplicitWeightedConfig() ExplicitConfig {
	return ExplicitConfig{
		Mode: ModeWeighted,
		Routes: []RouteRule{
			{ProviderID: "provider-a", Enabled: true, Weight: 50},
			{ProviderID: "provider-b", Enabled: true, Weight: 50},
		},
	}
}

func validExplicitDynamicConfig() ExplicitConfig {
	return ExplicitConfig{
		Mode: ModeDynamic,
		Routes: []RouteRule{
			{ProviderID: "provider-a", Enabled: true, AdminPriority: 1, RelativeCost: CostLow},
			{ProviderID: "provider-b", Enabled: true, AdminPriority: 2, RelativeCost: CostHigh},
		},
		Factors: FactorWeights{
			Stability:     35,
			Latency:       25,
			Cost:          25,
			AdminPriority: 15,
		},
	}
}

func requireExplicitValidateErrorContains(t *testing.T, cfg ExplicitConfig, substrings ...string) {
	t.Helper()
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate() error = nil, want error containing %q", substrings)
	}
	for _, substring := range substrings {
		if !strings.Contains(err.Error(), substring) {
			t.Fatalf("Validate() error = %q, want substring %q", err, substring)
		}
	}
}

func requireExactJSONKeys(t *testing.T, object map[string]any, want ...string) {
	t.Helper()
	if len(object) != len(want) {
		t.Fatalf("JSON keys = %v, want exactly %v", object, want)
	}
	for _, key := range want {
		if _, ok := object[key]; !ok {
			t.Fatalf("JSON object %v missing key %q", object, key)
		}
	}
}

func requireValidateErrorContains(t *testing.T, cfg Config, scope Scope, substrings ...string) {
	t.Helper()
	err := cfg.Validate(scope)
	if err == nil {
		t.Fatalf("Validate() error = nil, want error containing %q", substrings)
	}
	for _, substring := range substrings {
		if !strings.Contains(err.Error(), substring) {
			t.Fatalf("Validate() error = %q, want substring %q", err, substring)
		}
	}
}
