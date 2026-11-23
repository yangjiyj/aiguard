package handler

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelrouting"
	"github.com/go-chi/chi/v5"
)

const modelRoutingBodyLimit = 1 << 20

type saveModelRoutingRequest struct {
	ExpectedVersion int64                 `json:"expected_version"`
	ModelName       string                `json:"model_name,omitempty"`
	Config          modelRoutingConfigDTO `json:"config"`
}

// modelRoutingConfigDTO is the only customer-facing routing contract.  Stable
// route_ref values deliberately replace database provider IDs.
type modelRoutingProviderDTO struct {
	RouteRef       string                   `json:"route_ref"`
	DisplayName    string                   `json:"display_name"`
	Enabled        bool                     `json:"enabled"`
	Priority       int                      `json:"priority"`
	Weight         int                      `json:"weight"`
	RelativeCost   modelrouting.CostLevel   `json:"relative_cost,omitempty"`
	ActualCost     *modelrouting.TokenPrice `json:"actual_cost,omitempty"`
	CostConfigured bool                     `json:"cost_configured,omitempty"`
}

type modelRoutingConfigDTO struct {
	Strategy      modelrouting.Strategy     `json:"strategy"`
	Objective     modelrouting.Objective    `json:"objective,omitempty"`
	CustomOrder   []modelrouting.Objective  `json:"custom_order,omitempty"`
	CostBasis     modelrouting.CostBasis    `json:"cost_basis"`
	FixedRouteRef string                    `json:"fixed_route_ref,omitempty"`
	Providers     []modelRoutingProviderDTO `json:"providers"`
}

type modelRoutingDefaultDTO struct {
	Config        modelRoutingConfigDTO `json:"config"`
	ConfigVersion int64                 `json:"config_version"`
	Enabled       bool                  `json:"enabled"`
	Invalid       bool                  `json:"invalid,omitempty"`
	InvalidReason string                `json:"invalid_reason,omitempty"`
}

type modelRoutingExceptionDTO struct {
	ModelName     string                `json:"model_name"`
	Config        modelRoutingConfigDTO `json:"config"`
	ConfigVersion int64                 `json:"config_version"`
	Enabled       bool                  `json:"enabled"`
	Invalid       bool                  `json:"invalid,omitempty"`
	InvalidReason string                `json:"invalid_reason,omitempty"`
}

type modelRoutingLegacyDTO struct {
	Scope       string `json:"scope"`
	ModelName   string `json:"model_name,omitempty"`
	Strategy    string `json:"strategy"`
	Convertible bool   `json:"convertible"`
	Reason      string `json:"reason"`
}

type modelRoutingOverviewDTO struct {
	DefaultRule            *modelRoutingDefaultDTO    `json:"default_rule"`
	ModelExceptions        []modelRoutingExceptionDTO `json:"model_exceptions"`
	MultiRouteModelCount   int                        `json:"multi_route_model_count"`
	TodayFallbackCount     int                        `json:"today_fallback_count"`
	UnhealthyRouteCount    int                        `json:"unhealthy_route_count"`
	LegacyReport           []modelRoutingLegacyDTO    `json:"legacy_report"`
	OutboundRouteAvailable bool                       `json:"outbound_route_available"`
}

// modelRoutingRouteStatusDTO 是模型路由页「线路行」的展示数据：
// 状态、近 30 分钟首 token 延迟与失败数、定价。route_ref 为脱敏线路标识。
type modelRoutingRouteStatusDTO struct {
	RouteRef         string   `json:"route_ref"`
	ProviderName     string   `json:"provider_name"`
	AvgTTFTMs        *int64   `json:"avg_ttft_ms"`
	Samples30m       int      `json:"samples_30m"`
	Failures30m      int      `json:"failures_30m"`
	InputPerMillion  *float64 `json:"input_per_million,omitempty"`
	OutputPerMillion *float64 `json:"output_per_million,omitempty"`
	CapabilityState  string   `json:"capability_state"`
	HealthState      string   `json:"health_state"`
}

type modelRoutingStatusItemDTO struct {
	ModelName                string                       `json:"model_name"`
	State                    string                       `json:"state"` // single/pending/configured/unavailable
	RouteCount               int                          `json:"route_count"`
	ConfiguredCandidateCount int                          `json:"configured_candidate_count"`
	EligibleCandidateCount   int                          `json:"eligible_candidate_count"`
	EndpointType             string                       `json:"endpoint_type"`
	ConfigVersion            int64                        `json:"config_version"`
	Routes                   []modelRoutingRouteStatusDTO `json:"routes"`
}

type modelRoutingModelDTO struct {
	ModelName     string   `json:"model_name"`
	RouteCount    int      `json:"route_count"`
	ProviderNames []string `json:"provider_names"`
}

type modelRoutingValidation struct {
	providers     []*repository.Provider
	providerNames []string
}

type modelRoutingRouteMap struct {
	byRef map[string]*repository.Provider
}

func modelRoutingRouteRef(tenantID, providerID string) string {
	sum := sha256.Sum256([]byte("jjdguard:model-routing:route-ref:v1\x00" + tenantID + "\x00" + providerID))
	return fmt.Sprintf("rt_%x", sum[:16])
}

func loadModelRoutingRoutes(r *http.Request, deps *Dependencies, tenantID string) (modelRoutingRouteMap, error) {
	result := modelRoutingRouteMap{byRef: map[string]*repository.Provider{}}
	if deps == nil || deps.ProviderRepo == nil {
		return result, errors.New("provider repository unavailable")
	}
	providers, err := deps.ProviderRepo.List(r.Context(), tenantID)
	if err != nil {
		return result, err
	}
	for _, provider := range providers {
		if provider == nil || provider.TenantID != tenantID {
			continue
		}
		result.byRef[modelRoutingRouteRef(tenantID, provider.ID)] = provider
	}
	return result, nil
}

func (m modelRoutingRouteMap) internalConfig(dto modelRoutingConfigDTO) (modelrouting.Config, error) {
	cfg := modelrouting.Config{Strategy: dto.Strategy, Objective: dto.Objective, CustomOrder: dto.CustomOrder, CostBasis: dto.CostBasis}
	if dto.FixedRouteRef != "" {
		provider := m.byRef[dto.FixedRouteRef]
		if provider == nil {
			return cfg, errors.New("route reference is not accessible")
		}
		cfg.FixedProviderID = provider.ID
	}
	for _, rule := range dto.Providers {
		provider := m.byRef[rule.RouteRef]
		if provider == nil {
			return cfg, errors.New("route reference is not accessible")
		}
		cfg.Providers = append(cfg.Providers, modelrouting.ProviderRule{ProviderID: provider.ID, Enabled: rule.Enabled, Priority: rule.Priority, Weight: rule.Weight, RelativeCost: rule.RelativeCost, ActualCost: rule.ActualCost})
	}
	return cfg, nil
}

func (m modelRoutingRouteMap) publicConfig(cfg modelrouting.Config, showAmounts bool) (modelRoutingConfigDTO, error) {
	dto := modelRoutingConfigDTO{Strategy: cfg.Strategy, Objective: cfg.Objective, CustomOrder: cfg.CustomOrder, CostBasis: cfg.CostBasis, Providers: make([]modelRoutingProviderDTO, 0, len(cfg.Providers))}
	if cfg.FixedProviderID != "" {
		provider := m.providerByID(cfg.FixedProviderID)
		if !modelRoutingProviderUsable(provider) {
			return dto, errors.New("configured route no longer exists")
		}
		dto.FixedRouteRef = modelRoutingRouteRef(provider.TenantID, provider.ID)
	}
	for _, rule := range cfg.Providers {
		provider := m.providerByID(rule.ProviderID)
		if !modelRoutingProviderUsable(provider) {
			return dto, errors.New("configured route no longer exists")
		}
		item := modelRoutingProviderDTO{RouteRef: modelRoutingRouteRef(provider.TenantID, provider.ID), DisplayName: provider.Name, Enabled: rule.Enabled, Priority: rule.Priority, Weight: rule.Weight, RelativeCost: rule.RelativeCost, CostConfigured: rule.ActualCost != nil}
		if showAmounts {
			item.ActualCost = rule.ActualCost
		}
		dto.Providers = append(dto.Providers, item)
	}
	return dto, nil
}

func modelRoutingProviderUsable(provider *repository.Provider) bool {
	return provider != nil && provider.Status == "active" && provider.HasCredential
}

func (m modelRoutingRouteMap) providerByID(id string) *repository.Provider {
	for _, provider := range m.byRef {
		if provider.ID == id {
			return provider
		}
	}
	return nil
}

func modelRoutingCanWrite(role string) bool {
	return role == "platform_admin" || role == "tenant_owner"
}

func appendModelRoutingExceptions(resp *modelRoutingOverviewDTO, routes modelRoutingRouteMap, policies []repository.ModelRoutingPolicy, showAmounts bool) {
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		cfg, convertErr := routes.publicConfig(policy.Config, showAmounts)
		if convertErr != nil {
			resp.ModelExceptions = append(resp.ModelExceptions, modelRoutingExceptionDTO{
				ModelName:     policy.ScopeRef,
				ConfigVersion: policy.ConfigVersion,
				Enabled:       policy.Enabled,
				Invalid:       true,
				InvalidReason: "configured_route_removed",
			})
			continue
		}
		resp.ModelExceptions = append(resp.ModelExceptions, modelRoutingExceptionDTO{ModelName: policy.ScopeRef, Config: cfg, ConfigVersion: policy.ConfigVersion, Enabled: policy.Enabled})
	}
}

func modelRoutingDefaultDTOForPolicy(policy *repository.ModelRoutingPolicy, routes modelRoutingRouteMap, showAmounts bool) *modelRoutingDefaultDTO {
	if policy == nil {
		return nil
	}
	cfg, err := routes.publicConfig(policy.Config, showAmounts)
	if err == nil {
		return &modelRoutingDefaultDTO{Config: cfg, ConfigVersion: policy.ConfigVersion, Enabled: policy.Enabled}
	}
	return &modelRoutingDefaultDTO{
		Config: modelRoutingConfigDTO{
			Strategy: policy.Config.Strategy, Objective: policy.Config.Objective,
			CustomOrder: policy.Config.CustomOrder, CostBasis: policy.Config.CostBasis,
			Providers: []modelRoutingProviderDTO{},
		},
		ConfigVersion: policy.ConfigVersion, Enabled: policy.Enabled,
		Invalid: true, InvalidReason: "configured_route_removed",
	}
}

func GetModelRouting(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		if deps == nil || deps.ModelRoutingRepo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to load model routing")
			return
		}
		overview, err := deps.ModelRoutingRepo.Overview(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to load model routing")
			return
		}
		legacy, err := deps.ModelRoutingRepo.LegacyInventory(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to load model routing")
			return
		}
		routes, err := loadModelRoutingRoutes(r, deps, user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to load model routing")
			return
		}
		resp := modelRoutingOverviewDTO{
			ModelExceptions:        make([]modelRoutingExceptionDTO, 0, len(overview.Overrides)),
			MultiRouteModelCount:   overview.MultiRouteModelCount,
			LegacyReport:           make([]modelRoutingLegacyDTO, 0, len(legacy)),
			OutboundRouteAvailable: overview.OutboundRouteAvailable,
		}
		if fallbackCount, countErr := deps.ModelRoutingRepo.TodayFallbackCount(r.Context(), user.TenantID); countErr == nil {
			resp.TodayFallbackCount = fallbackCount
		}
		if metrics, metricsErr := deps.ModelRoutingRepo.RecentRouteMetrics(r.Context(), user.TenantID, 30); metricsErr == nil {
			for _, item := range metrics {
				if item.Failures > 0 {
					resp.UnhealthyRouteCount++
				}
			}
		}
		if overview.Default != nil {
			resp.DefaultRule = modelRoutingDefaultDTOForPolicy(overview.Default, routes, modelRoutingCanWrite(user.Role))
		}
		appendModelRoutingExceptions(&resp, routes, overview.Overrides, modelRoutingCanWrite(user.Role))
		for _, report := range legacy {
			item := modelRoutingLegacyDTO{Scope: report.ScopeType, Strategy: report.Strategy, Convertible: report.Convertible, Reason: report.Reason}
			if report.ScopeType == "model" {
				item.ModelName = report.ScopeRef
			}
			resp.LegacyReport = append(resp.LegacyReport, item)
		}
		writeModelRoutingJSON(w, http.StatusOK, resp)
	}
}

// GetModelRoutingStatus 按模型分组返回全部线路的展示数据（模型路由页主体）：
// 每个模型的线路列表 + 近 30 分钟指标 + 定价，支持搜索、状态与渠道过滤。
func GetModelRoutingStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		if deps == nil || deps.ModelRoutingRepo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to load model routing status")
			return
		}
		q := r.URL.Query()
		limit := 0
		if raw := q.Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "limit must be a positive integer")
				return
			}
			limit = parsed
		}
		routeCount := 0
		if raw := q.Get("route_count"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 0 {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "route_count must not be negative")
				return
			}
			routeCount = parsed
		}
		minRouteCount := 0
		if raw := q.Get("min_route_count"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 0 {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "min_route_count must not be negative")
				return
			}
			minRouteCount = parsed
		}
		filter := repository.RoutingStatusFilter{
			State:         q.Get("state"),
			Query:         q.Get("q"),
			ProviderRef:   q.Get("provider"),
			Cursor:        q.Get("cursor"),
			Endpoint:      q.Get("endpoint"),
			RouteCount:    routeCount,
			MinRouteCount: minRouteCount,
			Limit:         limit,
		}
		if strings.TrimSpace(filter.Endpoint) == "" {
			filter.Endpoint = "chat"
		}
		items, nextCursor, err := deps.ModelRoutingRepo.ListRoutingStatus(r.Context(), user.TenantID, filter)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "unable to load model routing status")
			return
		}
		metrics, err := deps.ModelRoutingRepo.RecentRouteMetrics(r.Context(), user.TenantID, 30)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to load route metrics")
			return
		}
		prices, err := deps.ModelRoutingRepo.RoutePrices(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to load route prices")
			return
		}
		models := make([]modelRoutingStatusItemDTO, 0, len(items))
		for _, item := range items {
			dto := modelRoutingStatusItemDTO{
				ModelName:                item.ModelName,
				State:                    item.State,
				RouteCount:               item.RouteCount,
				ConfiguredCandidateCount: item.ConfiguredCandidateCount,
				EligibleCandidateCount:   item.EligibleCandidateCount,
				EndpointType:             filter.Endpoint,
				ConfigVersion:            item.ConfigVersion,
				Routes:                   make([]modelRoutingRouteStatusDTO, 0, len(item.Routes)),
			}
			for _, route := range item.Routes {
				entry := modelRoutingRouteStatusDTO{
					RouteRef:        modelRoutingRouteRef(user.TenantID, route.ProviderID),
					ProviderName:    route.ProviderName,
					CapabilityState: route.CapabilityState,
					HealthState:     route.HealthState,
				}
				key := repository.RouteMetricsKeyFor(item.ModelName, route.ProviderID)
				if metric, ok := metrics[key]; ok {
					entry.AvgTTFTMs = metric.AvgTTFTMs
					entry.Samples30m = metric.Samples
					entry.Failures30m = metric.Failures
				}
				if price, ok := prices[key]; ok {
					entry.InputPerMillion = price.InputPerMillion
					entry.OutputPerMillion = price.OutputPerMillion
				}
				dto.Routes = append(dto.Routes, entry)
			}
			models = append(models, dto)
		}
		writeModelRoutingJSON(w, http.StatusOK, map[string]any{"models": models, "next_cursor": nextCursor})
	}
}

func ListModelRoutingRoutes(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		routes, err := loadModelRoutingRoutes(r, deps, user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to load routes")
			return
		}
		items := make([]modelRoutingProviderDTO, 0, len(routes.byRef))
		for ref, provider := range routes.byRef {
			if provider.Status != "active" || !provider.HasCredential {
				continue
			}
			items = append(items, modelRoutingProviderDTO{RouteRef: ref, DisplayName: provider.Name})
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].DisplayName == items[j].DisplayName {
				return items[i].RouteRef < items[j].RouteRef
			}
			return items[i].DisplayName < items[j].DisplayName
		})
		writeModelRoutingJSON(w, http.StatusOK, map[string]any{"routes": items})
	}
}

func SearchModelRoutingModels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		limit := 20
		if raw := r.URL.Query().Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "limit must be a positive integer")
				return
			}
			limit = parsed
		}
		if deps == nil || deps.ModelRoutingRepo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to search models")
			return
		}
		models, err := deps.ModelRoutingRepo.SearchModels(r.Context(), user.TenantID, r.URL.Query().Get("q"), limit)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to search models")
			return
		}
		items := make([]modelRoutingModelDTO, 0, len(models))
		for _, model := range models {
			items = append(items, modelRoutingModelDTO{ModelName: model.ModelName, RouteCount: model.RouteCount, ProviderNames: model.ProviderNames})
		}
		writeModelRoutingJSON(w, http.StatusOK, map[string]any{"models": items})
	}
}

func PutModelRoutingDefault(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		req, ok := decodeModelRoutingRequest(w, r)
		if !ok {
			return
		}
		if req.ModelName != "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "model_name is only allowed for validation")
			return
		}
		routes, err := loadModelRoutingRoutes(r, deps, user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to validate model routing")
			return
		}
		cfg, err := routes.internalConfig(req.Config)
		if err != nil {
			writeErrorWithStatus(w, http.StatusForbidden, "route_not_accessible", "one or more routes are not accessible")
			return
		}
		validation, ok := validateModelRoutingRequest(w, r, deps, user.TenantID, "", modelrouting.ScopeDefault, cfg)
		if !ok {
			return
		}
		if deps.ModelRoutingRepo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to save model routing")
			return
		}
		policy, err := deps.ModelRoutingRepo.UpsertDefault(r.Context(), user.TenantID, req.ExpectedVersion, cfg)
		if !handleModelRoutingWriteError(w, err) {
			return
		}
		logAudit(r, deps, "model_routing_default_saved", modelRoutingAuditDetail("default", "", req.ExpectedVersion, policy.ConfigVersion, cfg, len(validation.providers)), "model_routing", "default")
		public, err := routes.publicConfig(policy.Config, true)
		if err != nil {
			writeErrorWithStatus(w, 500, "internal_error", "unable to save model routing")
			return
		}
		writeModelRoutingJSON(w, http.StatusOK, modelRoutingDefaultDTO{Config: public, ConfigVersion: policy.ConfigVersion, Enabled: policy.Enabled})
	}
}

func PutModelRoutingOverride(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		modelName := modelRoutingPathName(r)
		if modelName == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "model name is required")
			return
		}
		req, ok := decodeModelRoutingRequest(w, r)
		if !ok {
			return
		}
		if req.ModelName != "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "model_name is only allowed for validation")
			return
		}
		routes, err := loadModelRoutingRoutes(r, deps, user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, 500, "internal_error", "unable to validate model routing")
			return
		}
		cfg, err := routes.internalConfig(req.Config)
		if err != nil {
			writeErrorWithStatus(w, http.StatusForbidden, "route_not_accessible", "one or more routes are not accessible")
			return
		}
		validation, ok := validateModelRoutingRequest(w, r, deps, user.TenantID, modelName, modelrouting.ScopeOverride, cfg)
		if !ok {
			return
		}
		if deps.ModelRoutingRepo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to save model routing")
			return
		}
		policy, err := deps.ModelRoutingRepo.UpsertOverride(r.Context(), user.TenantID, modelName, req.ExpectedVersion, cfg)
		if !handleModelRoutingWriteError(w, err) {
			return
		}
		logAudit(r, deps, "model_routing_override_saved", modelRoutingAuditDetail("override", modelName, req.ExpectedVersion, policy.ConfigVersion, cfg, len(validation.providers)), "model_routing", modelName)
		public, err := routes.publicConfig(policy.Config, true)
		if err != nil {
			writeErrorWithStatus(w, 500, "internal_error", "unable to save model routing")
			return
		}
		writeModelRoutingJSON(w, http.StatusOK, modelRoutingExceptionDTO{ModelName: modelName, Config: public, ConfigVersion: policy.ConfigVersion, Enabled: policy.Enabled})
	}
}

func DeleteModelRoutingDefault(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		if deps == nil || deps.ModelRoutingRepo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to delete model routing")
			return
		}
		if err := deps.ModelRoutingRepo.DeleteDefault(r.Context(), user.TenantID); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to delete model routing")
			return
		}
		logAudit(r, deps, "model_routing_default_deleted", map[string]any{"scope": "default"}, "model_routing", "default")
		writeModelRoutingJSON(w, http.StatusOK, map[string]any{"deleted": true})
	}
}

func DeleteModelRoutingOverride(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		modelName := modelRoutingPathName(r)
		if modelName == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "model name is required")
			return
		}
		if deps == nil || deps.ModelRoutingRepo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to delete model routing")
			return
		}
		if err := deps.ModelRoutingRepo.DeleteOverride(r.Context(), user.TenantID, modelName); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to delete model routing")
			return
		}
		logAudit(r, deps, "model_routing_override_deleted", map[string]any{"scope": "override", "model_name": modelName}, "model_routing", modelName)
		writeModelRoutingJSON(w, http.StatusOK, map[string]any{"deleted": true, "model_name": modelName})
	}
}

func ValidateModelRouting(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		req, ok := decodeModelRoutingRequest(w, r)
		if !ok {
			return
		}
		modelName := strings.TrimSpace(req.ModelName)
		scope := modelrouting.ScopeDefault
		if modelName != "" {
			scope = modelrouting.ScopeOverride
		}
		routes, err := loadModelRoutingRoutes(r, deps, user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, 500, "internal_error", "unable to validate model routing")
			return
		}
		cfg, err := routes.internalConfig(req.Config)
		if err != nil {
			writeErrorWithStatus(w, http.StatusForbidden, "route_not_accessible", "one or more routes are not accessible")
			return
		}
		validation, ok := validateModelRoutingRequest(w, r, deps, user.TenantID, modelName, scope, cfg)
		if !ok {
			return
		}
		writeModelRoutingJSON(w, http.StatusOK, map[string]any{
			"valid": true, "scope": string(scope), "model_name": modelName,
			"provider_count": len(validation.providers), "provider_names": validation.providerNames,
			"warnings": []string{},
		})
	}
}

func decodeModelRoutingRequest(w http.ResponseWriter, r *http.Request) (saveModelRoutingRequest, bool) {
	var req saveModelRoutingRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, modelRoutingBodyLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "request body must be one valid JSON object")
		return req, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "request body must contain one JSON object")
		return req, false
	}
	if req.ExpectedVersion < 0 {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "expected_version cannot be negative")
		return req, false
	}
	return req, true
}

func validateModelRoutingRequest(w http.ResponseWriter, r *http.Request, deps *Dependencies, tenantID, modelName string, scope modelrouting.Scope, cfg modelrouting.Config) (modelRoutingValidation, bool) {
	var result modelRoutingValidation
	if err := cfg.Validate(scope); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_config", "model routing configuration is invalid")
		return result, false
	}
	if deps == nil || deps.ProviderRepo == nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to validate model routing")
		return result, false
	}
	ids := make(map[string]struct{}, len(cfg.Providers)+1)
	for _, rule := range cfg.Providers {
		if rule.Enabled {
			ids[rule.ProviderID] = struct{}{}
		}
	}
	if cfg.FixedProviderID != "" {
		ids[cfg.FixedProviderID] = struct{}{}
	}
	orderedIDs := make([]string, 0, len(ids))
	for id := range ids {
		orderedIDs = append(orderedIDs, id)
	}
	sort.Strings(orderedIDs)
	for _, id := range orderedIDs {
		provider, err := deps.ProviderRepo.GetByID(r.Context(), tenantID, id)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to validate model routing")
			return result, false
		}
		if provider == nil {
			writeErrorWithStatus(w, http.StatusForbidden, "provider_not_accessible", "one or more providers are not accessible")
			return result, false
		}
		if provider.Status != "active" || !provider.HasCredential {
			writeErrorWithStatus(w, http.StatusBadRequest, "provider_unavailable", "one or more providers are unavailable")
			return result, false
		}
		result.providers = append(result.providers, provider)
		result.providerNames = append(result.providerNames, provider.Name)
	}
	sort.Strings(result.providerNames)
	if deps.ModelRoutingRepo != nil {
		if err := deps.ModelRoutingRepo.ValidateProviderCandidates(r.Context(), tenantID, modelName, "", orderedIDs); err != nil {
			if errors.Is(err, repository.ErrModelRouteUnavailable) {
				writeErrorWithStatus(w, http.StatusBadRequest, "model_route_unavailable", "no usable model route matches the selected providers")
				return result, false
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to validate model routing")
			return result, false
		}
	}
	if modelName != "" {
		if deps.ModelRepo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to validate provider models")
			return result, false
		}
		checkIDs := make(map[string]struct{})
		for _, rule := range cfg.Providers {
			if rule.Enabled {
				checkIDs[rule.ProviderID] = struct{}{}
			}
		}
		if cfg.FixedProviderID != "" {
			checkIDs[cfg.FixedProviderID] = struct{}{}
		}
		for id := range checkIDs {
			model, err := deps.ModelRepo.GetByProviderAndName(r.Context(), id, modelName)
			if err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to validate provider models")
				return result, false
			}
			if model == nil || model.Status != "active" {
				writeErrorWithStatus(w, http.StatusBadRequest, "provider_model_unavailable", "one or more providers do not offer an active matching model")
				return result, false
			}
		}
	}
	return result, true
}

func modelRoutingPathName(r *http.Request) string {
	name := chi.URLParam(r, "model_name")
	if name == "" {
		name = chi.URLParam(r, "*")
	}
	return strings.Trim(strings.TrimSpace(name), "/")
}

func handleModelRoutingWriteError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, repository.ErrVersionConflict) {
		writeErrorWithStatus(w, http.StatusConflict, "version_conflict", "model routing configuration changed; reload and retry")
		return false
	}
	if errors.Is(err, repository.ErrModelRouteUnavailable) {
		writeErrorWithStatus(w, http.StatusConflict, "model_route_unavailable", "no usable model route matches the selected providers")
		return false
	}
	writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "unable to save model routing")
	return false
}

func modelRoutingAuditDetail(scope, modelName string, expectedVersion, configVersion int64, cfg modelrouting.Config, providerCount int) map[string]any {
	detail := map[string]any{
		"scope": scope, "strategy": cfg.Strategy, "provider_count": providerCount,
		"cost_basis": cfg.CostBasis, "expected_version": expectedVersion, "config_version": configVersion,
	}
	if modelName != "" {
		detail["model_name"] = modelName
	}
	return detail
}

func writeModelRoutingJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
