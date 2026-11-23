package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentguardmatch"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/go-chi/chi/v5"
)

func resolveInternalTenantID(r *http.Request) string {
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" {
		return tenantID
	}
	if user := auth.GetUser(r.Context()); user != nil {
		return user.TenantID
	}
	if session := auth.GetSession(r.Context()); session != nil {
		return session.TenantID
	}
	return ""
}

// ToolRiskConfigInfo represents tool risk config API response
type ToolRiskConfigInfo struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	ToolName    string `json:"tool_name"`
	ToolType    string `json:"tool_type"`
	RiskLevel   string `json:"risk_level"`
	Action      string `json:"action"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

// ToolRiskConfigCreateRequest represents create request
type ToolRiskConfigCreateRequest struct {
	ToolName    string `json:"tool_name"`
	ToolType    string `json:"tool_type"`
	RiskLevel   string `json:"risk_level"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
}

// ToolRiskConfigUpdateRequest represents update request
type ToolRiskConfigUpdateRequest struct {
	ToolType    string `json:"tool_type"`
	RiskLevel   string `json:"risk_level"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
}

// ToolRiskConfigBatchRequest represents batch upsert request
type ToolRiskConfigBatchRequest struct {
	Configs          []ToolRiskConfigCreateRequest `json:"configs"`
	PreserveExisting bool                          `json:"preserve_existing"`
}

func decodeToolRiskRequest(w http.ResponseWriter, r *http.Request, request any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(request); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("request must contain one JSON object")
	}
	return nil
}

// mapToolRiskConfigToInfo converts repository.ToolRiskConfig to ToolRiskConfigInfo
func mapToolRiskConfigToInfo(c *repository.ToolRiskConfig) ToolRiskConfigInfo {
	return ToolRiskConfigInfo{
		ID:          c.ID,
		TenantID:    c.TenantID,
		ToolName:    c.ToolName,
		ToolType:    c.ToolType,
		RiskLevel:   c.RiskLevel,
		Action:      c.Action,
		Description: c.Description,
		CreatedAt:   c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   c.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

// GetToolRiskConfigs lists all tool risk configurations for the tenant
func GetToolRiskConfigs(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := resolveInternalTenantID(r)
		if user := auth.GetUser(r.Context()); user != nil {
			tenantID = user.TenantID
		}
		if tenantID == "" {
			writeUnauthorized(w, "tenant context not found")
			return
		}

		toolName := r.URL.Query().Get("tool_name")
		data := []ToolRiskConfigInfo{}
		if toolName != "" {
			config, err := deps.ToolRiskConfigRepo.GetByToolName(r.Context(), tenantID, toolName)
			if err != nil {
				log.Printf("GetToolRiskConfigs error: %v", err)
				writeError(w, "internal_error", "failed to get tool config")
				return
			}
			if config != nil {
				data = append(data, mapToolRiskConfigToInfo(config))
			}
		} else {
			configs, err := deps.ToolRiskConfigRepo.List(r.Context(), tenantID)
			if err != nil {
				log.Printf("GetToolRiskConfigs error: %v", err)
				writeError(w, "internal_error", "failed to list tool configs")
				return
			}

			data = make([]ToolRiskConfigInfo, len(configs))
			for i, c := range configs {
				data[i] = mapToolRiskConfigToInfo(&c)
			}
		}

		resp := map[string]interface{}{
			"data":  data,
			"total": len(data),
		}
		if r.URL.Query().Get("observed") == "true" {
			user := auth.GetUser(r.Context())
			if user == nil {
				writeUnauthorized(w, "authenticated tenant context is required for observed tools")
				return
			}
			if deps.ToolCallLogRepo == nil {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "observed tool inventory is unavailable")
				return
			}
			end := time.Now().UTC()
			start := end.Add(-7 * 24 * time.Hour)
			items, truncated, err := deps.ToolCallLogRepo.GetObservedTools(r.Context(), user.TenantID, start, end)
			if err != nil {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "observed tool inventory is unavailable")
				return
			}
			configuredTypes := make(map[string]string, len(data))
			for _, config := range data {
				configuredTypes[config.ToolName] = config.ToolType
			}
			for index := range items {
				items[index].RuntimeToolType, items[index].RuntimeTypeSource = agentguardmatch.ResolveObservedToolType(items[index].ToolName, configuredTypes[items[index].ToolName])
				if items[index].MCPGatewayObserved {
					items[index].RuntimeToolType, items[index].RuntimeTypeSource = "mcp", "mcp_gateway_observations"
				}
			}
			resp["observed_tools"] = items
			resp["observed_window"] = map[string]any{"start_time": start, "end_time": end}
			resp["observed_source"] = "tenant_gateway_observations"
			resp["observed_limit"] = repository.ObservedToolInventoryLimit
			resp["observed_truncated"] = truncated
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// CreateToolRiskConfig creates a new tool risk configuration
func CreateToolRiskConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can create tool configs")
			return
		}

		var req ToolRiskConfigCreateRequest
		if err := decodeToolRiskRequest(w, r, &req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		if req.ToolName == "" || req.ToolType == "" {
			writeError(w, "invalid_request", "tool_name and tool_type are required")
			return
		}

		// Default values
		riskLevel := req.RiskLevel
		if riskLevel == "" {
			riskLevel = "medium"
		}
		action := req.Action
		if action == "" {
			action = "audit"
		}

		config := &repository.ToolRiskConfig{
			TenantID:    user.TenantID,
			ToolName:    req.ToolName,
			ToolType:    req.ToolType,
			RiskLevel:   riskLevel,
			Action:      action,
			Description: req.Description,
		}
		if err := repository.ValidateToolRiskConfig(config); err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		if err := deps.ToolRiskConfigRepo.Create(r.Context(), config); err != nil {
			log.Printf("CreateToolRiskConfig error: %v", err)
			writeError(w, "internal_error", "failed to create tool config")
			return
		}

		detail := map[string]interface{}{
			"tool_name":  req.ToolName,
			"tool_type":  req.ToolType,
			"risk_level": riskLevel,
			"action":     action,
		}
		regenerateEndpointBundle(r.Context(), deps, user.TenantID, user.ID)
		logAudit(r, deps, "create_tool_config", detail, "tool_config", config.ID)

		resp := mapToolRiskConfigToInfo(config)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}
}

// UpdateToolRiskConfig updates an existing tool risk configuration
func UpdateToolRiskConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can update tool configs")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id is required")
			return
		}

		var req ToolRiskConfigUpdateRequest
		if err := decodeToolRiskRequest(w, r, &req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		// Check if exists
		existing, err := deps.ToolRiskConfigRepo.GetByID(r.Context(), user.TenantID, id)
		if err != nil {
			log.Printf("UpdateToolRiskConfig error fetching: %v", err)
			writeError(w, "internal_error", "failed to get tool config")
			return
		}
		if existing == nil {
			writeError(w, "not_found", "tool config not found")
			return
		}

		// Apply updates
		toolType := req.ToolType
		if toolType == "" {
			toolType = existing.ToolType
		}
		riskLevel := req.RiskLevel
		if riskLevel == "" {
			riskLevel = existing.RiskLevel
		}
		action := req.Action
		if action == "" {
			action = existing.Action
		}
		candidate := &repository.ToolRiskConfig{ToolName: existing.ToolName, ToolType: toolType, RiskLevel: riskLevel, Action: action, Description: req.Description}
		if err := repository.ValidateToolRiskConfig(candidate); err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		if err := deps.ToolRiskConfigRepo.Update(r.Context(), user.TenantID, id, toolType, riskLevel, action, req.Description); err != nil {
			log.Printf("UpdateToolRiskConfig error: %v", err)
			writeError(w, "internal_error", "failed to update tool config")
			return
		}

		detail := map[string]interface{}{
			"config_id":  id,
			"tool_name":  existing.ToolName,
			"tool_type":  toolType,
			"risk_level": riskLevel,
			"action":     action,
		}
		regenerateEndpointBundle(r.Context(), deps, user.TenantID, user.ID)
		logAudit(r, deps, "update_tool_config", detail, "tool_config", id)

		// Return updated config
		updated, err := deps.ToolRiskConfigRepo.GetByID(r.Context(), user.TenantID, id)
		if err != nil || updated == nil {
			writeError(w, "internal_error", "failed to get updated tool config")
			return
		}

		resp := mapToolRiskConfigToInfo(updated)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// DeleteToolRiskConfig deletes a tool risk configuration
func DeleteToolRiskConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can delete tool configs")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id is required")
			return
		}

		// Get tool name for audit log before deletion
		existing, err := deps.ToolRiskConfigRepo.GetByID(r.Context(), user.TenantID, id)
		if err != nil {
			log.Printf("DeleteToolRiskConfig error fetching: %v", err)
			writeError(w, "internal_error", "failed to get tool config")
			return
		}
		if existing == nil {
			writeError(w, "not_found", "tool config not found")
			return
		}

		if err := deps.ToolRiskConfigRepo.Delete(r.Context(), user.TenantID, id); err != nil {
			log.Printf("DeleteToolRiskConfig error: %v", err)
			writeError(w, "internal_error", "failed to delete tool config")
			return
		}

		detail := map[string]interface{}{
			"config_id": id,
			"tool_name": existing.ToolName,
		}
		regenerateEndpointBundle(r.Context(), deps, user.TenantID, user.ID)
		logAudit(r, deps, "delete_tool_config", detail, "tool_config", id)

		w.WriteHeader(http.StatusNoContent)
	}
}

// BatchUpsertToolRiskConfigs batch creates or updates tool risk configurations
func BatchUpsertToolRiskConfigs(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can batch update tool configs")
			return
		}

		var req ToolRiskConfigBatchRequest
		if err := decodeToolRiskRequest(w, r, &req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		if len(req.Configs) == 0 || len(req.Configs) > 200 {
			writeError(w, "invalid_request", "configs array is required and must not be empty")
			return
		}

		configs := make([]repository.ToolRiskConfig, len(req.Configs))
		seen := make(map[string]bool, len(req.Configs))
		for i, c := range req.Configs {
			riskLevel := c.RiskLevel
			if riskLevel == "" {
				riskLevel = "medium"
			}
			action := c.Action
			if action == "" {
				action = "audit"
			}
			configs[i] = repository.ToolRiskConfig{
				ToolName:    c.ToolName,
				ToolType:    c.ToolType,
				RiskLevel:   riskLevel,
				Action:      action,
				Description: c.Description,
			}
			if err := repository.ValidateToolRiskConfig(&configs[i]); err != nil {
				writeError(w, "invalid_request", err.Error())
				return
			}
			if seen[c.ToolName] {
				writeError(w, "invalid_request", "duplicate tool_name in configs")
				return
			}
			seen[c.ToolName] = true
		}

		upserted, skipped, err := deps.ToolRiskConfigRepo.BatchUpsertPreserving(r.Context(), user.TenantID, configs, req.PreserveExisting)
		if err != nil {
			log.Printf("BatchUpsertToolRiskConfigs error: %v", err)
			writeError(w, "internal_error", "failed to batch upsert tool configs")
			return
		}

		detail := map[string]interface{}{
			"configs_count":     len(req.Configs),
			"upserted":          upserted,
			"preserve_existing": req.PreserveExisting,
			"skipped":           skipped,
		}
		regenerateEndpointBundle(r.Context(), deps, user.TenantID, user.ID)
		logAudit(r, deps, "batch_upsert_tool_configs", detail, "tool_config", "")

		// Return all configs after batch operation
		allConfigs, err := deps.ToolRiskConfigRepo.List(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to list tool configs after batch")
			return
		}

		data := make([]ToolRiskConfigInfo, len(allConfigs))
		for i, c := range allConfigs {
			data[i] = mapToolRiskConfigToInfo(&c)
		}

		resp := map[string]interface{}{
			"data":     data,
			"total":    len(data),
			"upserted": upserted,
			"skipped":  skipped,
		}
		if req.PreserveExisting {
			resp["inserted"] = upserted
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
