package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func billingCustomerGroupResponse(group *billing.CustomerGroup) map[string]any {
	return map[string]any{
		"id": group.ID, "tenant_id": group.TenantID, "code": group.Code,
		"name": group.Name, "description": group.Description, "status": group.Status,
		"is_default": group.IsDefault, "member_count": group.MemberCount,
		"ratio_ppm":   group.RatioPPM,
		"price_count": group.PriceCount, "created_at": group.CreatedAt, "updated_at": group.UpdatedAt,
	}
}

func ListBillingCustomerGroups(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		groups, err := store.ListCustomerGroups(r.Context(), tenantID)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		data := make([]map[string]any, 0, len(groups))
		for index := range groups {
			data = append(data, billingCustomerGroupResponse(&groups[index]))
		}
		writeJSON(w, map[string]any{"data": data})
	}
}

type billingCustomerGroupCreateRequest struct {
	TenantID    string `json:"tenant_id"`
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	RatioPPM    int64  `json:"ratio_ppm"`
}

func CreateBillingCustomerGroup(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorID, ok := billingAdmin(w, r)
		if !ok {
			return
		}
		var request billingCustomerGroupCreateRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&request); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		request.TenantID = strings.TrimSpace(request.TenantID)
		request.Code = strings.TrimSpace(request.Code)
		request.Name = strings.TrimSpace(request.Name)
		request.Description = strings.TrimSpace(request.Description)
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		group, err := store.CreateCustomerGroup(r.Context(), billing.NewCustomerGroup{
			TenantID: request.TenantID, Code: request.Code, Name: request.Name,
			Description: request.Description, RatioPPM: request.RatioPPM, CreatedBy: actorID,
		})
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.customer_group.create", map[string]interface{}{
			"tenant_id": group.TenantID, "code": group.Code, "name": group.Name,
			"ratio_ppm": group.RatioPPM,
		}, "billing_customer_group", group.ID)
		writeJSON(w, map[string]any{"data": billingCustomerGroupResponse(group)})
	}
}

type billingCustomerGroupUpdateRequest struct {
	TenantID    string `json:"tenant_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	RatioPPM    int64  `json:"ratio_ppm"`
}

func UpdateBillingCustomerGroup(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorID, ok := billingAdmin(w, r)
		if !ok {
			return
		}
		var request billingCustomerGroupUpdateRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&request); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		request.TenantID = strings.TrimSpace(request.TenantID)
		request.Name = strings.TrimSpace(request.Name)
		request.Description = strings.TrimSpace(request.Description)
		request.Status = strings.TrimSpace(request.Status)
		groupID := strings.TrimSpace(chi.URLParam(r, "id"))
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		group, err := store.UpdateCustomerGroup(r.Context(), request.TenantID, groupID, billing.CustomerGroupUpdate{
			Name: request.Name, Description: request.Description, Status: request.Status, RatioPPM: request.RatioPPM,
		})
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.customer_group.update", map[string]interface{}{
			"tenant_id": group.TenantID, "code": group.Code, "name": group.Name,
			"status": group.Status, "actor_id": actorID,
			"ratio_ppm": group.RatioPPM,
		}, "billing_customer_group", group.ID)
		writeJSON(w, map[string]any{"data": billingCustomerGroupResponse(group)})
	}
}

type billingCustomerGroupAssignmentRequest struct {
	TenantID      string `json:"tenant_id"`
	CustomerGroup string `json:"customer_group"`
}

func AssignBillingCustomerGroup(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorID, ok := billingAdmin(w, r)
		if !ok {
			return
		}
		var request billingCustomerGroupAssignmentRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&request); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		request.TenantID = strings.TrimSpace(request.TenantID)
		request.CustomerGroup = strings.TrimSpace(request.CustomerGroup)
		userID := strings.TrimSpace(chi.URLParam(r, "id"))
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		group, err := store.AssignCustomerGroup(r.Context(), request.TenantID, userID, request.CustomerGroup, actorID)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.customer_group.assign", map[string]interface{}{
			"tenant_id": request.TenantID, "user_id": userID, "customer_group": group.Code,
		}, "user", userID)
		writeJSON(w, map[string]any{"data": map[string]any{
			"user_id": userID, "customer_group": group.Code, "customer_group_name": group.Name,
		}})
	}
}
