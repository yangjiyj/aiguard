package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

const agentIntentAuthorizationBodyLimit = 32 << 10

type intentAuthorizationRepository interface {
	ResolveIntentAuthorizationContext(context.Context, string, string, agentintent.AuthorizationResolveRequest) (repository.AgentIntentAuthorizationContext, error)
}

// ResolveIntentAuthorizations is only mounted behind both the internal
// service-secret middleware and endpoint-token middleware. Tenant/endpoint
// authority comes exclusively from that endpoint token context; the body
// contains the exact T14 call tuple and facets to be recomputed against T13.
func (h *AgentEndpointAPI) ResolveIntentAuthorizations(w http.ResponseWriter, r *http.Request) {
	endpoint := endpointContext(r)
	if endpoint == nil || h.AuthorizationRepo == nil {
		http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
		return
	}
	var request agentintent.AuthorizationResolveRequest
	if err := decodeStrictJSON(http.MaxBytesReader(w, r.Body, agentIntentAuthorizationBodyLimit), &request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if endpoint.AgentProduct == "" || request.Product != endpoint.AgentProduct {
		http.Error(w, "endpoint product mismatch", http.StatusConflict)
		return
	}
	resolved, err := h.AuthorizationRepo.ResolveIntentAuthorizationContext(r.Context(), endpoint.TenantID, endpoint.EndpointID, request)
	if err != nil {
		http.Error(w, "authorization unresolved", http.StatusConflict)
		return
	}
	response := agentintent.AuthorizationResolveResponse{
		Resolutions: resolved.Resolutions, AuthorizationStatus: resolved.AuthorizationStatus,
		TaskStatus: resolved.TaskStatus,
	}
	if resolved.Task != nil {
		task := resolved.Task
		response.Task = &agentintent.ResolvedIntentTask{
			ID: task.ID, Purpose: task.Purpose, PurposeSHA256: task.PurposeSHA256,
			SourceScope:       agentintent.IntentTaskSourceScope{AllowedKinds: task.SourceScope.AllowedKinds, AllowedHashes: task.SourceScope.AllowedHashes},
			SourceScopeSHA256: task.SourceScopeSHA256, ScopeSHA256: task.ScopeSHA256, ExpiresAt: task.ExpiresAt,
			FacetScopeState: task.FacetScopeState,
			Grants:          make([]agentintent.IntentTaskGrantScope, 0, len(task.Grants)),
			History:         task.History, HistoryTruncated: task.HistoryTruncated,
			HistorySHA256: agentintent.IntentTaskHistoryHash(task.History, task.HistoryTruncated), SourceLinks: task.SourceLinks,
		}
		for _, grant := range task.Grants {
			response.Task.Grants = append(response.Task.Grants, agentintent.IntentTaskGrantScope{
				Action: grant.Action, ResourceType: grant.ResourceType,
				ResourceRefHash: grant.ResourceRefHash, ExpiresAt: grant.ExpiresAt,
			})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
