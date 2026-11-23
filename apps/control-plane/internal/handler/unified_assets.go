package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

type AgentUnifiedAssetRepo interface {
	List(context.Context, string, repository.AgentUnifiedAssetFilter) (*repository.AgentUnifiedAssetPage, error)
	ListHistory(context.Context, string, string, int, int) (*repository.AgentUnifiedAssetHistoryPage, bool, error)
	FindNativeReferenceAsset(context.Context, string, string, string) (string, bool, error)
	UpdateOwnership(context.Context, string, string, repository.AgentAssetOwnershipUpdate) (bool, error)
	UpdateCatalog(context.Context, string, string, string, repository.AgentAssetCatalogUpdate) (bool, error)
	LinkSource(context.Context, string, string, string, repository.AgentAssetSourceRef) error
	Merge(context.Context, string, string, string) (bool, error)
}

type AgentUnifiedAssetAPI struct {
	Repo AgentUnifiedAssetRepo
	Deps *Dependencies
}

func NewAgentUnifiedAssetAPI(repo AgentUnifiedAssetRepo, deps *Dependencies) *AgentUnifiedAssetAPI {
	return &AgentUnifiedAssetAPI{Repo: repo, Deps: deps}
}

func (h *AgentUnifiedAssetAPI) ready(w http.ResponseWriter) bool {
	if h == nil || h.Repo == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "unified asset service is not configured")
		return false
	}
	return true
}

func decodeAgentAssetBody(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid unified asset request")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "request must contain one JSON object")
		return false
	}
	return true
}

func validUnifiedAssetText(value string, maxBytes int, allowEmpty bool) bool {
	if (!allowEmpty && strings.TrimSpace(value) == "") || len(value) > maxBytes {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validFullNativeReferenceHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func (h *AgentUnifiedAssetAPI) List(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	page, size, valid := agentAdminPageOrError(w, r)
	if !valid {
		return
	}
	q := r.URL.Query()
	filter := repository.AgentUnifiedAssetFilter{
		AssetID: strings.TrimSpace(q.Get("asset_id")), AssetType: strings.TrimSpace(q.Get("asset_type")),
		CatalogStatus: strings.TrimSpace(q.Get("catalog_status")), Page: page, PageSize: size,
	}
	if filter.AssetID != "" && !validUnifiedAssetText(filter.AssetID, 128, false) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid asset_id")
		return
	}
	if filter.AssetType != "" && !validUnifiedAssetText(filter.AssetType, 64, false) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid asset_type")
		return
	}
	value, err := h.Repo.List(r.Context(), user.TenantID, filter)
	if errors.Is(err, repository.ErrAgentAssetInvalidInput) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid catalog_status")
		return
	}
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list unified assets")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, value)
}

// FindNativeReferenceAsset resolves only the exact identity_event tuple used by
// the native timeline: namespace native:<source_id> and the complete ref_hash.
func (h *AgentUnifiedAssetAPI) FindNativeReferenceAsset(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	q := r.URL.Query()
	sourceID, refHash := q.Get("source_id"), q.Get("ref_hash")
	if len(q["source_id"]) != 1 || len(q["ref_hash"]) != 1 ||
		!validUnifiedAssetText(sourceID, 128, false) || sourceID != strings.TrimSpace(sourceID) || !validFullNativeReferenceHash(refHash) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "source_id and a complete ref_hash are required")
		return
	}
	assetID, found, err := h.Repo.FindNativeReferenceAsset(r.Context(), user.TenantID, sourceID, refHash)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to resolve native asset link")
		return
	}
	response := map[string]interface{}{"linked": found}
	if found {
		response["asset_id"] = assetID
	}
	writeAgentAdminJSON(w, http.StatusOK, response)
}

func (h *AgentUnifiedAssetAPI) ListHistory(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	assetID := strings.TrimSpace(chi.URLParam(r, "id"))
	if !validUnifiedAssetText(assetID, 128, false) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid asset id")
		return
	}
	page, size, valid := agentAdminPageOrError(w, r)
	if !valid {
		return
	}
	value, found, err := h.Repo.ListHistory(r.Context(), user.TenantID, assetID, page, size)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list asset history")
		return
	}
	if !found {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "unified asset not found")
		return
	}
	if !canReadFullTenantContentEvidence(user) {
		for i := range value.Items {
			value.Items[i].Evidence = redactRawContent(value.Items[i].Evidence)
		}
	}
	writeAgentAdminJSON(w, http.StatusOK, value)
}

func (h *AgentUnifiedAssetAPI) UpdateOwnership(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	assetID := strings.TrimSpace(chi.URLParam(r, "id"))
	if !validUnifiedAssetText(assetID, 128, false) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid asset id")
		return
	}
	var body struct {
		OwnerUserID     *string `json:"owner_user_id"`
		BusinessUnit    *string `json:"business_unit"`
		BusinessService *string `json:"business_service"`
	}
	if !decodeAgentAssetBody(w, r, &body) {
		return
	}
	if body.OwnerUserID == nil || body.BusinessUnit == nil || body.BusinessService == nil ||
		!validUnifiedAssetText(*body.OwnerUserID, 64, true) ||
		!validUnifiedAssetText(*body.BusinessUnit, 255, true) ||
		!validUnifiedAssetText(*body.BusinessService, 255, true) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "owner_user_id, business_unit, and business_service are required")
		return
	}
	updated, err := h.Repo.UpdateOwnership(r.Context(), user.TenantID, assetID, repository.AgentAssetOwnershipUpdate{
		OwnerUserID: strings.TrimSpace(*body.OwnerUserID), BusinessUnit: strings.TrimSpace(*body.BusinessUnit),
		BusinessService: strings.TrimSpace(*body.BusinessService),
	})
	if errors.Is(err, repository.ErrAgentAssetOwnerNotFound) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "owner user is not in the authenticated tenant")
		return
	}
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to update asset ownership")
		return
	}
	if !updated {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "unified asset not found")
		return
	}
	logAudit(r, h.Deps, "agent.asset.ownership.update", map[string]interface{}{"asset_id": assetID}, "agent_unified_asset", assetID)
	writeAgentAdminJSON(w, http.StatusOK, map[string]bool{"updated": true})
}

func (h *AgentUnifiedAssetAPI) UpdateCatalog(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	assetID := strings.TrimSpace(chi.URLParam(r, "id"))
	if !validUnifiedAssetText(assetID, 128, false) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid asset id")
		return
	}
	var body struct {
		Status    *string `json:"status"`
		Reason    *string `json:"reason"`
		ExpiresAt *string `json:"expires_at"`
	}
	if !decodeAgentAssetBody(w, r, &body) {
		return
	}
	if body.Status == nil || body.Reason == nil || body.ExpiresAt == nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "status, reason, and expires_at are required")
		return
	}
	status, reason := strings.TrimSpace(*body.Status), strings.TrimSpace(*body.Reason)
	var expiresAt *time.Time
	if strings.TrimSpace(*body.ExpiresAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*body.ExpiresAt))
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "expires_at must be RFC3339")
			return
		}
		parsed = parsed.UTC()
		expiresAt = &parsed
	}
	if (status == "exception" && (reason == "" || expiresAt == nil || !expiresAt.After(time.Now()))) ||
		((status == "approved" || status == "unreviewed") && (reason != "" || expiresAt != nil)) ||
		(status != "exception" && status != "approved" && status != "unreviewed") ||
		!validUnifiedAssetText(reason, 1024, true) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "exception requires a reason and future expiry; other statuses require empty reason and expiry")
		return
	}
	updated, err := h.Repo.UpdateCatalog(r.Context(), user.TenantID, assetID, user.ID, repository.AgentAssetCatalogUpdate{
		Status: status, Reason: reason, ExpiresAt: expiresAt,
	})
	if errors.Is(err, repository.ErrAgentAssetInvalidInput) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid catalog decision")
		return
	}
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to update asset catalog")
		return
	}
	if !updated {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "unified asset not found")
		return
	}
	logAudit(r, h.Deps, "agent.asset.catalog.update", map[string]interface{}{"asset_id": assetID, "status": status}, "agent_unified_asset", assetID)
	writeAgentAdminJSON(w, http.StatusOK, map[string]bool{"updated": true})
}

func (h *AgentUnifiedAssetAPI) LinkSource(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	assetID := strings.TrimSpace(chi.URLParam(r, "id"))
	if !validUnifiedAssetText(assetID, 128, false) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid asset id")
		return
	}
	var body struct {
		SourceType      *string `json:"source_type"`
		SourceNamespace *string `json:"source_namespace"`
		NativeID        *string `json:"native_id"`
	}
	if !decodeAgentAssetBody(w, r, &body) {
		return
	}
	if body.SourceType == nil || body.SourceNamespace == nil || body.NativeID == nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "source_type, source_namespace, and native_id are required")
		return
	}
	input := repository.AgentAssetSourceRef{
		SourceType:      strings.TrimSpace(*body.SourceType),
		SourceNamespace: strings.TrimSpace(*body.SourceNamespace),
		NativeID:        strings.TrimSpace(*body.NativeID),
	}
	if input.SourceType != "identity_event" ||
		!validUnifiedAssetText(input.SourceNamespace, 255, false) ||
		!validUnifiedAssetText(input.NativeID, 512, false) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "manual source linking supports identity_event references only")
		return
	}
	err := h.Repo.LinkSource(r.Context(), user.TenantID, assetID, user.ID, input)
	switch {
	case errors.Is(err, repository.ErrAgentUnifiedAssetNotFound):
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "unified asset not found")
		return
	case errors.Is(err, repository.ErrAgentAssetSourceConflict):
		writeErrorWithStatus(w, http.StatusConflict, "conflict", "source identity is already linked to another asset")
		return
	case errors.Is(err, repository.ErrAgentAssetInvalidInput):
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid source reference")
		return
	case err != nil:
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to link source reference")
		return
	}
	logAudit(r, h.Deps, "agent.asset.source.link", map[string]interface{}{"asset_id": assetID, "source_type": input.SourceType}, "agent_unified_asset", assetID)
	writeAgentAdminJSON(w, http.StatusOK, map[string]bool{"linked": true})
}

func (h *AgentUnifiedAssetAPI) Merge(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	sourceAssetID := strings.TrimSpace(chi.URLParam(r, "id"))
	if !validUnifiedAssetText(sourceAssetID, 128, false) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid source asset id")
		return
	}
	var body struct {
		TargetAssetID *string `json:"target_asset_id"`
	}
	if !decodeAgentAssetBody(w, r, &body) {
		return
	}
	if body.TargetAssetID == nil || !validUnifiedAssetText(strings.TrimSpace(*body.TargetAssetID), 128, false) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "target_asset_id is required")
		return
	}
	targetAssetID := strings.TrimSpace(*body.TargetAssetID)
	merged, err := h.Repo.Merge(r.Context(), user.TenantID, sourceAssetID, targetAssetID)
	if errors.Is(err, repository.ErrAgentAssetMergeConflict) {
		writeErrorWithStatus(w, http.StatusConflict, "conflict", "asset metadata conflicts; reconcile it before merging")
		return
	}
	if errors.Is(err, repository.ErrAgentAssetInvalidInput) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid merge request")
		return
	}
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to merge assets")
		return
	}
	if !merged {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "unified asset not found")
		return
	}
	logAudit(r, h.Deps, "agent.asset.merge", map[string]interface{}{"source_asset_id": sourceAssetID, "target_asset_id": targetAssetID}, "agent_unified_asset", targetAssetID)
	writeAgentAdminJSON(w, http.StatusOK, map[string]interface{}{"merged": true, "asset_id": targetAssetID})
}
