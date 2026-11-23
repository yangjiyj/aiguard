package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type agentKubernetesSnapshotRepo interface {
	CreateCluster(context.Context, string, string, repository.KubernetesClusterCreate) (*repository.KubernetesClusterRegistration, error)
	RegisterNamespace(context.Context, string, string, string, repository.KubernetesNamespaceRegister) (*repository.KubernetesNamespaceRegistrationSummary, error)
	ListClusters(context.Context, string) ([]repository.KubernetesClusterRegistration, error)
	RevokeNamespace(context.Context, string, string, string) (bool, error)
	GetCoverage(context.Context, string, string) (*repository.KubernetesClusterCoverage, error)
	BeginSnapshotRun(context.Context, *repository.AgentEndpointContext, repository.KubernetesSnapshotRunRequest) (*repository.KubernetesSnapshotRun, error)
	IngestSnapshot(context.Context, *repository.AgentEndpointContext, repository.KubernetesObservationReport) (*repository.KubernetesSnapshotIngestResult, error)
}

type AgentKubernetesSnapshotAPI struct {
	Repo agentKubernetesSnapshotRepo
}

func NewAgentKubernetesSnapshotAPI(repo agentKubernetesSnapshotRepo) *AgentKubernetesSnapshotAPI {
	return &AgentKubernetesSnapshotAPI{Repo: repo}
}

func (h *AgentKubernetesSnapshotAPI) ready(w http.ResponseWriter) bool {
	if h == nil || h.Repo == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "Kubernetes inventory is not configured")
		return false
	}
	return true
}

func (h *AgentKubernetesSnapshotAPI) CreateCluster(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	var body struct {
		DisplayName  string `json:"display_name"`
		ClusterLabel string `json:"cluster_label"`
	}
	if !decodeAgentAssetBody(w, r, &body) {
		return
	}
	cluster, err := h.Repo.CreateCluster(r.Context(), user.TenantID, user.ID, repository.KubernetesClusterCreate{
		DisplayName: body.DisplayName, ClusterLabel: body.ClusterLabel,
	})
	if writeKubernetesAPIError(w, err) {
		return
	}
	writeAgentAdminJSON(w, http.StatusCreated, cluster)
}

func (h *AgentKubernetesSnapshotAPI) ListClusters(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	clusters, err := h.Repo.ListClusters(r.Context(), user.TenantID)
	if writeKubernetesAPIError(w, err) {
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, map[string]any{"clusters": clusters})
}

func (h *AgentKubernetesSnapshotAPI) RegisterNamespace(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	var body repository.KubernetesNamespaceRegister
	if !decodeAgentAssetBody(w, r, &body) {
		return
	}
	registration, err := h.Repo.RegisterNamespace(r.Context(), user.TenantID, user.ID, chi.URLParam(r, "cluster_id"), body)
	if writeKubernetesAPIError(w, err) {
		return
	}
	writeAgentAdminJSON(w, http.StatusCreated, registration)
}

func (h *AgentKubernetesSnapshotAPI) RevokeNamespace(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	found, err := h.Repo.RevokeNamespace(r.Context(), user.TenantID, user.ID, chi.URLParam(r, "registration_id"))
	if writeKubernetesAPIError(w, err) {
		return
	}
	if !found {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "namespace registration not found")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

func (h *AgentKubernetesSnapshotAPI) Coverage(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	coverage, err := h.Repo.GetCoverage(r.Context(), user.TenantID, chi.URLParam(r, "cluster_id"))
	if writeKubernetesAPIError(w, err) {
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, coverage)
}

func (h *AgentKubernetesSnapshotAPI) BeginSnapshotRun(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	endpoint := endpointContext(r)
	if endpoint == nil || endpoint.AgentProduct != repository.KubernetesCollectorProduct {
		writeErrorWithStatus(w, http.StatusForbidden, "kubernetes_collector_required", "registered Kubernetes collector required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var request repository.KubernetesSnapshotRunRequest
	if err := decodeStrictJSON(r.Body, &request); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid snapshot run request")
		return
	}
	run, err := h.Repo.BeginSnapshotRun(r.Context(), endpoint, request)
	if writeKubernetesAPIError(w, err) {
		return
	}
	writeAgentAdminJSON(w, http.StatusCreated, run)
}

func (h *AgentKubernetesSnapshotAPI) IngestSnapshot(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	endpoint := endpointContext(r)
	if endpoint == nil || endpoint.AgentProduct != repository.KubernetesCollectorProduct {
		writeErrorWithStatus(w, http.StatusForbidden, "kubernetes_collector_required", "registered Kubernetes collector required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, repository.KubernetesMaxReportBytes)
	var report repository.KubernetesObservationReport
	if err := decodeStrictJSON(r.Body, &report); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid snapshot report")
		return
	}
	result, err := h.Repo.IngestSnapshot(r.Context(), endpoint, report)
	if writeKubernetesAPIError(w, err) {
		return
	}
	writeAgentAdminJSON(w, http.StatusAccepted, result)
}

func writeKubernetesAPIError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, repository.ErrKubernetesInvalid):
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid Kubernetes inventory request")
	case errors.Is(err, repository.ErrKubernetesUnauthorized):
		writeErrorWithStatus(w, http.StatusForbidden, "scope_not_registered", "collector is not registered for this Kubernetes scope")
	case errors.Is(err, repository.ErrKubernetesConflict):
		writeErrorWithStatus(w, http.StatusConflict, "snapshot_conflict", "Kubernetes registration or report conflicts with existing state")
	case errors.Is(err, repository.ErrKubernetesNotFound):
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "Kubernetes registration not found")
	default:
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "Kubernetes inventory operation failed")
	}
	return true
}
