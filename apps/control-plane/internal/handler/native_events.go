package handler

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const nativeEventBodyLimit = 1 << 20

type NativeEventRepository interface {
	Ingest(context.Context, repository.NativeEventTransport, []byte) (*repository.NativeEventReceipt, error)
	List(context.Context, string, repository.NativeEventFilter) (*repository.NativeEventPage, error)
}
type NativeEventAPI struct{ Repo NativeEventRepository }

func NewNativeEventAPI(repo NativeEventRepository) *NativeEventAPI {
	return &NativeEventAPI{Repo: repo}
}

func (h *NativeEventAPI) Ingest(w http.ResponseWriter, r *http.Request) {
	ep := endpointContext(r)
	auth := r.Header.Get("Authorization")
	if ep == nil || ep.TenantID == "" || ep.EndpointID == "" || ep.Revoked || !strings.HasPrefix(strings.ToLower(auth), "bearer ") || strings.TrimSpace(auth[7:]) == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
		return
	}
	if encoding := r.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		http.Error(w, "unsupported content encoding", http.StatusUnsupportedMediaType)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, nativeEventBodyLimit))
	if err != nil {
		var size *http.MaxBytesError
		if errors.As(err, &size) {
			http.Error(w, "batch too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid body", http.StatusBadRequest)
		}
		return
	}
	if h.Repo == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	result, err := h.Repo.Ingest(r.Context(), repository.NativeEventTransport{
		TenantID: ep.TenantID, EndpointID: ep.EndpointID, CredentialHash: repository.HashAgentToken(strings.TrimSpace(auth[7:])),
	}, raw)
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrNativeEventUnauthorized):
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case errors.Is(err, repository.ErrNativeEventInvalid):
			http.Error(w, "invalid native event batch", http.StatusUnprocessableEntity)
		case errors.Is(err, repository.ErrNativeEventConflict):
			http.Error(w, "conflicting native event identity", http.StatusConflict)
		default:
			http.Error(w, "native event storage failed", http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeAgentAdminJSON(w, http.StatusOK, result)
}
func (h *NativeEventAPI) List(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	// Reject ambiguous/unknown filters, including attempted tenant overrides.
	for key, values := range q {
		if len(values) != 1 {
			http.Error(w, "invalid query", http.StatusBadRequest)
			return
		}
		switch key {
		case "endpoint_id", "source_id", "ref_hash", "before_sequence", "limit":
		default:
			http.Error(w, "invalid query", http.StatusBadRequest)
			return
		}
	}
	filter := repository.NativeEventFilter{EndpointID: q.Get("endpoint_id"), SourceID: q.Get("source_id"), RefHash: q.Get("ref_hash"), Limit: 50}
	if q.Has("before_sequence") {
		value, err := strconv.ParseInt(q.Get("before_sequence"), 10, 64)
		if err != nil || value < 1 {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		filter.BeforeSequence = value
	}
	if q.Has("limit") {
		value, err := strconv.Atoi(q.Get("limit"))
		if err != nil || value < 1 || value > 200 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		filter.Limit = value
	}
	if h.Repo == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	result, err := h.Repo.List(r.Context(), user.TenantID, filter)
	if errors.Is(err, repository.ErrNativeEventInvalid) {
		http.Error(w, "invalid query", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "native event query failed", http.StatusInternalServerError)
		return
	}
	if !canReadFullTenantContentEvidence(user) {
		for i := range result.Items {
			result.Items[i].Payload = nil
			result.Items[i].Investigation = nil
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeAgentAdminJSON(w, http.StatusOK, result)
}
