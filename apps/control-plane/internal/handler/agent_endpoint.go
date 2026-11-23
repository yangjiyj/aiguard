package handler

import (
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/endpointevents"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const (
	agentRegisterBodyLimit = 64 << 10
	agentEventsBodyLimit   = 8 << 20
	agentEventsGzipLimit   = 8 << 20
)

type agentEndpointRepository interface {
	Resolve(context.Context, string) (*repository.AgentEndpointContext, error)
	Register(context.Context, string, repository.AgentEndpointRegisterRequest) (map[string]any, error)
	Heartbeat(context.Context, string, string, any, int64, int64) error
	Policy(context.Context, string) (map[string]any, error)
	AcceptEventBatch(context.Context, string, string, repository.AgentEventBatchRequest) (*repository.AgentEventBatchResult, error)
}

type AgentEndpointAPI struct {
	Repo              agentEndpointRepository
	ToolLogs          *repository.ToolCallLogRepository
	AuthorizationRepo intentAuthorizationRepository
	Deps              *Dependencies
}

func NewAgentEndpointAPI(repo *repository.AgentEndpointRepository, logs ...*repository.ToolCallLogRepository) *AgentEndpointAPI {
	var toolLogs *repository.ToolCallLogRepository
	if len(logs) > 0 {
		toolLogs = logs[0]
	}
	return &AgentEndpointAPI{Repo: repo, ToolLogs: toolLogs}
}

func agentSecurityLicensed(r *http.Request, deps *Dependencies) (bool, error) {
	if deps == nil || deps.SystemRepo == nil {
		return false, fmt.Errorf("license repository unavailable")
	}
	stored, err := getLicenseSetting(r, deps, LicenseSettingKey)
	if err != nil {
		return false, err
	}
	status := licenseStatusFromStored(r, deps, stored, "", time.Now().UTC())
	return status.Valid && licenseHasFeature(status, "agent_security"), nil
}

func (h *AgentEndpointAPI) LicenseStatus(w http.ResponseWriter, r *http.Request) {
	licensed, err := agentSecurityLicensed(r, h.Deps)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"licensed": licensed})
}

func decodeStrictJSON(r io.Reader, dst any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func (h *AgentEndpointAPI) Resolve(w http.ResponseWriter, r *http.Request) {
	var q struct {
		TokenHash string `json:"token_hash"`
	}
	if decodeStrictJSON(r.Body, &q) != nil || len(q.TokenHash) != 64 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if _, err := hex.DecodeString(q.TokenHash); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	v, err := h.Repo.Resolve(r.Context(), q.TokenHash)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if v == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	licensed, err := agentSecurityLicensed(r, h.Deps)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		*repository.AgentEndpointContext
		Licensed bool `json:"licensed"`
	}{v, licensed})
}

func (h *AgentEndpointAPI) Register(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, agentRegisterBodyLimit)
	q, decodeErr := decodeAgentRegistration(body)
	if decodeErr != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	enrollmentToken := strings.TrimSpace(auth[7:])
	if enrollmentToken == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	licensed, err := agentSecurityLicensed(r, h.Deps)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !licensed {
		http.Error(w, "AGENT_UNLICENSED", http.StatusForbidden)
		return
	}
	v, err := h.Repo.Register(r.Context(), repository.HashAgentToken(enrollmentToken), q)
	if err != nil {
		http.Error(w, "enrollment rejected", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (h *AgentEndpointAPI) Heartbeat(w http.ResponseWriter, r *http.Request) {
	var q struct {
		EndpointID    string `json:"endpoint_id"`
		PolicyVersion int64  `json:"policy_version"`
		ConfigVersion int64  `json:"config_version"`
		Health        any    `json:"health"`
	}
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	ctx := endpointContext(r)
	if ctx == nil || subtle.ConstantTimeCompare([]byte(ctx.EndpointID), []byte(q.EndpointID)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	if h.Repo.Heartbeat(r.Context(), ctx.TenantID, q.EndpointID, q.Health, q.PolicyVersion, q.ConfigVersion) != nil {
		http.Error(w, "internal error", 500)
		return
	}
	policy, err := h.Repo.Policy(r.Context(), ctx.TenantID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"server_time": time.Now().UTC(), "mode": ctx.Mode, "capture_level": ctx.CaptureLevel, "policy": map[string]any{"version": policy["version"], "checksum": policy["checksum"]}, "revoked": false})
}
func (h *AgentEndpointAPI) Events(w http.ResponseWriter, r *http.Request) {
	ctx := endpointContext(r)
	if ctx == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var request repository.AgentEventBatchRequest
	var body io.Reader
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
	case "", "identity":
		body = http.MaxBytesReader(w, r.Body, agentEventsBodyLimit)
	case "gzip":
		compressed := http.MaxBytesReader(w, r.Body, agentEventsGzipLimit)
		reader, err := gzip.NewReader(compressed)
		if err != nil {
			writeAgentEventBatchError(w, http.StatusUnprocessableEntity, "invalid_batch", nil)
			return
		}
		defer reader.Close()
		body = http.MaxBytesReader(w, reader, agentEventsBodyLimit)
	default:
		writeAgentEventBatchError(w, http.StatusUnsupportedMediaType, "unsupported_content_encoding", nil)
		return
	}
	if err := decodeStrictJSON(body, &request); err != nil {
		writeAgentEventBatchError(w, http.StatusUnprocessableEntity, "invalid_batch", nil)
		return
	}
	if request.EndpointID != ctx.EndpointID {
		writeAgentEventBatchError(w, http.StatusUnauthorized, "endpoint_mismatch", nil)
		return
	}
	if strings.TrimSpace(request.HookdVersion) == "" || strings.TrimSpace(request.SentAt) == "" {
		writeAgentEventBatchError(w, http.StatusUnprocessableEntity, "invalid_batch", nil)
		return
	}
	for _, raw := range request.Events {
		event, err := endpointevents.Decode(raw)
		if err != nil {
			writeAgentEventBatchError(w, http.StatusUnprocessableEntity, "invalid_event", nil)
			return
		}
		if endpointevents.IsNested(event) {
			if err := endpointevents.ValidateEvent(event, time.Now(), ctx.CaptureLevel); err != nil {
				writeAgentEventBatchError(w, http.StatusUnprocessableEntity, "invalid_event", nil)
				return
			}
		} else if err := endpointevents.ValidateLegacyCapture(event, ctx.CaptureLevel); err != nil {
			writeAgentEventBatchError(w, http.StatusUnprocessableEntity, "invalid_event", nil)
			return
		}
	}
	// Endpoint context carries the last applied version, not necessarily the
	// current downloadable bundle. Resolve the same source as Policy/Heartbeat
	// before committing events so policy failures cannot strand a committed ACK.
	policy, err := h.Repo.Policy(r.Context(), ctx.TenantID)
	if err != nil {
		writeAgentEventBatchError(w, http.StatusServiceUnavailable, "policy_unavailable", nil)
		return
	}
	version, versionOK := policy["version"].(int64)
	checksum, checksumOK := policy["checksum"].(string)
	digest := strings.TrimPrefix(checksum, "sha256:")
	_, checksumErr := hex.DecodeString(digest)
	if !versionOK || version < 1 || !checksumOK || !strings.HasPrefix(checksum, "sha256:") ||
		len(digest) != 64 || checksumErr != nil || digest == strings.Repeat("0", 64) {
		writeAgentEventBatchError(w, http.StatusServiceUnavailable, "policy_unavailable", nil)
		return
	}
	result, err := h.Repo.AcceptEventBatch(r.Context(), ctx.TenantID, ctx.EndpointID, request)
	if err != nil {
		var batchErr *repository.AgentEventBatchError
		if errors.As(err, &batchErr) {
			status := http.StatusUnprocessableEntity
			if batchErr.Code == "event_conflict" {
				status = http.StatusConflict
			}
			writeAgentEventBatchError(w, status, batchErr.Code, batchErr.EventIDs)
			return
		}
		writeAgentEventBatchError(w, http.StatusInternalServerError, "batch_failed", nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted": result.Accepted, "duplicates": result.Duplicates, "rejected": result.Rejected, "rejections": result.Rejections,
		"server_time": time.Now().UTC(), "mode": ctx.Mode,
		"policy": map[string]any{"version": version, "checksum": checksum},
	})
}

func writeAgentEventBatchError(w http.ResponseWriter, status int, code string, rejected []string) {
	if rejected == nil {
		rejected = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted": []string{}, "duplicates": []string{}, "rejected": rejected, "error": code,
	})
}
func (h *AgentEndpointAPI) Policy(w http.ResponseWriter, r *http.Request) {
	ctx := endpointContext(r)
	if ctx == nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	v, e := h.Repo.Policy(r.Context(), ctx.TenantID)
	if e != nil {
		http.Error(w, "internal error", 500)
		return
	}
	etag := ""
	if checksum, ok := v["checksum"].(string); ok && checksum != "" {
		etag = `"` + checksum + `"`
		w.Header().Set("ETag", etag)
	}
	if etag != "" && r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func endpointContext(r *http.Request) *repository.AgentEndpointContext {
	v, _ := r.Context().Value(agentEndpointContextKey{}).(*repository.AgentEndpointContext)
	return v
}

type agentEndpointContextKey struct{}

func EndpointAuth(repo *repository.AgentEndpointRepository, deps *Dependencies) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a := r.Header.Get("Authorization")
			if !strings.HasPrefix(strings.ToLower(a), "bearer ") {
				http.Error(w, "AGENT_UNAUTHORIZED", 401)
				return
			}
			v, e := repo.Resolve(r.Context(), repository.HashAgentToken(strings.TrimSpace(a[7:])))
			if e != nil || v == nil {
				http.Error(w, "AGENT_UNAUTHORIZED", 401)
				return
			}
			licensed, err := agentSecurityLicensed(r, deps)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if !licensed {
				http.Error(w, "AGENT_UNLICENSED", http.StatusForbidden)
				return
			}
			if v.Revoked {
				http.Error(w, "AGENT_ENDPOINT_REVOKED", 403)
				return
			}
			next.ServeHTTP(w, r.WithContext(contextWithEndpoint(r.Context(), v)))
		})
	}
}
func contextWithEndpoint(ctx context.Context, v *repository.AgentEndpointContext) context.Context {
	return context.WithValue(ctx, agentEndpointContextKey{}, v)
}
