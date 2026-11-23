package handler

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const agentAuthorizationBodyLimit = 64 << 10

type agentAuthorizationRepository interface {
	RegisterPrincipal(context.Context, string, repository.AgentAuthorizationPrincipalCreate) (*repository.AgentAuthorizationPrincipalCreated, error)
	ListPrincipals(context.Context, string) ([]repository.AgentAuthorizationPrincipal, error)
	RevokePrincipal(context.Context, string, string) (bool, error)
	RotatePrincipalCredential(context.Context, string, string, string) (string, bool, error)
	ResolvePrincipalCredential(context.Context, string) (*repository.TrustedAgentPrincipal, error)
	Authorize(context.Context, repository.TrustedAgentPrincipal, repository.AgentAuthorizationRequest) (*repository.AgentAuthorizationDecision, error)
}

// agentAuthorizationRotationEffectsRepository is implemented by the PostgreSQL repository:
// rotation also revokes pre-rotation exceptions and unclaimed approvals, reported for audit.
type agentAuthorizationRotationEffectsRepository interface {
	RotatePrincipalCredentialWithEffects(context.Context, string, string, string) (string, bool, repository.AgentAuthorizationRotationEffects, error)
}

type AgentAuthorizationAPI struct {
	Repo agentAuthorizationRepository
	Deps *Dependencies
}

func NewAgentAuthorizationAPI(repo agentAuthorizationRepository, deps *Dependencies) *AgentAuthorizationAPI {
	return &AgentAuthorizationAPI{Repo: repo, Deps: deps}
}

type trustedAgentAuthorizationContextKey struct{}

func trustedAgentAuthorizationPrincipal(r *http.Request) *repository.TrustedAgentPrincipal {
	value, _ := r.Context().Value(trustedAgentAuthorizationContextKey{}).(*repository.TrustedAgentPrincipal)
	return value
}

func agentAuthorizationBearerHash(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", false
	}
	return repository.HashAgentToken(parts[1]), true
}

// Authenticate resolves the bearer token to a server-issued principal. The request
// body and optional identity headers are never used to construct that identity.
func (h *AgentAuthorizationAPI) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHash, ok := agentAuthorizationBearerHash(r.Header.Get("Authorization"))
		if !ok {
			writeUnauthorized(w, "agent credential required")
			return
		}
		principal, err := h.Repo.ResolvePrincipalCredential(r.Context(), tokenHash)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to authenticate agent")
			return
		}
		if principal == nil {
			writeUnauthorized(w, "invalid or expired agent credential")
			return
		}
		licensed, err := agentSecurityLicensed(r, h.Deps)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "agent authorization unavailable")
			return
		}
		if !licensed {
			writeErrorWithStatus(w, http.StatusForbidden, "agent_security_unlicensed", "agent security is not licensed")
			return
		}
		ctx := context.WithValue(r.Context(), trustedAgentAuthorizationContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *AgentAuthorizationAPI) RegisterPrincipal(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	var request struct {
		Name      string                               `json:"name"`
		ExpiresAt time.Time                            `json:"expires_at"`
		Grants    []repository.AgentAuthorizationGrant `json:"grants"`
	}
	if err := decodeStrictJSON(http.MaxBytesReader(w, r.Body, agentAuthorizationBodyLimit), &request); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid agent principal registration")
		return
	}
	created, err := h.Repo.RegisterPrincipal(r.Context(), user.TenantID, repository.AgentAuthorizationPrincipalCreate{
		Name: request.Name, ExpiresAt: request.ExpiresAt, CreatedBy: user.ID, Grants: request.Grants,
	})
	if err != nil {
		if errors.Is(err, repository.ErrAgentAuthorizationInvalid) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid agent principal registration")
			return
		}
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to register agent principal")
		return
	}
	grantIDs := make([]string, 0, len(created.Grants))
	for _, grant := range created.Grants {
		grantIDs = append(grantIDs, grant.ID)
	}
	// Never include the one-time credential in the audit record.
	logAudit(r, h.Deps, "agent_authorization_principal.register", map[string]any{
		"principal_id": created.Principal.ID, "name": created.Principal.Name, "created_by": created.Principal.CreatedBy,
		"expires_at": created.Principal.ExpiresAt, "grant_ids": grantIDs,
	}, "agent_authorization_principal", created.Principal.ID)
	writeAgentAdminSecretJSON(w, http.StatusCreated, created)
}

func (h *AgentAuthorizationAPI) ListPrincipals(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	items, err := h.Repo.ListPrincipals(r.Context(), user.TenantID)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list agent principals")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *AgentAuthorizationAPI) RevokePrincipal(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	principalID := chi.URLParam(r, "id")
	found, err := h.Repo.RevokePrincipal(r.Context(), user.TenantID, principalID)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to revoke agent principal")
		return
	}
	if !found {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "agent principal not found")
		return
	}
	logAudit(r, h.Deps, "agent_authorization_principal.revoke", map[string]any{"principal_id": principalID},
		"agent_authorization_principal", principalID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AgentAuthorizationAPI) RotatePrincipalCredential(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	principalID := chi.URLParam(r, "id")
	var credential string
	var found bool
	var err error
	var effects repository.AgentAuthorizationRotationEffects
	if repo, ok := h.Repo.(agentAuthorizationRotationEffectsRepository); ok {
		credential, found, effects, err = repo.RotatePrincipalCredentialWithEffects(r.Context(), user.TenantID, principalID, user.ID)
	} else {
		credential, found, err = h.Repo.RotatePrincipalCredential(r.Context(), user.TenantID, principalID, user.ID)
	}
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to rotate agent credential")
		return
	}
	if !found {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "active agent principal not found")
		return
	}
	// The rotator now holds a working agent credential; record who (never the credential).
	logAudit(r, h.Deps, "agent_authorization_principal.rotate", map[string]any{"principal_id": principalID, "rotated_by": user.ID},
		"agent_authorization_principal", principalID)
	if n := len(effects.RevokedExceptionIDs) + len(effects.RevokedApprovalIDs); n > 0 {
		// Authorization granted before the rotation was invalidated; ids and counts only.
		logAudit(r, h.Deps, "agent_authorization_principal.rotate_invalidated", map[string]any{
			"principal_id":            principalID,
			"revoked_exception_count": len(effects.RevokedExceptionIDs), "revoked_exception_ids": effects.RevokedExceptionIDs,
			"revoked_approval_count": len(effects.RevokedApprovalIDs), "revoked_approval_ids": effects.RevokedApprovalIDs,
		}, "agent_authorization_principal", principalID)
	}
	writeAgentAdminSecretJSON(w, http.StatusOK, map[string]string{"credential": credential})
}

func (h *AgentAuthorizationAPI) Authorize(w http.ResponseWriter, r *http.Request) {
	principal := trustedAgentAuthorizationPrincipal(r)
	if principal == nil {
		writeUnauthorized(w, "agent credential required")
		return
	}
	var request repository.AgentAuthorizationRequest
	if err := decodeStrictJSON(http.MaxBytesReader(w, r.Body, agentAuthorizationBodyLimit), &request); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid authorization request")
		return
	}
	decision, err := h.Repo.Authorize(r.Context(), *principal, request)
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrAgentAuthorizationInvalid):
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid authorization request")
		case errors.Is(err, repository.ErrAgentAuthorizationPrincipalUnauthorized):
			writeUnauthorized(w, "agent credential is no longer active")
		case errors.Is(err, repository.ErrAgentAuthorizationIdempotencyConflict):
			writeErrorWithStatus(w, http.StatusConflict, "idempotency_conflict", "idempotency key belongs to a different request")
		default:
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "authorization decision unavailable")
		}
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, decision)
}
