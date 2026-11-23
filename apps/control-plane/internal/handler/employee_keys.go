package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

type employeeKeyRequest struct {
	UserID                 string `json:"user_id"`
	LoginMode              string `json:"login_mode"`
	ExternalSubject        string `json:"external_subject"`
	LocalCredentialVersion int64  `json:"local_credential_version,omitempty"`
	ExpectedKeyID          string `json:"expected_key_id,omitempty"`
	ExpectedGeneration     int64  `json:"expected_generation,omitempty"`
}
type employeeKeyContext struct {
	tenant  string
	user    *repository.User
	project string
}

// Identity coordinates come only from a trusted server's signed session.
// Credentials never select a user, department, project or privileges here.
func resolveEmployeeKeyContext(w http.ResponseWriter, r *http.Request, deps *Dependencies, req employeeKeyRequest) (*employeeKeyContext, bool) {
	tenant, ok := portalTenantID(w, r)
	if !ok {
		return nil, false
	}
	if deps == nil || deps.UserRepo == nil || deps.EmployeeKeyRepo == nil || deps.ProjectUserRepo == nil {
		portalNotConfigured(w, "employee credential repository")
		return nil, false
	}
	req.UserID = strings.TrimSpace(req.UserID)
	req.ExternalSubject = strings.TrimSpace(req.ExternalSubject)
	if req.UserID == "" || req.ExternalSubject == "" || (req.LoginMode != "local" && req.LoginMode != "oidc") {
		writeErrorWithStatus(w, 400, "invalid_request", "signed employee identity is required")
		return nil, false
	}
	user, err := deps.UserRepo.GetByID(r.Context(), req.UserID)
	if err != nil {
		writeErrorWithStatus(w, 503, "authorization_unavailable", "employee authorization unavailable")
		return nil, false
	}
	if user == nil || user.TenantID != tenant || !roles.CanLoginPortal(user.Role) || user.Status != "active" || user.MustChangePassword || user.DepartmentID == "" || user.DepartmentVersion <= 0 || user.DepartmentAssignmentMode == identitybinding.ModeEmergency || user.DepartmentAssignmentMode == "service" {
		writeEmployeeKeyError(w, repository.ErrEmployeeKeyDenied)
		return nil, false
	}
	issuer := strings.TrimSuffix(strings.TrimSpace(deps.IdentityRuntimeConfig.IssuerURL), "/")
	if req.LoginMode == "local" {
		if deps.ChatLoginTickets == nil {
			portalNotConfigured(w, "local identity binding lookup")
			return nil, false
		}
		identity, err := deps.ChatLoginTickets.CurrentIdentity(r.Context(), tenant, user.ID, issuer)
		if err != nil {
			writeErrorWithStatus(w, 503, "authorization_unavailable", "employee identity unavailable")
			return nil, false
		}
		if identity == nil || identity.ExternalSubject != req.ExternalSubject || req.LocalCredentialVersion <= 0 || req.LocalCredentialVersion != identity.LocalCredentialVersion {
			writeEmployeeKeyError(w, repository.ErrEmployeeKeyDenied)
			return nil, false
		}
	} else {
		reader, configured := deps.UserIdentityLinkLookup.(interface {
			GetByStableKey(context.Context, identitybinding.ExternalIdentity) (*identitybinding.UserIdentityLink, error)
		})
		if !configured || issuer == "" {
			portalNotConfigured(w, "employee identity binding lookup")
			return nil, false
		}
		sourceID := ""
		if deps.IdentitySourceLookup != nil {
			source, err := deps.IdentitySourceLookup.GetActive(r.Context(), tenant)
			if err != nil {
				writeErrorWithStatus(w, 503, "authorization_unavailable", "identity source unavailable")
				return nil, false
			}
			if source != nil {
				sourceID = source.ID
			}
		}
		link, err := reader.GetByStableKey(r.Context(), identitybinding.ExternalIdentity{TenantID: tenant, Issuer: issuer, SourceType: "oidc", SourceID: sourceID, ExternalSubject: req.ExternalSubject})
		if err != nil {
			writeErrorWithStatus(w, 503, "authorization_unavailable", "employee identity unavailable")
			return nil, false
		}
		if link == nil || link.UserID != user.ID || link.TenantID != tenant {
			writeEmployeeKeyError(w, repository.ErrEmployeeKeyDenied)
			return nil, false
		}
	}
	if deps.UserModelRepo != nil {
		access, err := deps.UserModelRepo.GetAccess(r.Context(), tenant, user.ID)
		if err != nil {
			writeErrorWithStatus(w, 503, "authorization_unavailable", "employee model authorization unavailable")
			return nil, false
		}
		if !access.ChatAllowed {
			writeEmployeeKeyError(w, repository.ErrEmployeeKeyDenied)
			return nil, false
		}
	}
	project, err := portalDefaultProject(r.Context(), deps, tenant, user.DepartmentID)
	if err != nil {
		writeErrorWithStatus(w, 503, "authorization_unavailable", "employee application unavailable")
		return nil, false
	}
	if project == "" {
		writeEmployeeKeyError(w, repository.ErrEmployeeKeyDenied)
		return nil, false
	}
	return &employeeKeyContext{tenant: tenant, user: user, project: project}, true
}
func bindEmployeeProject(ctx context.Context, deps *Dependencies, tenant string, user *repository.User, project string) error {
	bound, err := deps.ProjectUserRepo.BindPortalDefaultProject(ctx, tenant, user.ID, project, user.DepartmentID, user.DepartmentVersion)
	if err != nil {
		return err
	}
	if !bound {
		return repository.ErrEmployeeKeyDenied
	}
	return nil
}
func ensureEmployeeCredential(ctx context.Context, deps *Dependencies, tenant string, user *repository.User, project string, expectedLocalVersion ...int64) (*repository.EmployeeAPIKey, bool, error) {
	if err := bindEmployeeProject(ctx, deps, tenant, user, project); err != nil {
		return nil, false, err
	}
	return deps.EmployeeKeyRepo.Ensure(ctx, tenant, user.ID, project, user.DepartmentID, user.DepartmentVersion, expectedLocalVersion...)
}
func writeEmployeeKeyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repository.ErrEmployeeKeyDenied):
		writeErrorWithStatus(w, 403, "authorization_denied", "employee credential is not authorized")
	case errors.Is(err, repository.ErrEmployeeKeyConflict):
		writeErrorWithStatus(w, 409, "employee_key_conflict", "employee credential changed; refresh and retry")
	case errors.Is(err, repository.ErrEmployeeKeyEncryptionUnavailable):
		writeErrorWithStatus(w, 409, "created_before_encryption", "this legacy credential requires explicit reset")
	case errors.Is(err, repository.ErrEmployeeKeyAlreadyClaimed):
		writeErrorWithStatus(w, 409, "employee_key_already_claimed", "employee credential has already been claimed; reset to obtain a new credential")
	default:
		writeErrorWithStatus(w, 503, "employee_key_unavailable", "employee credential service unavailable")
	}
}
func decodeEmployeeKeyRequest(w http.ResponseWriter, r *http.Request) (employeeKeyRequest, bool) {
	var req employeeKeyRequest
	if r.Method == http.MethodGet {
		req.UserID = r.URL.Query().Get("user_id")
		req.LoginMode = r.URL.Query().Get("login_mode")
		req.ExternalSubject = r.URL.Query().Get("external_subject")
		req.LocalCredentialVersion, _ = strconv.ParseInt(r.URL.Query().Get("local_credential_version"), 10, 64)
		return req, true
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeErrorWithStatus(w, 400, "invalid_request", "invalid employee credential request")
		return req, false
	}
	return req, true
}
func EmployeeKeyEndpoint(deps *Dependencies, action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Pragma", "no-cache")
		req, ok := decodeEmployeeKeyRequest(w, r)
		if !ok {
			return
		}
		identity, ok := resolveEmployeeKeyContext(w, r, deps, req)
		if !ok {
			return
		}
		var versions []int64
		if req.LoginMode == "local" {
			versions = []int64{req.LocalCredentialVersion}
		}
		var key *repository.EmployeeAPIKey
		var raw string
		var created bool
		var err error
		switch action {
		case "metadata":
			key, err = deps.EmployeeKeyRepo.Current(r.Context(), identity.tenant, identity.user.ID, versions...)
		case "ensure":
			key, created, err = ensureEmployeeCredential(r.Context(), deps, identity.tenant, identity.user, identity.project, versions...)
		case "credential":
			key, raw, err = deps.EmployeeKeyRepo.Credential(r.Context(), identity.tenant, identity.user.ID, versions...)
		case "claim", "reset":
			if strings.TrimSpace(req.ExpectedKeyID) == "" || req.ExpectedGeneration <= 0 {
				writeErrorWithStatus(w, 400, "invalid_request", "expected credential id and generation are required")
				return
			}
			if action == "claim" {
				key, raw, err = deps.EmployeeKeyRepo.Claim(r.Context(), identity.tenant, identity.user.ID, req.ExpectedKeyID, req.ExpectedGeneration, versions...)
			} else {
				if err = bindEmployeeProject(r.Context(), deps, identity.tenant, identity.user, identity.project); err == nil {
					key, raw, err = deps.EmployeeKeyRepo.Reset(r.Context(), identity.tenant, identity.user.ID, req.ExpectedKeyID, req.ExpectedGeneration, identity.project, identity.user.DepartmentID, identity.user.DepartmentVersion, versions...)
				}
			}
		default:
			writeErrorWithStatus(w, 404, "not_found", "employee credential operation not found")
			return
		}
		if err != nil {
			writeEmployeeKeyError(w, err)
			return
		}
		if key == nil {
			writeErrorWithStatus(w, 404, "employee_key_not_found", "employee credential not found")
			return
		}
		result := map[string]any{"key": key}
		if action == "ensure" {
			result["created"] = created
		}
		if action == "claim" || action == "reset" {
			result["full_key"] = raw
			portalLogAudit(r, deps, identity.tenant, "employee_key_"+action, map[string]interface{}{"user_id": identity.user.ID, "key_id": key.ID, "generation": key.Generation}, "key", key.ID)
		}
		if action == "credential" {
			result["credential"] = raw
		}
		writeJSON(w, result)
	}
}
