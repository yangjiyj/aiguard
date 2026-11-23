package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

const mcpAdmissionRequestMaxBytes = 4 << 10

var mcpAdmissionHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type MCPSupplyChainRepo interface {
	ApplySupplyChainSync(context.Context, repository.MCPSupplyChainSyncInput) (*repository.MCPSupplyChainSyncResult, error)
	ResolveMCPSupplyChain(context.Context, string, string, string) (repository.MCPSupplyChainResolution, error)
	SetMCPServerAdmission(context.Context, string, string, string, string, string, string, string) (*repository.MCPAdmissionMutation, error)
	SetMCPToolAdmission(context.Context, string, string, string, string, string, string) (*repository.MCPAdmissionMutation, error)
}

type mcpAdmissionRequest struct {
	Status            string `json:"status"`
	ExpectedHash      string `json:"expected_hash"`
	Reason            string `json:"reason"`
	ExpectedRouteHash string `json:"expected_route_hash"`
}

func decodeMCPAdmissionRequest(w http.ResponseWriter, r *http.Request) (mcpAdmissionRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, mcpAdmissionRequestMaxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request mcpAdmissionRequest
	if err := decoder.Decode(&request); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid admission request")
		return request, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "request must contain one JSON object")
		return request, false
	}
	request.Status = strings.ToLower(strings.TrimSpace(request.Status))
	request.ExpectedHash = strings.ToLower(strings.TrimSpace(request.ExpectedHash))
	request.ExpectedRouteHash = strings.ToLower(strings.TrimSpace(request.ExpectedRouteHash))
	request.Reason = strings.TrimSpace(request.Reason)
	if !mcpAdmissionHashPattern.MatchString(request.ExpectedHash) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "expected_hash must be a sha256 hex digest")
		return request, false
	}
	if request.Status != "approved" && request.Status != "quarantined" && request.Status != "revoked" {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "status must be approved, quarantined, or revoked")
		return request, false
	}
	if len(request.Reason) > 512 {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "reason is too long")
		return request, false
	}
	return request, true
}

func mcpAdmissionAdmin(w http.ResponseWriter, r *http.Request) *repository.User {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "no user")
		return nil
	}
	if !canManageAgentGuard(user.Role) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only unit administrators can manage MCP supply-chain admission")
		return nil
	}
	return user
}

func SetMCPServerAdmission(deps *Dependencies) http.HandlerFunc {
	return setMCPAdmission(deps, "server")
}

func SetMCPToolAdmission(deps *Dependencies) http.HandlerFunc {
	return setMCPAdmission(deps, "tool")
}

func setMCPAdmission(deps *Dependencies, assetType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := mcpAdmissionAdmin(w, r)
		if user == nil {
			return
		}
		if deps == nil || deps.MCPSupplyChainRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "MCP supply-chain admission is not configured")
			return
		}
		id := strings.TrimSpace(chi.URLParam(r, "id"))
		if id == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "asset id is required")
			return
		}
		request, ok := decodeMCPAdmissionRequest(w, r)
		if !ok {
			return
		}
		if assetType == "server" && !mcpAdmissionHashPattern.MatchString(request.ExpectedRouteHash) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "expected_route_hash must be a sha256 hex digest")
			return
		}
		var (
			mutation *repository.MCPAdmissionMutation
			err      error
		)
		if assetType == "server" {
			mutation, err = deps.MCPSupplyChainRepo.SetMCPServerAdmission(
				r.Context(), user.TenantID, id, request.Status, request.ExpectedHash, request.ExpectedRouteHash, request.Reason, user.ID)
		} else {
			mutation, err = deps.MCPSupplyChainRepo.SetMCPToolAdmission(
				r.Context(), user.TenantID, id, request.Status, request.ExpectedHash, request.Reason, user.ID)
		}
		switch {
		case errors.Is(err, repository.ErrMCPAdmissionSnapshotConflict):
			writeErrorWithStatus(w, http.StatusConflict, "snapshot_changed", "observed snapshot changed; refresh before reviewing")
			return
		case errors.Is(err, pgx.ErrNoRows):
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "MCP asset not found")
			return
		case err != nil:
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to change MCP supply-chain admission")
			return
		}
		logAudit(r, deps, "mcp_"+assetType+".admission", map[string]any{
			"asset_type": assetType, "asset_id": id, "status": request.Status,
			"expected_hash": request.ExpectedHash, "reason": request.Reason,
			"expected_route_hash": request.ExpectedRouteHash,
			"admission_revision":  mutation.Revision,
		}, "mcp_"+assetType, id)
		writeJSON(w, map[string]any{"data": mutation})
	}
}
