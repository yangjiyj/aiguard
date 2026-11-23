package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"github.com/go-chi/chi/v5"
)

type IntegrationRepo interface {
	GetCredential(context.Context, string, string) (*ai.Credential, error)
	UpdateCredential(context.Context, string, string, ai.CredentialUpdate) (*ai.Credential, error)
	IssueCredential(context.Context, string, ai.Credential, string, string) (*ai.Credential, error)
	ListCredentials(context.Context, string, string) ([]ai.Credential, error)
	RevokeCredential(context.Context, string, string) (*ai.Credential, error)
	WritePolicy(context.Context, string, string, string, ai.Policy) (*ai.Policy, error)
	ListPolicies(context.Context, string, string) ([]ai.Policy, error)
	EnforcementStatus(context.Context, string, string, string, bool, []string) (*ai.Status, error)
	ListEvents(context.Context, string, string, time.Time, time.Time, int, int) ([]repository.IntegrationEvent, int, error)
	ListUpstreams(context.Context, string) ([]repository.IntegrationUpstream, error)
	ListProjects(context.Context, string) ([]repository.IntegrationProject, error)
}

func integrationActor(w http.ResponseWriter, r *http.Request, deps *Dependencies) (*repository.User, bool) {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeErrorWithStatus(w, 401, "unauthorized", "请先使用服务身份登录")
		return nil, false
	}
	// 服务身份与系统管理员原本就可用。安全员/审计员按三员分立只在各自职责类别内放行（permission/sod_routes.go：
	// 记录类读审计员也可，配置/目录类读与策略写仅安全员），由 SoD 守卫判定后打上 SoDAllowed 标记；
	// 这里只认「官员角色 + SoD 已放行」，不自行重复类别表，避免两边漂移。
	officerAllowed := (roles.IsSecurityOfficer(user.Role) || roles.IsAuditor(user.Role)) && permission.SoDAllowed(r.Context())
	if user.Role != "platform_connector" && !roles.IsSystemAdmin(user.Role) && !officerAllowed {
		writeErrorWithStatus(w, 403, "permission_denied", "当前身份没有集成接口权限")
		return nil, false
	}
	if deps == nil || deps.IntegrationRepo == nil {
		writeErrorWithStatus(w, 503, "integration_unavailable", "集成服务暂时不可用")
		return nil, false
	}
	return user, true
}

func integrationDecode(w http.ResponseWriter, r *http.Request, dst any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		writeErrorWithStatus(w, 400, "invalid_request", "请求内容不符合接口要求")
		return false
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		writeErrorWithStatus(w, 400, "invalid_request", "请求包含多余内容")
		return false
	}
	return true
}

func integrationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ai.ErrNotFound):
		writeErrorWithStatus(w, 404, "not_found", "当前租户中未找到该对象")
	case errors.Is(err, ai.ErrConflict):
		writeErrorWithStatus(w, 409, "version_conflict", "版本或绑定关系发生冲突，请重新读取后再试")
	case errors.Is(err, ai.ErrInvalid):
		writeErrorWithStatus(w, 400, "invalid_request", "请求参数不符合要求")
	default:
		writeErrorWithStatus(w, 503, "integration_unavailable", "集成操作暂时不可用")
	}
}

func integrationWriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type integrationCredentialRequest struct {
	AgentInstanceID  string   `json:"agent_instance_id"`
	ProjectID        string   `json:"project_id"`
	Scopes           []string `json:"scopes"`
	Name             string   `json:"name"`
	ExpiresAt        string   `json:"expires_at"`
	ModelRestriction string   `json:"model_restriction"`
	ModelAllowlist   []string `json:"model_allowlist"`
	Enforcement      string   `json:"enforcement"`
	DLPEnforcement   string   `json:"dlp_enforcement"`
}

func normalizeIntegrationScopes(scopes []string) ([]string, error) {
	allowed := map[string]bool{"chat": true, "responses": true, "models": true, "embeddings": true, "files": true, "mcp": true}
	seen := map[string]bool{}
	result := []string{}
	for _, scope := range scopes {
		if !allowed[scope] {
			return nil, ai.ErrInvalid
		}
		if !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}
	if len(result) == 0 {
		return nil, ai.ErrInvalid
	}
	return result, nil
}

func IssueAgentCredential(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		var req integrationCredentialRequest
		if !integrationDecode(w, r, &req) {
			return
		}
		scopes, err := normalizeIntegrationScopes(req.Scopes)
		if err != nil || !ai.ValidID(req.AgentInstanceID) || !ai.ValidID(req.ProjectID) {
			integrationError(w, ai.ErrInvalid)
			return
		}
		name, err := normalizeKeyName(req.Name)
		if err != nil {
			integrationError(w, ai.ErrInvalid)
			return
		}
		expires, err := parseKeyExpiresAt(req.ExpiresAt)
		if err != nil {
			integrationError(w, ai.ErrInvalid)
			return
		}
		if expires == nil {
			value := time.Now().UTC().Add(30 * 24 * time.Hour)
			expires = &value
		}
		controls := ai.Credential{ModelRestriction: req.ModelRestriction, ModelAllowlist: req.ModelAllowlist, Enforcement: req.Enforcement, DLPEnforcement: req.DLPEnforcement}
		if ai.ValidateCredentialControls(controls) != nil {
			integrationError(w, ai.ErrInvalid)
			return
		}
		raw := generateSecureKey()
		key, err := deps.IntegrationRepo.IssueCredential(r.Context(), user.TenantID, ai.Credential{AgentInstanceID: req.AgentInstanceID, ProjectID: req.ProjectID, Scopes: scopes, Name: name, ExpiresAt: expires, ModelRestriction: controls.ModelRestriction, ModelAllowlist: controls.ModelAllowlist, Enforcement: controls.Enforcement, DLPEnforcement: controls.DLPEnforcement}, raw, "")
		if err != nil {
			integrationError(w, err)
			return
		}
		logAudit(r, deps, "integration.credential.issue", map[string]any{"agent_instance_id": key.AgentInstanceID, "key_id": key.KeyID}, "key", key.KeyID)
		integrationWriteJSON(w, 201, struct {
			ai.Credential
			FullKey string `json:"full_key"`
		}{*key, raw})
	}
}

func ListAgentCredentials(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		agent := r.URL.Query().Get("agent_instance_id")
		if !ai.ValidID(agent) {
			integrationError(w, ai.ErrInvalid)
			return
		}
		keys, err := deps.IntegrationRepo.ListCredentials(r.Context(), user.TenantID, agent)
		if err != nil {
			integrationError(w, err)
			return
		}
		integrationWriteJSON(w, 200, map[string]any{"data": keys})
	}
}

func RotateAgentCredential(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		id := chi.URLParam(r, "id")
		if !ai.ValidID(id) {
			integrationError(w, ai.ErrInvalid)
			return
		}
		var req struct {
			ExpiresAt string `json:"expires_at"`
		}
		if !integrationDecode(w, r, &req) {
			return
		}
		expires, err := parseKeyExpiresAt(req.ExpiresAt)
		if err != nil {
			integrationError(w, ai.ErrInvalid)
			return
		}
		raw := generateSecureKey()
		key, err := deps.IntegrationRepo.IssueCredential(r.Context(), user.TenantID, ai.Credential{AgentInstanceID: "rotation", ExpiresAt: expires}, raw, id)
		if err != nil {
			integrationError(w, err)
			return
		}
		logAudit(r, deps, "integration.credential.rotate", map[string]any{"agent_instance_id": key.AgentInstanceID, "replaced_key_id": id, "key_id": key.KeyID}, "key", key.KeyID)
		integrationWriteJSON(w, 201, struct {
			ai.Credential
			FullKey       string `json:"full_key"`
			ReplacedKeyID string `json:"replaced_key_id"`
		}{*key, raw, id})
	}
}

func RevokeAgentCredential(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		id := chi.URLParam(r, "id")
		if !ai.ValidID(id) {
			integrationError(w, ai.ErrInvalid)
			return
		}
		key, err := deps.IntegrationRepo.RevokeCredential(r.Context(), user.TenantID, id)
		if err != nil {
			integrationError(w, err)
			return
		}
		logAudit(r, deps, "integration.credential.revoke", map[string]any{"agent_instance_id": key.AgentInstanceID, "key_id": key.KeyID}, "key", key.KeyID)
		integrationWriteJSON(w, 200, key)
	}
}

func WriteAgentPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		var req struct {
			AgentInstanceID string `json:"agent_instance_id"`
			Action          string `json:"action"`
			Enabled         *bool  `json:"enabled"`
			Mode            string `json:"mode"`
			MCPServerID     string `json:"mcp_server_id"`
			ExpectedVersion string `json:"expected_version"`
		}
		if !integrationDecode(w, r, &req) {
			return
		}
		if req.Enabled == nil {
			integrationError(w, ai.ErrInvalid)
			return
		}
		id := chi.URLParam(r, "id")
		if id != "" && !ai.ValidID(id) {
			integrationError(w, ai.ErrInvalid)
			return
		}
		p, err := deps.IntegrationRepo.WritePolicy(r.Context(), user.TenantID, id, req.ExpectedVersion, ai.Policy{AgentInstanceID: req.AgentInstanceID, Action: req.Action, Enabled: *req.Enabled, Mode: req.Mode, MCPServerID: req.MCPServerID})
		if err != nil {
			integrationError(w, err)
			return
		}
		logAudit(r, deps, "integration.policy.write", map[string]any{"policy_id": p.ID, "agent_instance_id": p.AgentInstanceID, "desired_version": p.Version, "action": p.Action}, "policy", p.ID)
		status := 200
		if id == "" {
			status = 201
		}
		integrationWriteJSON(w, status, map[string]any{"data": p, "desired_version": p.Version})
	}
}

func ListAgentPolicies(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		agent := r.URL.Query().Get("agent_instance_id")
		if agent != "" && !ai.ValidID(agent) {
			integrationError(w, ai.ErrInvalid)
			return
		}
		policies, err := deps.IntegrationRepo.ListPolicies(r.Context(), user.TenantID, agent)
		if err != nil {
			integrationError(w, err)
			return
		}
		integrationWriteJSON(w, 200, map[string]any{"data": policies})
	}
}

func GetIntegrationEnforcementStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		q := r.URL.Query()
		id, version := q.Get("policy_id"), q.Get("expected_version")
		if !ai.ValidID(id) {
			integrationError(w, ai.ErrInvalid)
			return
		}
		if version != "" {
			n, err := strconv.ParseInt(version, 10, 64)
			if err != nil || n < 1 {
				integrationError(w, ai.ErrInvalid)
				return
			}
		}
		requireHit := false
		if q.Has("require_hit") {
			var err error
			requireHit, err = strconv.ParseBool(q.Get("require_hit"))
			if err != nil {
				integrationError(w, ai.ErrInvalid)
				return
			}
		}
		status, err := deps.IntegrationRepo.EnforcementStatus(r.Context(), user.TenantID, id, version, requireHit, strings.Split(os.Getenv("GATEWAY_EXPECTED_INSTANCE_IDS"), ","))
		if err != nil {
			integrationError(w, err)
			return
		}
		integrationWriteJSON(w, 200, status)
	}
}

func ListIntegrationAuditEvents(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		q := r.URL.Query()
		agent := q.Get("agent_instance_id")
		if agent != "" && !ai.ValidID(agent) {
			integrationError(w, ai.ErrInvalid)
			return
		}
		limit, err := parseEvalIntegrationLimit(q.Get("limit"))
		if err != nil {
			integrationError(w, ai.ErrInvalid)
			return
		}
		if limit > 200 {
			integrationError(w, ai.ErrInvalid)
			return
		}
		offset, err := parseEvalIntegrationCursor(q.Get("cursor"))
		if err != nil {
			integrationError(w, ai.ErrInvalid)
			return
		}
		start, end, err := defaultBoundedTimeWindow(r, 24*time.Hour)
		if err != nil {
			integrationError(w, ai.ErrInvalid)
			return
		}
		data, total, err := deps.IntegrationRepo.ListEvents(r.Context(), user.TenantID, agent, start, end, limit, offset)
		if err != nil {
			integrationError(w, err)
			return
		}
		cursor := ""
		if offset+len(data) < total {
			cursor = strconv.Itoa(offset + len(data))
		}
		integrationWriteJSON(w, 200, map[string]any{"data": data, "total": total, "next_cursor": cursor, "has_more": cursor != ""})
	}
}

func ListIntegrationUpstreams(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		data, err := deps.IntegrationRepo.ListUpstreams(r.Context(), user.TenantID)
		if err != nil {
			integrationError(w, err)
			return
		}
		gatewayURL, aliases := integrationGatewayURLs(deps.IntegrationGatewayURL)
		if gatewayURL == "" {
			writeErrorWithStatus(w, 503, "gateway_public_url_unavailable", "public HTTPS gateway URL unavailable")
			return
		}
		integrationWriteJSON(w, 200, map[string]any{"data": data, "gateway_base_url": gatewayURL, "gateway_aliases": aliases})
	}
}

func integrationGatewayURLs(internalURL string) (string, []string) {
	publicURL := ai.SafeURL(os.Getenv("GATEWAY_PUBLIC_BASE_URL"))
	if !strings.HasPrefix(publicURL, "https://") {
		return "", []string{}
	}
	aliases := []string{publicURL}
	seen := map[string]bool{publicURL: true}
	for _, raw := range append(strings.Split(os.Getenv("GATEWAY_PUBLIC_ALIASES"), ","), internalURL) {
		alias := ai.SafeURL(strings.TrimSpace(raw))
		if strings.HasPrefix(alias, "https://") && !seen[alias] {
			seen[alias] = true
			aliases = append(aliases, alias)
		}
	}
	return publicURL, aliases
}

func ListIntegrationProjects(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		projects, err := deps.IntegrationRepo.ListProjects(r.Context(), user.TenantID)
		if err != nil {
			integrationError(w, err)
			return
		}
		if projects == nil {
			projects = []repository.IntegrationProject{}
		}
		integrationWriteJSON(w, 200, map[string]any{"data": projects})
	}
}
