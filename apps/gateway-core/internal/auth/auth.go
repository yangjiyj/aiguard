package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/clientip"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/headercompat"
	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

type contextKey string

const (
	TenantKey                   contextKey = "tenant_id"
	ProjectKey                  contextKey = "project_id"
	UserKey                     contextKey = "user_id"
	KeyIDKey                    contextKey = "key_id"
	KeyModelAllowlistKey        contextKey = "key_model_allowlist"
	AgentInstanceIDKey          contextKey = "agent_instance_id"
	SessionIDKey                contextKey = "session_id"
	AgentTypeKey                contextKey = "agent_type"
	AgentRuntimeKey             contextKey = "agent_runtime"
	AgentDetectionSourceKey     contextKey = "agent_detection_source"
	AgentDetectionConfidenceKey contextKey = "agent_detection_confidence"
	WorkspaceKey                contextKey = "workspace_id"
	RequestIDKey                contextKey = "request_id"
	KeyPrefixKey                contextKey = "key_prefix"
	EnvironmentScopeKey         contextKey = "environment_scope"
	TraceIDKey                  contextKey = "trace_id"
	LSEEvalRunIDKey             contextKey = "lse_eval_run_id"
	LSETaskIDKey                contextKey = "lse_task_id"
	LSESampleIDKey              contextKey = "lse_sample_id"
	LSETargetIDKey              contextKey = "lse_target_id"
	LSECorrelationTrustedKey    contextKey = "lse_correlation_trusted"
	PrincipalKey                contextKey = "principal_context"

	// Proxy request context keys
	ProxyRequestKey contextKey = "is_proxy_request"
	ClientIPKey     contextKey = "client_ip"
)

type AuthInfo struct {
	AgentInstanceID          string
	AgentIdentityHeaders     string
	UserAgent                string
	TenantID                 string
	ProjectID                string
	UserID                   string
	KeyID                    string
	Scopes                   []string
	SessionID                string
	AgentType                string
	AgentRuntime             string
	AgentDetectionSource     string
	AgentDetectionConfidence float64
	WorkspaceID              string
	RequestID                string
	KeyPrefix                string
	EnvironmentScope         string
	ClientIP                 string
	TraceID                  string
	LSEEvalRunID             string
	LSETaskID                string
	LSECorrelationTrusted    bool
	LSESampleID              string
	LSETargetID              string
	Principal                *principal.Context
}

type LSECorrelation struct {
	EvalRunID string
	TaskID    string
	SampleID  string
	TargetID  string
	TraceID   string
}

type KeyRecord struct {
	IntegrationDLPBlockKeyIDs []string
	ModelEnforcement          string
	DLPEnforcement            string
	ModelAllowlist            []string
	AgentInstanceID           string
	ID                        string
	TenantID                  string
	ProjectID                 string
	UserID                    string
	KeyHash                   string
	KeyPrefix                 string
	Scopes                    []string
	ExpiresAt                 *time.Time
	LastUsedAt                *time.Time
	Status                    string
	CreatedAt                 time.Time
	ApplicationDepartmentID   string
	// OwnerStatus is users.status of the key owner; empty for project-level
	// keys (no user_id) and for keys whose owner row is missing.
	OwnerStatus         string
	EmployeeRoleChanged bool
}

// ownerBlocksKey reports whether a user-owned key must be rejected because
// its owner is no longer active (W2.1). Project-level keys are unaffected.
func ownerBlocksKey(key *KeyRecord) bool {
	return key.UserID != "" && (key.OwnerStatus != "active" || key.EmployeeRoleChanged)
}

// AuthMiddleware validates internal API keys using database lookup
type AuthMiddleware struct {
	db          *pgxpool.Pool
	redis       *redis.Client
	rateLimiter *RateLimiter
	headerAudit *headeraudit.Client
}

// NewAuthMiddleware requires the critical-audit client in every build. Tests
// that intentionally exercise fail-closed behavior pass nil explicitly.
func NewAuthMiddleware(db *pgxpool.Pool, redisClient *redis.Client, headerAudit *headeraudit.Client) *AuthMiddleware {
	return &AuthMiddleware{db: db, redis: redisClient, rateLimiter: NewRateLimiter(redisClient), headerAudit: headerAudit}
}

// Middleware returns the auth middleware handler
func (a *AuthMiddleware) Middleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Generate request ID for tracking
			requestID := generateRequestID()
			ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
			if isAnthropicMessagesRequest(r) {
				w.Header().Set("X-Request-Id", requestID)
			}

			metadata, ok := a.preflightHeaderContract(w, r, requestID)
			if !ok {
				return
			}

			// Base URL 多写一层 /v1 的路径没有任何处理器；在凭据校验前直接给出 404 改法，
			// 否则用户只会看到与路径无关的 401。必须排在请求头冲突审计之后。
			if r.URL != nil {
				if protocol, duplicated := classifyDuplicateV1Prefix(r.URL.Path); duplicated {
					writeDuplicateV1PrefixHint(w, protocol, requestID)
					return
				}
			}

			// Extract authorization header
			authHeader := r.Header.Get("Authorization")
			apiKeyHeader := r.Header.Get("X-Api-Key")

			if authHeader == "" && apiKeyHeader == "" {
				writeAuthError(w, r, "unauthorized", "missing authorization header", requestID)
				return
			}

			token := extractRequestToken(r)
			if token == "" {
				writeAuthError(w, r, "unauthorized", "invalid authorization format", requestID)
				return
			}

			// Calculate key hash
			hash := sha256.Sum256([]byte(token))
			keyHash := hex.EncodeToString(hash[:])

			// Validate key against database
			keyRecord, err := a.validateKey(r.Context(), keyHash)
			if err != nil {
				writeAuthError(w, r, "internal_error", "key validation failed", requestID)
				return
			}

			if keyRecord == nil {
				writeAuthError(w, r, "unauthorized", "invalid api key", requestID)
				return
			}

			// Check key status
			if keyRecord.Status != "active" {
				writeAuthError(w, r, "key_revoked", "api key has been revoked", requestID)
				return
			}

			// Check expiration
			if keyRecord.ExpiresAt != nil && time.Now().After(*keyRecord.ExpiresAt) {
				writeAuthError(w, r, "key_expired", "api key has expired", requestID)
				return
			}

			// Owner lifecycle gate (W2.1): a key bound to a disabled/deleted/
			// not-yet-active user is rejected even if the key row is still
			// active. Fail-closed when the owner row is missing.
			if keyRecord.EmployeeRoleChanged {
				if isAnthropicMessagesRequest(r) {
					writeAnthropicAuthError(w, http.StatusForbidden, "permission_error", "account role changed; renew the personal credential", requestID)
				} else {
					writeModelAccessError(w, http.StatusForbidden, "employee_key_role_changed", "账号角色已变化，请重新生成个人 Key")
				}
				return
			}
			if ownerBlocksKey(keyRecord) {
				writeAuthError(w, r, "key_owner_inactive", "api key owner is not active", requestID)
				return
			}

			// Manual pause gate (P0-3a): reject keys an operator paused via the
			// control-plane budget API. Fail-open on Redis trouble (see isKeyPaused).
			if a.redis != nil && isKeyPaused(r.Context(), a.redis, keyRecord.KeyPrefix) {
				writeAuthError(w, r, "key_paused", "api key has been manually paused", requestID)
				return
			}

			agentInstanceID, bindingErr := resolveAgentInstanceID(keyRecord.AgentInstanceID, r.Header.Get("X-Agent-Instance-Id"))
			if bindingErr != nil {
				a.recordAgentBindingDenial(r.Context(), keyRecord, requestID)
				rejectAgentInstanceBinding(w, r, requestID)
				return
			}

			// Update last used timestamp asynchronously with a bounded background context.
			go a.updateLastUsed(context.WithoutCancel(r.Context()), keyRecord.ID)

			principalContext, err := principal.Normalize(principal.Context{
				TenantID: keyRecord.TenantID, KeyOwnerUserID: keyRecord.UserID,
				ProjectID: keyRecord.ProjectID, ApplicationID: keyRecord.ProjectID,
				ApplicationDepartmentID: keyRecord.ApplicationDepartmentID,
				KeyID:                   keyRecord.ID, IdentitySource: principal.SourceAPIKey,
				TrustLevel: principal.TrustKeyBound, IdentityVersion: "1",
			})
			if err != nil {
				writeAuthError(w, r, "internal_error", "key identity is invalid", requestID)
				return
			}
			// Build auth info. UserID remains legacy resource attribution; the
			// trusted actor is represented only by Principal.ActorUserID.
			authInfo := &AuthInfo{
				AgentInstanceID:      agentInstanceID,
				AgentIdentityHeaders: agentdetect.IdentityHeaders(r.Header),
				UserAgent:            agentdetect.BoundedIdentityValue(r.UserAgent(), 512),
				TenantID:             keyRecord.TenantID,
				ProjectID:            keyRecord.ProjectID,
				UserID:               keyRecord.UserID,
				KeyID:                keyRecord.ID,
				Scopes:               keyRecord.Scopes,
				RequestID:            requestID,
				KeyPrefix:            keyRecord.KeyPrefix,
				EnvironmentScope:     ResolveEnvironmentScope(keyRecord.Scopes, cfg.EnvironmentScope),
				Principal:            &principalContext,
			}

			if err := enforceRouteScope(r, authInfo.Scopes); err != nil {
				writeAuthError(w, r, "insufficient_scope", err.Error(), requestID)
				return
			}

			// Metadata was resolved at the outer boundary before any key lookup.
			sessionID := metadata.sessionID
			agentType := metadata.agentType
			agentRuntime := metadata.agentRuntime
			agentDetectionSource := metadata.agentDetectionSource
			agentDetectionConfidence := metadata.agentDetectionConfidence
			workspaceID := metadata.workspaceID

			if sessionID != "" {
				authInfo.SessionID = sessionID
				ctx = context.WithValue(ctx, SessionIDKey, sessionID)
			}
			if agentType != "" {
				authInfo.AgentType = agentType
				ctx = context.WithValue(ctx, AgentTypeKey, agentType)
			}
			if agentRuntime != "" {
				authInfo.AgentRuntime = agentRuntime
				ctx = context.WithValue(ctx, AgentRuntimeKey, agentRuntime)
			}
			if agentDetectionSource != "" {
				authInfo.AgentDetectionSource = agentDetectionSource
				ctx = context.WithValue(ctx, AgentDetectionSourceKey, agentDetectionSource)
			}
			if agentDetectionConfidence > 0 {
				authInfo.AgentDetectionConfidence = agentDetectionConfidence
				ctx = context.WithValue(ctx, AgentDetectionConfidenceKey, agentDetectionConfidence)
			}
			if workspaceID != "" {
				authInfo.WorkspaceID = workspaceID
				ctx = context.WithValue(ctx, WorkspaceKey, workspaceID)
			}

			corr, corrTrusted := extractVerifiedLSECorrelation(r)
			authInfo.LSECorrelationTrusted = corrTrusted
			ctx = context.WithValue(ctx, LSECorrelationTrustedKey, corrTrusted)
			if corr.TraceID != "" {
				authInfo.TraceID = corr.TraceID
				ctx = context.WithValue(ctx, TraceIDKey, corr.TraceID)
			}
			if corr.EvalRunID != "" {
				authInfo.LSEEvalRunID = corr.EvalRunID
				ctx = context.WithValue(ctx, LSEEvalRunIDKey, corr.EvalRunID)
			}
			if corr.TaskID != "" {
				authInfo.LSETaskID = corr.TaskID
				ctx = context.WithValue(ctx, LSETaskIDKey, corr.TaskID)
			}
			if corr.SampleID != "" {
				authInfo.LSESampleID = corr.SampleID
				ctx = context.WithValue(ctx, LSESampleIDKey, corr.SampleID)
			}
			if corr.TargetID != "" {
				authInfo.LSETargetID = corr.TargetID
				ctx = context.WithValue(ctx, LSETargetIDKey, corr.TargetID)
			}

			// Set context values
			ctx = context.WithValue(ctx, TenantKey, authInfo.TenantID)
			ctx = context.WithValue(ctx, ProjectKey, authInfo.ProjectID)
			ctx = context.WithValue(ctx, UserKey, authInfo.UserID)
			ctx = context.WithValue(ctx, KeyIDKey, authInfo.KeyID)
			ctx = context.WithValue(ctx, KeyModelAllowlistKey, keyRecord.ModelAllowlist)
			ctx = context.WithValue(ctx, KeyModelEnforcementKey, keyRecord.ModelEnforcement)
			ctx = context.WithValue(ctx, KeyDLPEnforcementKey, keyRecord.DLPEnforcement)
			ctx = context.WithValue(ctx, IntegrationDLPBlockKeysKey, keyRecord.IntegrationDLPBlockKeyIDs)
			ctx = context.WithValue(ctx, KeyModelObservationKey, &ModelObservation{})
			ctx = context.WithValue(ctx, AgentInstanceIDKey, authInfo.AgentInstanceID)
			ctx = context.WithValue(ctx, KeyPrefixKey, authInfo.KeyPrefix)
			ctx = context.WithValue(ctx, EnvironmentScopeKey, authInfo.EnvironmentScope)
			ctx = context.WithValue(ctx, PrincipalKey, authInfo.Principal)

			// P2: 只读采集客户端源 IP（审计/留证增强）。clientip.ClientIP 默认仅
			// 信任 RemoteAddr（除非 peer 命中 TRUSTED_PROXY_CIDRS），不参与任何
			// 拦截决策；ClientIPKey 仅供 getClientIP 读取，下游 IP 白名单校验恒被
			// isProxyRequest 门控（主链 ProxyRequestKey 从不置位），故不会因此拦截。
			if clientIP := clientip.ClientIP(r); clientIP != "" {
				authInfo.ClientIP = clientIP
				ctx = context.WithValue(ctx, ClientIPKey, clientIP)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractRequestToken(r *http.Request) string {
	if token := extractBearerToken(r.Header.Get("Authorization")); token != "" {
		return token
	}
	return strings.TrimSpace(r.Header.Get("X-Api-Key"))
}

func extractLSECorrelationHeaders(header http.Header) LSECorrelation {
	return LSECorrelation{
		EvalRunID: sanitizeCorrelationID(header.Get("X-LSE-Eval-Run-Id")),
		TaskID:    sanitizeCorrelationID(header.Get("X-LSE-Task-Id")),
		SampleID:  sanitizeCorrelationID(header.Get("X-LSE-Sample-Id")),
		TargetID:  sanitizeCorrelationID(header.Get("X-LSE-Target-Id")),
		TraceID:   sanitizeCorrelationID(header.Get("X-LSE-Trace-Id")),
	}
}

func sanitizeCorrelationID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return ""
		}
	}
	return value
}

// validateKey looks up the key in the database by its hash
// user_id 可为 NULL（portal-integration 无归属发放的 key），裸 string Scan 会在
// NULL 行报错并打挂整条 key 认证，必须 COALESCE 规整为空串。
func (a *AuthMiddleware) validateKey(ctx context.Context, keyHash string) (*KeyRecord, error) {
	query := `
		SELECT ik.id, ik.tenant_id, ik.project_id, COALESCE(ik.user_id,''), ik.key_hash,
		       ik.key_prefix, ik.scopes_json, ik.expires_at, ik.last_used_at, ik.status, ik.created_at,
		       COALESCE(p.team_id,''), COALESCE(u.status,''), COALESCE(ik.agent_instance_id,''),COALESCE(employee.issued_role<>u.role,FALSE),ik.model_allowlist,ik.model_enforcement,ik.dlp_enforcement,
		       CASE WHEN $2 AND ik.dlp_enforcement='block' AND COALESCE(ik.agent_instance_id,'')<>'' THEN ARRAY(
		         SELECT bound.id FROM internal_keys bound WHERE bound.tenant_id=ik.tenant_id
		         AND COALESCE(bound.agent_instance_id,'')<>'' AND bound.status='active'
		         AND bound.dlp_enforcement='block' AND (bound.expires_at IS NULL OR bound.expires_at>NOW()) ORDER BY bound.id
		       ) ELSE '{}'::text[] END
		FROM internal_keys ik
		JOIN projects p ON p.id=ik.project_id AND p.tenant_id=ik.tenant_id
		LEFT JOIN users u ON u.id=ik.user_id AND u.tenant_id=ik.tenant_id
 LEFT JOIN employee_api_keys employee ON employee.key_id=ik.id AND employee.tenant_id=ik.tenant_id AND employee.user_id=ik.user_id
		WHERE ik.key_hash = $1
	`

	row := a.db.QueryRow(ctx, query, keyHash, integrationDLPBlockGateOpen())
	var key KeyRecord
	var scopesJSON []byte

	err := row.Scan(
		&key.ID,
		&key.TenantID,
		&key.ProjectID,
		&key.UserID,
		&key.KeyHash,
		&key.KeyPrefix,
		&scopesJSON,
		&key.ExpiresAt,
		&key.LastUsedAt,
		&key.Status,
		&key.CreatedAt,
		&key.ApplicationDepartmentID,
		&key.OwnerStatus,
		&key.AgentInstanceID,
		&key.EmployeeRoleChanged,
		&key.ModelAllowlist,
		&key.ModelEnforcement, &key.DLPEnforcement,
		&key.IntegrationDLPBlockKeyIDs,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil // Key not found
		}
		return nil, err
	}

	key.Scopes = parseScopesJSON(scopesJSON)

	return &key, nil
}

// updateLastUsed updates the last_used_at timestamp asynchronously.
func (a *AuthMiddleware) updateLastUsed(parent context.Context, keyID string) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	query := `UPDATE internal_keys SET last_used_at = NOW() WHERE id = $1`
	if _, err := a.db.Exec(ctx, query, keyID); err != nil {
		return
	}
}

// Legacy Middleware is intentionally disabled.
// It remains here only to fail closed for any stale callers that still wire
// the old entrypoint instead of the database-backed AuthMiddleware.
func Middleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := generateRequestID()
			writeAuthError(w, r, "auth_misconfigured", "legacy auth middleware is disabled; use database-backed auth middleware", requestID)
		})
	}
}

func enforceRouteScope(r *http.Request, scopes []string) error {
	requiredScope := requiredScopeForRequest(r)
	if requiredScope == "" || hasScope(scopes, "*") {
		return nil
	}
	if len(scopes) == 0 {
		if requiredScope == "mcp" {
			return &scopeError{RequiredScope: requiredScope}
		}
		return nil
	}
	if hasScope(scopes, requiredScope) {
		return nil
	}
	return &scopeError{RequiredScope: requiredScope}
}

func requiredScopeForRequest(r *http.Request) string {
	switch {
	case (r.Method == http.MethodPost || r.Method == http.MethodGet || r.Method == http.MethodDelete) &&
		(r.URL.Path == "/mcp" || strings.HasPrefix(r.URL.Path, "/mcp/")):
		return "mcp"
	case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
		return "chat"
	case r.Method == http.MethodPost && r.URL.Path == "/v1/messages":
		return "chat"
	case r.Method == http.MethodPost && r.URL.Path == "/v1/responses":
		return "responses"
	case r.Method == http.MethodPost && r.URL.Path == "/v1/embeddings":
		return "embeddings"
	case r.Method == http.MethodPost && r.URL.Path == "/v1/files":
		return "files"
	case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
		return "models"
	default:
		return ""
	}
}

func hasScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if strings.EqualFold(scope, required) {
			return true
		}
	}
	return false
}

// EnvironmentScopeFromAPIKeyScopes accepts only the explicit environment
// scope carried by the authenticated key. Headers, workspace IDs and
// principals are deliberately not consulted.
func EnvironmentScopeFromAPIKeyScopes(scopes []string) string {
	for _, scope := range scopes {
		switch strings.ToLower(strings.TrimSpace(scope)) {
		case "customer", "home", "claude", "codex":
			return strings.ToLower(strings.TrimSpace(scope))
		}
	}
	return retentionartifact.LegacyEnvironmentScope
}

// ResolveEnvironmentScope treats a trusted non-legacy deployment scope as the
// outer evidence boundary. A key issued for another environment must not move
// customer traffic out of the customer retention view. Explicit key scope is
// used only when the deployment has no classified boundary.
func ResolveEnvironmentScope(scopes []string, deploymentDefault string) string {
	return retentionartifact.ResolveEnvironmentScope(EnvironmentScopeFromAPIKeyScopes(scopes), deploymentDefault)
}

func parseScopesJSON(scopesJSON []byte) []string {
	if len(scopesJSON) == 0 {
		return []string{}
	}
	var scopes []string
	if err := json.Unmarshal(scopesJSON, &scopes); err != nil {
		return []string{}
	}
	return scopes
}

type scopeError struct {
	RequiredScope string
}

func (e *scopeError) Error() string {
	return "api key does not grant " + e.RequiredScope + " scope"
}

func extractBearerToken(authHeader string) string {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return parts[1]
}

func GetAuthInfo(r *http.Request) *AuthInfo {
	ctx := r.Context()
	return &AuthInfo{
		AgentInstanceID:          getStringFromCtx(ctx, AgentInstanceIDKey),
		AgentIdentityHeaders:     agentdetect.IdentityHeaders(r.Header),
		UserAgent:                agentdetect.BoundedIdentityValue(r.UserAgent(), 512),
		TenantID:                 getStringFromCtx(ctx, TenantKey),
		ProjectID:                getStringFromCtx(ctx, ProjectKey),
		UserID:                   getStringFromCtx(ctx, UserKey),
		KeyID:                    getStringFromCtx(ctx, KeyIDKey),
		SessionID:                getStringFromCtx(ctx, SessionIDKey),
		AgentType:                getStringFromCtx(ctx, AgentTypeKey),
		AgentRuntime:             getStringFromCtx(ctx, AgentRuntimeKey),
		AgentDetectionSource:     getStringFromCtx(ctx, AgentDetectionSourceKey),
		AgentDetectionConfidence: getFloatFromCtx(ctx, AgentDetectionConfidenceKey),
		WorkspaceID:              getStringFromCtx(ctx, WorkspaceKey),
		RequestID:                getStringFromCtx(ctx, RequestIDKey),
		KeyPrefix:                getStringFromCtx(ctx, KeyPrefixKey),
		EnvironmentScope:         getStringFromCtx(ctx, EnvironmentScopeKey),
		ClientIP:                 getStringFromCtx(ctx, ClientIPKey),
		TraceID:                  getStringFromCtx(ctx, TraceIDKey),
		LSEEvalRunID:             getStringFromCtx(ctx, LSEEvalRunIDKey),
		LSETaskID:                getStringFromCtx(ctx, LSETaskIDKey),
		LSECorrelationTrusted:    getBoolFromCtx(ctx, LSECorrelationTrustedKey),
		LSESampleID:              getStringFromCtx(ctx, LSESampleIDKey),
		LSETargetID:              getStringFromCtx(ctx, LSETargetIDKey),
		Principal:                getPrincipalFromCtx(ctx),
	}
}

func getPrincipalFromCtx(ctx context.Context) *principal.Context {
	value, _ := ctx.Value(PrincipalKey).(*principal.Context)
	return value
}

func getStringFromCtx(ctx context.Context, key contextKey) string {
	if v := ctx.Value(key); v != nil {
		return v.(string)
	}
	return ""
}

func writeError(w http.ResponseWriter, code, message, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	resp := map[string]map[string]string{
		"error": {
			"code":       code,
			"message":    message,
			"request_id": requestID,
		},
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return
	}
}

func writeAuthError(w http.ResponseWriter, r *http.Request, code, message, requestID string) {
	if !isAnthropicMessagesRequest(r) {
		writeError(w, code, message, requestID)
		return
	}
	status := http.StatusUnauthorized
	errorType := "authentication_error"
	switch code {
	case "insufficient_scope", "key_paused":
		status = http.StatusForbidden
		errorType = "permission_error"
	case "internal_error", "auth_misconfigured":
		status = http.StatusInternalServerError
		errorType = "api_error"
	}
	writeAnthropicAuthError(w, status, errorType, message, requestID)
}

func writeAnthropicAuthError(w http.ResponseWriter, status int, errorType, message, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Request-Id", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "error",
		"error": map[string]string{
			"type":    errorType,
			"message": message,
		},
		"request_id": requestID,
	})
}

func isAnthropicMessagesRequest(r *http.Request) bool {
	return r != nil && r.Method == http.MethodPost && r.URL != nil && r.URL.Path == "/v1/messages"
}

func generateRequestID() string {
	return "req_" + uuid.NewString()
}

func getBoolFromCtx(ctx context.Context, key contextKey) bool {
	v, _ := ctx.Value(key).(bool)
	return v
}

func getFloatFromCtx(ctx context.Context, key contextKey) float64 {
	v, _ := ctx.Value(key).(float64)
	return v
}

type resolvedRequestMetadata struct {
	sessionID, workspaceID, agentType, agentRuntime, agentDetectionSource string
	agentDetectionConfidence                                              float64
}

func (a *AuthMiddleware) preflightHeaderContract(w http.ResponseWriter, r *http.Request, requestID string) (resolvedRequestMetadata, bool) {
	var out resolvedRequestMetadata
	var err error
	out.sessionID, _, err = headercompat.Resolve(r.Header, "X-JJDGuard-Session-Id", "X-NewAPI-Session-Id")
	if err != nil {
		return out, a.rejectHeaderConflict(w, r, requestID, "session_id")
	}
	out.workspaceID, _, err = headercompat.Resolve(r.Header, "X-JJDGuard-Workspace-Id", "X-NewAPI-Workspace-Id")
	if err != nil {
		return out, a.rejectHeaderConflict(w, r, requestID, "workspace_id")
	}
	detection, err := agentdetect.DetectFromHeaders(r.Header)
	if err != nil {
		return out, a.rejectHeaderConflict(w, r, requestID, "agent_type")
	}
	out.agentType = detection.Product
	out.agentRuntime = detection.Runtime
	out.agentDetectionSource = detection.Source
	out.agentDetectionConfidence = detection.Confidence
	return out, true
}

func (a *AuthMiddleware) rejectHeaderConflict(w http.ResponseWriter, r *http.Request, requestID, kind string) bool {
	event, err := headeraudit.NewEvent("gateway-core.api", kind, r.Header, r.RemoteAddr)
	if err != nil || a.headerAudit == nil || a.headerAudit.AppendCritical(r.Context(), event) != nil {
		writeHeaderContractError(w, r, http.StatusServiceUnavailable, "header_conflict_audit_unavailable", "security audit unavailable", requestID)
		return false
	}
	writeHeaderContractError(w, r, http.StatusBadRequest, "header_value_conflict", "conflicting request metadata", requestID)
	return false
}

func writeHeaderContractError(w http.ResponseWriter, r *http.Request, status int, code, message, requestID string) {
	if isAnthropicMessagesRequest(r) {
		errorType := "invalid_request_error"
		if status >= http.StatusInternalServerError {
			errorType = "api_error"
		}
		writeAnthropicAuthError(w, status, errorType, message, requestID)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]map[string]string{"error": {"code": code, "message": message}})
}
