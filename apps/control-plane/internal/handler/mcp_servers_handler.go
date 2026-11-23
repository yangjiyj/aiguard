package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

// mcpSyncTimeout 能力同步（initialize+tools/list）的 handler 内部超时。
// 全局路由中间件是 30s Timeout，慢 MCP 服务器必须在这之前被掐掉。
const mcpSyncTimeout = 10 * time.Second

// mcpPoisonScanBudget 是 sync 时全部工具描述投毒送检的总时间预算（observe-only）。
// 兜底防止工具数多 + security-engine 慢时把描述投毒扫描顶穿路由 30s 超时；超预算的工具
// poison_flags 留空（fail-open）。单次调用另有 securityEngineScanTimeout(5s) 兜底。
const mcpPoisonScanBudget = 12 * time.Second

// mcpPoisonScanBudgetFor 读 mcp.scan_unavailable 的 timeout_seconds（默认 12 秒，即原常量）。
func mcpPoisonScanBudgetFor(settings protection.Settings) time.Duration {
	if seconds := settings.IntParam(protection.KeyMCPScanUnavailable, "timeout_seconds"); seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return mcpPoisonScanBudget
}

// mcpTenantProtections 读租户的防护项设置；没装配设置仓库时用注册表默认（nil）。
// 读失败返回错误：不能按默认（告警放行）去覆盖已配置的阻断。
func mcpTenantProtections(ctx context.Context, deps *Dependencies, tenantID string) (protection.Settings, error) {
	if deps == nil || deps.ProtectionSettingsStore == nil {
		return nil, nil
	}
	settings, err := deps.ProtectionSettingsStore.Settings(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read protection settings for tenant %s: %w", tenantID, err)
	}
	return settings, nil
}

// validMCPTransport 传输方式白名单：auto（自动识别，新建默认）/ streamable_http / sse（旧版 HTTP+SSE）。
// 空串由 repository 落默认 streamable_http（存量行为不变）。
func validMCPTransport(transport string) bool {
	switch transport {
	case "", "auto", "streamable_http", "sse":
		return true
	default:
		return false
	}
}

// mcpServerView 是列表/详情响应体：在库表字段之上补 tool_count（在册工具数）。
// 响应里的 server_url 一律对 query 值脱敏（存量行里可能仍带明文 ?key=）；
// upstream 汇总上游连接配置与协商结果，供管理台展示（不含任何密钥）。
type mcpServerView struct {
	*repository.MCPServer
	ToolCount int                `json:"tool_count"`
	Upstream  mcpUpstreamSummary `json:"upstream"`
	// ServerURL 覆盖内嵌结构体的同名字段（外层字段优先序列化）。
	ServerURL string `json:"server_url"`
}

// mcpUpstreamSummary 是展示用的上游连接摘要。
type mcpUpstreamSummary struct {
	Transport             string            `json:"transport"`
	DetectedTransport     string            `json:"detected_transport,omitempty"`
	EffectiveTransport    string            `json:"effective_transport"`
	AuthLocation          string            `json:"auth_location"`
	AuthName              string            `json:"auth_name"`
	AuthTemplate          string            `json:"auth_template"`
	ExtraHeaders          map[string]string `json:"extra_headers,omitempty"`
	ProtocolVersion       string            `json:"protocol_version,omitempty"`
	ProtocolVersionRaw    string            `json:"protocol_version_raw,omitempty"`
	URLHasPlaintextSecret bool              `json:"url_has_plaintext_secret"`
	ConfigError           string            `json:"config_error,omitempty"`
}

func newMCPServerView(s *repository.MCPServer, toolCount int) mcpServerView {
	view := mcpServerView{MCPServer: s, ToolCount: toolCount, ServerURL: mcpupstream.RedactURL(s.ServerURL)}
	sum := mcpUpstreamSummary{Transport: s.Transport}
	if cfg, err := mcpupstream.ParseConfig(s.Transport, s.Capabilities); err == nil {
		sum.Transport = cfg.Transport
		sum.DetectedTransport = cfg.DetectedTransport
		sum.EffectiveTransport = cfg.EffectiveTransport()
		sum.AuthLocation, sum.AuthName, sum.AuthTemplate = cfg.AuthLocation, cfg.AuthName, cfg.AuthTemplate
		sum.ExtraHeaders = cfg.ExtraHeaders
	} else {
		sum.ConfigError = err.Error()
	}
	sum.ProtocolVersion, _ = s.Capabilities[mcpupstream.CapProtocolVersion].(string)
	sum.ProtocolVersionRaw, _ = s.Capabilities[mcpupstream.CapProtocolVersionRaw].(string)
	if _, ex, err := mcpupstream.SplitURLSecrets(s.ServerURL); err == nil && ex != nil {
		sum.URLHasPlaintextSecret = true
	}
	view.Upstream = sum
	return view
}

// ListMCPServers handles GET /admin/v1/mcp-servers
// MCP 服务器资产列表；099 起补新列（transport/manifest_hash/last_synced_at 等）与 tool_count。
func ListMCPServers(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.MCPServerRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp servers not configured")
			return
		}

		servers, err := deps.MCPServerRepo.ListByTenant(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		toolCounts := map[string]int{}
		if deps.MCPToolRepo != nil {
			if counts, err := deps.MCPToolRepo.CountActiveByTenant(r.Context(), user.TenantID); err == nil {
				toolCounts = counts
			}
		}
		views := make([]mcpServerView, 0, len(servers))
		for _, s := range servers {
			views = append(views, newMCPServerView(s, toolCounts[s.ID]))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"servers": views})
	}
}

// CreateMCPServer handles POST /admin/v1/mcp-servers
// Body: {name, server_url, owner, trust_level, capabilities, status,
//
//	transport, auth_token(明文只写，落库前加密), allow_private_egress}
func CreateMCPServer(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.MCPServerRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp servers not configured")
			return
		}

		var req struct {
			Name               string                 `json:"name"`
			ServerURL          string                 `json:"server_url"`
			Owner              string                 `json:"owner"`
			TrustLevel         string                 `json:"trust_level"`
			Capabilities       map[string]interface{} `json:"capabilities"`
			Status             string                 `json:"status"`
			Transport          string                 `json:"transport"`
			AuthToken          string                 `json:"auth_token"`
			AllowPrivateEgress bool                   `json:"allow_private_egress"`
			// EgressOverrides 是高级出站放行；严格解析，省略时全部拒绝（更新时保持不变）。
			EgressOverrides json.RawMessage `json:"egress_overrides,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON")
			return
		}
		if req.Name == "" {
			writeError(w, "invalid_request", "name required")
			return
		}
		prepared, err := prepareMCPServerInput(req.ServerURL, req.Transport, req.Capabilities, req.AuthToken, nil)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		req.ServerURL, req.Capabilities, req.AuthToken = prepared.ServerURL, prepared.Capabilities, prepared.AuthToken
		overrides, err := safetarget.ParseEgressOverrides(req.EgressOverrides)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "egress_overrides is invalid: "+err.Error())
			return
		}
		if len(overrides.Enabled()) > 0 && !canLoosenEgress(user) {
			writeErrorWithStatus(w, http.StatusForbidden, "egress_override_requires_platform_role", egressLooseningForbiddenMessage)
			return
		}

		// 鉴权凭据：明文只在请求体存在一瞬，落库前 AES-GCM 加密（enc:v1:），响应绝不回传。
		authCiphertext, authKeyRef := "", ""
		if req.AuthToken != "" {
			var err error
			authCiphertext, authKeyRef, err = secrets.EncryptProviderSecret(req.AuthToken)
			if err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "凭据加密失败（检查 JJD_PROVIDER_SECRET_KEY/JJD_MASTER_KEY）")
				return
			}
		}

		m := &repository.MCPServer{
			TenantID:           user.TenantID,
			Name:               req.Name,
			ServerURL:          req.ServerURL,
			Owner:              req.Owner,
			TrustLevel:         req.TrustLevel,
			Capabilities:       req.Capabilities,
			Status:             req.Status,
			Transport:          req.Transport,
			AuthCiphertext:     authCiphertext,
			AuthKeyRef:         authKeyRef,
			AllowPrivateEgress: req.AllowPrivateEgress,
			EgressOverrides:    overrides,
		}
		if err := deps.MCPServerRepo.Create(r.Context(), m); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "mcp_server.create", map[string]interface{}{
			"server_id": m.ID, "name": m.Name, "trust_level": m.TrustLevel,
			"transport": m.Transport, "allow_private_egress": m.AllowPrivateEgress,
			"auth_configured": m.AuthConfigured, "server_url": mcpupstream.RedactURL(m.ServerURL),
			"secret_split_from_url": prepared.Extracted != nil, "egress_overrides": m.EgressOverrides.Enabled(),
		}, "mcp_server", m.ID)
		auditEgressOverrideEnable(r, deps, "mcp_server", m.ID, safetarget.EgressOverrides{}, m.EgressOverrides)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(newMCPServerView(m, 0))
	}
}

// UpdateMCPServer handles PUT /admin/v1/mcp-servers/{id}
// Body 同 Create；auth_token 传空 = 凭据保持不变（避免每次编辑清空已配置凭据）；
// capabilities 省略 = 保持不变（前端编辑表单不回传该字段，无条件覆盖会清空）。
func UpdateMCPServer(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.MCPServerRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp servers not configured")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}

		var req struct {
			Name               string                 `json:"name"`
			ServerURL          string                 `json:"server_url"`
			Owner              string                 `json:"owner"`
			TrustLevel         string                 `json:"trust_level"`
			Capabilities       map[string]interface{} `json:"capabilities"`
			Status             string                 `json:"status"`
			Transport          string                 `json:"transport"`
			AuthToken          string                 `json:"auth_token"`
			AllowPrivateEgress bool                   `json:"allow_private_egress"`
			// EgressOverrides 是高级出站放行；严格解析，省略时全部拒绝（更新时保持不变）。
			EgressOverrides json.RawMessage `json:"egress_overrides,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON")
			return
		}
		if req.TrustLevel == "" {
			req.TrustLevel = "low"
		}
		if req.Status == "" {
			req.Status = "active"
		}
		current, gerr := deps.MCPServerRepo.Get(r.Context(), user.TenantID, id)
		if gerr != nil {
			if errors.Is(gerr, pgx.ErrNoRows) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "mcp server not found")
				return
			}
			// 读不到现有记录就无法判断本次编辑是否会把旧密钥带去新地址：直接失败，绝不继续写库。
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "读取现有 MCP 服务配置失败")
			return
		}
		existingCaps := current.Capabilities
		restored, rerr := restoreRedactedQueryValues(req.ServerURL, current.ServerURL)
		if rerr != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", rerr.Error())
			return
		}
		req.ServerURL = restored
		prepared, err := prepareMCPServerInput(req.ServerURL, req.Transport, req.Capabilities, req.AuthToken, existingCaps)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		req.ServerURL, req.Capabilities, req.AuthToken = prepared.ServerURL, prepared.Capabilities, prepared.AuthToken
		var newOverrides *safetarget.EgressOverrides
		if len(req.EgressOverrides) > 0 {
			parsed, err := safetarget.ParseEgressOverrides(req.EgressOverrides)
			if err != nil {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "egress_overrides is invalid: "+err.Error())
				return
			}
			newOverrides = &parsed
		}

		// 上游地址（scheme/host/port/path）或鉴权形态（位置/头名/参数名/值模板）变化时，必须同时重新提交密钥：
		// 否则库里的旧密文会被原样发往新地址或按新格式注入，等于把旧密钥送给未经审批的目标。
		// capabilities 省略（nil）表示保持不变，此时按库内现有配置比较。
		effectiveCaps := req.Capabilities
		if effectiveCaps == nil {
			effectiveCaps = existingCaps
		}
		if newOverrides != nil && len(safetarget.NewlyEnabled(current.EgressOverrides, *newOverrides)) > 0 && !canLoosenEgress(user) {
			writeErrorWithStatus(w, http.StatusForbidden, "egress_override_requires_platform_role", egressLooseningForbiddenMessage)
			return
		}
		if strings.TrimSpace(req.AuthToken) == "" && current.AuthCiphertext != "" &&
			upstreamRouteOrAuthChanged(current.ServerURL, req.ServerURL, current.Transport, req.Transport, existingCaps, effectiveCaps) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", mcpReenterSecretHint)
			return
		}

		params := repository.MCPServerUpdateParams{
			Name:               req.Name,
			ServerURL:          req.ServerURL,
			Owner:              req.Owner,
			TrustLevel:         req.TrustLevel,
			Capabilities:       req.Capabilities,
			Status:             req.Status,
			Transport:          req.Transport,
			AllowPrivateEgress: req.AllowPrivateEgress,
			EgressOverrides:    newOverrides,
		}
		if req.AuthToken != "" {
			authCiphertext, authKeyRef, err := secrets.EncryptProviderSecret(req.AuthToken)
			if err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "凭据加密失败（检查 JJD_PROVIDER_SECRET_KEY/JJD_MASTER_KEY）")
				return
			}
			params.SetAuth = true
			params.AuthCiphertext = authCiphertext
			params.AuthKeyRef = authKeyRef
		}

		// 租户硬隔离：repository WHERE id AND tenant_id（修复历史 IDOR），打不到即 404。
		if err := deps.MCPServerRepo.Update(r.Context(), user.TenantID, id, params); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "mcp server not found")
				return
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "mcp_server.update", map[string]interface{}{
			"server_id": id, "name": req.Name, "trust_level": req.TrustLevel, "status": req.Status,
			"transport": req.Transport, "allow_private_egress": req.AllowPrivateEgress,
			"auth_rotated": req.AuthToken != "", "server_url": mcpupstream.RedactURL(req.ServerURL),
			"secret_split_from_url": prepared.Extracted != nil,
		}, "mcp_server", id)
		if newOverrides != nil {
			auditEgressOverrideEnable(r, deps, "mcp_server", id, current.EgressOverrides, *newOverrides)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}
}

// DeleteMCPServer handles DELETE /admin/v1/mcp-servers/{id}
func DeleteMCPServer(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.MCPServerRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp servers not configured")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}

		if err := deps.MCPServerRepo.Delete(r.Context(), user.TenantID, id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "mcp server not found")
				return
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "mcp_server.delete", map[string]interface{}{"server_id": id}, "mcp_server", id)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}
}

// SyncMCPServer handles POST /admin/v1/mcp-servers/{id}/sync
// 能力同步：拉 initialize+tools/list → 风险启发式标注 → 整批 upsert mcp_tools →
// manifest_hash 比对（变更即 rug-pull 信号，刷新 last_manifest_changed_at）。
// 响应: {manifest_hash, changed, previous_hash, tool_count, tools:[...]}
func SyncMCPServer(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.MCPServerRepo == nil || deps.MCPToolRepo == nil || deps.MCPSupplyChainRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp gateway not configured")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}

		server, err := deps.MCPServerRepo.Get(r.Context(), user.TenantID, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "mcp server not found")
				return
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if server.ServerURL == "" {
			writeError(w, "invalid_request", "该 MCP 服务器未登记地址（server_url），无法同步能力")
			return
		}

		outcome, err := runMCPServerSync(r.Context(), deps, user.TenantID, server, fetchMCPManifestForServer,
			newSecurityEngineClient(deps.SecurityEngineURL, deps.SecurityEngineInternalToken).ScanToolDescriptionChecked)
		if err != nil {
			var fetchErr *mcpSyncFetchError
			if errors.As(err, &fetchErr) {
				if ue := (*mcpupstream.Error)(nil); errors.As(fetchErr.Err, &ue) && ue.RetryAfter != "" {
					w.Header().Set("Retry-After", ue.RetryAfter)
				}
				writeErrorWithStatus(w, http.StatusBadGateway, "mcp_sync_failed", fetchErr.Err.Error())
				return
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		newHash, previousHash, changed := outcome.NewHash, outcome.PreviousHash, outcome.Changed
		toolRows, poisonedCount, protocolVersion, supplyResult := outcome.Tools, outcome.PoisonedCount, outcome.ProtocolVersion, outcome.Supply

		logAudit(r, deps, "mcp_server.sync", map[string]interface{}{
			"server_id": server.ID, "manifest_hash": newHash, "previous_hash": previousHash,
			"changed": changed, "tool_count": len(toolRows), "poisoned_tool_count": poisonedCount,
			"protocol_version": protocolVersion, "supply_chain": supplyResult,
			"server_url": mcpupstream.RedactURL(server.ServerURL),
		}, "mcp_server", server.ID)

		tools, err := deps.MCPToolRepo.ListByServer(r.Context(), user.TenantID, server.ID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		writeJSON(w, map[string]interface{}{
			"manifest_hash":       newHash,
			"changed":             changed,
			"previous_hash":       previousHash,
			"tool_count":          len(toolRows),
			"poisoned_tool_count": poisonedCount,
			"protocol_version":    protocolVersion,
			"tools":               tools,
			"supply_chain":        supplyResult,
		})
	}
}

// TestMCPServer handles POST /admin/v1/mcp-servers/{id}/test-connection
// 连通性探活：只发一次 JSON-RPC initialize（不落库、不同步工具、不改 manifest），
// 返回 {ok, error_kind, message, server_info}。用于登记后一键自检，给出可操作的中文错误分类
// （DNS/超时/TLS/401/5xx/解析），替代同步失败时"同步能力失败"一句话。
func TestMCPServer(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.MCPServerRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp servers not configured")
			return
		}
		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}
		// 租户硬隔离：打不到本租户的 server 即 404。
		server, err := deps.MCPServerRepo.Get(r.Context(), user.TenantID, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "mcp server not found")
				return
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if server.ServerURL == "" {
			writeJSON(w, map[string]interface{}{
				"ok": false, "error_kind": "url", "message": "该 MCP 服务器未登记地址（server_url），无法测试连接",
			})
			return
		}

		// 自限超时，慢 server 不能顶穿全局请求超时。
		testCtx, cancel := context.WithTimeout(r.Context(), mcpSyncTimeout)
		defer cancel()

		serverInfo, errKind, testErr := testMCPServerConnection(testCtx, server)
		logAudit(r, deps, "mcp_server.test_connection", map[string]interface{}{
			"server_id": server.ID, "ok": testErr == nil, "error_kind": errKind,
			"server_url": mcpupstream.RedactURL(server.ServerURL),
		}, "mcp_server", server.ID)
		if testErr != nil {
			writeJSON(w, map[string]interface{}{
				"ok": false, "error_kind": errKind, "message": testErr.Error(),
			})
			return
		}
		writeJSON(w, map[string]interface{}{
			"ok": true, "server_info": serverInfo,
		})
	}
}

// ListMCPServerTools handles GET /admin/v1/mcp-servers/{id}/tools
// 响应: {items:[{id,tool_name,description,input_schema,risk_tags,first_seen_at,last_seen_at,removed}]}
func ListMCPServerTools(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.MCPServerRepo == nil || deps.MCPToolRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp gateway not configured")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}
		// 先确认 server 归属本租户（工具查询本身也带 tenant 谓词，双保险）。
		if _, err := deps.MCPServerRepo.Get(r.Context(), user.TenantID, id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "mcp server not found")
				return
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		tools, err := deps.MCPToolRepo.ListByServer(r.Context(), user.TenantID, id)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if tools == nil {
			tools = []*repository.MCPTool{}
		}
		writeJSON(w, map[string]interface{}{"items": tools})
	}
}

// MCPToolShadowCheck handles GET /admin/v1/mcp-tools/shadow-check
// 影子工具检测（observe-only）：找租户内同一 tool_name 出现在多台 MCP 服务上的情况。
// 零 DB 写入；口径纯函数 DetectShadowTools，可单测。
func MCPToolShadowCheck(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.MCPToolRepo == nil || deps.MCPServerRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp gateway not configured")
			return
		}
		tools, err := deps.MCPToolRepo.ListByTenant(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		// server_id→中文名，供告警可读展示（缺失回退 id）
		names := map[string]string{}
		if servers, serr := deps.MCPServerRepo.ListByTenant(r.Context(), user.TenantID); serr == nil {
			for _, s := range servers {
				if s != nil {
					names[s.ID] = s.Name
				}
			}
		}
		warnings := repository.DetectShadowTools(tools, names)
		if warnings == nil {
			warnings = []repository.MCPShadowToolWarning{}
		}
		writeJSON(w, map[string]interface{}{"warnings": warnings})
	}
}
