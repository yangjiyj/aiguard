package handler

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
)

// 注意：会话登记表字段挂在 MCPProxyHandler 上，见 mcp_proxy.go（sessionStoreMu / sessionStore）。

const (
	mcpDuplicateHeaderBody     = `{"error":{"code":"mcp_duplicate_header","message":"请求头 Mcp-Session-Id / MCP-Protocol-Version 不允许重复出现"}}`
	mcpSessionTableFullBody    = `{"error":{"code":"mcp_session_table_full","message":"MCP 会话登记表已满，请稍后重试"}}`
	mcpStreamableNoSessionBody = `{"error":{"code":"mcp_session_not_found","message":"MCP 会话不存在、已过期或不属于当前调用方，请重新 initialize"}}`
	mcpSessionStoreDownBody    = `{"error":{"code":"mcp_session_store_unavailable","message":"MCP 会话校验暂时不可用，请稍后重试"}}`
)

type mcpSessionStoreHolder struct {
	mu    sync.Mutex
	store mcpSessionStore
}

func (h *mcpSessionStoreHolder) get() mcpSessionStore {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.store == nil {
		h.store = newMCPMemorySessionStore()
	}
	return h.store
}

func (h *mcpSessionStoreHolder) set(s mcpSessionStore) {
	h.mu.Lock()
	h.store = s
	h.mu.Unlock()
}

// SetMCPSessionStore 替换会话登记表（多副本时注入共享实现；测试里模拟重启）。
func (h *MCPProxyHandler) SetMCPSessionStore(s mcpSessionStore) {
	if h != nil && s != nil {
		h.sessions.set(s)
	}
}

// mcpStreamablePrincipalFromReplay 把 HITL 重放的主体键（带租户前缀）还原为登记时的主体键。
func mcpStreamablePrincipalFromReplay(tenantID, replayPrincipal string) string {
	return strings.TrimPrefix(replayPrincipal, tenantID+"\x1f")
}

func mcpStreamablePrincipal(ctx context.Context, server *mcpServerRoute, r *http.Request) string {
	if replay, ok := ctx.Value(mcpReplayContextKey{}).(mcpReplayPrincipal); ok {
		return mcpStreamablePrincipalFromReplay(server.TenantID, replay.principal)
	}
	return mcpBridgePrincipal(auth.GetAuthInfo(r))
}

// mcpSingleValuedHeaders 是网关据以做安全判定、同时又会转发给上游的关键头：必须恰好零个或一个值。
// 复审 High-1：校验用 Header.Get 只看第一个值，而 copyHeaders 会把全部值转发，攻击者可以「第一个放自己的合法
// 会话、第二个放别人的」绕过归属校验。多值一律拒绝，不做「取第一个」之类的猜测。
var mcpSingleValuedHeaders = []string{"Mcp-Session-Id", "MCP-Protocol-Version"}

// mcpDuplicateCriticalHeader 返回出现多个值（或同名头重复出现）的关键头名；没有则返回空串。
func mcpDuplicateCriticalHeader(h http.Header) string {
	for _, name := range mcpSingleValuedHeaders {
		if len(h.Values(name)) > 1 {
			return name
		}
	}
	return ""
}

// checkStreamableSession 在转发前校验客户端带来的 Mcp-Session-Id。
// 返回非 nil 响应表示拒绝（未转发的合成响应）；返回 nil 表示放行（无会话 id 或归属一致）。
func (h *MCPProxyHandler) checkStreamableSession(ctx context.Context, server *mcpServerRoute, r *http.Request, targetURL *url.URL) *http.Response {
	sid := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if sid == "" {
		return nil
	}
	if len(r.Header.Values("Mcp-Session-Id")) > 1 { // 纵深防御：上层已拒绝，这里再兜一次
		return mcpNotForwardedResponse(http.StatusBadRequest, mcpDuplicateHeaderBody)
	}
	store := h.sessions.get()
	principal := mcpStreamablePrincipal(ctx, server, r)
	b, ok, err := store.Get(ctx, server.TenantID, server.ID, sid)
	if err != nil {
		log.Printf("MCP 会话登记表不可用，按 fail-closed 拒绝 (server=%s): %v", server.ID, err)
		return mcpNotForwardedResponse(http.StatusServiceUnavailable, mcpSessionStoreDownBody)
	}
	if !ok || b.Principal != principal {
		// 不区分「不存在」与「属于别人」，不泄露他人会话是否存在；也绝不据此删除别人的会话。
		return mcpNotForwardedResponse(http.StatusNotFound, mcpStreamableNoSessionBody)
	}
	if b.RouteHash != server.RouteHash {
		// 管理员改了地址/密钥/鉴权配置：旧配置下建立的会话作废。
		_ = store.Delete(ctx, server.TenantID, server.ID, sid)
		return mcpNotForwardedResponse(http.StatusNotFound, mcpStreamableNoSessionBody)
	}
	return nil
}

// recordStreamableSession 在 initialize 成功且上游签发了会话 id 时登记归属；终止成功的 DELETE 则注销。
func (h *MCPProxyHandler) recordStreamableSession(ctx context.Context, server *mcpServerRoute, r *http.Request, body []byte, resp *http.Response) error {
	if resp == nil {
		return nil
	}
	store := h.sessions.get()
	switch r.Method {
	case http.MethodDelete:
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if sid := strings.TrimSpace(r.Header.Get("Mcp-Session-Id")); sid != "" {
				_ = store.Delete(ctx, server.TenantID, server.ID, sid)
			}
		}
	case http.MethodPost:
		if !mcpBodyIsInitialize(body) || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil
		}
		sid := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id"))
		if sid == "" {
			return nil
		}
		if err := store.Put(ctx, server.TenantID, server.ID, sid, mcpSessionBinding{
			Principal: mcpStreamablePrincipal(ctx, server, r), RouteHash: server.RouteHash,
		}); err != nil {
			// 登记失败：不能把一个事后必 404 的会话 id 交给客户端。调用方据此返回 503（未转发之外的明确失败），
			// 客户端稍后重新 initialize；已存在的他人会话不受影响。
			log.Printf("MCP 会话登记失败，已拒绝本次 initialize 的会话 (server=%s tenant=%s): %v", server.ID, server.TenantID, err)
			return err
		}
	}
	return nil
}
