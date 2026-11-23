package handler

import (
	"context"
	"testing"
)

// registerStreamableTestSession 把一条「上游已签发」的会话登记进网关会话表。
// D3 之后网关只放行登记过且归属一致的 Mcp-Session-Id；老用例手写的会话 id 需先登记，
// 它们要验证的转发语义本身不变。principal 形如 mcpBridgePrincipal：KeyID\x1fUserID\x1fProjectID。
func registerStreamableTestSession(t *testing.T, h *MCPProxyHandler, tenantID, serverID, sessionID, principal, routeHash string) {
	t.Helper()
	if err := h.sessions.get().Put(context.Background(), tenantID, serverID, sessionID,
		mcpSessionBinding{Principal: principal, RouteHash: routeHash}); err != nil {
		t.Fatal(err)
	}
}
