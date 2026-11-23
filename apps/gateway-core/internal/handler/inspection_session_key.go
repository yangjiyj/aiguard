package handler

import (
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/aiconvo"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
)

// inspectionSessionKey 返回输入检测折叠用的会话键；取不到可信会话时返回空串。
//
// 优先显式 X-JJDGuard-Session-Id（已在 auth 中解析为 envelope.SessionID）。Codex 的
// /v1/responses 请求每次都带 thread-id / session_id 头（同一会话不变，新会话换新值），
// 用 aiconvo.CodexThreadKey 按租户 + 调用方（API Key，没有则用户、来源 IP）隔离后作为会话键，
// 与反向代理路径归组 Codex 会话用的是同一把键。其它客户端没有显式会话时不给键：
// 宁可每次请求各出一条事件，也不跨会话误折叠。
func inspectionSessionKey(header http.Header, envelope *modelrouter.RequestEnvelope) string {
	if envelope == nil {
		return ""
	}
	if session := strings.TrimSpace(envelope.SessionID); session != "" {
		return scanfp.SHA256Hex(strings.Join([]string{"explicit_session_v1", envelope.TenantID, session}, "\x00"))
	}
	if agentdetect.NormalizeAgentType(envelope.AgentType) != "openai-codex" || header == nil {
		return ""
	}
	caller := strings.TrimSpace(envelope.ClientID)
	if caller == "" {
		caller = strings.TrimSpace(envelope.UserID)
	}
	if caller == "" {
		caller = strings.TrimSpace(envelope.SourceIP)
	}
	if caller == "" {
		return ""
	}
	return aiconvo.CodexThreadKey(header, envelope.TenantID, caller)
}
