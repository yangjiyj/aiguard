package handler

import (
	"encoding/json"
	"log"
	"net/url"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
	"github.com/jackc/pgx/v5"
)

// mcpServerRouteSelect 是 lookupServer 与审批后重放（lookupMCPServerForApprovedExecution）共用的
// 热路径投影，保证两处读到的上游连接配置一致。capabilities_json 整体取出后在 Go 侧解析，
// 新增的上游连接配置键（鉴权位置、值模板、额外请求头、auto 探测结果等）无需再改 SQL。
const mcpServerRouteSelect = `
	SELECT id, tenant_id, name, COALESCE(server_url, ''), status,
	       COALESCE(transport, 'streamable_http'),
	       COALESCE(auth_ciphertext, ''), COALESCE(auth_key_ref, ''),
	       COALESCE(capabilities_json->>'auth_header_name', ''),
	       COALESCE(capabilities_json->>'protocol_version', ''),
	       COALESCE(allow_private_egress, FALSE),
	       COALESCE(observed_route_hash, ''),
	       COALESCE(capabilities_json::text, '{}'),
	       COALESCE(egress_overrides, '{}'::jsonb)::text
	FROM mcp_servers
	WHERE id = $1 AND tenant_id = $2`

func scanMCPServerRoute(row pgx.Row) (*mcpServerRoute, error) {
	var route mcpServerRoute
	var capsText, overridesText string
	if err := row.Scan(
		&route.ID, &route.TenantID, &route.Name, &route.ServerURL, &route.Status,
		&route.Transport, &route.AuthCiphertext, &route.AuthKeyRef,
		&route.AuthHeaderName, &route.ProtocolVersion, &route.AllowPrivateEgress, &route.RouteHash,
		&capsText, &overridesText,
	); err != nil {
		return nil, err
	}
	if overrides, err := safetarget.ParseEgressOverrides([]byte(overridesText)); err == nil {
		route.EgressOverrides = overrides
	} else {
		// 坏值按默认（全部拒绝）处理。
		log.Printf("MCP server %s egress_overrides invalid, ignored: %v", route.ID, err)
	}
	if capsText != "" {
		_ = json.Unmarshal([]byte(capsText), &route.Capabilities)
	}
	return &route, nil
}

// upstreamConfig 解析该 server 的上游连接配置。route.AuthHeaderName 是历史字段（测试夹具与存量代码
// 直接设置），仅在 capabilities 没有同名键时补入，保证存量行为不变。
func (s *mcpServerRoute) upstreamConfig() (mcpupstream.Config, error) {
	caps := make(map[string]interface{}, len(s.Capabilities)+1)
	for k, v := range s.Capabilities {
		caps[k] = v
	}
	if name := strings.TrimSpace(s.AuthHeaderName); name != "" {
		if _, ok := caps[mcpupstream.CapAuthHeaderName]; !ok {
			caps[mcpupstream.CapAuthHeaderName] = name
		}
	}
	return mcpupstream.ParseConfig(s.Transport, caps)
}

// mcpResolveTransport 返回网关转发该 server 时实际使用的 transport。
// 网关热路径不做探测：显式配置优先；auto 用控制面同步时记录的探测结果，
// 尚无探测结果时按路径推断（以 /sse 结尾→旧 SSE，否则 Streamable HTTP）。
func mcpResolveTransport(cfg mcpupstream.Config, serverURL string) string {
	if t := cfg.EffectiveTransport(); t != mcpupstream.TransportAuto {
		return t
	}
	if u, err := url.Parse(strings.TrimSpace(serverURL)); err == nil && mcpupstream.PathEndsWithSSE(u) {
		return mcpupstream.TransportSSE
	}
	return mcpupstream.TransportStreamableHTTP
}

// usesSSEBridge 判断该 server 是否走旧 SSE 桥接。配置解析失败时按 Streamable 处理，
// 由后续构造请求处报出凭据/配置错误（fail-closed，不会放行）。
func (s *mcpServerRoute) usesSSEBridge() bool {
	cfg, err := s.upstreamConfig()
	if err != nil {
		return false
	}
	return mcpResolveTransport(cfg, s.ServerURL) == mcpupstream.TransportSSE
}
