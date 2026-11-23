package repository

import (
	"os"
	"strings"
)

// 会话归属投影（任务 3a）：部门、智能体、对话 ID、上游主体。
//
// 两支会话查询（content_logs 会话 / 正向代理留存会话）共用同一组列；实现方式只在
// 最终 SELECT 追加标量子查询与 LEFT JOIN LATERAL，不改分页、排序、总数与风险过滤路径。
//
// 归属口径：
//   - department_id：反代路径取 request_logs.principal_context_json->>'application_department_id'，
//     为空时退回 team_members 里该 user_id 的第一个 team；正向路径本来就没有 principal_context，
//     故直接走 team_members 回退。
//   - department_name：teams.name by 选中的 department_id（跨租户同名 team 由 tenant_id 约束住）。
//   - agent_type：代表请求 request_logs.agent_type。
//   - conversation_id：正向留证取 access_content_logs.conversation_id，取不到则用 session_id
//     （反代会话的 session_id 本身就是会话键）。
//   - principal_key / principal_source：来自 principal_context_json，正向路径由 proxy-server
//     在同一列写入上游账号/凭据指纹（任务 3b）。
//   - principal_proxy_nat：proxy_source_ip 与 source_ip 相同 => 只看到网关 NAT 地址，
//     不能把这条流量定位到具体的人。IP 白名单（ALERT_NAT_SOURCE_IPS）在 handler 侧合并。
const contentSessionAttributionColumns = `
       COALESCE(NULLIF(attr.principal_context_json->>'application_department_id', ''), dep_fallback.department_id, '') AS department_id,
       COALESCE(dep_team.name, '') AS department_name,
       COALESCE(NULLIF(attr.agent_type, ''), '') AS agent_type,
       COALESCE(NULLIF(attr.conversation_id, ''), p.session_id) AS conversation_id,
       COALESCE(NULLIF(attr.principal_context_json->>'principal_key', ''), '') AS principal_key,
       COALESCE(NULLIF(attr.principal_context_json->>'identity_source', ''), '') AS principal_source,
       COALESCE(NULLIF(attr.source_ip, ''), '') AS principal_source_ip,
       (COALESCE(NULLIF(attr.proxy_mode, ''), '') = 'forward'
        AND COALESCE(NULLIF(attr.proxy_source_ip, ''), '') <> ''
        AND COALESCE(NULLIF(attr.proxy_source_ip, ''), '') = COALESCE(NULLIF(attr.source_ip, ''), '')) AS principal_proxy_nat`

// 部门归属回退与名称解析：department_id 只用于展示，不参与任何授权判定。
const contentSessionAttributionJoins = `LEFT JOIN LATERAL (
SELECT tm.team_id AS department_id
FROM team_members tm
WHERE tm.user_id = p.user_id
ORDER BY tm.created_at ASC, tm.team_id ASC
LIMIT 1
) dep_fallback ON TRUE
LEFT JOIN teams dep_team
  ON dep_team.tenant_id = $1
 AND dep_team.id = COALESCE(NULLIF(attr.principal_context_json->>'application_department_id', ''), dep_fallback.department_id)
`

// Fast path (alert_only / skip_total): page already carries request_key, so the
// representative request is a direct key lookup.
//
// Alias discipline: the environment-scope rewrite in scopeContentSessionListQuery
// is a blind strings.ReplaceAll on "cl.tenant_id = $1" / " rl.tenant_id = $1",
// so no alias used here may end in "cl" -- an earlier "acl" alias was silently
// mangled into a dangling cl reference. TestContentSessionAttributionAliasesSurviveScopedRewrite
// keeps that invariant.
const contentSessionAttributionAttrFast = `LEFT JOIN LATERAL (
SELECT rl.agent_type, rl.source_ip, rl.proxy_source_ip, rl.proxy_mode, rl.principal_context_json,
       conv_pick.conversation_id
FROM request_logs rl
LEFT JOIN LATERAL (
SELECT acc.conversation_id
FROM access_content_logs acc
WHERE acc.tenant_id = $1
  AND acc.request_id = COALESCE(NULLIF(rl.request_id, ''), p.request_key)
  AND COALESCE(acc.conversation_id, '') <> ''
ORDER BY acc.created_at DESC
LIMIT 1
) conv_pick ON TRUE
WHERE rl.tenant_id = $1
  AND rl.request_id = p.request_key
  AND rl.created_at >= $2 AND rl.created_at <= $3
ORDER BY rl.created_at DESC
LIMIT 1
) attr ON TRUE
`

// 全量路径：page 只有 session_id，按会话取最后一条 request_logs 作为代表请求。
const contentSessionAttributionAttrScoped = `LEFT JOIN LATERAL (
SELECT rl.agent_type, rl.source_ip, rl.proxy_source_ip, rl.proxy_mode, rl.principal_context_json,
       conv_pick.conversation_id
FROM content_logs cl
JOIN request_logs rl ON rl.id = cl.request_id
LEFT JOIN LATERAL (
SELECT acc.conversation_id
FROM access_content_logs acc
WHERE acc.tenant_id = $1
  AND acc.request_id = COALESCE(NULLIF(rl.request_id, ''), cl.request_id)
  AND COALESCE(acc.conversation_id, '') <> ''
ORDER BY acc.created_at DESC
LIMIT 1
) conv_pick ON TRUE
WHERE cl.tenant_id = $1
  AND cl.session_id = p.session_id
  AND cl.created_at >= $2 AND cl.created_at <= $3
ORDER BY cl.created_at DESC
LIMIT 1
) attr ON TRUE
`

const contentSessionFinalSelectNeedle = "FROM page p"
const contentSessionAttributionJoinNeedle = "LEFT JOIN page_group_totals pgt ON pgt.session_id = p.session_id"

type contentSessionAttributionAnchor struct {
	afterNeedle string
	// lastNeedle 指向最终投影的最后一个列（总数表达式），快路径为空表示 afterNeedle 本身即最后一列。
	lastNeedle string
	attrJoin   string
}

var (
	contentSessionAttributionFastAnchor = contentSessionAttributionAnchor{
		afterNeedle: "0::bigint as total_count",
		attrJoin:    contentSessionAttributionAttrFast,
	}
	contentSessionAttributionScopedAnchor = contentSessionAttributionAnchor{
		afterNeedle: "'' AS request_id",
		lastNeedle:  "as total_count",
		attrJoin:    contentSessionAttributionAttrScoped,
	}
)

// appendContentSessionAttribution 把归属列插到最终 SELECT 的最后一个投影之后，
// 并把代表请求的 LATERAL 与部门解析 join 插进 FROM 子句。
// 定位失败时原样返回，让集成测试与查询执行直接暴露问题，而不是静默产出错列。
func appendContentSessionAttribution(query string, anchor contentSessionAttributionAnchor) (string, bool) {
	start := strings.Index(query, anchor.afterNeedle)
	if start < 0 {
		return query, false
	}
	selectAt := start + len(anchor.afterNeedle)
	if anchor.lastNeedle != "" {
		last := strings.Index(query[selectAt:], anchor.lastNeedle)
		if last < 0 {
			return query, false
		}
		selectAt += last + len(anchor.lastNeedle)
	}
	fromAt := strings.Index(query[selectAt:], contentSessionFinalSelectNeedle)
	if fromAt < 0 {
		return query, false
	}
	fromAt += selectAt
	if strings.TrimSpace(query[selectAt:fromAt]) != "" {
		return query, false
	}
	joinAt := strings.Index(query[fromAt:], contentSessionAttributionJoinNeedle)
	if joinAt < 0 {
		return query, false
	}
	joinAt += fromAt

	head := query[:fromAt] + "," + contentSessionAttributionColumns + "\n"
	tail := query[fromAt:joinAt] + anchor.attrJoin + contentSessionAttributionJoins + query[joinAt:]
	return head + tail, true
}

func addContentSessionAttributionFast(query string) string {
	if patched, ok := appendContentSessionAttribution(query, contentSessionAttributionFastAnchor); ok {
		return patched
	}
	return query
}

func addContentSessionAttributionScoped(query string) string {
	if patched, ok := appendContentSessionAttribution(query, contentSessionAttributionScopedAnchor); ok {
		return patched
	}
	return query
}

// scanContentSessionAttribution 与 contentSessionAttributionColumns 的列序一一对应。
type contentSessionAttribution struct {
	DepartmentID    string
	DepartmentName  string
	AgentType       string
	ConversationID  string
	PrincipalKey    string
	PrincipalSource string
	SourceIP        string
	ProxyNAT        bool
}

// principal_label 的四种读法，优先级即声明顺序：用户 > 上游账号 > 上游凭据指纹 > 来源 IP。
// 文案与执行提示词逐字一致，由脚本按码位注入，避免形近字。
const (
	principalLabelUserPrefix       = "用户 "
	principalLabelUpstreamPrefix   = "上游账号 "
	principalLabelCredentialPrefix = "上游凭据指纹 "
	principalLabelSourcePrefix     = "来源 IP "
	principalLabelNATSuffix        = "（经 NAT，不能定位到人）"
)

// alertNATSourceIPs 读 ALERT_NAT_SOURCE_IPS（逗号分隔，默认空）。
// 不缓存：现网靠环境变量下发，也让测试能就地开关。
func alertNATSourceIPs() []string {
	raw := strings.TrimSpace(os.Getenv("ALERT_NAT_SOURCE_IPS"))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// proxyNAT 判定这条流量是否只留下网关出口地址，从而不能定位到具体的人：
// 1) source_ip 命中 ALERT_NAT_SOURCE_IPS；或
// 2) 正向代理流量里 source_ip 与 proxy_source_ip 相同（转发器丢了真实源地址）。
func (a contentSessionAttribution) proxyNAT() bool {
	sourceIP := strings.TrimSpace(a.SourceIP)
	if sourceIP == "" {
		return false
	}
	if a.ProxyNAT {
		return true
	}
	for _, candidate := range alertNATSourceIPs() {
		if candidate == sourceIP {
			return true
		}
	}
	return false
}

// upstreamPrincipalLabel 把 upstream:<kind>:<value> 指纹还原成人能读的主体名。
// 只认 handler 侧写下的两种形态；其它形态返回空，让调用方退回来源 IP。
func upstreamPrincipalLabel(principalKey string) string {
	key := strings.TrimSpace(principalKey)
	const prefix = "upstream:"
	if !strings.HasPrefix(key, prefix) {
		return ""
	}
	parts := strings.SplitN(strings.TrimPrefix(key, prefix), ":", 2)
	if len(parts) != 2 {
		return ""
	}
	kind, value := parts[0], strings.TrimSpace(parts[1])
	if value == "" {
		return ""
	}
	switch {
	case strings.HasSuffix(kind, "_account"):
		return principalLabelUpstreamPrefix + strings.TrimSuffix(kind, "_account") + ":" + truncatePrincipalValue(value, 8)
	case kind == "credential":
		return principalLabelCredentialPrefix + value
	}
	return ""
}

func truncatePrincipalValue(value string, size int) string {
	if size <= 0 || len(value) <= size {
		return value
	}
	return value[:size]
}

// principalLabel 生成会话行的责任主体文案。username 取自同一行的 key_owner/request_user。
func (a contentSessionAttribution) principalLabel(username string) string {
	if trimmed := strings.TrimSpace(username); trimmed != "" {
		return principalLabelUserPrefix + trimmed
	}
	if label := upstreamPrincipalLabel(a.PrincipalKey); label != "" {
		return label
	}
	sourceIP := strings.TrimSpace(a.SourceIP)
	if sourceIP == "" {
		return ""
	}
	if a.proxyNAT() {
		return principalLabelSourcePrefix + sourceIP + principalLabelNATSuffix
	}
	return principalLabelSourcePrefix + sourceIP
}

func (a contentSessionAttribution) apply(session map[string]interface{}) {
	username, _ := session["username"].(string)
	session["department_id"] = a.DepartmentID
	session["department_name"] = a.DepartmentName
	session["agent_type"] = a.AgentType
	session["conversation_id"] = a.ConversationID
	session["principal_key"] = a.PrincipalKey
	session["principal_source"] = a.PrincipalSource
	session["principal_source_ip"] = a.SourceIP
	session["principal_proxy_nat"] = a.proxyNAT()
	session["principal_label"] = a.principalLabel(username)
}
