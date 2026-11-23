package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
)

// 配置类工具：get_model_routes / get_provider / get_user_access / get_quota_policies / get_license。
// 全部只读；不输出任何凭据（密钥哈希、密文、渠道凭据、base_url 的口令与路径）。

// ConfigTools 返回配置类只读工具。
func ConfigTools() []Tool {
	return []Tool{t4ModelRoutes{}, t4Provider{}, t4UserAccess{}, t4QuotaPolicies{}, t4License{}}
}

// ---------- 公共辅助 ----------

func t4Marshal(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	return json.RawMessage(b), err
}

func t4Scope(scope Scope) error {
	if scope.TenantID == "" {
		return errors.New("缺少租户信息")
	}
	if !scope.IsAdmin && scope.UserID == "" {
		return errors.New("员工身份缺少用户信息")
	}
	return nil
}

func t4Parse(args json.RawMessage, dst any) error {
	if len(strings.TrimSpace(string(args))) == 0 {
		return nil
	}
	if err := json.Unmarshal(args, dst); err != nil {
		return fmt.Errorf("参数不是合法 JSON: %w", err)
	}
	return nil
}

func t4Str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func t4Int(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int32:
		return int64(t)
	case int:
		return int64(t)
	case int16:
		return int64(t)
	case float64:
		return int64(t)
	}
	return 0
}

func t4Bool(v any) bool {
	b, _ := v.(bool)
	return b
}

// t4Time 解析 Exec 返回的时间（RFC3339Nano 字符串）。
func t4Time(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t.UTC(), true
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if tm, err := time.Parse(layout, t); err == nil {
				return tm.UTC(), true
			}
		}
	}
	return time.Time{}, false
}

func t4StrList(v any) []string {
	out := []string{}
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, t...)
	}
	return out
}

func t4Rate(success, total int64) any {
	if total == 0 {
		return nil
	}
	return float64(success*10000/total) / 10000
}

func t4NotFound(what string) (json.RawMessage, error) {
	return t4Marshal(map[string]any{"found": false, "message": "未找到" + what})
}

// t4HostOnly 只保留 host[:port]，丢弃口令、路径与查询串；无法解析时返回空串，绝不回显原文。
func t4HostOnly(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "//" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// ---------- get_model_routes ----------

type t4ModelRoutes struct{}

func (t4ModelRoutes) Name() string { return "get_model_routes" }
func (t4ModelRoutes) Description() string {
	return "查询某个模型名（或模型 ID）的路由配置：每条路由的渠道、模型/渠道状态、upstream_model_id、降级目标、渠道健康快照状态（healthy/degraded/unhealthy/unknown，快照过期按 unknown），" +
		"相关路由策略，以及是否存在可用的备用渠道（usable_routes≥2 才算有备用）。用于判断“模型不可用/频繁失败是否因路由或渠道状态”。参数：model（必填，模型名或模型 ID）。仅管理员可用。"
}
func (t4ModelRoutes) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"model":{"type":"string","description":"模型名或模型 ID"}},"required":["model"],"additionalProperties":false}`)
}
func (t4ModelRoutes) AdminOnly() bool { return true }
func (t4ModelRoutes) Run(ctx context.Context, q Querier, scope Scope, args json.RawMessage) (json.RawMessage, error) {
	if err := t4Scope(scope); err != nil {
		return nil, err
	}
	var a struct {
		Model string `json:"model"`
	}
	if err := t4Parse(args, &a); err != nil {
		return nil, err
	}
	a.Model = strings.TrimSpace(a.Model)
	if a.Model == "" {
		return nil, errors.New("缺少参数 model")
	}
	rows, err := q.Query(ctx, `
SELECT m.id AS model_id, m.model_name, COALESCE(m.upstream_model_id,'') AS upstream_model_id,
       m.status AS model_status, COALESCE(m.downgrade_to,'') AS downgrade_to,
       p.id AS provider_id, p.name AS provider_name, p.status AS provider_status,
       CASE WHEN s.expires_at > now() THEN s.state ELSE 'unknown' END AS health_state,
       (s.state IS NOT NULL AND s.expires_at <= now()) AS snapshot_expired,
       COALESCE(s.failure_category,'') AS failure_category, s.observed_at AS observed_at
FROM models m
JOIN providers p ON p.id = m.provider_id
LEFT JOIN model_route_health_snapshots s
       ON s.tenant_id = p.tenant_id AND s.model_name = m.model_name AND s.provider_id = p.id
WHERE p.tenant_id = $1 AND (m.id = $2 OR m.model_name = $2)
ORDER BY p.name, m.id
LIMIT 50`, scope.TenantID, a.Model)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return t4NotFound("该模型")
	}
	routes := make([]map[string]any, 0, len(rows))
	refs := map[string]bool{a.Model: true}
	var usableProviders []string
	for _, r := range rows {
		refs[t4Str(r["model_id"])] = true
		refs[t4Str(r["model_name"])] = true
		health := t4Str(r["health_state"])
		usable := t4Str(r["provider_status"]) == "active" && t4Str(r["model_status"]) == "active" && health != "unhealthy"
		route := map[string]any{
			"model_id": r["model_id"], "model_name": r["model_name"], "upstream_model_id": r["upstream_model_id"],
			"model_status": r["model_status"], "downgrade_to": r["downgrade_to"],
			"provider_id": r["provider_id"], "provider_name": r["provider_name"], "provider_status": r["provider_status"],
			"health_state": health, "snapshot_expired": r["snapshot_expired"], "failure_category": r["failure_category"],
			"usable": usable,
		}
		if at, ok := t4Time(r["observed_at"]); ok {
			route["observed_at"] = at.Format(time.RFC3339)
		}
		routes = append(routes, route)
		if usable {
			usableProviders = append(usableProviders, t4Str(r["provider_id"]))
		}
	}
	refList := make([]string, 0, len(refs))
	for k := range refs {
		refList = append(refList, k)
	}
	sort.Strings(refList)
	prows, err := q.Query(ctx, `
SELECT id, scope_type, COALESCE(scope_ref,'') AS scope_ref, layer, strategy, enabled, config_json, updated_at
FROM routing_policies
WHERE tenant_id = $1 AND ((scope_type = 'model' AND scope_ref = ANY($2::text[])) OR scope_type = 'tenant')
ORDER BY updated_at DESC NULLS LAST
LIMIT 20`, scope.TenantID, refList)
	if err != nil {
		return nil, err
	}
	policies := make([]map[string]any, 0, len(prows))
	for _, r := range prows {
		p := map[string]any{"id": r["id"], "scope_type": r["scope_type"], "scope_ref": r["scope_ref"], "layer": r["layer"],
			"strategy": r["strategy"], "enabled": r["enabled"], "config": r["config_json"]}
		if at, ok := t4Time(r["updated_at"]); ok {
			p["updated_at"] = at.Format(time.RFC3339)
		}
		policies = append(policies, p)
	}
	standby := []string{}
	if len(usableProviders) >= 2 {
		standby = usableProviders[1:]
	}
	return t4Marshal(map[string]any{
		"found": true, "routes": routes, "routing_policies": policies,
		"usable_routes": len(usableProviders), "has_standby": len(usableProviders) >= 2, "standby_providers": standby,
	})
}

// ---------- get_provider ----------

type t4Provider struct{}

func (t4Provider) Name() string { return "get_provider" }
func (t4Provider) Description() string {
	return "查询渠道（上游供应商）信息：名称、类型、base_url 的 host（口令/路径/查询串一律不返回）、auth_mode、状态、是否配置了有效凭据（只给是否，不给内容）、模型数，" +
		"以及最近 1 小时的请求数、成功率与失败分类分布。凭据绝不输出。参数：provider（必填，渠道 ID 或名称）。仅管理员可用。"
}
func (t4Provider) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"provider":{"type":"string","description":"渠道 ID 或名称"}},"required":["provider"],"additionalProperties":false}`)
}
func (t4Provider) AdminOnly() bool { return true }
func (t4Provider) Run(ctx context.Context, q Querier, scope Scope, args json.RawMessage) (json.RawMessage, error) {
	if err := t4Scope(scope); err != nil {
		return nil, err
	}
	var a struct {
		Provider string `json:"provider"`
	}
	if err := t4Parse(args, &a); err != nil {
		return nil, err
	}
	a.Provider = strings.TrimSpace(a.Provider)
	if a.Provider == "" {
		return nil, errors.New("缺少参数 provider")
	}
	rows, err := q.Query(ctx, `
SELECT p.id, p.name, p.provider_type, COALESCE(p.base_url,'') AS base_url, COALESCE(p.auth_mode,'') AS auth_mode,
       COALESCE(p.is_default,false) AS is_default, p.status, p.updated_at,
       EXISTS (SELECT 1 FROM provider_credentials c WHERE c.provider_id = p.id AND c.status = 'active') AS has_active_credential,
       (SELECT count(*) FROM models m WHERE m.provider_id = p.id AND m.status = 'active')::bigint AS active_models
FROM providers p
WHERE p.tenant_id = $1 AND (p.id = $2 OR p.name = $2)
ORDER BY (p.id = $2) DESC
LIMIT 1`, scope.TenantID, a.Provider)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return t4NotFound("该渠道")
	}
	p := rows[0]
	pid := t4Str(p["id"])
	srows, err := q.Query(ctx, `
SELECT st, cat, code, count(*)::bigint AS n FROM (
  SELECT (`+repository.UsageRequestStatusSQL+`) AS st,
         (`+repository.UsageFailureCategorySQL+`) AS cat,
         COALESCE(rl.upstream_status_code, 0) AS code
  FROM request_logs rl
  WHERE rl.tenant_id = $1 AND rl.provider_id = $2
    AND rl.created_at >= now() - interval '1 hour'
    AND COALESCE(rl.endpoint_type,'') <> 'proxy'
    AND COALESCE(rl.request_status,'') NOT IN ('received','in_progress')
) s GROUP BY st, cat, code`, scope.TenantID, pid)
	if err != nil {
		return nil, err
	}
	var total, success int64
	cats := map[string]int64{}
	codes := map[int64]int64{}
	for _, r := range srows {
		n := t4Int(r["n"])
		total += n
		if t4Str(r["st"]) == "success" {
			success += n
			continue
		}
		if c := t4Str(r["cat"]); c != "" {
			cats[c] += n
		}
		if code := t4Int(r["code"]); code > 0 {
			codes[code] += n
		}
	}
	catList := make([]map[string]any, 0, len(cats))
	for c, n := range cats {
		catList = append(catList, map[string]any{"category": c, "count": n})
	}
	sort.Slice(catList, func(i, j int) bool {
		ci, cj := catList[i]["count"].(int64), catList[j]["count"].(int64)
		if ci != cj {
			return ci > cj
		}
		return catList[i]["category"].(string) < catList[j]["category"].(string)
	})
	codeList := make([]map[string]any, 0, len(codes))
	for c, n := range codes {
		codeList = append(codeList, map[string]any{"status_code": c, "count": n})
	}
	sort.Slice(codeList, func(i, j int) bool {
		ci, cj := codeList[i]["count"].(int64), codeList[j]["count"].(int64)
		if ci != cj {
			return ci > cj
		}
		return codeList[i]["status_code"].(int64) < codeList[j]["status_code"].(int64)
	})
	out := map[string]any{
		"found": true, "id": p["id"], "name": p["name"], "provider_type": p["provider_type"],
		"base_url_host": t4HostOnly(t4Str(p["base_url"])), "auth_mode": p["auth_mode"], "is_default": p["is_default"],
		"status": p["status"], "has_active_credential": p["has_active_credential"], "active_models": p["active_models"],
		"last_hour": map[string]any{"total": total, "success": success, "success_rate": t4Rate(success, total),
			"failure_categories": catList, "failure_status_codes": codeList},
	}
	if at, ok := t4Time(p["updated_at"]); ok {
		out["updated_at"] = at.Format(time.RFC3339)
	}
	return t4Marshal(out)
}

// ---------- get_user_access ----------

// t4UserAccessSQL 与 packages/shared-go/modelaccess.ReadAccess 同口径（部门授权只算
// 供应商与模型都 active 的模型；chat_allowed 的判定逐字一致），但列带名字，便于经 Querier 读取。
// TestT4GetUserAccessMatchesGatewayReadAccess 直接对照网关实现，防止漂移。
const t4UserAccessSQL = `
WITH granted AS (
  SELECT m.id, m.model_name FROM models m JOIN providers p ON p.id = m.provider_id
  WHERE p.tenant_id = $1 AND p.status = 'active' AND m.status = 'active'
)
SELECT u.id AS user_id, u.username AS username, u.role AS role, u.status AS user_status,
  COALESCE(u.department_id,'') AS department_id, COALESCE(t.name,'') AS department_name,
  COALESCE(t.model_access_mode,'') AS department_access_mode, COALESCE(t.system_key,'') AS system_key,
  COALESCE(u.department_assignment_mode,'') AS assignment_mode,
  (u.status = 'active' AND t.id IS NOT NULL AND COALESCE(t.system_key,'') <> 'unassigned'
     AND COALESCE(u.department_assignment_mode,'') NOT IN ('emergency','service')) AS chat_allowed,
  COALESCE(um.mode,'inherit') AS policy_mode, COALESCE(um.model_names,'[]'::jsonb) AS policy_models,
  ARRAY(SELECT DISTINCT i.model_name::text FROM granted i
        LEFT JOIN team_models tm ON tm.team_id = t.id AND tm.model_id = i.id
        WHERE (t.model_access_mode = 'all_active' OR (t.model_access_mode = 'allowlist' AND tm.allowed = TRUE))
        ORDER BY i.model_name::text) AS department_models,
  ARRAY(SELECT DISTINCT i.model_name::text FROM granted i ORDER BY i.model_name::text) AS active_models,
  ARRAY(SELECT DISTINCT m2.model_name::text FROM models m2 JOIN providers p2 ON p2.id = m2.provider_id
        WHERE p2.tenant_id = $1 ORDER BY 1) AS known_models,
  COALESCE((SELECT jsonb_agg(jsonb_build_object('id',g.id,'model',g.model,'reason',g.reason,'expires_at',g.expires_at,
        'created_by',g.created_by,'created_at',g.created_at,'revoked_at',g.revoked_at) ORDER BY g.created_at, g.id)
        FROM user_model_extra_grants g WHERE g.tenant_id = u.tenant_id AND g.user_id = u.id), '[]'::jsonb) AS extra_grants,
  statement_timestamp() AS snapshot_at
FROM users u
LEFT JOIN teams t ON t.id = u.department_id AND t.tenant_id = u.tenant_id
LEFT JOIN user_model_policies um ON um.user_id = u.id AND um.tenant_id = u.tenant_id
WHERE u.tenant_id = $1 AND u.id = $2`

type t4UserAccess struct{}

func (t4UserAccess) Name() string { return "get_user_access" }
func (t4UserAccess) Description() string {
	return "查询用户的模型使用授权，口径与网关放行一致（诊断 forbidden_model 的依据）：账号状态、所属部门、chat_allowed（是否有聊天资格；应急/服务账号、未分配部门、停用账号为 false，网关会直接返回 forbidden_model）、" +
		"个人白名单、额外授权、最终可用模型清单 effective_models 及来源，以及该用户的 API Key 列表（前缀、状态、过期、Key 级模型限制，不含密钥）。" +
		"传 model 时额外给出 model_check：该模型是否放行，被拒时给出原因码（chat_not_allowed / model_unknown / model_inactive / department_not_granted / personal_allowlist_excludes）。" +
		"参数：user（用户 ID 或用户名，管理员必填；员工身份下被忽略，只能查自己），model（可选）。"
}
func (t4UserAccess) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"user":{"type":"string","description":"用户 ID 或用户名（员工身份下被忽略）"},"model":{"type":"string","description":"要核对的模型名"}},"additionalProperties":false}`)
}
func (t4UserAccess) AdminOnly() bool { return false }
func (t4UserAccess) Run(ctx context.Context, q Querier, scope Scope, args json.RawMessage) (json.RawMessage, error) {
	if err := t4Scope(scope); err != nil {
		return nil, err
	}
	var a struct {
		User  string `json:"user"`
		Model string `json:"model"`
	}
	if err := t4Parse(args, &a); err != nil {
		return nil, err
	}
	uid := scope.UserID
	if scope.IsAdmin {
		var ok bool
		var err error
		if uid, ok, err = t4ResolveUser(ctx, q, scope.TenantID, a.User); err != nil {
			return nil, err
		} else if !ok {
			if strings.TrimSpace(a.User) == "" {
				return nil, errors.New("缺少参数 user")
			}
			return t4NotFound("该用户")
		}
	}
	rows, err := q.Query(ctx, t4UserAccessSQL, scope.TenantID, uid)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return t4NotFound("该用户")
	}
	r := rows[0]

	var grants []modelaccess.ExtraGrant
	if err := t4Roundtrip(r["extra_grants"], &grants); err != nil {
		return nil, fmt.Errorf("解析额外授权失败: %w", err)
	}
	var policyModels []string
	if err := t4Roundtrip(r["policy_models"], &policyModels); err != nil {
		return nil, fmt.Errorf("解析个人白名单失败: %w", err)
	}
	policy := modelaccess.Policy{Mode: t4Str(r["policy_mode"]), ModelNames: policyModels}
	deptModels := t4StrList(r["department_models"])
	snapshot, ok := t4Time(r["snapshot_at"])
	if !ok {
		snapshot = time.Now().UTC()
	}
	effective, sources, stale, err := modelaccess.ResolveWithExtras(deptModels, policy, grants, nil, snapshot)
	if err != nil {
		return nil, fmt.Errorf("个人模型策略不合法: %w", err)
	}
	chat := t4Bool(r["chat_allowed"])
	var denied []string
	if !chat {
		effective, sources = []string{}, map[string]string{}
		if s := t4Str(r["user_status"]); s != "active" {
			denied = append(denied, fmt.Sprintf("账号状态为 %s（非 active）", s))
		}
		if t4Str(r["department_id"]) == "" || t4Str(r["department_name"]) == "" {
			denied = append(denied, "账号未归属任何部门")
		}
		if t4Str(r["system_key"]) == "unassigned" {
			denied = append(denied, "账号在“未分配”系统部门")
		}
		if m := t4Str(r["assignment_mode"]); m == "emergency" || m == "service" {
			denied = append(denied, fmt.Sprintf("账号为 %s 类型（应急/服务账号无聊天资格）", m))
		}
	}

	extras := make([]map[string]any, 0, len(grants))
	for _, g := range grants {
		active := g.RevokedAt == nil && (g.ExpiresAt == nil || g.ExpiresAt.After(snapshot))
		e := map[string]any{"model": g.Model, "reason": g.Reason, "active": active}
		if g.ExpiresAt != nil {
			e["expires_at"] = g.ExpiresAt.UTC().Format(time.RFC3339)
		}
		if g.RevokedAt != nil {
			e["revoked_at"] = g.RevokedAt.UTC().Format(time.RFC3339)
		}
		extras = append(extras, e)
	}

	krows, err := q.Query(ctx, `
SELECT id, key_prefix, name, status, expires_at, last_used_at, model_allowlist, model_enforcement,
       (expires_at IS NOT NULL AND expires_at < now()) AS expired,
       (COALESCE(agent_instance_id,'') <> '') AS agent_bound
FROM internal_keys WHERE tenant_id = $1 AND user_id = $2
ORDER BY created_at DESC LIMIT 50`, scope.TenantID, uid)
	if err != nil {
		return nil, err
	}
	keys := make([]map[string]any, 0, len(krows))
	for _, k := range krows {
		km := map[string]any{"key_id": k["id"], "key_prefix": k["key_prefix"], "name": k["name"], "status": k["status"],
			"expired": k["expired"], "model_allowlist": t4StrList(k["model_allowlist"]), "model_enforcement": k["model_enforcement"],
			"agent_bound": k["agent_bound"]}
		if at, ok := t4Time(k["expires_at"]); ok {
			km["expires_at"] = at.Format(time.RFC3339)
		}
		if at, ok := t4Time(k["last_used_at"]); ok {
			km["last_used_at"] = at.Format(time.RFC3339)
		}
		keys = append(keys, km)
	}

	out := map[string]any{
		"found": true, "user_id": r["user_id"], "username": r["username"], "role": r["role"], "status": r["user_status"],
		"department_id": r["department_id"], "department_name": r["department_name"],
		"department_access_mode": r["department_access_mode"], "assignment_mode": r["assignment_mode"],
		"chat_allowed": chat, "chat_denied_reasons": denied,
		"personal_policy":  map[string]any{"mode": policy.Mode, "models": policyModels},
		"extra_grants":     extras,
		"effective_models": effective, "model_sources": sources, "stale_models": stale,
		"keys": keys,
	}
	if m := strings.TrimSpace(a.Model); m != "" {
		out["model_check"] = t4ModelCheck(m, chat, effective, sources, deptModels, t4StrList(r["active_models"]), t4StrList(r["known_models"]), keys)
	}
	return t4Marshal(out)
}

func t4ModelCheck(model string, chat bool, effective []string, sources map[string]string, dept, active, known []string, keys []map[string]any) map[string]any {
	chk := map[string]any{"model": model}
	set := func(allowed bool, code, reason string) map[string]any {
		chk["allowed"], chk["reason_code"], chk["reason"] = allowed, code, reason
		return chk
	}
	has := func(list []string, s string) bool {
		for _, e := range list {
			if e == s {
				return true
			}
		}
		return false
	}
	switch {
	case !chat:
		return set(false, "chat_not_allowed", "账号没有聊天资格，网关对其所有模型返回 forbidden_model")
	case has(effective, model):
		chk["allowed"], chk["source"] = true, sources[model]
		// 与网关 auth.keyModelAdmission 对齐：只有仍可用（启用、未过期）的密钥才会走到白名单判断；
		// 白名单为空表示不限制。
		var blocked []string
		for _, k := range keys {
			al, _ := k["model_allowlist"].([]string)
			if len(al) == 0 || has(al, model) {
				continue
			}
			if t4Str(k["status"]) != "active" || t4Bool(k["expired"]) {
				continue
			}
			if t4Bool(k["agent_bound"]) {
				// 绑定智能体的密钥是否真拦截，取决于网关环境变量 INTEGRATION_KEY_ENFORCEMENT（控制面读不到），不下确定结论。
				continue
			}
			blocked = append(blocked, t4Str(k["key_prefix"]))
		}
		if len(blocked) > 0 {
			chk["key_allowlist_excludes"] = blocked
		}
		return chk
	case !has(known, model):
		return set(false, "model_unknown", "租户内不存在该模型名")
	case !has(active, model):
		return set(false, "model_inactive", "该模型或其渠道已停用，不在可调用范围内")
	case !has(dept, model):
		return set(false, "department_not_granted", "所属部门未授权该模型")
	default:
		return set(false, "personal_allowlist_excludes", "部门已授权，但个人白名单把它排除了")
	}
}

func t4Roundtrip(src, dst any) error {
	b, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

// t4ResolveUser 把用户 ID 或用户名解析成用户 ID（限定租户）。
func t4ResolveUser(ctx context.Context, q Querier, tenantID, ref string) (string, bool, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", false, nil
	}
	rows, err := q.Query(ctx, `SELECT id FROM users WHERE tenant_id = $1 AND (id = $2 OR username = $2) ORDER BY (id = $2) DESC LIMIT 1`, tenantID, ref)
	if err != nil || len(rows) == 0 {
		return "", false, err
	}
	return t4Str(rows[0]["id"]), true, nil
}

// ---------- get_quota_policies ----------

const t4PolicyCols = `
  qp.id, qp.scope_type, COALESCE(qp.scope_ref,'') AS scope_ref, COALESCE(qp.user_id,'') AS user_id,
  COALESCE(qp.key_id,'') AS key_id, COALESCE(qp.project_id,'') AS project_id,
  COALESCE(qp.daily_token_limit_canonical, GREATEST(COALESCE(qp.daily_token_limit,0),0)) AS daily_token_limit, qp.daily_token_blocked,
  COALESCE(qp.monthly_token_limit_canonical, GREATEST(COALESCE(qp.monthly_token_limit,0),0)) AS monthly_token_limit, qp.monthly_token_blocked,
  COALESCE(qp.rpm_limit_canonical, GREATEST(COALESCE(qp.rpm_limit,0),0)) AS rpm_limit, qp.rpm_blocked,
  COALESCE(qp.tpm_limit,0) AS tpm_limit, qp.tpm_blocked,
  COALESCE(qp.concurrency_limit_canonical, GREATEST(COALESCE(qp.concurrency_limit,0),0)) AS concurrency_limit, qp.concurrency_blocked,
  COALESCE(qp.daily_budget_micros, CASE WHEN COALESCE(qp.daily_budget_limit,0) > 0 THEN ROUND(qp.daily_budget_limit * 1000000)::bigint ELSE 0 END) AS daily_budget_micros, qp.daily_budget_blocked,
  COALESCE(qp.monthly_budget_micros, CASE WHEN COALESCE(qp.monthly_budget_limit,0) > 0 THEN ROUND(qp.monthly_budget_limit * 1000000)::bigint ELSE 0 END) AS monthly_budget_micros, qp.monthly_budget_blocked,
  COALESCE(qp.overage_action,'notify') AS overage_action, COALESCE(qp.enforcement_mode,'soft') AS enforcement_mode,
  COALESCE(qp.quota_timezone,'Asia/Shanghai') AS quota_timezone`

const t4DefaultTZ = "Asia/Shanghai"

type t4QuotaPolicies struct{}

func (t4QuotaPolicies) Name() string { return "get_quota_policies" }
func (t4QuotaPolicies) Description() string {
	return "查询命中某用户的生效配额策略及当前用量：用户级、API Key 级、部门级、项目级、租户级策略的日/月 token 上限、RPM/TPM、并发、日/月预算（micros，1 元=1000000）、" +
		"*_blocked=true 表示该维度被直接封禁、超限动作 overage_action、强制模式，以及该用户今日/本月已用 token 与各 Key 今日用量（按策略时区）。" +
		"参数：user（用户 ID 或用户名，管理员可选；员工身份下被忽略，只能查自己），key（Key ID 或前缀，可选，用于缩小到某个 Key）。管理员两者都不传时列出租户内全部生效策略。"
}
func (t4QuotaPolicies) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"user":{"type":"string","description":"用户 ID 或用户名（员工身份下被忽略）"},"key":{"type":"string","description":"API Key ID 或前缀"}},"additionalProperties":false}`)
}
func (t4QuotaPolicies) AdminOnly() bool { return false }
func (t4QuotaPolicies) Run(ctx context.Context, q Querier, scope Scope, args json.RawMessage) (json.RawMessage, error) {
	if err := t4Scope(scope); err != nil {
		return nil, err
	}
	var a struct {
		User string `json:"user"`
		Key  string `json:"key"`
	}
	if err := t4Parse(args, &a); err != nil {
		return nil, err
	}
	a.Key = strings.TrimSpace(a.Key)

	// 解析目标 Key 与目标用户。
	var keyRow map[string]any
	if a.Key != "" {
		sql := `SELECT id, key_prefix, COALESCE(user_id,'') AS user_id FROM internal_keys WHERE tenant_id = $1 AND (id = $2 OR key_prefix = $2)`
		qargs := []any{scope.TenantID, a.Key}
		if !scope.IsAdmin {
			sql += ` AND user_id = $3`
			qargs = append(qargs, scope.UserID)
		}
		rows, err := q.Query(ctx, sql+` ORDER BY created_at DESC LIMIT 1`, qargs...)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return t4NotFound("该 API Key")
		}
		keyRow = rows[0]
	}
	uid := scope.UserID
	if scope.IsAdmin {
		uid = ""
		if strings.TrimSpace(a.User) != "" {
			id, ok, err := t4ResolveUser(ctx, q, scope.TenantID, a.User)
			if err != nil {
				return nil, err
			}
			if !ok {
				return t4NotFound("该用户")
			}
			uid = id
		} else if keyRow != nil {
			uid = t4Str(keyRow["user_id"])
		}
		if uid == "" && keyRow == nil {
			// 管理员未指定对象：列出租户内全部生效策略。
			rows, err := q.Query(ctx, `SELECT `+t4PolicyCols+` FROM quota_policies qp WHERE qp.tenant_id = $1 AND qp.status = 'active' ORDER BY qp.created_at LIMIT 100`, scope.TenantID)
			if err != nil {
				return nil, err
			}
			return t4Marshal(map[string]any{"found": true, "scope": "tenant", "policies": rows})
		}
	}

	// 用户的部门、Key、项目。
	var dept string
	if uid != "" {
		urows, err := q.Query(ctx, `SELECT COALESCE(department_id,'') AS dept FROM users WHERE tenant_id = $1 AND id = $2`, scope.TenantID, uid)
		if err != nil {
			return nil, err
		}
		if len(urows) == 0 {
			return t4NotFound("该用户")
		}
		dept = t4Str(urows[0]["dept"])
	}
	keyIDs, projectIDs := []string{}, []string{}
	prefixByID := map[string]string{}
	if keyRow != nil {
		keyIDs = append(keyIDs, t4Str(keyRow["id"]))
		prefixByID[t4Str(keyRow["id"])] = t4Str(keyRow["key_prefix"])
	} else if uid != "" {
		krows, err := q.Query(ctx, `SELECT id, key_prefix, project_id FROM internal_keys WHERE tenant_id = $1 AND user_id = $2 ORDER BY created_at DESC LIMIT 100`, scope.TenantID, uid)
		if err != nil {
			return nil, err
		}
		for _, k := range krows {
			keyIDs = append(keyIDs, t4Str(k["id"]))
			prefixByID[t4Str(k["id"])] = t4Str(k["key_prefix"])
		}
	}
	if len(keyIDs) > 0 {
		prows, err := q.Query(ctx, `SELECT DISTINCT project_id FROM internal_keys WHERE tenant_id = $1 AND id = ANY($2::text[])`, scope.TenantID, keyIDs)
		if err != nil {
			return nil, err
		}
		for _, r := range prows {
			projectIDs = append(projectIDs, t4Str(r["project_id"]))
		}
	}

	policies, err := q.Query(ctx, `SELECT `+t4PolicyCols+`
FROM quota_policies qp
WHERE qp.tenant_id = $1 AND qp.status = 'active' AND (
     (qp.scope_type = 'user' AND qp.user_id = $2)
  OR (qp.scope_type = 'key' AND qp.key_id = ANY($3::text[]))
  OR (qp.scope_type = 'team' AND $4 <> '' AND qp.scope_ref = $4)
  OR (qp.scope_type = 'project' AND qp.project_id = ANY($5::text[]))
  OR qp.scope_type = 'tenant')
ORDER BY qp.created_at LIMIT 100`, scope.TenantID, uid, keyIDs, dept, projectIDs)
	if err != nil {
		return nil, err
	}
	tz := t4DefaultTZ
	for _, p := range policies {
		if z := t4Str(p["quota_timezone"]); z != "" && (p["scope_type"] == "user" || p["scope_type"] == "key") {
			tz = z
			break
		}
	}
	out := map[string]any{"found": true, "user_id": uid, "department_id": dept, "policies": policies, "timezone": tz}
	if keyRow != nil {
		out["key_id"], out["key_prefix"] = keyRow["id"], keyRow["key_prefix"]
	}
	if uid != "" {
		usage, kusage, err := t4Usage(ctx, q, scope.TenantID, uid, keyIDs, prefixByID, tz)
		if err != nil && tz != t4DefaultTZ { // 策略里的时区名无效时退回默认
			out["timezone"] = t4DefaultTZ
			usage, kusage, err = t4Usage(ctx, q, scope.TenantID, uid, keyIDs, prefixByID, t4DefaultTZ)
		}
		if err != nil {
			return nil, err
		}
		out["usage"], out["key_usage"] = usage, kusage
	}
	return t4Marshal(out)
}

const t4DayStart = `(date_trunc('day', now() AT TIME ZONE $%d::text) AT TIME ZONE $%d::text)`
const t4MonthStart = `(date_trunc('month', now() AT TIME ZONE $%d::text) AT TIME ZONE $%d::text)`

func t4Usage(ctx context.Context, q Querier, tenantID, uid string, keyIDs []string, prefixByID map[string]string, tz string) (map[string]any, []map[string]any, error) {
	day, month := fmt.Sprintf(t4DayStart, 3, 3), fmt.Sprintf(t4MonthStart, 3, 3)
	rows, err := q.Query(ctx, `
SELECT COALESCE(SUM(COALESCE(rl.input_tokens,0) + COALESCE(rl.output_tokens,0)) FILTER (WHERE rl.created_at >= `+day+`), 0)::bigint AS day_tokens,
       COALESCE(SUM(COALESCE(rl.input_tokens,0) + COALESCE(rl.output_tokens,0)), 0)::bigint AS month_tokens,
       (count(*) FILTER (WHERE rl.created_at >= `+day+`))::bigint AS day_requests
FROM request_logs rl
WHERE rl.tenant_id = $1 AND rl.user_id = $2 AND rl.created_at >= `+month, tenantID, uid, tz)
	if err != nil {
		return nil, nil, err
	}
	usage := map[string]any{"day_tokens": int64(0), "month_tokens": int64(0), "day_requests": int64(0)}
	if len(rows) == 1 {
		usage["day_tokens"], usage["month_tokens"], usage["day_requests"] = t4Int(rows[0]["day_tokens"]), t4Int(rows[0]["month_tokens"]), t4Int(rows[0]["day_requests"])
	}
	kusage := []map[string]any{}
	if len(keyIDs) > 0 {
		krows, err := q.Query(ctx, `
SELECT rl.client_id AS key_id, COALESCE(SUM(COALESCE(rl.input_tokens,0) + COALESCE(rl.output_tokens,0)), 0)::bigint AS day_tokens, count(*)::bigint AS day_requests
FROM request_logs rl
WHERE rl.tenant_id = $1 AND rl.client_id = ANY($2::text[]) AND rl.created_at >= `+day+`
GROUP BY rl.client_id ORDER BY 2 DESC`, tenantID, keyIDs, tz)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range krows {
			id := t4Str(r["key_id"])
			kusage = append(kusage, map[string]any{"key_id": id, "key_prefix": prefixByID[id], "day_tokens": t4Int(r["day_tokens"]), "day_requests": t4Int(r["day_requests"])})
		}
	}
	return usage, kusage, nil
}

// ---------- get_license ----------

type t4License struct{}

func (t4License) Name() string { return "get_license" }
func (t4License) Description() string {
	return "查询平台授权状态：有效 / 试用 / 已过期但宽限期内 / 已过期（只读）/ 无效 等，到期日与剩余天数。授权过期后平台进入只读，所有修改配置的操作会失败（HTTP 402 license_required）。无参数。" +
		"员工身份只返回状态和到期日；管理员额外得到失败原因、宽限截止、授权编号、部署绑定与吊销情况。"
}
func (t4License) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)
}
func (t4License) AdminOnly() bool { return false }

var t4LicenseLabels = map[string]string{
	license.StatusActive: "有效", license.StatusTrial: "试用中", license.StatusGrace: "已过期，宽限期内（功能仍可用）",
	license.StatusExpired: "已过期（平台只读）", license.StatusPending: "尚未生效", license.StatusInvalid: "无效",
	license.StatusMissing: "未导入授权", license.StatusClockRollback: "检测到系统时钟回拨",
}

func (t4License) Run(ctx context.Context, q Querier, scope Scope, _ json.RawMessage) (json.RawMessage, error) {
	if err := t4Scope(scope); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT key, value FROM system_settings WHERE key = ANY($1::text[])`,
		[]string{license.SettingKeyLicense, license.SettingKeyImportedAt, license.SettingKeyTimeState, license.SettingKeyDeploymentID, license.SettingKeyInstallAnchor})
	if err != nil {
		return nil, err
	}
	set := map[string]string{}
	for _, r := range rows {
		set[t4Str(r["key"])] = t4Str(r["value"])
	}
	now := time.Now().UTC()
	// 与 handler.licenseStatusFromStored 共用 license.EvaluateStored / BaseVerificationOptions；
	// 这里只读：不会像接口那样顺带写入时间状态或生成部署 ID。
	opts := license.BaseVerificationOptions(now)
	if dep := strings.TrimSpace(set[license.SettingKeyDeploymentID]); dep != "" {
		opts.DeploymentFingerprints = append(opts.DeploymentFingerprints, license.Fingerprint{
			Scope: "deployment", Algorithm: "sha256", Value: license.DeploymentFingerprint(dep)})
	}
	opts.TimeState = license.ParseTimeState(set[license.SettingKeyTimeState])
	st := license.EvaluateStored(set[license.SettingKeyLicense], set[license.SettingKeyImportedAt], set[license.SettingKeyInstallAnchor], opts, now)

	var expires string
	switch {
	case st.PayloadV2 != nil:
		expires = st.PayloadV2.ExpiresAt
	case st.Payload != nil && !st.Payload.ExpiresAt.IsZero():
		expires = st.Payload.ExpiresAt.UTC().Format(time.RFC3339)
	case st.Status == license.StatusTrial || (st.Status == license.StatusExpired && strings.TrimSpace(set[license.SettingKeyLicense]) == ""):
		if anchor, err := time.Parse(time.RFC3339, strings.TrimSpace(set[license.SettingKeyInstallAnchor])); err == nil {
			expires = anchor.AddDate(0, 0, license.TrialWindowDays).UTC().Format(time.RFC3339)
		}
	}
	label := t4LicenseLabels[st.Status]
	if label == "" {
		label = st.Status
	}
	out := map[string]any{"status": st.Status, "status_label": label, "valid": st.Valid, "read_only": !st.Valid, "days_left": st.DaysLeft}
	if expires != "" {
		out["expires_at"] = expires
	}
	if !scope.IsAdmin {
		return t4Marshal(out)
	}
	if st.Reason != "" {
		out["reason"] = st.Reason
	}
	if st.Grace != nil {
		out["grace_until"], out["grace_days_left"] = st.Grace.Until, st.Grace.Days
	}
	if st.PayloadV2 != nil {
		out["license_id"] = st.PayloadV2.LicenseID
	} else if st.Payload != nil {
		out["license_id"] = st.Payload.LicenseID
	}
	if st.Binding != nil {
		out["binding_mode"], out["binding_matched"] = st.Binding.Mode, st.Binding.Matched
	}
	if st.Clock != nil && st.Clock.RollbackDetected {
		out["clock_rollback_detected"] = true
	}
	if st.Revocation != nil && st.Revocation.Revoked {
		out["revoked"] = true
	}
	return t4Marshal(out)
}
