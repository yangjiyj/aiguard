package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// change_timeline：把升级、配置类审计、模型运维配置、渠道/模型更新按时间合并，用于回答“出问题前改过什么”。

const (
	t4TimelineDefaultH = 24
	t4TimelineMaxH     = 168
	t4TimelineMaxEv    = 100
	t4DetailMax        = 100
)

// ChangeTools 返回变更时间线工具。
func ChangeTools() []Tool { return []Tool{t4ChangeTimeline{}} }

// t4ConfigActionPrefixes 是 audit_operations.action_type 的配置变更类前缀白名单
// （渠道 / 模型 / 路由 / 策略 / 配额 / 授权 / 设置），取自 handler 里 logAudit 的真实写入点。
// 登录、读取类（usage.user.read、evidence.read）、告警、权限拒绝等不在其中。
var t4ConfigActionPrefixes = []string{
	// 渠道
	"create_provider", "update_provider", "delete_provider", "restore_provider", "rotate_provider_credential",
	// 模型与路由（含 update_model_status / update_model_routing / update_model_proxy_config / update_model_operations_config）
	"create_model", "update_model", "delete_model", "batch_delete_models", "sync_models", "sync_verified_models",
	"model.", "model_routing_", "model_catalog_",
	// 策略
	"routing_policy.", "security_policy.", "security_reply_policy.", "policy_center.", "update_builtin_policy_action",
	// 配额与预算
	"quota_policy.", "team.budget.", "team.models.", "user.model_access.",
	// 授权与设置
	"license.", "system_settings.", "settings.",
}

func t4IsConfigAction(a string) bool {
	for _, p := range t4ConfigActionPrefixes {
		if strings.HasPrefix(a, p) {
			return true
		}
	}
	return false
}

func t4ConfigActionPatterns() []string {
	out := make([]string, 0, len(t4ConfigActionPrefixes))
	for _, p := range t4ConfigActionPrefixes {
		out = append(out, strings.NewReplacer(`\`, `\\`, `_`, `\_`, `%`, `\%`).Replace(p)+"%")
	}
	return out
}

type t4ChangeTimeline struct{}

func (t4ChangeTimeline) Name() string { return "change_timeline" }
func (t4ChangeTimeline) Description() string {
	return "按时间顺序列出最近的配置变更，用于判断故障是否由某次变更引起：系统升级（版本从→到）、渠道/模型/路由/策略/配额/授权/设置类审计操作、模型运维配置版本变化、渠道与模型的配置更新。" +
		"每条含 at（RFC3339）、kind、summary。最多 100 条，超出时保留最近的并标注 truncated。" +
		"参数：window_hours（回溯小时数，默认 24，最大 168），around（可选，RFC3339 时间；给出时查看该时刻前后各 window_hours 小时，用于定位“首次出现故障的时间点附近改了什么”）。仅管理员可用。"
}
func (t4ChangeTimeline) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"window_hours":{"type":"integer","description":"回溯小时数，默认 24，最大 168"},"around":{"type":"string","description":"RFC3339 时间，查看该时刻前后各 window_hours 小时"}},"additionalProperties":false}`)
}
func (t4ChangeTimeline) AdminOnly() bool { return true }

type t4Event struct {
	at      time.Time
	kind    string
	summary string
}

func (t4ChangeTimeline) Run(ctx context.Context, q Querier, scope Scope, args json.RawMessage) (json.RawMessage, error) {
	if err := t4Scope(scope); err != nil {
		return nil, err
	}
	var a struct {
		WindowHours int    `json:"window_hours"`
		Around      string `json:"around"`
	}
	if err := t4Parse(args, &a); err != nil {
		return nil, err
	}
	w := a.WindowHours
	if w <= 0 {
		w = t4TimelineDefaultH
	}
	if w > t4TimelineMaxH {
		w = t4TimelineMaxH
	}
	hi := time.Now().UTC()
	lo := hi.Add(-time.Duration(w) * time.Hour)
	if s := strings.TrimSpace(a.Around); s != "" {
		c, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil, errors.New("around 必须是 RFC3339 时间，例如 2026-10-24T10:00:00+08:00")
		}
		lo, hi = c.UTC().Add(-time.Duration(w)*time.Hour), c.UTC().Add(time.Duration(w)*time.Hour)
	}

	var evs []t4Event
	limit := t4TimelineMaxEv + 1 // 多取一条用于判断是否截断

	// 1. 系统升级（全局，不分租户）
	rows, err := q.Query(ctx, `SELECT COALESCE(version_from,'?') AS vf, COALESCE(version_to,'?') AS vt, status, created_at, completed_at
FROM upgrade_history WHERE created_at >= $1 AND created_at <= $2 ORDER BY created_at DESC LIMIT $3`, lo, hi, limit)
	if err != nil {
		return nil, fmt.Errorf("读取升级历史: %w", err)
	}
	for _, r := range rows {
		at, ok := t4Time(r["created_at"])
		if !ok {
			continue
		}
		s := fmt.Sprintf("系统升级 %s → %s（状态 %s）", t4Str(r["vf"]), t4Str(r["vt"]), t4Str(r["status"]))
		if done, ok := t4Time(r["completed_at"]); ok {
			s += "，完成于 " + done.Format(time.RFC3339)
		}
		evs = append(evs, t4Event{at, "upgrade", s})
	}

	// 2. 配置类审计操作。历史写入口不填 tenant_id，靠操作人所属租户归属。
	rows, err = q.Query(ctx, `
SELECT a.action_type, COALESCE(a.target_type,'') AS target_type, COALESCE(a.target_id,'') AS target_id,
       COALESCE(u.username, a.user_id, '') AS actor, COALESCE(left(a.action_detail::text, $5), '') AS detail, a.created_at
FROM audit_operations a
LEFT JOIN users u ON u.id = a.user_id
WHERE a.created_at >= $1 AND a.created_at <= $2
  AND (a.tenant_id = $3 OR (a.tenant_id IS NULL AND u.tenant_id = $3))
  AND a.action_type LIKE ANY($4::text[])
ORDER BY a.created_at DESC LIMIT $6`, lo, hi, scope.TenantID, t4ConfigActionPatterns(), t4DetailMax, limit)
	if err != nil {
		return nil, fmt.Errorf("读取审计操作: %w", err)
	}
	for _, r := range rows {
		at, ok := t4Time(r["created_at"])
		if !ok {
			continue
		}
		s := fmt.Sprintf("配置变更 %s", t4Str(r["action_type"]))
		if tt, id := t4Str(r["target_type"]), t4Str(r["target_id"]); tt != "" || id != "" {
			s += fmt.Sprintf("，对象 %s %s", tt, id)
		}
		if actor := t4Str(r["actor"]); actor != "" {
			s += "，操作人 " + actor
		}
		if d := t4Str(r["detail"]); d != "" && d != "{}" {
			s += "，详情 " + d
		}
		evs = append(evs, t4Event{at, "config_audit", s})
	}

	// 3. 模型运维配置版本（只给版本与操作人，不给配置内容）
	rows, err = q.Query(ctx, `SELECT previous_version, version, actor, cost_confirmed, created_at
FROM model_ops_config_audit WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3 ORDER BY created_at DESC LIMIT $4`, scope.TenantID, lo, hi, limit)
	if err != nil {
		return nil, fmt.Errorf("读取模型运维配置审计: %w", err)
	}
	for _, r := range rows {
		at, ok := t4Time(r["created_at"])
		if !ok {
			continue
		}
		s := fmt.Sprintf("模型运维配置 v%d → v%d，操作人 %s", t4Int(r["previous_version"]), t4Int(r["version"]), t4Str(r["actor"]))
		if t4Bool(r["cost_confirmed"]) {
			s += "（已确认成本）"
		}
		evs = append(evs, t4Event{at, "model_ops_config", s})
	}

	// 4. 渠道与模型的配置更新（updated_at 晚于 created_at 才算更新，排除刚创建的）
	rows, err = q.Query(ctx, `SELECT name, provider_type, status, updated_at FROM providers
WHERE tenant_id = $1 AND updated_at > created_at AND updated_at >= $2 AND updated_at <= $3 ORDER BY updated_at DESC LIMIT $4`, scope.TenantID, lo, hi, limit)
	if err != nil {
		return nil, fmt.Errorf("读取渠道更新: %w", err)
	}
	for _, r := range rows {
		if at, ok := t4Time(r["updated_at"]); ok {
			evs = append(evs, t4Event{at, "provider", fmt.Sprintf("渠道 %s（%s）配置更新，当前状态 %s", t4Str(r["name"]), t4Str(r["provider_type"]), t4Str(r["status"]))})
		}
	}
	rows, err = q.Query(ctx, `SELECT m.model_name, p.name AS provider_name, m.status, m.updated_at
FROM models m JOIN providers p ON p.id = m.provider_id
WHERE p.tenant_id = $1 AND m.updated_at > m.created_at AND m.updated_at >= $2 AND m.updated_at <= $3 ORDER BY m.updated_at DESC LIMIT $4`, scope.TenantID, lo, hi, limit)
	if err != nil {
		return nil, fmt.Errorf("读取模型更新: %w", err)
	}
	for _, r := range rows {
		if at, ok := t4Time(r["updated_at"]); ok {
			evs = append(evs, t4Event{at, "model", fmt.Sprintf("模型 %s（渠道 %s）配置更新，当前状态 %s", t4Str(r["model_name"]), t4Str(r["provider_name"]), t4Str(r["status"]))})
		}
	}

	sort.SliceStable(evs, func(i, j int) bool { return evs[i].at.Before(evs[j].at) })
	truncated := len(evs) > t4TimelineMaxEv
	if truncated {
		evs = evs[len(evs)-t4TimelineMaxEv:]
	}
	out := make([]map[string]any, 0, len(evs))
	for _, e := range evs {
		out = append(out, map[string]any{"at": e.at.Format(time.RFC3339), "kind": e.kind, "summary": e.summary})
	}
	res := map[string]any{"window_hours": w, "from": lo.Format(time.RFC3339), "to": hi.Format(time.RFC3339), "events": out, "truncated": truncated}
	if a.Around != "" {
		res["around"] = a.Around
	}
	return t4Marshal(res)
}
