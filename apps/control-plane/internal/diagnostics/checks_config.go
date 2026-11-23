package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// 配置类检查：直接用 Querier 写 SQL（不依赖 tools_config 的内部实现）。
// 授权状态复用 get_license 工具（同一套 license.EvaluateStored 逻辑）。

func t6CheckLicense(ctx context.Context, _ *t6Env, q Querier, s Scope, _ Input, _ *HostView) (t6Result, error) {
	out, err := t4License{}.Run(ctx, q, s, nil)
	if err != nil {
		return t6Result{}, err
	}
	var st struct {
		Status      string `json:"status"`
		StatusLabel string `json:"status_label"`
		Valid       bool   `json:"valid"`
		ReadOnly    bool   `json:"read_only"`
		DaysLeft    int    `json:"days_left"`
		ExpiresAt   string `json:"expires_at"`
		GraceUntil  string `json:"grace_until"`
		Reason      string `json:"reason"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return t6Result{}, err
	}
	data := json.RawMessage(out)
	link := "/system/license"
	ev := []Evidence{{Kind: "config", Ref: "license", Summary: "授权状态：" + st.StatusLabel, Raw: t6Raw(st.Reason)}}
	switch {
	case st.Status == "expired" || st.ReadOnly || (!st.Valid && st.Status != "trial"):
		title := "平台授权已失效，当前为只读状态"
		if st.Status == "missing" {
			title = "平台尚未导入授权，当前为只读状态"
		}
		return t6Result{Data: data, Findings: []Finding{t6Find("license", SevError, LevelConfirmed, title,
			"所有修改配置的操作都会被拒绝，已有的调用转发不受影响",
			[]Advice{t6Adv(s, "导入新的授权文件", link)}, nil, ev)}}, nil
	case st.Status == "grace":
		return t6Result{Data: data, Findings: []Finding{t6Find("license", SevWarn, LevelConfirmed,
			"平台授权已过期，正处于宽限期",
			"宽限期结束后平台将进入只读状态",
			[]Advice{t6Adv(s, "尽快导入新的授权文件", link)}, nil, ev)}}, nil
	case st.DaysLeft > 0 && st.DaysLeft <= 30:
		return t6Result{Data: data, Findings: []Finding{t6Find("license", SevWarn, LevelConfirmed,
			fmt.Sprintf("平台授权将在 %d 天内到期", st.DaysLeft),
			fmt.Sprintf("剩余 %d 天，到期后平台将进入只读状态", st.DaysLeft),
			[]Advice{t6Adv(s, "提前联系厂商续期并导入新的授权文件", link)}, nil, ev)}}, nil
	}
	return t6Result{Data: data}, nil
}

func t6StrList(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	case []string:
		out = t
	}
	return out
}

// t6PolicyRefsProvider 判断路由策略 rp 是否真正把流量派给渠道 p（SQL 谓词，要求外层有别名 rp、p）。
// 按 routing_policies.config_json 的真实结构取字段，不做字符串近似匹配。结构来源：
//   - schema_version=2（控制面 ModelRoutingRepository.upsert 写入，网关 PolicyCache.GetV2Policy 读取，
//     结构为 packages/shared-go/modelrouting.Config）：providers[].provider_id 且 enabled=true
//     （网关 configuredCandidates 跳过 enabled=false 的条目）；strategy=fixed 时 fixed_provider_id
//     （网关 selectFixedRoute 只认它）。strategy 非 fixed 时遗留的 fixed_provider_id 网关不会使用，不算。
//   - schema_version=3（ExplicitConfig，迁移 116 留的约束）：routes[].provider_id 且 enabled=true。
//   - schema_version=1 且 layer=provider（旧版，网关 ProviderSelector 读取）：fallback 的 provider_chain[]，
//     lb 的 weighted_providers[].id（weight>0，网关跳过 id 为空或 weight<=0 的条目），
//     canary 的 stable_provider / canary_provider。
//
// 其余字段（如 high_keywords、model 层的 default_model 等）里即使出现渠道 ID 的字符串也不算引用。
// jsonb_array_elements 前都用 CASE 判断类型，避免非数组值让整条查询报错。
const t6PolicyRefsProvider = `(rp.tenant_id = p.tenant_id AND rp.enabled AND rp.layer = 'provider' AND (
  (rp.schema_version = 2 AND (
    EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(rp.config_json -> 'providers') = 'array'
                                                    THEN rp.config_json -> 'providers' ELSE '[]'::jsonb END) c
            WHERE c ->> 'provider_id' = p.id AND c -> 'enabled' = 'true'::jsonb)
    OR (rp.config_json ->> 'strategy' = 'fixed' AND rp.config_json ->> 'fixed_provider_id' = p.id)))
  OR (rp.schema_version = 3 AND
    EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(rp.config_json -> 'routes') = 'array'
                                                    THEN rp.config_json -> 'routes' ELSE '[]'::jsonb END) c
            WHERE c ->> 'provider_id' = p.id AND c -> 'enabled' = 'true'::jsonb))
  OR (rp.schema_version = 1 AND (
    (rp.strategy = 'fallback' AND
      EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(rp.config_json -> 'provider_chain') = 'array'
                                                      THEN rp.config_json -> 'provider_chain' ELSE '[]'::jsonb END) c
              WHERE jsonb_typeof(c) = 'string' AND c #>> '{}' = p.id))
    OR (rp.strategy = 'lb' AND
      EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(rp.config_json -> 'weighted_providers') = 'array'
                                                      THEN rp.config_json -> 'weighted_providers' ELSE '[]'::jsonb END) c
              WHERE c ->> 'id' = p.id
                AND CASE WHEN jsonb_typeof(c -> 'weight') = 'number' THEN (c -> 'weight')::numeric > 0 ELSE false END))
    OR (rp.strategy = 'canary' AND (rp.config_json ->> 'stable_provider' = p.id OR rp.config_json ->> 'canary_provider' = p.id))))
))`

func t6CheckProviderDown(ctx context.Context, _ *t6Env, q Querier, s Scope, _ Input, _ *HostView) (t6Result, error) {
	rows, err := q.Query(ctx, `/* t6:provider_down */
SELECT p.id, p.name, p.status,
       COALESCE((SELECT array_agg(m.model_name ORDER BY m.model_name) FROM models m
                 WHERE m.provider_id = p.id AND m.status = 'active'), ARRAY[]::text[]) AS models,
       (SELECT count(*)::bigint FROM routing_policies rp WHERE `+t6PolicyRefsProvider+`) AS policies
FROM providers p
WHERE p.tenant_id = $1 AND p.status <> 'active'
  AND (EXISTS (SELECT 1 FROM models m WHERE m.provider_id = p.id AND m.status = 'active')
       OR EXISTS (SELECT 1 FROM routing_policies rp WHERE `+t6PolicyRefsProvider+`))
ORDER BY p.name LIMIT 20`, s.TenantID)
	if err != nil {
		return t6Result{}, err
	}
	var fs []Finding
	for _, r := range rows {
		name := t6Str(r["name"])
		models := t6StrList(r["models"])
		impact := "路由仍指向该渠道，相关请求会失败或被迫走备用渠道"
		if len(models) > 0 {
			impact = fmt.Sprintf("模型%s仍指向该渠道，相关请求会失败或被迫走备用渠道", t6Quote(models))
		}
		fs = append(fs, t6Find("provider_down", SevError, LevelConfirmed,
			fmt.Sprintf("渠道「%s」已停用，但仍有路由指向它", name), impact,
			[]Advice{t6Adv(s, "启用该渠道，或在模型运维中把路由改到其他渠道", "/model-operations")},
			nil, []Evidence{{Kind: "config", Ref: t6Str(r["id"]), Summary: "渠道状态：" + t6Str(r["status"])}}))
	}
	return t6Result{Findings: fs, Data: map[string]any{"providers": rows}}, nil
}

func t6CheckNoRoute(ctx context.Context, _ *t6Env, q Querier, s Scope, in Input, _ *HostView) (t6Result, error) {
	h := t6Window(in.WindowH)
	// 先只按模型计数（不排序、不取样例），再对排名前 100 的模型用 LATERAL 走 (tenant_id, created_at) 索引各取 3 条样例。
	// 原写法对窗口内全部请求做 array_agg ORDER BY，24 小时窗口约 29 万行要整体排序，实测 0.5–1 秒。
	used, err := q.Query(ctx, `/* t6:no_route_used */
SELECT COALESCE(NULLIF(m.model_label, ''), m.model_name) AS model_label, m.model_name, u.c AS requests, smp.s AS samples
FROM (
  SELECT rl.model_id, count(*)::bigint AS c
  FROM request_logs rl
  WHERE rl.tenant_id = $1 AND rl.created_at >= now() - make_interval(hours => $2)
    AND COALESCE(rl.endpoint_type, '') <> 'proxy'
    AND COALESCE(rl.request_status, '') NOT IN ('received', 'in_progress')
    AND rl.model_id IS NOT NULL
  GROUP BY rl.model_id
  ORDER BY c DESC LIMIT 100
) u JOIN models m ON m.id = u.model_id
CROSS JOIN LATERAL (
  SELECT array_agg(x.request_id ORDER BY x.created_at DESC) AS s FROM (
    SELECT rl2.request_id, rl2.created_at FROM request_logs rl2
    WHERE rl2.tenant_id = $1 AND rl2.model_id = u.model_id AND rl2.created_at >= now() - make_interval(hours => $2)
      AND COALESCE(rl2.endpoint_type, '') <> 'proxy'
      AND COALESCE(rl2.request_status, '') NOT IN ('received', 'in_progress')
    ORDER BY rl2.created_at DESC LIMIT 3
  ) x
) smp
ORDER BY u.c DESC LIMIT 100`, s.TenantID, h)
	if err != nil {
		return t6Result{}, err
	}
	names := []string{}
	for _, r := range used {
		names = append(names, t6Str(r["model_name"]))
	}
	data := map[string]any{"window_hours": h, "used_models": used}
	if len(names) == 0 {
		return t6Result{Data: data}, nil
	}
	okRows, err := q.Query(ctx, `/* t6:no_route_ok */
SELECT DISTINCT m.model_name FROM models m JOIN providers p ON p.id = m.provider_id
WHERE p.tenant_id = $1 AND p.status = 'active' AND m.status = 'active' AND m.model_name = ANY($2::text[])`,
		s.TenantID, names)
	if err != nil {
		return t6Result{}, err
	}
	okSet := map[string]bool{}
	for _, r := range okRows {
		okSet[t6Str(r["model_name"])] = true
	}
	data["usable_models"] = okRows
	var fs []Finding
	seen := map[string]bool{}
	for _, r := range used {
		n := t6Str(r["model_name"])
		if okSet[n] || seen[n] {
			continue
		}
		seen[n] = true
		label := t6Str(r["model_label"])
		if label == "" {
			label = n
		}
		ids := t6Samples(r["samples"])
		fs = append(fs, t6Find("no_route", SevError, LevelConfirmed,
			fmt.Sprintf("模型「%s」没有任何可用渠道", label),
			fmt.Sprintf("近 %d 小时有 %d 条请求使用该模型，但它所在的渠道或模型本身均已停用", h, t6Int(r["requests"])),
			append([]Advice{t6Adv(s, "启用该模型所在渠道，或为它添加可用渠道", "/model-operations?model="+strings.ReplaceAll(n, " ", "%20"))}, t6RecordsAdvice(ids)...),
			nil, t6ReqEvidence(ids, "该模型当前没有可用渠道", "")))
	}
	return t6Result{Findings: fs, Data: data}, nil
}
