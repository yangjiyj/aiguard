package handler

// 2.9.22 防护项设置：
//
//	GET /admin/v1/protection-settings   管理台查看；能否读取由 RBAC（agent_operation_policy:read）与三员分立（SoDSecurityConfigRead）在中间件里决定
//	PUT /admin/v1/protection-settings   修改 {items:{key:{action,params}}}；中间件按 agent_operation_policy:write 与 SoDSecurityWrite 放行，handler 内再校验 CanManageSecurityPolicy
//
// 租户级设置随 AgentGuard 有效策略的 data.protections 下发给网关。

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// ProtectionSettingsStore 是防护项设置的最小仓库面（真实实现 *repository.ProtectionSettingsRepository）。
type ProtectionSettingsStore interface {
	StoredRows(ctx context.Context, tenantID string) ([]repository.ProtectionSettingRow, error)
	Settings(ctx context.Context, tenantID string) (protection.Settings, error)
	Upsert(ctx context.Context, tenantID, actor string, in map[string]protection.Setting) (map[string]protection.Setting, error)
}

type protectionSettingsUpdate struct {
	Items map[string]protection.Setting `json:"items"`
}

type protectionSettingView struct {
	Key           string              `json:"key"`
	Group         protection.Group    `json:"group"`
	Label         string              `json:"label"`
	Actions       []protection.Action `json:"actions"`
	DefaultAction protection.Action   `json:"default_action"`
	Action        protection.Action   `json:"action"`
	Configured    bool                `json:"configured"`
	Params        map[string]any      `json:"params"`
	ParamSpecs    []protection.Param  `json:"param_specs"`
	UpdatedBy     string              `json:"updated_by"`
	UpdatedAt     *time.Time          `json:"updated_at"`
	// Source 为 legacy 表示没有保存这一项，生效值由旧字段折算（behavior_json 的突发阈值、
	// dlp_json 的密钥外发），网关按它执行；保存后以表里的行为准。
	Source string `json:"source,omitempty"`
}

func buildProtectionSettingViews(rows []repository.ProtectionSettingRow, legacy map[string]protection.Setting) []protectionSettingView {
	stored := make(map[string]repository.ProtectionSettingRow, len(rows))
	for _, row := range rows {
		stored[row.Key] = row
	}
	out := []protectionSettingView{}
	for _, item := range protection.All() {
		if item.Group == protection.GroupAgentRestricted {
			continue // 受限文件在“受限文件”页单独配置
		}
		v := protectionSettingView{
			Key: item.Key, Group: item.Group, Label: item.Label, Actions: item.Actions,
			DefaultAction: item.Default, Action: item.Default, Params: map[string]any{}, ParamSpecs: item.Params,
		}
		if v.ParamSpecs == nil {
			v.ParamSpecs = []protection.Param{}
		}
		if row, ok := stored[item.Key]; ok && item.Allows(protection.Action(row.Action)) {
			v.Action, v.Configured, v.UpdatedBy = protection.Action(row.Action), true, row.UpdatedBy
			if row.Params != nil {
				v.Params = row.Params
			}
			v.UpdatedAt = row.UpdatedAt
		} else if setting, ok := legacy[item.Key]; ok && item.Allows(setting.Action) {
			v.Action, v.Configured, v.Source = setting.Action, true, "legacy"
		}
		out = append(out, v)
	}
	return out
}

func protectionStoreReady(w http.ResponseWriter, deps *Dependencies) bool {
	if deps == nil || deps.ProtectionSettingsStore == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "protection settings not configured")
		return false
	}
	return true
}

// GetProtectionSettings handles GET /admin/v1/protection-settings
func GetProtectionSettings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !protectionStoreReady(w, deps) {
			return
		}
		rows, err := deps.ProtectionSettingsStore.StoredRows(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load protection settings")
			return
		}
		legacy, err := tenantLegacyProtections(r.Context(), deps, user.TenantID, rows)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load protection settings")
			return
		}
		writeJSON(w, map[string]interface{}{"items": buildProtectionSettingViews(rows, legacy)})
	}
}

// UpdateProtectionSettings handles PUT /admin/v1/protection-settings
func UpdateProtectionSettings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only security policy managers can change protection settings")
			return
		}
		if !protectionStoreReady(w, deps) {
			return
		}
		var req protectionSettingsUpdate
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		for key := range req.Items {
			if item, ok := protection.Lookup(strings.TrimSpace(key)); ok && item.Group == protection.GroupAgentRestricted {
				writeError(w, "invalid_request", "protection item "+item.Key+" is configured on the restricted files page")
				return
			}
		}
		items, err := protection.Normalize(req.Items)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		before, err := deps.ProtectionSettingsStore.Upsert(r.Context(), user.TenantID, user.ID, items)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to save protection settings")
			return
		}
		logAudit(r, deps, "protection_settings.update", map[string]interface{}{
			"before": before, "after": items,
		}, "protection_settings", user.TenantID)
		// 端侧内置规则（endpoint.rule.*）的动作写进端侧策略包：立即重建，端侧下次拉取就拿到新动作。
		regenerateEndpointBundle(r.Context(), deps, user.TenantID, user.ID)
		rows, err := deps.ProtectionSettingsStore.StoredRows(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load protection settings")
			return
		}
		legacy, err := tenantLegacyProtections(r.Context(), deps, user.TenantID, rows)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load protection settings")
			return
		}
		writeJSON(w, map[string]interface{}{"items": buildProtectionSettingViews(rows, legacy)})
	}
}

// protectionsForEffectivePolicy 取租户已存的防护项，并把旧 dlp_json 的 high_confidence_secret_egress
// 折算成 agent.secret_egress（仓库无该行时）：block→block，audit/allow→record。
// 仓库读失败返回错误，调用方须 500，避免网关把读失败当成“全默认”。
func protectionsForEffectivePolicy(ctx context.Context, deps *Dependencies, tenantID string, legacyDLP, legacyBehavior map[string]any) (map[string]protection.Setting, error) {
	out := map[string]protection.Setting{}
	// 仓库为 nil 只出现在没有接线仓库的单元测试里；生产启动时 main.go 会在它为 nil 时直接报错。
	if deps.ProtectionSettingsStore != nil {
		settings, err := deps.ProtectionSettingsStore.Settings(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		for k, v := range settings {
			if v.Params == nil {
				v.Params = map[string]any{}
			}
			out[k] = v
		}
	}
	for key, setting := range legacyProtectionFallbacks(out, legacyDLP, legacyBehavior) {
		out[key] = setting
	}
	return out, nil
}

// legacyProtectionFallbacks 是没保存的防护项由旧字段折算出的生效值（下发给网关与 GET 显示共用这一处）：
//   - 旧版 dlp_json 的 high_confidence_secret_egress → agent.secret_egress：block→block，audit/allow→record；
//   - 旧版 behavior_json 里管理员配过的突发阈值（*_burst_10s）→ agent.burst=确认（2.9.21 起它们按
//     “配置的行为结论”执行确认；阈值本身仍从 behavior 下发，窗口 10 秒与该项默认值一致；只配了序列
//     规则窗口的不算）。
func legacyProtectionFallbacks(stored map[string]protection.Setting, legacyDLP, legacyBehavior map[string]any) map[string]protection.Setting {
	out := map[string]protection.Setting{}
	// 密钥外发的防护项键取自注册表（该原因码只登记在一个项下）。
	if item, ok := protection.ItemForReason("high_confidence_secret_egress"); ok {
		if _, saved := stored[item.Key]; !saved {
			if v, ok := legacyDLP["high_confidence_secret_egress"].(string); ok {
				switch v {
				case "block":
					out[item.Key] = protection.Setting{Action: protection.ActionBlock, Params: map[string]any{}}
				case "audit", "allow":
					out[item.Key] = protection.Setting{Action: protection.ActionRecord, Params: map[string]any{}}
				}
			}
		}
	}
	if _, saved := stored[protectionKeyBurst]; !saved && legacyBehaviorConfiguresBurst(legacyBehavior) {
		out[protectionKeyBurst] = protection.Setting{Action: protection.ActionConfirm, Params: map[string]any{}}
	}
	return out
}

// tenantLegacyProtections 取租户范围 AgentGuard 策略的旧字段折算值，供 GET 显示实际生效值。
func tenantLegacyProtections(ctx context.Context, deps *Dependencies, tenantID string, rows []repository.ProtectionSettingRow) (map[string]protection.Setting, error) {
	if deps.AgentGuardPolicyRepo == nil {
		return nil, nil
	}
	policies, err := deps.AgentGuardPolicyRepo.ListPolicies(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	policy := repository.ResolveAgentGuardPolicy(policies, repository.AgentGuardPolicyScope{TenantID: tenantID})
	if policy == nil {
		return nil, nil
	}
	stored := make(map[string]protection.Setting, len(rows))
	for _, row := range rows {
		stored[row.Key] = protection.Setting{Action: protection.Action(row.Action)}
	}
	return legacyProtectionFallbacks(stored, agentGuardDLPFromJSON(policy.DLPJSON), agentGuardBehaviorFromJSON(policy.BehaviorJSON)), nil
}

const protectionKeyBurst = protection.KeyBurst

func legacyBehaviorConfiguresBurst(behavior map[string]any) bool {
	for _, key := range []string{"file_read_burst_10s", "network_egress_burst_10s", "command_execute_burst_10s"} {
		if _, ok := behavior[key]; ok {
			return true
		}
	}
	return false
}
