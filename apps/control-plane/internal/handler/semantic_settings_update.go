package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"context"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

// 语义检测配置属于安全策略（docs/design/ws4-rbac-matrix.md：security_write），安全员应能保存；
// 但 PUT /system/settings 归 SoDSystem（含登录策略、管理员 IP 白名单、出口代理、许可证等系统键），不能为此放开。
// 所以语义检测控制台走这个专用入口：复用 /system/settings 的全部校验与密钥加密、审计脱敏，
// 只是把可写的键收窄到下面的白名单，白名单外的键一律 400（不是静默丢弃）。
//
// 研判服务（judge）决定「受检内容被发到哪里」，是出口控制，不是普通的检测开关：
//   - judge_url、judge_backend=custom、judge_api_key 一律只允许系统管理员修改——安全员能改的话，等于能把受检内容外发到任意地址；
//   - 安全员只能在 judge_backend=bundled（随包内置）与 judge_backend=provider（系统管理员已登记的 provider_id）之间切换。
//
// 配置存放在全局 system_settings，是全平台共享、不分租户的：任何一个租户的人改了，所有租户的检测都跟着变。
// 所以租户级安全员不能改，只有平台级（平台默认租户 semanticConfigTenant，provider 解析用的同一个租户）的安全员与平台管理员可以。
var semanticSettingsWritableKeys = map[string]bool{
	// 语义检测开关与预算
	"semantic_enabled": true, "semantic_input_enabled": true, "semantic_agent_enabled": true,
	"semantic_output_enabled": true, "semantic_total_timeout": true, "semantic_sample_rate": true,
	// 策略「智能分析命中时」选拦截后，裁判置信度达到该阈值才真拦截。
	semanticBlockMinConfidenceKey: true,
	// 检测范围与误报抑制
	"inspect_user_input": true, "inspect_model_output": true, "inspect_tool_results": true,
	"inspect_builtin_context": true, "inspect_history": true, "fp_suppression_enabled": true,
	// 研判模型
	"judge_backend": true, "judge_provider_id": true, "judge_url": true, "judge_model": true,
	"judge_api_key": true, "judge_allow_private_egress": true,
	// 故障处理与检测执行（2.9.22，键名见 packages/shared-go/runtimeoptions）
	"security_capacity_fail_mode": true, "mcp_policy_fail_mode": true, "retention_failure_mode": true,
	"output_security_mode": true, "output_strict_max_bytes": true, "upload_inspection_failure_action": true,
	"semantic_block_stages": true, "agent_security_monitor_disposition": true, "model_output_classified_disposition": true,
	guardrailFailClosedSettingKey: true, "confidence_gating_enabled": true, "confidence_threshold": true,
}

// semanticVersionGuardKeys 是并发控制的版本依据：这些键里任何一个被改过，版本就变。
// 取全部可写键，保证「A 改开关、B 改模型」这种不同键的并发写也能被发现并要求重新读取。
func semanticVersionGuardKeys() []string {
	keys := make([]string, 0, len(semanticSettingsWritableKeys))
	for k := range semanticSettingsWritableKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// semanticVersionOf 把各键的 updated_at 折成一个短摘要，作为 ETag 式的版本号。键不存在不参与（与「从未设置过」等价）。
func semanticVersionOf(updated map[string]time.Time) string {
	keys := make([]string, 0, len(updated))
	for k := range updated {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(updated[k].UTC().Format(time.RFC3339Nano)))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// semanticConfigVersion 读取当前语义配置的版本号。
func semanticConfigVersion(ctx context.Context, deps *Dependencies) (string, error) {
	repo, ok := deps.SystemRepo.(versionedSettingsRepo)
	if !ok {
		return "", nil
	}
	updated, err := repo.GetUpdatedAt(ctx, semanticVersionGuardKeys())
	if err != nil {
		return "", err
	}
	return semanticVersionOf(updated), nil
}

// isPlatformLevel 判断调用者是否属于平台级：与语义配置共用的 provider 解析租户（平台默认租户）。
func isPlatformLevel(user *repository.User) bool {
	return user != nil && (user.TenantID == semanticConfigTenant || user.TenantID == repository.SystemTenantID)
}

// UpdateSemanticSettings PUT /admin/v1/security/semantic/settings。
func UpdateSemanticSettings(deps *Dependencies) http.HandlerFunc {
	return updateSemanticSettingsWithNetwork(deps, defaultSemanticJudgeNetwork())
}

const judgeAdminOnlyMessage = "研判服务地址与密钥由系统管理员配置；安全员只能在内置研判与系统管理员已登记的研判服务之间切换"

func updateSemanticSettingsWithNetwork(deps *Dependencies, network semanticJudgeNetwork) http.HandlerFunc {
	return updateSettingsWithScope(deps, network, systemSettingsScope{
		authorize:           func(user *repository.User) bool { return roles.CanManageSecurityPolicy(user.Role) },
		allowedKeys:         semanticSettingsWritableKeys,
		auditAction:         "update_semantic_settings",
		stripBeforeValidate: []string{"expected_version"},
		auditKeys:           append([]string{"judge_backend", "judge_provider_id", "judge_url", "judge_model", "judge_api_key", "semantic_enabled", "semantic_input_enabled", "semantic_agent_enabled", "judge_allow_private_egress", semanticBlockMinConfidenceKey}, runtimeSecurityWritableKeys...),
		preflight: func(r *http.Request, deps *Dependencies, user *repository.User, raw map[string]interface{}) (string, int, string, string) {
			// 全局配置：租户级安全员不能改。
			if !roles.IsSystemAdmin(user.Role) && !isPlatformLevel(user) {
				return "", http.StatusForbidden, "global_config_requires_platform_level",
					"语义检测配置是全平台共享的，租户级账号不能修改；请使用平台级安全员或系统管理员账号"
			}
			// 越权类拒绝先于版本校验：没有权限的人不应该被引导去「重新读取后再试」。
			if code, msg := semanticEndpointGuard(user, raw); code != "" {
				return "", http.StatusForbidden, code, msg
			}
			// 并发控制：必须带回读取时拿到的版本号。
			expected, _ := raw["expected_version"].(string)
			if strings.TrimSpace(expected) == "" {
				return "", http.StatusBadRequest, "invalid_request", "缺少 expected_version：请先读取当前配置，保存时带回它的 config_version"
			}
			// 安全员选 provider 模式时，provider_id 必须是系统管理员在平台租户下已登记的服务（与运行时解析同一个租户）。
			if !roles.IsSystemAdmin(user.Role) {
				if b, _ := raw["judge_backend"].(string); strings.TrimSpace(b) == "provider" {
					id, _ := raw["judge_provider_id"].(string)
					id = strings.TrimSpace(id)
					registered := false
					if id != "" && deps != nil && deps.ProviderRepo != nil {
						if p, err := deps.ProviderRepo.GetByID(r.Context(), semanticConfigTenant, id); err == nil && p != nil {
							registered = true
						}
					}
					if !registered {
						return "", http.StatusBadRequest, "judge_provider_not_registered",
							"所选研判服务未登记：请从系统管理员已登记的研判服务中选择"
					}
				}
			}
			return strings.TrimSpace(expected), 0, "", ""
		},
		beforeWrite: semanticEndpointGuard,
		commit: func(r *http.Request, deps *Dependencies, expected string, settings map[string]string) (int, string, string) {
			repo, ok := deps.SystemRepo.(versionedSettingsRepo)
			if !ok {
				return http.StatusInternalServerError, "internal_error", "配置存储不支持版本控制"
			}
			err := repo.SetMultipleIfVersion(r.Context(), semanticVersionGuardKeys(), expected, semanticVersionOf, settings)
			switch {
			case err == nil:
				return 0, "", ""
			case errors.Is(err, repository.ErrSystemSettingsVersionConflict):
				return http.StatusConflict, "version_conflict", "配置已被其他人修改，请刷新页面重新读取后再保存"
			default:
				return http.StatusInternalServerError, "internal_error", "failed to update settings"
			}
		},
		auditDetail: func(before, after map[string]string, detail map[string]interface{}) {
			changes := map[string]interface{}{}
			// judge_url / judge_backend / judge_provider_id 等记变更前后的值；judge_api_key 只记「已变更/未变更」。
			for _, k := range []string{"judge_backend", "judge_provider_id", "judge_url", "judge_model", "semantic_enabled", "semantic_input_enabled", "semantic_agent_enabled", "judge_allow_private_egress", semanticBlockMinConfidenceKey} {
				if newVal, touched := after[k]; touched {
					changes[k] = map[string]interface{}{"before": before[k], "after": newVal}
				}
			}
			delete(detail, "judge_api_key")
			if _, touched := after["judge_api_key"]; touched {
				detail["judge_api_key"] = "changed"
			} else {
				detail["judge_api_key"] = "unchanged"
			}
			detail["changes"] = changes
		},
	})
}

// semanticEndpointGuard 是安全员的出口闸门：judge_url、judge_api_key、judge_backend=custom 一律拒绝；
// 「允许研判走内网地址」只能由系统管理员打开。系统管理员不受限制。
func semanticEndpointGuard(user *repository.User, raw map[string]interface{}) (string, string) {
	if roles.IsSystemAdmin(user.Role) {
		return "", ""
	}
	for _, k := range []string{"judge_url", "judge_api_key"} {
		if _, ok := raw[k]; ok {
			return "judge_endpoint_admin_only", judgeAdminOnlyMessage
		}
	}
	if v, ok := raw["judge_backend"].(string); ok {
		switch strings.TrimSpace(v) {
		case "bundled", "provider":
		default:
			return "judge_endpoint_admin_only", judgeAdminOnlyMessage
		}
	}
	if v, ok := raw["judge_allow_private_egress"]; ok && settingValueTrue(v) {
		return "private_egress_requires_system_admin", "只有系统管理员可以允许研判服务访问内网地址"
	}
	return "", ""
}

func settingValueTrue(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(strings.TrimSpace(x), "true")
	}
	return false
}

// GetSemanticSettings GET /admin/v1/security/semantic/settings：返回语义检测配置与 config_version。
// 密钥只显示占位，绝不回传明文或密文。
func GetSemanticSettings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		all, err := deps.SystemRepo.GetAll(r.Context())
		if err != nil {
			writeError(w, "internal_error", "failed to get settings")
			return
		}
		out := map[string]any{}
		for _, st := range all {
			if semanticSettingsWritableKeys[st.Key] {
				out[st.Key] = st.Value
			}
		}
		if v, ok := out["judge_api_key"].(string); ok && strings.TrimSpace(v) != "" {
			out["judge_api_key"] = maskedSecretValue
		}
		version, err := semanticConfigVersion(r.Context(), deps)
		if err != nil {
			writeError(w, "internal_error", "failed to read settings version")
			return
		}
		out["config_version"] = version
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"`+version+`"`)
		_ = json.NewEncoder(w).Encode(out)
	}
}
