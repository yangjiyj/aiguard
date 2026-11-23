package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryldap"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

// 防跳板出站（设计 D5）：放行开关和名单默认全部拒绝；改成放行时除了通用的设置审计，
// 另写一条 egress_override.enable，方便按动作检索“谁放开了出站”。
const egressOverrideEnableAuditAction = "egress_override.enable"

// platformEgressSettingKeys 是写在 system_settings 里的平台级出站设置键。
func platformEgressSettingKeys() []string {
	keys := append([]string(nil), egresspolicy.Keys...)
	return append(keys, identityEgressSettingKeys...)
}

// normalizePlatformEgressSettings 校验并规范化一次写入里出现的出站设置键。
func normalizePlatformEgressSettings(settings map[string]string) error {
	if err := egresspolicy.NormalizeUpdate(settings); err != nil {
		return err
	}
	return normalizeIdentityEgressSettings(settings)
}

// platformEgressSettingsBefore 读出本次写入涉及的出站键在写入前的生效值，用来判断是否放宽：库里有键用
// 库里的值；缺键用环境变量折算出的值（与控制台显示的生效值同一来源）；LDAP 目标名单库里的值坏了时生效
// 的是部署名单，也按它算；读失败按最严（拦私网、名单为空、未登记目标拒绝）。
func platformEgressSettingsBefore(ctx context.Context, deps *Dependencies, settings map[string]string) map[string]string {
	before := map[string]string{}
	if deps == nil || deps.SystemRepo == nil {
		return before
	}
	envValues, _ := platformEgressEnvValues()
	for _, key := range platformEgressSettingKeys() {
		if _, ok := settings[key]; !ok {
			continue
		}
		setting, err := deps.SystemRepo.Get(ctx, key)
		switch {
		case err != nil:
			log.Printf("[WARN] read %s before update failed, judging loosening against the strictest value: %v", key, err)
			before[key] = identityEgressStrictestValues[key]
		case setting == nil, storedLDAPTargetsInvalid(key, setting.Value):
			before[key] = envValues[key]
		default:
			before[key] = setting.Value
		}
	}
	return before
}

// storedLDAPTargetsInvalid：库里的 LDAP 目标名单格式不对（运行时回落部署名单）。
func storedLDAPTargetsInvalid(key, value string) bool {
	if key != directoryldap.LDAPAllowedTargetsSetting {
		return false
	}
	_, err := directoryldap.ParseAllowedTargetsSetting(value)
	return err != nil
}

// auditPlatformEgressLoosening 在出站设置被放宽时写一条 egress_override.enable。
func auditPlatformEgressLoosening(r *http.Request, deps *Dependencies, before, after map[string]string) {
	if keys := egresspolicy.Loosened(before, after); len(keys) > 0 {
		detail := map[string]interface{}{"scope": "forward_proxy", "keys": keys}
		for _, key := range keys {
			detail[key] = after[key]
		}
		logAudit(r, deps, egressOverrideEnableAuditAction, detail, "system", "forward_proxy")
	}
	if keys := identityEgressLoosened(before, after); len(keys) > 0 {
		detail := map[string]interface{}{"scope": "identity", "keys": keys}
		for _, key := range keys {
			detail[key] = after[key]
		}
		logAudit(r, deps, egressOverrideEnableAuditAction, detail, "system", "identity")
	}
}

// addForwardProxyGatewayProjection 把正向代理出站设置放进网关签名投影。开关和名单总是下发
// （缺键为拒绝）；未登记目标与白名单读取失败的处置只在库里有该键时下发，没有时网关用部署
// 环境变量作初值。库里某个键的坏值只丢这个键（按默认拒绝下发），不让整份配置失败。
func addForwardProxyGatewayProjection(out map[string]any, values map[string]string) {
	settings, _ := egresspolicy.FromValues(values)
	out[egresspolicy.KeyAllowPrivate] = settings.AllowPrivate
	out[egresspolicy.KeyAllowLoopback] = settings.AllowLoopback
	out[egresspolicy.KeyAllowMetadata] = settings.AllowMetadata
	cidrs := make([]string, 0, len(settings.AllowedCIDRs))
	for _, prefix := range settings.AllowedCIDRs {
		cidrs = append(cidrs, prefix.String())
	}
	hosts := settings.AllowedHosts
	if hosts == nil {
		hosts = []string{}
	}
	encodedCIDRs, _ := json.Marshal(cidrs)
	encodedHosts, _ := json.Marshal(hosts)
	out[egresspolicy.KeyAllowedCIDRs] = string(encodedCIDRs)
	out[egresspolicy.KeyAllowedHosts] = string(encodedHosts)
	if raw, ok := values[egresspolicy.KeyUnlistedAction]; ok && strings.TrimSpace(raw) != "" {
		out[egresspolicy.KeyUnlistedAction] = egresspolicy.UnlistedAction(values, "")
	}
	if raw, ok := values[egresspolicy.KeyWhitelistFailMode]; ok && strings.TrimSpace(raw) != "" {
		out[egresspolicy.KeyWhitelistFailMode] = egresspolicy.WhitelistFailMode(values, "")
	}
}

// auditEgressOverrideEnable 在对象级出站放行（反向代理路由、MCP 服务）新打开任一项时写一条
// egress_override.enable。关掉不写这一条（通用的对象更新审计里有前后值）。
func auditEgressOverrideEnable(r *http.Request, deps *Dependencies, targetType, targetID string, before, after safetarget.EgressOverrides) {
	enabled := safetarget.NewlyEnabled(before, after)
	if len(enabled) == 0 {
		return
	}
	logAudit(r, deps, egressOverrideEnableAuditAction, map[string]interface{}{
		"scope": targetType, "enabled": enabled, "all_enabled": after.Enabled(),
	}, targetType, targetID)
}

// notifyChannelAllowsPrivateTarget 读通知渠道 config_json 的 allow_private_target（只认布尔 true）。
func notifyChannelAllowsPrivateTarget(config map[string]any) bool {
	value, _ := config["allow_private_target"].(bool)
	return value
}

// auditNotifyChannelPrivateTarget 在通知渠道打开“允许内网地址”时写一条 egress_override.enable。
func auditNotifyChannelPrivateTarget(r *http.Request, deps *Dependencies, channelID string, before, after map[string]any) {
	if !notifyChannelAllowsPrivateTarget(after) || notifyChannelAllowsPrivateTarget(before) {
		return
	}
	logAudit(r, deps, egressOverrideEnableAuditAction, map[string]interface{}{
		"scope": "notify_channel", "enabled": []string{"allow_private_target"},
	}, "notify_channel", channelID)
}

// canLoosenEgress：打开出站放宽（对象的 egress_overrides、通知渠道的 allow_private_target）只允许平台级
// 角色——平台管理员和平台级安全员（D8）。租户级角色可以编辑这些对象的其他字段、保持或关闭这些开关。
func canLoosenEgress(user *repository.User) bool {
	if user == nil {
		return false
	}
	if roles.IsSystemAdmin(user.Role) {
		return true
	}
	return roles.IsSecurityOfficer(user.Role) && isPlatformLevel(user)
}

const egressLooseningForbiddenMessage = "打开出站放宽（允许访问回环、链路本地、元数据、内网等）需要平台管理员或平台级安全员"

// notifyPrivateTargetForbidden：把通知渠道的“允许内网地址”从关改开，且调用者不是平台级角色。
func notifyPrivateTargetForbidden(user *repository.User, before, after map[string]any) bool {
	return notifyChannelAllowsPrivateTarget(after) && !notifyChannelAllowsPrivateTarget(before) && !canLoosenEgress(user)
}

// platformEgressEnvValues 是平台级出站键在库里缺键时的生效值：环境变量折算出的值（没有环境变量时为
// 代码默认），以及来源 env/default。控制台显示的生效值和放宽审计的“改前”都用它。
func platformEgressEnvValues() (values, sources map[string]string) {
	values, sources = map[string]string{}, map[string]string{}
	set := func(key, value, source string) {
		values[key], sources[key] = value, source
	}
	envSource := func(name string) string {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return "env"
		}
		return "default"
	}
	for _, key := range []string{egresspolicy.KeyAllowPrivate, egresspolicy.KeyAllowLoopback, egresspolicy.KeyAllowMetadata} {
		set(key, "false", "default")
	}
	set(egresspolicy.KeyAllowedCIDRs, "[]", "default")
	set(egresspolicy.KeyAllowedHosts, "[]", "default")
	set(egresspolicy.KeyUnlistedAction, egresspolicy.UnlistedAction(nil, os.Getenv("GATEWAY_FORWARD_PROXY_MODE")), envSource("GATEWAY_FORWARD_PROXY_MODE"))
	set(egresspolicy.KeyWhitelistFailMode, egresspolicy.WhitelistFailMode(nil, os.Getenv("PROXY_WHITELIST_FAIL_MODE")), envSource("PROXY_WHITELIST_FAIL_MODE"))
	set(identity.SettingBlockPrivate, strconv.FormatBool(strings.EqualFold(strings.TrimSpace(os.Getenv("JJD_IDP_BLOCK_PRIVATE")), "true")), envSource("JJD_IDP_BLOCK_PRIVATE"))
	cidrs := map[string]string{identity.SettingAllowedCIDRs: os.Getenv("JJD_IDP_ALLOW_CIDRS")}
	if err := normalizeIdentityEgressSettings(cidrs); err != nil {
		cidrs[identity.SettingAllowedCIDRs] = "[]"
	}
	set(identity.SettingAllowedCIDRs, cidrs[identity.SettingAllowedCIDRs], envSource("JJD_IDP_ALLOW_CIDRS"))
	targets := []string{}
	for _, entry := range strings.Split(os.Getenv("DIRECTORY_LDAP_TARGET_ALLOWLIST"), ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			targets = append(targets, entry)
		}
	}
	encodedTargets, _ := json.Marshal(targets)
	ldap := map[string]string{directoryldap.LDAPAllowedTargetsSetting: string(encodedTargets)}
	if err := normalizeIdentityEgressSettings(ldap); err != nil {
		ldap[directoryldap.LDAPAllowedTargetsSetting] = "[]"
	}
	set(directoryldap.LDAPAllowedTargetsSetting, ldap[directoryldap.LDAPAllowedTargetsSetting], envSource("DIRECTORY_LDAP_TARGET_ALLOWLIST"))
	return values, sources
}

// fillPlatformEgressEffectiveValues 让控制台读到实际生效值：本批的平台级出站键在库里没有时，填入环境
// 变量折算出的值（没有环境变量时为代码默认），并在 egress_setting_sources 里标来源 db/env/default。
// LDAP 目标名单库里的值坏了时生效的是部署名单：显示部署名单，来源标 invalid，并记错误日志。
// 语义不变：环境变量只在库里缺键时兜底，这里只是把兜底值显示出来，不写库。
func fillPlatformEgressEffectiveValues(data map[string]any) {
	envValues, envSources := platformEgressEnvValues()
	sources := map[string]string{}
	for _, key := range platformEgressSettingKeys() {
		stored, ok := data[key]
		if !ok {
			data[key], sources[key] = envValues[key], envSources[key]
			continue
		}
		if raw, _ := stored.(string); storedLDAPTargetsInvalid(key, raw) {
			log.Printf("[ERROR] stored %s is invalid, the deployment list applies: %q", key, raw)
			data[key], sources[key] = envValues[key], "invalid"
			continue
		}
		sources[key] = "db"
	}
	data["egress_setting_sources"] = sources
}
