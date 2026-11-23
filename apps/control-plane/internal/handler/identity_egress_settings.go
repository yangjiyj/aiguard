package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryldap"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity"
)

// identityEgressSettingKeys 是身份源与 LDAP 出站设置键：库里有该键时替换部署环境变量
// JJD_IDP_BLOCK_PRIVATE、JJD_IDP_ALLOW_CIDRS、DIRECTORY_LDAP_TARGET_ALLOWLIST，没有时环境变量作初值。
var identityEgressSettingKeys = []string{identity.SettingBlockPrivate, identity.SettingAllowedCIDRs, directoryldap.LDAPAllowedTargetsSetting}

// normalizeIdentityEgressSettings 校验并规范化写入里的身份源出站键（名单统一存 JSON 数组）。
func normalizeIdentityEgressSettings(settings map[string]string) error {
	if raw, ok := settings[identity.SettingBlockPrivate]; ok {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "true":
			settings[identity.SettingBlockPrivate] = "true"
		case "false":
			settings[identity.SettingBlockPrivate] = "false"
		default:
			return fmt.Errorf("%s must be true or false", identity.SettingBlockPrivate)
		}
	}
	if raw, ok := settings[identity.SettingAllowedCIDRs]; ok {
		list := []string{}
		for _, entry := range identity.ParseAllowedCIDRSetting(raw) {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return fmt.Errorf("%s: invalid CIDR %q", identity.SettingAllowedCIDRs, entry)
			}
			list = append(list, prefix.Masked().String())
		}
		if strings.HasPrefix(strings.TrimSpace(raw), "[") && identity.ParseAllowedCIDRSetting(raw) == nil && strings.TrimSpace(raw) != "[]" {
			return fmt.Errorf("%s must be a JSON string array", identity.SettingAllowedCIDRs)
		}
		encoded, _ := json.Marshal(list)
		settings[identity.SettingAllowedCIDRs] = string(encoded)
	}
	if raw, ok := settings[directoryldap.LDAPAllowedTargetsSetting]; ok {
		targets, err := directoryldap.ParseAllowedTargetsSetting(raw)
		if err != nil {
			return fmt.Errorf("%s: each entry must be host[:port] (no IP literals)", directoryldap.LDAPAllowedTargetsSetting)
		}
		if targets == nil {
			targets = []string{}
		}
		encoded, _ := json.Marshal(targets)
		settings[directoryldap.LDAPAllowedTargetsSetting] = string(encoded)
	}
	return nil
}

// identityEgressLoosened 列出放宽了的身份源出站键：拦私网从开改关（原值缺键不算）、网段或 LDAP 目标新增了项。
func identityEgressLoosened(before, after map[string]string) []string {
	var keys []string
	if raw, ok := after[identity.SettingBlockPrivate]; ok && raw == "false" && before[identity.SettingBlockPrivate] == "true" {
		keys = append(keys, identity.SettingBlockPrivate)
	}
	added := func(key string, parse func(string) []string) {
		raw, ok := after[key]
		if !ok {
			return
		}
		known := map[string]bool{}
		for _, item := range parse(before[key]) {
			known[strings.TrimSpace(item)] = true
		}
		for _, item := range parse(raw) {
			if item = strings.TrimSpace(item); item != "" && !known[item] {
				keys = append(keys, key)
				return
			}
		}
	}
	added(identity.SettingAllowedCIDRs, identity.ParseAllowedCIDRSetting)
	added(directoryldap.LDAPAllowedTargetsSetting, func(raw string) []string {
		list, _ := directoryldap.ParseAllowedTargetsSetting(raw)
		return list
	})
	return keys
}

// identityEgressStrictestValues 是读身份源出站设置失败时的取值：拦私网、不放行任何网段。
// 读失败不能当缺键让环境变量兜底（环境变量可能更宽）。
var identityEgressStrictestValues = map[string]string{
	identity.SettingBlockPrivate: "true",
	identity.SettingAllowedCIDRs: "[]",
}

// IdentityEgressSettingsSource 返回给 identity 包读身份源出站设置的函数：只取存在的键（缺键由环境变量兜底），
// 读失败的键按最严处理。
func IdentityEgressSettingsSource(deps *Dependencies) func() map[string]string {
	return func() map[string]string {
		values := map[string]string{}
		if deps == nil || deps.SystemRepo == nil {
			return values
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, key := range []string{identity.SettingBlockPrivate, identity.SettingAllowedCIDRs} {
			setting, err := deps.SystemRepo.Get(ctx, key)
			if err != nil {
				log.Printf("read %s failed, using strictest value %s: %v", key, identityEgressStrictestValues[key], err)
				values[key] = identityEgressStrictestValues[key]
				continue
			}
			if setting != nil {
				values[key] = setting.Value
			}
		}
		return values
	}
}

// DirectoryTargetPolicyFor 返回当前生效的 LDAP 目标策略：库里有 ldap_allowed_targets 时用它
// 替换部署目标名单（网段名单仍取部署环境变量）；没有该键或值坏时用启动时加载的部署策略；
// 读设置失败时目标名单为空（全部拒绝），不回落到部署名单。
func DirectoryTargetPolicyFor(ctx context.Context, deps *Dependencies) directoryldap.TargetPolicy {
	if deps == nil {
		return directoryldap.TargetPolicy{}
	}
	base := deps.DirectoryTargetPolicy
	if deps.SystemRepo == nil {
		return base
	}
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	setting, err := deps.SystemRepo.Get(readCtx, directoryldap.LDAPAllowedTargetsSetting)
	if err != nil {
		log.Printf("read %s failed, allowing no LDAP targets: %v", directoryldap.LDAPAllowedTargetsSetting, err)
		empty, _ := base.WithAllowedTargets(nil)
		return empty
	}
	if setting == nil {
		return base
	}
	targets, err := directoryldap.ParseAllowedTargetsSetting(setting.Value)
	if err == nil {
		var replaced directoryldap.TargetPolicy
		if replaced, err = base.WithAllowedTargets(targets); err == nil {
			return replaced
		}
	}
	log.Printf("[ERROR] stored %s is invalid, the deployment list applies: %v", directoryldap.LDAPAllowedTargetsSetting, err)
	return base
}

// PlatformTenantID 是平台级事件（平台自身出站被拒等）记账的租户，与语义检测配置同一个平台租户。
const PlatformTenantID = semanticConfigTenant
