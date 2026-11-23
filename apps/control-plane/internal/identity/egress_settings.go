package identity

import (
	"encoding/json"
	"strings"
	"sync"
)

// 身份源出站设置（system_settings）。库里有该键时用库里的；没有时才用部署环境变量
// JJD_IDP_BLOCK_PRIVATE、JJD_IDP_ALLOW_CIDRS 作初值，升级后行为不变。
const (
	SettingBlockPrivate = "idp_block_private"
	SettingAllowedCIDRs = "idp_allowed_cidrs"
)

var (
	egressSettingsMu     sync.RWMutex
	egressSettingsSource func() map[string]string
)

// SetEgressSettingsSource 注入读取 system_settings 的函数（控制面启动时装配）；nil 表示只用环境变量。
func SetEgressSettingsSource(source func() map[string]string) {
	egressSettingsMu.Lock()
	defer egressSettingsMu.Unlock()
	egressSettingsSource = source
}

func currentEgressSettings() map[string]string {
	egressSettingsMu.RLock()
	source := egressSettingsSource
	egressSettingsMu.RUnlock()
	if source == nil {
		return nil
	}
	return source()
}

// ParseAllowedCIDRSetting 把 idp_allowed_cidrs 的值（JSON 字符串数组，兼容逗号分隔）拆成条目。
func ParseAllowedCIDRSetting(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var list []string
	if strings.HasPrefix(raw, "[") {
		if err := json.Unmarshal([]byte(raw), &list); err == nil {
			return list
		}
		return nil
	}
	return strings.Split(raw, ",")
}

// egressBlockPrivate 与 egressAllowedCIDRs 返回生效值：库里有键用库里的，否则用环境变量。
func egressBlockPrivate(envValue string) bool {
	if raw, ok := currentEgressSettings()[SettingBlockPrivate]; ok {
		return strings.EqualFold(strings.TrimSpace(raw), "true")
	}
	return strings.EqualFold(strings.TrimSpace(envValue), "true")
}

func egressAllowedCIDRs(envValue string) []string {
	if raw, ok := currentEgressSettings()[SettingAllowedCIDRs]; ok {
		return ParseAllowedCIDRSetting(raw)
	}
	return strings.Split(envValue, ",")
}

// EgressDeniedRecorder 在身份源地址被防跳板出站拒绝时记安全事件（控制面启动时装配）。
var EgressDeniedRecorder func(host string)
