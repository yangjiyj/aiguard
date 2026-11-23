package rules

import "strings"

// 引擎能力协商：引擎拉规则包时在 X-Engine-Capabilities 头里声明自己认识的新字段。
// 旧引擎的 CompiledPolicy 是 extra=forbid 严格 DTO，收到不认识的字段会拒收整个规则包
// （保持 last-good，新配置全部不生效）。因此新字段只下发给声明了对应能力的引擎；
// 旧引擎收到去掉新字段的包，并在 warnings 里得到"需升级引擎"提示。

const (
	// EngineCapabilitySemanticAction：认识 CompiledPolicy.semantic_action（2.9.12 起）。
	EngineCapabilitySemanticAction = "semantic_action"
	// WarningEngineUpgradeRequired：策略配置了新引擎才支持的功能，当前引擎版本过旧未下发。
	WarningEngineUpgradeRequired = "engine_upgrade_required"
)

// AdaptForEngine 按引擎声明的能力裁剪规则包，返回该引擎缺少、且本包实际用到的能力。
// 有裁剪时重新计算 Version（版本必须覆盖实际下发内容），并标记 Degraded。
// 只替换 pack.Policies 切片，不改动调用方共享的底层数组。
func AdaptForEngine(pack *RulePack, capabilityHeader string) []string {
	if pack == nil {
		return nil
	}
	declared := map[string]bool{}
	for _, item := range strings.Split(capabilityHeader, ",") {
		if value := strings.ToLower(strings.TrimSpace(item)); value != "" {
			declared[value] = true
		}
	}
	var missing []string
	if !declared[EngineCapabilitySemanticAction] {
		var stripped []CompiledPolicy
		for index, policy := range pack.Policies {
			if policy.SemanticAction == "" {
				continue
			}
			if stripped == nil {
				stripped = append([]CompiledPolicy(nil), pack.Policies...)
			}
			stripped[index].SemanticAction = ""
		}
		if stripped != nil {
			pack.Policies = stripped
			missing = append(missing, EngineCapabilitySemanticAction)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	pack.Warnings = append(append([]string(nil), pack.Warnings...), WarningEngineUpgradeRequired)
	pack.Degraded = true
	pack.Version = ContentVersion(*pack)
	return missing
}
