package handler

import (
	"fmt"

	"github.com/yangjiyj/aiguard/packages/shared-go/aicontentlabel"
)

// normalizeAIContentLabelSettings 校验并规范化 AI 生成内容标识的四个设置键（只处理本次提交的键）。
func normalizeAIContentLabelSettings(settings map[string]string) error {
	for _, key := range aicontentlabel.SettingKeys {
		raw, ok := settings[key]
		if !ok {
			continue
		}
		value, _, err := aicontentlabel.NormalizeSettingValue(key, raw)
		if err != nil {
			return fmt.Errorf("%s", err.Error())
		}
		settings[key] = value
	}
	return nil
}

// fillAIContentLabelDefaults 给控制台展示补上未配置键的出厂值，避免界面显示空白。
func fillAIContentLabelDefaults(data map[string]any) {
	defaults := aicontentlabel.DefaultSettings()
	if _, ok := data[aicontentlabel.KeyExplicitEnabled]; !ok {
		data[aicontentlabel.KeyExplicitEnabled] = "false"
	}
	if _, ok := data[aicontentlabel.KeyWatermarkEnabled]; !ok {
		data[aicontentlabel.KeyWatermarkEnabled] = "false"
	}
	if _, ok := data[aicontentlabel.KeyExplicitText]; !ok {
		data[aicontentlabel.KeyExplicitText] = defaults.ExplicitText
	}
	if _, ok := data[aicontentlabel.KeyAgentTypes]; !ok {
		data[aicontentlabel.KeyAgentTypes] = `["` + aicontentlabel.PortalAgentType + `"]`
	}
}
