package aicontentlabel

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
)

// 系统设置键。控制面校验写入，网关经 /admin/v1/internal/system/settings 轮询读取。
const (
	KeyExplicitEnabled  = "ai_content_explicit_label_enabled"
	KeyExplicitText     = "ai_content_explicit_label_text"
	KeyWatermarkEnabled = "ai_content_watermark_enabled"
	KeyAgentTypes       = "ai_content_label_agent_types"

	// DefaultExplicitText 是显式标识的默认文案，渲染时加全角括号。
	DefaultExplicitText = "以上内容由 AI 生成"
	// PortalAgentType 是企业门户经 portal-proxy 转发时声明的客户端类型。
	PortalAgentType = "enterprise-portal"

	maxExplicitTextRunes = 40
	maxAgentTypes        = 16
)

// SettingKeys 列出全部设置键，供控制面白名单与测试使用。
var SettingKeys = []string{KeyExplicitEnabled, KeyExplicitText, KeyWatermarkEnabled, KeyAgentTypes}

// Settings 是网关生效的内容标识配置。
type Settings struct {
	ExplicitEnabled  bool
	ExplicitText     string
	WatermarkEnabled bool
	AgentTypes       []string
}

// DefaultSettings 返回出厂配置：全部关闭，生效范围只有企业门户。
func DefaultSettings() Settings {
	return Settings{ExplicitText: DefaultExplicitText, AgentTypes: []string{PortalAgentType}}
}

// ParseSettings 从系统设置读出配置。缺失或非法的键回落到默认值，不报错。
func ParseSettings(values map[string]string) Settings {
	s := DefaultSettings()
	s.ExplicitEnabled = strings.EqualFold(strings.TrimSpace(values[KeyExplicitEnabled]), "true")
	s.WatermarkEnabled = strings.EqualFold(strings.TrimSpace(values[KeyWatermarkEnabled]), "true")
	if text, err := NormalizeExplicitText(values[KeyExplicitText]); err == nil && text != "" {
		s.ExplicitText = text
	}
	if raw := strings.TrimSpace(values[KeyAgentTypes]); raw != "" {
		if types, err := NormalizeAgentTypes(raw); err == nil {
			s.AgentTypes = types
		}
	}
	return s
}

// AppliesTo 判断某个客户端类型的回复是否需要加标识。
func (s Settings) AppliesTo(agentType string) bool {
	if !s.ExplicitEnabled && !s.WatermarkEnabled {
		return false
	}
	agentType = agentdetect.NormalizeAgentType(agentType)
	if agentType == "" {
		return false
	}
	for _, t := range s.AgentTypes {
		if t == agentType {
			return true
		}
	}
	return false
}

// ExplicitLine 返回追加到正文末尾的显式标识；未开启时为空。
func (s Settings) ExplicitLine() string {
	if !s.ExplicitEnabled {
		return ""
	}
	text := s.ExplicitText
	if text == "" {
		text = DefaultExplicitText
	}
	return "（" + text + "）"
}

// NormalizeExplicitText 校验显式标识文案：去首尾空白，1–40 个字符，不含换行和控制字符。
// 空字符串表示使用默认文案。
func NormalizeExplicitText(raw string) (string, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return "", nil
	}
	if utf8.RuneCountInString(text) > maxExplicitTextRunes {
		return "", fmt.Errorf("显式标识文案不能超过 %d 个字符", maxExplicitTextRunes)
	}
	for _, r := range text {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", fmt.Errorf("显式标识文案不能包含换行、控制字符或不可见字符")
		}
	}
	return text, nil
}

// NormalizeAgentTypes 校验生效客户端类型：JSON 字符串数组，最多 16 项，按网关的识别规则归一并去重。
// 返回的切片可能为空，表示不对任何客户端生效。
func NormalizeAgentTypes(raw string) ([]string, error) {
	var values []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &values); err != nil {
		return nil, fmt.Errorf("生效客户端类型必须是字符串数组")
	}
	if len(values) > maxAgentTypes {
		return nil, fmt.Errorf("生效客户端类型最多 %d 项", maxAgentTypes)
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		t := agentdetect.NormalizeAgentType(v)
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out, nil
}

// NormalizeSettingValue 校验并规范化单个设置键的值，供控制面写入前调用。
// 不认识的键返回 ok=false。
func NormalizeSettingValue(key, raw string) (value string, ok bool, err error) {
	switch key {
	case KeyExplicitEnabled, KeyWatermarkEnabled:
		v := strings.ToLower(strings.TrimSpace(raw))
		if v != "true" && v != "false" {
			return "", true, fmt.Errorf("%s 只能是 true 或 false", key)
		}
		return v, true, nil
	case KeyExplicitText:
		text, err := NormalizeExplicitText(raw)
		if err != nil {
			return "", true, err
		}
		if text == "" {
			text = DefaultExplicitText
		}
		return text, true, nil
	case KeyAgentTypes:
		types, err := NormalizeAgentTypes(raw)
		if err != nil {
			return "", true, err
		}
		encoded, _ := json.Marshal(types)
		return string(encoded), true, nil
	}
	return "", false, nil
}
