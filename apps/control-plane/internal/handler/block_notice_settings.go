package handler

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// The gateway renders the agent-facing block notice from these two settings
// (gateway-core handler/block_notice.go keeps the same contract).
const (
	blockResponseModeSettingKey   = "security_block_response_mode"
	blockNoticeTemplateSettingKey = "security_block_notice_template"
	maxBlockNoticeTemplateRunes   = 2000
)

// defaultBlockNoticeTemplate mirrors gateway-core DefaultBlockNoticeTemplate;
// the console shows it when no custom template is saved.
const defaultBlockNoticeTemplate = "【JJDGuard 安全网关】本次请求已被安全策略阻断。\n" +
	"阻断原因：{reason}\n" +
	"命中规则：{rule}\n" +
	"命中内容：{detail}\n" +
	"阻断编号：{block_id}\n" +
	"操作编号：{operation_id}\n" +
	"如需放行，请联系管理员并提供阻断编号（管理后台「安全护栏 → 阻断记录」可查）。"

var blockNoticePlaceholders = []string{"{reason}", "{rule}", "{detail}", "{block_id}", "{operation_id}", "{request_id}"}

// normalizeBlockNoticeSettings validates and canonicalizes the block-notice
// keys of a settings update in place.
func normalizeBlockNoticeSettings(settings map[string]string) error {
	if raw, ok := settings[blockResponseModeSettingKey]; ok {
		mode := strings.ToLower(strings.TrimSpace(raw))
		if mode != "error" && mode != "message" {
			return fmt.Errorf("阻断提示方式只能是 error（返回错误）或 message（以助手消息返回）")
		}
		settings[blockResponseModeSettingKey] = mode
	}
	if raw, ok := settings[blockNoticeTemplateSettingKey]; ok {
		template := strings.TrimSpace(strings.ReplaceAll(raw, "\r\n", "\n"))
		if utf8.RuneCountInString(template) > maxBlockNoticeTemplateRunes {
			return fmt.Errorf("阻断提示模板不能超过 %d 个字符", maxBlockNoticeTemplateRunes)
		}
		rest := template
		for {
			start := strings.Index(rest, "{")
			if start < 0 {
				break
			}
			end := strings.Index(rest[start:], "}")
			if end < 0 {
				break
			}
			token := rest[start : start+end+1]
			known := false
			for _, placeholder := range blockNoticePlaceholders {
				if token == placeholder {
					known = true
					break
				}
			}
			if !known {
				return fmt.Errorf("阻断提示模板包含未知占位符 %s，可用：%s", token, strings.Join(blockNoticePlaceholders, " "))
			}
			rest = rest[start+end+1:]
		}
		settings[blockNoticeTemplateSettingKey] = template
	}
	return nil
}
