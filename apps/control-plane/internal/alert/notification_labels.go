package alert

import (
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// notificationBody 是发往外部渠道（钉钉、企业微信、飞书、邮件、Webhook）的正文：在告警正文的副本上
// 补事件类型、处置动作的中文叫法（event_type_label / action_label）。英文码字段原样保留给 Webhook
// 程序读，群机器人只显示中文叫法；没有中文叫法的码不补，那一行就不出现，和控制台省略未知处置一致。
// 收件箱与告警组里存的正文不变。
func notificationBody(ev *repository.SecurityEvent, body map[string]any) map[string]any {
	out := make(map[string]any, len(body)+2)
	for key, value := range body {
		out[key] = value
	}
	if action, _ := body["action"].(string); action != "" {
		if label, ok := actionLabelsCN[strings.ToLower(strings.TrimSpace(action))]; ok {
			out["action_label"] = label
		}
	}
	// 运行告警的标题已经写明是哪种故障，落库的事件类型（如 security_check）对它没有意义。
	if alertTypeForSecurityEvent(ev) != "runtime_fault" {
		if eventType, _ := body["event_type"].(string); strings.TrimSpace(eventType) != "" {
			if label := eventTypeLabelCN(eventType); label != eventType {
				out["event_type_label"] = label
			}
		}
	}
	return out
}
