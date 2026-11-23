package notify

import (
	"strings"
	"testing"
)

// 运维告警（计费/审计/预算预警）外发时 body 用中文字段名，机器人消息必须带上范围与处置建议。
func TestChatbotBodyLinesKeepsOpsAlertChineseFields(t *testing.T) {
	lines := strings.Join(chatbotBodyLines(map[string]any{
		"类型": "预算已用 80%", "范围": "员工 张三（¥800.00 / ¥1,000.00，已用 80%）", "次数": 1, "处置建议": "请提前追加预算", "internal_id": "x",
	}), "\n")
	for _, want := range []string{"类型：预算已用 80%", "范围：员工 张三", "处置建议：请提前追加预算"} {
		if !strings.Contains(lines, want) {
			t.Fatalf("missing %q in %q", want, lines)
		}
	}
	if !strings.HasPrefix(lines, "类型：") || strings.Index(lines, "范围：") > strings.Index(lines, "处置建议：") {
		t.Fatalf("字段顺序应为 类型→范围→次数→处置建议: %q", lines)
	}
	if strings.Contains(lines, "internal_id") {
		t.Fatalf("技术字段不应外发: %q", lines)
	}
}
