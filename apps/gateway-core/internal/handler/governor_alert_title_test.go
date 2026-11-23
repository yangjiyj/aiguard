package handler

import (
	"regexp"
	"testing"
)

// 客户现场消息中心 3000 条里约 2500 条标题是「governor 事件：alert」「governor 事件：quota.admission.reservation_overrun」。
// 标题会原样进入消息导出，必须是中文。
func TestGovernorAlertTitlesAreReadableChinese(t *testing.T) {
	cases := []struct{ eventType, reason, want string }{
		{"alert", "model not allowed for team", "模型未对该团队开放"},
		{"alert", "fail-open: timeout", "额度检查超时，已放行请求"},
		{"alert", "fail-open: quota error: timeout: context deadline exceeded", "额度检查超时，已放行请求"},
		{"alert", "fail-open: quota error: connection refused", "额度检查异常，已放行请求"},
		{"quota.admission.reservation_overrun", "actual token usage exceeded the conservative reservation", "额度预占超出（Token）"},
		{"quota.admission.cost_reservation_overrun", "actual billable amount exceeded the conservative reservation", "额度预占超出（费用）"},
		{"quota.admission.runtime_fault", "soft quota observation unavailable", "额度观测故障"},
		{"governor.something_new", "whatever", "访问与额度治理通知"},
	}
	latin := regexp.MustCompile(`[A-Za-z]{2,}`)
	for _, tc := range cases {
		got := governorAlertTitle(tc.eventType, tc.reason)
		if got != tc.want {
			t.Fatalf("%s/%s: want %q, got %q", tc.eventType, tc.reason, tc.want, got)
		}
		if latin.MatchString(got) && got != "额度预占超出（Token）" {
			t.Fatalf("标题不应含英文代号: %q", got)
		}
	}
}
