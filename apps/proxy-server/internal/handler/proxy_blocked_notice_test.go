package handler

import (
	"strings"
	"testing"
)

// A forward-proxy block names the configured rule, the redacted content, and
// the request number that 阻断记录 can look up.
func TestProxyBlockNoticeNamesRuleDetailAndRequest(t *testing.T) {
	notice := proxyBlockNotice("req-proxy-1", []map[string]interface{}{
		{"rule_id": "rule_audit", "rule_name": "告警规则", "action": "audit", "matched_text_preview": "irrelevant"},
		{"rule_id": "rule_525f3078", "rule_name": "密码明文检测", "action": "block", "matched_text_preview": "password=pass1996"},
	})
	for _, want := range []string{"密码明文检测（rule_525f3078）", "请求 ID：req-proxy-1", "阻断记录"} {
		if !strings.Contains(notice, want) {
			t.Fatalf("notice missing %q:\n%s", want, notice)
		}
	}
	if strings.Contains(notice, "pass1996") || strings.Contains(notice, "告警规则") {
		t.Fatalf("notice must show the blocking rule with redacted content only:\n%s", notice)
	}
}
