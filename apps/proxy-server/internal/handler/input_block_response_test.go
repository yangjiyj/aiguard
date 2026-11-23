package handler

import (
	"net/http"
	"testing"
)

// 走到拦截分支时一定是规则命中挣得了阻断（检测本身异常一律放行）。
// 不能再以 503"安全检测尚未完成"误导客户排查；只有请求体超检测上限保留 413。
func TestInputBlockResponseNeverClaimsInspectionPending(t *testing.T) {
	for _, tc := range []struct {
		name   string
		meta   *FingerprintScanMeta
		status int
		code   string
	}{
		{"no meta", nil, http.StatusForbidden, "security_blocked"},
		{"completed", &FingerprintScanMeta{ScanMode: "durable_inspection", SemanticStatus: "completed"}, http.StatusForbidden, "security_blocked"},
		{"incomplete durable", &FingerprintScanMeta{ScanMode: "durable_inspection", SemanticStatus: "incomplete", SemanticReason: "judge_timeout"}, http.StatusForbidden, "security_blocked"},
		{"body limit", &FingerprintScanMeta{ScanMode: "durable_inspection", SemanticStatus: "incomplete", SemanticReason: "request_body_limit_exceeded"}, http.StatusRequestEntityTooLarge, "request_body_limit_exceeded"},
	} {
		status, code := inputBlockResponse(tc.meta, nil)
		if status != tc.status || code != tc.code {
			t.Fatalf("%s: got %d %q want %d %q", tc.name, status, code, tc.status, tc.code)
		}
	}
}

// 受限文件/DLP 规则命中与请求体超限同时成立：规则挣得的阻断必须以 403 和规则说明返回，
// 不能被 413 盖掉；超限本身只是覆盖缺口（audit），不会解释这次阻断。
func TestInputBlockResponseRuleHitWinsOverBodyLimit(t *testing.T) {
	limit := &FingerprintScanMeta{ScanMode: "durable_inspection", SemanticStatus: "incomplete", SemanticReason: "request_body_limit_exceeded"}
	gap := map[string]interface{}{"type": "system", "category": "request_body_limit_exceeded", "action": "audit"}
	rule := map[string]interface{}{"type": "restricted_file", "rule_id": "rf-1", "action": "block"}
	if status, code := inputBlockResponse(limit, []map[string]interface{}{gap, rule}); status != http.StatusForbidden || code != "security_blocked" {
		t.Fatalf("rule hit + body limit: got %d %q, want 403 security_blocked", status, code)
	}
	if status, code := inputBlockResponse(limit, []map[string]interface{}{gap}); status != http.StatusRequestEntityTooLarge || code != "request_body_limit_exceeded" {
		t.Fatalf("body limit without a blocking finding: got %d %q, want 413", status, code)
	}
}
