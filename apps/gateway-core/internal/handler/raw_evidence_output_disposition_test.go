package handler

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// 输出侧"阻断"口径与输入侧一致：只有正文因命中被拦才按 blocked 留原文；检测不可用（fail-closed）、
// 严格模式超出完整检查预算、工具调用拦截都不是"内容命中阻断"，不留原文。
func TestRawEvidenceOutputBlockedOnlyForTextFindings(t *testing.T) {
	incomplete := &AuditResult{OutputAction: "block", ResponseMetadata: map[string]interface{}{"output_scan_incomplete": true}}
	blocked := &AuditResult{OutputAction: "block"}
	for name, tc := range map[string]struct {
		err   error
		audit *AuditResult
		want  bool
	}{
		"text_findings":         {outputTextBlockedError{choice: 0}, blocked, true},
		"detection_fail_closed": {fmt.Errorf("%w: output choice 0", errGuardrailDetectionUnavailable), incomplete, false},
		"strict_budget":         {errors.New("output_scan_incomplete: strict response exceeds 10-byte budget"), incomplete, false},
		"tool_blocked":          {errors.New("tool call blocked by policy"), blocked, false},
		"client_gone":           {fmt.Errorf("%w: output choice 0", errClientGoneDuringSecurity), blocked, false},
	} {
		if got := outputBlockRetainsOriginal(context.Background(), tc.err, tc.audit); got != tc.want {
			t.Errorf("%s: retain=%v want %v", name, got, tc.want)
		}
	}
	if (outputTextBlockedError{choice: 2}).Error() != "response blocked due to security findings in output choice 2" {
		t.Fatal("error text must stay unchanged for existing callers and logs")
	}
}

// 破坏性工具调用被拦后正文换成提示语：这是工具拦截，不是脱敏改写，不记 masked。
func TestRawEvidenceOutputToolNoticeIsNotMasked(t *testing.T) {
	raw := []byte(`{"id":"c","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"好的，我来删除","tool_calls":[{"id":"t1","type":"function","function":{"name":"rm","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`)
	secured := []byte(`{"id":"c","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"该操作已被安全策略拦截"},"finish_reason":"stop"}]}`)
	h, audit := rawEvidenceHandler(&MockSecurityChecker{})
	h.retainRawOutput(context.Background(), rawEvidenceEnvelope(), raw, secured, &AuditResult{OutputAction: "block"}, false)
	if len(audit.records) != 0 {
		t.Fatalf("tool block notice recorded as raw evidence: %+v", audit.records)
	}
	// 同一回复里另一个 choice 的正文确实被脱敏：照常留证。
	raw2 := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"x","tool_calls":[{"id":"t1","type":"function","function":{"name":"rm","arguments":"{}"}}]}},{"index":1,"message":{"role":"assistant","content":"电话 13800138000"}}]}`)
	secured2 := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"已拦截"}},{"index":1,"message":{"role":"assistant","content":"电话 <PHONE>"}}]}`)
	h.retainRawOutput(context.Background(), rawEvidenceEnvelope(), raw2, secured2, &AuditResult{OutputAction: "mask"}, false)
	if len(audit.records) != 1 || audit.records[0].Index != 1 || audit.records[0].Disposition != rawEvidenceMasked {
		t.Fatalf("masked choice not retained correctly: %+v", audit.records)
	}
}
