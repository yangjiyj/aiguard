package handler

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
)

// 2.9.22 起命中原文和前后文随安全事件入库，单个事件的异步写入载荷会超过事件总线通用的 64KB 上限。
// 超限会转同步写入（请求路径上多一次数据库往返）。安全事件写入事件单独放宽到 1MB，其他事件类型不变。

func phoneHitFindings(n int) []SecurityFinding {
	findings := make([]SecurityFinding, 0, n)
	for i := 0; i < n; i++ {
		before := strings.Repeat("客户资料登记表联系人电话如下请核对", 30)
		phone := fmt.Sprintf("138%08d", 10000000+i)
		after := strings.Repeat("备注信息请勿外传仅限内部使用谢谢", 30)
		start := len([]rune(before))
		index := i
		findings = append(findings, SecurityFinding{
			Type: "pii", Category: "pii_phone", Severity: "medium", RuleID: "pii_phone", RuleName: "中国大陆手机号",
			EvidenceKind: "literal", ContentSource: "user", MessageIndex: &index, MessageRole: "user",
			RawEvidence: phone, MatchedTextPreview: phone[:3] + "****" + phone[7:], RedactedEvidence: phone[:3] + "****" + phone[7:],
			EvidenceContext: before + phone + after, MatchedLocation: fmt.Sprintf("content[%d:%d]", start, start+len(phone)),
			Confidence: 0.95,
		})
	}
	return findings
}

func longChineseHitFinding() SecurityFinding {
	hit := strings.Repeat("项目代号天穹计划的预算与人员安排", 256) // 16 字 × 256 = 4096 字
	before, after := strings.Repeat("前文", 250), strings.Repeat("后文", 250)
	start := len([]rune(before))
	return SecurityFinding{
		Type: "custom", Category: "project_code", Severity: "high", RuleName: "涉密项目代号", EvidenceKind: "literal",
		RawEvidence: hit, MatchedTextPreview: "项目**", RedactedEvidence: "项目**",
		EvidenceContext: before + hit + after, MatchedLocation: fmt.Sprintf("content[%d:%d]", start, start+len([]rune(hit))),
	}
}

func TestAsyncSecurityEventWithRawEvidenceIsEnqueuedNotWrittenSynchronously(t *testing.T) {
	for name, findings := range map[string][]SecurityFinding{
		"50 个中文手机号命中":   phoneHitFindings(50),
		"单条 4096 字中文命中": {longChineseHitFinding()},
	} {
		syncWriter := &fakeSyncAuditWriter{}
		outbox := &fakeOutboxEnqueuer{}
		writer := NewAsyncAuditWriter(syncWriter, outbox)
		writer.now = func() time.Time { return time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC) }

		writer.WriteSecurityEvent(context.Background(), asyncAuditTestEnvelope(), findings, "block", "原文入库")

		if syncWriter.securityWrites != 0 || len(outbox.events) != 1 {
			t.Fatalf("%s: 应异步入队而不是转同步写入: sync=%d queued=%d", name, syncWriter.securityWrites, len(outbox.events))
		}
		event := outbox.events[0]
		if event.Type != eventbus.EventTypeAuditSecurityEventWrite || !strings.Contains(string(event.Payload), `"raw_evidence":`) {
			t.Fatalf("%s: 入队的是带原文的安全事件写入: %s", name, event.Type)
		}
		t.Logf("%s: 载荷 %d 字节", name, len(event.Payload))
	}
	// 前提：50 个手机号命中的载荷确实超过通用上限，本测试才在验证放宽。
	syncWriter, outbox := &fakeSyncAuditWriter{}, &fakeOutboxEnqueuer{}
	NewAsyncAuditWriter(syncWriter, outbox).WriteSecurityEvent(context.Background(), asyncAuditTestEnvelope(), phoneHitFindings(50), "block", "原文入库")
	if len(outbox.events) == 1 && len(outbox.events[0].Payload) <= eventbus.MaxPayloadBytes {
		t.Fatalf("测试数据应超过通用上限 %d 字节，实际 %d", eventbus.MaxPayloadBytes, len(outbox.events[0].Payload))
	}
}
