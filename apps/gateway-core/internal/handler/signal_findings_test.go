package handler

import (
	"context"
	"testing"
)

func boolPointer(value bool) *bool {
	return &value
}

func observationFinding() SecurityFinding {
	return SecurityFinding{
		Type:                    "pii",
		Category:                "email",
		Severity:                "low",
		RuleID:                  "regex_email",
		Action:                  "allow",
		CountsAsSecurityFinding: boolPointer(false),
	}
}

func securityFinding() SecurityFinding {
	return SecurityFinding{
		Type:                    "secret",
		Category:                "aws_access_key",
		Severity:                "critical",
		RuleID:                  "secret_aws_access_key",
		Action:                  "block",
		CountsAsSecurityFinding: boolPointer(true),
	}
}

func TestShouldPersistSecurityEventSkipsObservationOnly(t *testing.T) {
	findings := []SecurityFinding{observationFinding()}

	if shouldPersistSecurityEvent("allow", findings) {
		t.Fatal("纯 observation 不应持久化 security_event")
	}
	if shouldPersistSecurityEvent("audit", findings) {
		t.Fatal("检测器技术 audit 不能把纯 observation 升级成 security_event")
	}
}

func TestShouldPersistSecurityEventKeepsMixedEvidence(t *testing.T) {
	findings := []SecurityFinding{observationFinding(), securityFinding()}

	if !shouldPersistSecurityEvent("audit", findings) {
		t.Fatal("混合证据中存在安全 finding 时必须保留完整事件")
	}
}

func TestShouldPersistSecurityEventKeepsLegacyFindingWithoutFlag(t *testing.T) {
	findings := []SecurityFinding{{
		Type:     "custom",
		Category: "legacy_rule",
		Severity: "high",
	}}

	if !shouldPersistSecurityEvent("audit", findings) {
		t.Fatal("旧生产者未提供 counts_as_security_finding 时必须按安全 finding 兼容")
	}
}

func TestChatWriteSecurityEventSkipsObservationOnly(t *testing.T) {
	audit := &fakeSyncAuditWriter{}
	handler := &ChatCompletionsHandler{auditWriter: audit}

	handler.writeSecurityEvent(
		context.Background(),
		asyncAuditTestEnvelope(),
		[]SecurityFinding{observationFinding()},
		"security_audit",
		"候选命中",
	)

	if audit.securityWrites != 0 {
		t.Fatalf("纯 observation 写入了 %d 条安全事件", audit.securityWrites)
	}
}

func TestAsyncAuditWriterSkipsObservationOnly(t *testing.T) {
	syncWriter := &fakeSyncAuditWriter{}
	outbox := &fakeOutboxEnqueuer{}
	writer := NewAsyncAuditWriter(syncWriter, outbox)

	writer.WriteSecurityEvent(
		context.Background(),
		asyncAuditTestEnvelope(),
		[]SecurityFinding{observationFinding()},
		"security_audit",
		"候选命中",
	)

	if len(outbox.events) != 0 {
		t.Fatalf("纯 observation 写入了 %d 条 outbox 安全事件", len(outbox.events))
	}
	if syncWriter.securityWrites != 0 {
		t.Fatalf("纯 observation 回退写入了 %d 条同步安全事件", syncWriter.securityWrites)
	}
}

func TestReverseProxyAuditSkipsObservationOnly(t *testing.T) {
	audit := &fakeReverseProxyAuditRecorder{}
	handler := &ReverseProxyHandler{auditRecorder: audit}
	record := reverseProxyAuditRecord{
		RequestID:  "req-observation",
		TenantID:   "tenant_default",
		TargetHost: "model.example.com",
	}

	handler.writeReverseProxyAudit(
		context.Background(),
		record,
		nil,
		"",
		nil,
		"",
		reverseProxySecurityAudit{
			inputAction:   "allow",
			inputFindings: []SecurityFinding{observationFinding()},
		},
	)

	if len(audit.securityEvents) != 0 {
		t.Fatalf("反向代理为纯 observation 写入了 %d 条安全事件", len(audit.securityEvents))
	}
}

func TestSecurityFindingsToAuditMapsPreservesObservationFlag(t *testing.T) {
	items := securityFindingsToAuditMaps([]SecurityFinding{observationFinding()})
	if len(items) != 1 {
		t.Fatalf("审计映射数量 = %d，期望 1", len(items))
	}

	value, ok := items[0]["counts_as_security_finding"].(bool)
	if !ok || value {
		t.Fatalf("观察信号标记未透传，得到 %#v", items[0]["counts_as_security_finding"])
	}
}
