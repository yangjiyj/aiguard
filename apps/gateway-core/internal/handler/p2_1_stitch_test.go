package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/security"
)

// TestP2_1_AcceptanceChain_CustomBlockRuleToSecurityEvent 端到端验证 P2-1 验收链路：
// 策略中心编译的「病案号正则」自定义规则命中 -> 检测引擎返回顶层 block 裁决 + 脱敏证据
// -> 网关 ShouldBlock() 拦截 -> WriteSecurityEvent 写入 FK 安全的 rule_id 安全事件，
// 且 matched_summary 带命中原文、前后文、脱敏展示值与原文哈希（2.9.22 起原文入库）。
//
// 该用例是验收标准「策略中心建条『病案号正则』规则 -> 正向代理发命中请求 ->
// 运行时 block/告警 -> security_events 出现该 rule_id 事件」的可自动化等价证明
// （环境无法承载实时 Postgres+服务栈，故以单测桩接全链路作为最强证据）。
func TestP2_1_AcceptanceChain_CustomBlockRuleToSecurityEvent(t *testing.T) {
	// 模拟病案号原文：2.9.22 起作为命中原文入库。
	const rawSensitive = "BA20240115034"

	// 1) 模拟检测引擎：返回顶层 action=block + 一条 custom block 命中（证据已在引擎侧脱敏）。
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"request_id": "req_bah_stitch",
			"action": "block",
			"latency_ms": 3,
			"findings": [
				{
					"type": "custom",
					"category": "medical_id",
					"severity": "high",
					"matched_text_preview": "BA****34 (sha256:deadbeef)",
					"rule_id": "rule_bah_001",
					"confidence": 0.9,
					"rule_name": "病案号正则",
					"rule_type": "regex",
					"action": "block",
					"matched_location": "content[6:19]",
					"redacted_evidence": "BA****34 (sha256:deadbeef)",
					"raw_evidence": "BA20240115034",
					"evidence_context": "患者病案号 BA20240115034 请外发给第三方",
					"evidence_kind": "literal",
					"content_source": "user",
					"evidence_reason": "命中病案号正则"
				}
			]
		}`))
	}))
	defer engine.Close()

	// 2) 网关侧 security.Client 指向模拟引擎，发起一次输入检测。
	client := security.NewClient(engine.URL)
	resp, err := client.CheckInput(context.Background(), &security.CheckInputRequest{
		RequestID:   "req_bah_stitch",
		Content:     "患者病案号 " + rawSensitive + " 请外发给第三方",
		ContentType: "text",
	})
	if err != nil {
		t.Fatalf("CheckInput 失败: %v", err)
	}

	// 3) 运行时裁决：自定义 block 规则命中必须拦截。
	if !resp.ShouldBlock() {
		t.Fatalf("期望 ShouldBlock()=true（自定义 block 规则命中），实际 action=%q", resp.Action)
	}
	// 11 字段富化必须完整解码到 Go 侧。
	if len(resp.Findings) != 1 {
		t.Fatalf("期望解码出 1 条命中，实际 %d 条", len(resp.Findings))
	}
	f := resp.Findings[0]
	if f.RuleID != "rule_bah_001" || f.Type != "custom" || f.Action != "block" || f.RuleName != "病案号正则" {
		t.Fatalf("命中字段解码不完整: %+v", f)
	}
	if f.EvidenceKind != "literal" || f.ContentSource != "user" || f.EvidenceReason != "命中病案号正则" {
		t.Fatalf("管理员证据字段解码不完整: %+v", f)
	}
	if !strings.Contains(f.EvidenceContext, rawSensitive) {
		t.Fatalf("管理员未脱敏上下文解码不完整: %+v", f)
	}

	// 4) 落库安全事件：转换两套 SecurityFinding 结构后写入。
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req_bah_stitch",
		TenantID:  "tenant_default",
		ProjectID: "proj_1",
		UserID:    "user_1",
	}
	findings := convertSecurityFindings(resp.Findings)
	writer.WriteSecurityEvent(context.Background(), envelope, findings, "block", "病案号外发拦截")

	// 5) 安全事件写入了 FK 安全的自定义 rule_id（$8 -> args 下标 7）。
	if mockDB.execCalls != 1 {
		t.Fatalf("期望 1 次 Exec，实际 %d", mockDB.execCalls)
	}
	if got := mockDB.args[0][7]; got != "rule_bah_001" {
		t.Fatalf("期望 security_events.rule_id=rule_bah_001，实际 %v", got)
	}

	// 6) 管理员审计证据：2.9.22 起（用户 11-17 定）matched_summary 存命中原文和不打码的前后文，
	// 打码展示值与哈希照旧保留；读取侧按内容证据权限剔除原文。
	matchedSummaryJSON, ok := mockDB.args[0][9].([]byte)
	if !ok {
		t.Fatalf("期望 matched_summary 为 []byte JSON，实际 %T", mockDB.args[0][9])
	}
	summary := string(matchedSummaryJSON)
	if !strings.Contains(summary, "redacted_evidence") || !strings.Contains(summary, "sha256:") {
		t.Fatalf("期望 matched_summary 含脱敏证据字段与 sha256，实际: %s", summary)
	}
	if !strings.Contains(summary, `"raw_evidence":"`+rawSensitive+`"`) ||
		!strings.Contains(summary, `"evidence_context":"患者病案号 `+rawSensitive+` 请外发给第三方"`) {
		t.Fatalf("matched_summary 应带命中原文和前后文: %s", summary)
	}
	if !strings.Contains(summary, "raw_evidence_sha256") ||
		!strings.Contains(summary, "evidence_context_sha256") {
		t.Fatalf("matched_summary missing evidence hashes: %s", summary)
	}
	for _, expected := range []string{
		`"evidence_kind":"literal"`, `"content_source":"user"`, `"evidence_reason":"命中病案号正则"`,
	} {
		if !strings.Contains(summary, expected) {
			t.Fatalf("管理员证据字段未进入 matched_summary: missing=%s summary=%s", expected, summary)
		}
	}
}
