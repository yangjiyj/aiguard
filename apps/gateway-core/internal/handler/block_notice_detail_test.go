// apps/gateway-core/internal/handler/block_notice_detail_test.go
package handler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

const noticeTemplateForTest = "命中规则：{rule}\n命中内容：{detail}\n阻断编号：{block_id}"

// firstNoticeLine 取提示的第一行：renderBlockNotice 会给不含 {block_id} 的自定义模板补一行阻断编号。
func firstNoticeLine(notice string) string {
	return strings.SplitN(notice, "\n", 2)[0]
}

func privateKeyFinding() SecurityFinding {
	return SecurityFinding{
		Type: "code_config", Category: "ssh_private_key", Severity: "critical", Action: "block",
		RuleID: "rule_x", RuleName: "证书/私钥检测", MatchedTextPreview: "--****--",
		RedactedEvidence: "-----BEGIN RSA PRIVATE KEY-----（后续正文 96 字已隐藏）",
		RawEvidence:      "-----BEGIN RSA PRIVATE KEY-----",
		EvidenceKind:     "literal", MatchedLocation: "content[0:31]", ContentSource: "user",
	}
}

func TestInputBlockNoticeShowsOriginalFragment(t *testing.T) {
	ctx := withSecurityEventStage(context.Background(), "input")
	attribution := deriveBlockAttribution(ctx, "evt_1", []SecurityFinding{privateKeyFinding()}, "security_blocked", "blocked input message 0")
	if attribution.Layer != "input_content" {
		t.Fatalf("layer=%q", attribution.Layer)
	}
	notice := renderBlockNotice(noticeTemplateForTest, attribution)
	if !strings.Contains(notice, "命中内容：-----BEGIN RSA PRIVATE KEY-----\n") {
		t.Fatalf("提示应写命中原文: %q", notice)
	}
	if attribution.Detail != "-----BEGIN RSA PRIVATE KEY-----（后续正文 96 字已隐藏）" {
		t.Fatalf("阻断记录应存可读命中内容: %q", attribution.Detail)
	}
}

func TestInputBlockNoticeFlattensNewlinesAndIsBounded(t *testing.T) {
	finding := privateKeyFinding()
	finding.Category, finding.RuleName = "env_file", "环境变量文件"
	finding.RawEvidence = "A_KEY=1\nB_KEY=2\n" + strings.Repeat("C", 300)
	ctx := withSecurityEventStage(context.Background(), "input")
	attribution := deriveBlockAttribution(ctx, "evt_2", []SecurityFinding{finding}, "security_blocked", "blocked input message 0")
	notice := renderBlockNotice("命中内容：{detail}", attribution)
	// 换行压成空格后共 316 个字符，超长：保留开头 72 字和结尾 48 字，中间写 " … "（沿用 boundedNoticeText）。
	want := "命中内容：A_KEY=1 B_KEY=2 " + strings.Repeat("C", 56) + " … " + strings.Repeat("C", 48)
	if got := firstNoticeLine(notice); got != want {
		t.Fatalf("命中内容应为压平换行并限长后的精确文本:\n got=%q\nwant=%q", got, want)
	}
	if got := len([]rune(strings.TrimPrefix(firstNoticeLine(notice), "命中内容："))); got != 72+3+48 {
		t.Fatalf("限长后应为 123 个字符（72 + 省略号 3 + 48），得到 %d", got)
	}
}

func TestInputBlockNoticeForAIJudgementKeepsExplanation(t *testing.T) {
	finding := SecurityFinding{
		Type: "semantic_attack", Category: "semantic_roleplay", Severity: "high", Action: "block",
		RuleID: "rule_s", RuleName: "角色扮演注入检测",
		RedactedEvidence: "语义裁判判定：角色扮演（block）", RawEvidence: "用户的整段输入", EvidenceKind: "semantic",
	}
	ctx := withSecurityEventStage(context.Background(), "input")
	attribution := deriveBlockAttribution(ctx, "evt_3", []SecurityFinding{finding}, "security_blocked", "blocked input message 0")
	notice := renderBlockNotice("命中内容：{detail}", attribution)
	if firstNoticeLine(notice) != "命中内容：语义裁判判定：角色扮演（block）" {
		t.Fatalf("没有明确命中位置时沿用说明文字: %q", notice)
	}
}

func TestOutputBlockNoticeKeepsLegacyMask(t *testing.T) {
	finding := privateKeyFinding()
	ctx := withSecurityEventStage(context.Background(), "output")
	attribution := deriveBlockAttribution(ctx, "evt_4", []SecurityFinding{finding}, "security_blocked", "blocked output")
	if attribution.Layer != "output_content" {
		t.Fatalf("layer=%q", attribution.Layer)
	}
	notice := renderBlockNotice("命中内容：{detail}", attribution)
	if firstNoticeLine(notice) != "命中内容：--****--" {
		t.Fatalf("模型输出被拦不回显内容: %q", notice)
	}
}

func TestRetainedNoticeCopyNeverContainsTheOriginalFragment(t *testing.T) {
	finding := privateKeyFinding()
	finding.Category, finding.RawEvidence = "plain_password", "password=Example-Passw0rd"
	finding.RedactedEvidence = "password=Ex****rd（16 位）"
	ctx := withSecurityEventStage(context.Background(), "input")
	attribution := deriveBlockAttribution(ctx, "evt_5", []SecurityFinding{finding}, "security_blocked", "blocked input message 0")
	shown := renderBlockNotice(noticeTemplateForTest, attribution)
	retained := renderBlockNotice(noticeTemplateForTest, retainedNoticeAttribution(attribution))
	if !strings.Contains(shown, "Example-Passw0rd") {
		t.Fatalf("返回给使用者的提示应含原文: %q", shown)
	}
	if strings.Contains(retained, "Example-Passw0rd") || !strings.Contains(retained, "password=Ex****rd（16 位）") {
		t.Fatalf("留存副本应是可读命中内容: %q", retained)
	}
}

func TestRetainedNoticeCopyForOutputBlockIsUnchanged(t *testing.T) {
	ctx := withSecurityEventStage(context.Background(), "output")
	attribution := deriveBlockAttribution(ctx, "evt_6", []SecurityFinding{privateKeyFinding()}, "security_blocked", "blocked output")
	if got := firstNoticeLine(renderBlockNotice("{detail}", retainedNoticeAttribution(attribution))); got != "--****--" {
		t.Fatalf("输出阶段的留存副本沿用旧打码: %q", got)
	}
}

func TestDestructiveToolBlockNoticeShowsCommandSkeletonWithoutSecrets(t *testing.T) {
	command := "DB_PASSWORD=S3cretPw rm -rf /srv/target"
	args := `{"command":` + mustJSONString(command) + `}`
	decision := destructiveEvidenceDecision("shell_command", args, "filesystem_delete")
	call := ToolCall{Function: ToolCallFunc{Name: "shell_command", Arguments: args}}
	ctx := context.WithValue(context.Background(), blockOperationKey{}, agentGuardBlockOperation(call, decision))
	attribution := deriveBlockAttribution(ctx, "evt_7", nil, "tool_attempt_blocked", "blocked tool call")
	notice := renderBlockNotice("命中内容：{detail}", attribution)
	if firstNoticeLine(notice) != "命中内容：shell_command · 删除文件：DB_PASSWORD=… rm -rf /srv/target" {
		t.Fatalf("提示应写与告警证据相同的命令骨架: %q", notice)
	}
	if strings.Contains(notice, "S3cretPw") || strings.Contains(notice, "个目标") {
		t.Fatalf("提示不应含命令里的密码，也不应退回“N 个目标”概括: %q", notice)
	}
	if retained := renderBlockNotice("命中内容：{detail}", retainedNoticeAttribution(attribution)); retained != notice {
		t.Fatalf("工具调用阻断的留存副本与提示相同（骨架本身已脱敏）: %q vs %q", retained, notice)
	}
}

func TestOriginalFragmentNeverReachesPersistedBlockRecord(t *testing.T) {
	finding := privateKeyFinding()
	finding.Category, finding.RawEvidence = "plain_password", "password=Example-Passw0rd"
	finding.RedactedEvidence = "password=Ex****rd（16 位）"
	ctx := withSecurityEventStage(context.Background(), "input")
	attribution := deriveBlockAttribution(ctx, "evt_8", []SecurityFinding{finding}, "security_blocked", "blocked input message 0")
	if attribution.NoticeDetail == "" {
		t.Fatal("前提：提示应带原文片段")
	}
	// matched_summary.block 与 request_logs 的 block 字段都是这个结构的 JSON，NoticeDetail 只在内存里。
	encoded, err := json.Marshal(attribution)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "Example-Passw0rd") || !strings.Contains(string(encoded), "password=Ex****rd（16 位）") {
		t.Fatalf("阻断记录只能存可读命中内容: %s", encoded)
	}
}

func TestSecurityReplyContentLogGetsRetainedCopyButClientGetsOriginalFragment(t *testing.T) {
	finding := privateKeyFinding()
	finding.Category, finding.RawEvidence = "plain_password", "password=Example-Passw0rd"
	finding.RedactedEvidence = "password=Ex****rd（16 位）"
	ctx := withSecurityEventStage(context.Background(), "input")
	attribution := deriveBlockAttribution(ctx, "evt_9", []SecurityFinding{finding}, "security_blocked", "blocked input message 0")
	notice := securityBlockNotice{
		Mode:         blockResponseModeMessage,
		Text:         renderBlockNotice(noticeTemplateForTest, attribution),
		RetainedText: renderBlockNotice(noticeTemplateForTest, retainedNoticeAttribution(attribution)),
		Attribution:  attribution,
	}
	audit := &MockAuditWriter{}
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{}}, nil, nil)
	result := &ProcessedRequestResult{
		Envelope:      &modelrouter.RequestEnvelope{RequestID: "req-retained", TenantID: "tenant-1", Model: "gpt-4"},
		SecurityReply: &SecurityReplyResult{Content: notice.Text, Notice: &notice},
		StartedAt:     time.Now(),
	}
	body := h.finalizeSecurityReply(context.Background(), result)
	if !strings.Contains(string(body), "Example-Passw0rd") {
		t.Fatalf("返回给使用者的回复应含原文片段: %s", body)
	}
	if len(audit.ContentLogWrites) != 1 {
		t.Fatalf("content logs=%+v", audit.ContentLogWrites)
	}
	logged := audit.ContentLogWrites[0].Content
	if strings.Contains(logged, "Example-Passw0rd") || !strings.Contains(logged, "password=Ex****rd（16 位）") {
		t.Fatalf("内容留存只能写可读命中内容: %q", logged)
	}
}

func TestOriginalFragmentOnlyForTheUsersOwnMessages(t *testing.T) {
	for _, source := range []string{"user", "user_history", "verified_user_input", " User ", "USER"} {
		finding := privateKeyFinding()
		finding.ContentSource = source
		ctx := withSecurityEventStage(context.Background(), "input")
		attribution := deriveBlockAttribution(ctx, "evt_s", []SecurityFinding{finding}, "security_blocked", "blocked input message 0")
		if got := firstNoticeLine(renderBlockNotice("命中内容：{detail}", attribution)); got != "命中内容：-----BEGIN RSA PRIVATE KEY-----" {
			t.Errorf("来源 %q 是使用者自己的消息，应回显原文: %q", source, got)
		}
	}
	for _, source := range []string{
		"system_prompt", "tool_result", "assistant_history", "tool_def", "file_attachment", "rag", "rag_context",
		"retrieval", "retrieval_result", "web_content", "unknown", "verified_final_output", "model_output", "assistant_tool_call", "",
	} {
		finding := privateKeyFinding()
		finding.ContentSource = source
		ctx := withSecurityEventStage(context.Background(), "input")
		attribution := deriveBlockAttribution(ctx, "evt_n", []SecurityFinding{finding}, "security_blocked", "blocked input message 0")
		shown := renderBlockNotice(noticeTemplateForTest, attribution)
		if strings.Contains(shown, "命中内容：-----BEGIN RSA PRIVATE KEY-----\n") || !strings.Contains(shown, "-----BEGIN RSA PRIVATE KEY-----（后续正文 96 字已隐藏）") {
			t.Errorf("来源 %q 不是使用者自己的消息，应写可读命中内容: %q", source, shown)
		}
		if retained := renderBlockNotice(noticeTemplateForTest, retainedNoticeAttribution(attribution)); retained != shown {
			t.Errorf("来源 %q 的留存副本应与提示相同: %q vs %q", source, retained, shown)
		}
	}
}

func TestInputBlockNoticeStripsControlAndFormatCharacters(t *testing.T) {
	finding := privateKeyFinding()
	finding.Category = "plain_password"
	// U+202E 双向覆盖、U+0000 空字符、U+200B 零宽空格、U+2066/U+2069 隔离符、U+200E/U+200F 方向标记、U+0007 响铃。
	finding.RawEvidence = "pass\u202eword=\u0000Exa\u200bmple\u2066-\u2069Pw\u200e0\u200frd\x07\tend\r\nnext"
	ctx := withSecurityEventStage(context.Background(), "input")
	attribution := deriveBlockAttribution(ctx, "evt_c", []SecurityFinding{finding}, "security_blocked", "blocked input message 0")
	notice := renderBlockNotice(noticeTemplateForTest, attribution)
	if got := firstNoticeLine(strings.SplitN(notice, "命中内容：", 2)[1]); got != "password=Example-Pw0rd end next" {
		t.Fatalf("控制字符和格式控制符应被去掉、空白压平: %q", got)
	}
	for _, r := range "\u202e\u0000\u200b\u2066\u2069\u200e\u200f\x07" {
		if strings.ContainsRune(notice, r) {
			t.Fatalf("提示里不应出现 %U: %q", r, notice)
		}
	}
}

func TestSecurityReplyWithNoticeNeverFallsBackToFullText(t *testing.T) {
	notice := securityBlockNotice{Mode: blockResponseModeMessage, Text: "完整提示 password=Example-Passw0rd", RetainedText: "", Attribution: blockAttribution{BlockID: "evt_r"}}
	audit := &MockAuditWriter{}
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{}}, nil, nil)
	result := &ProcessedRequestResult{
		Envelope:      &modelrouter.RequestEnvelope{RequestID: "req-empty-retained", TenantID: "tenant-1", Model: "gpt-4"},
		SecurityReply: &SecurityReplyResult{Content: notice.Text, Notice: &notice},
		StartedAt:     time.Now(),
	}
	body := h.finalizeSecurityReply(context.Background(), result)
	if !strings.Contains(string(body), "Example-Passw0rd") {
		t.Fatalf("返回给使用者的回复仍是完整提示: %s", body)
	}
	if len(audit.ContentLogWrites) != 1 || strings.Contains(audit.ContentLogWrites[0].Content, "Example-Passw0rd") {
		t.Fatalf("有提示时留存只能写副本（即使是空串）: %+v", audit.ContentLogWrites)
	}

	// 没有 Notice 的安全代答仍写 Content。
	audit2 := &MockAuditWriter{}
	h.auditWriter = audit2
	result.SecurityReply = &SecurityReplyResult{Content: "请求已被安全策略拦截。"}
	h.finalizeSecurityReply(context.Background(), result)
	if len(audit2.ContentLogWrites) != 1 || audit2.ContentLogWrites[0].Content != "请求已被安全策略拦截。" {
		t.Fatalf("安全代答应写 Content: %+v", audit2.ContentLogWrites)
	}
}
