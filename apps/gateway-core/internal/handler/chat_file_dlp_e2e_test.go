package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// spySecurityChecker 记录 CheckInput 收到的 ctx 上的 attachments（验证附件真实进入 CheckInput 调用）。
type spySecurityChecker struct {
	action     string
	calls      int
	gotAtts    []map[string]interface{}
	gotContent []string
	findings   []SecurityFinding
	err        error
}

func (s *spySecurityChecker) CheckInput(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, contentSource string) (string, string, []SecurityFinding, error) {
	s.calls++
	s.gotContent = append(s.gotContent, content)
	s.gotAtts = attachmentsFromContext(ctx)
	if s.err != nil {
		return "", "", nil, s.err
	}
	a := s.action
	if a == "" {
		a = "allow"
	}
	return a, "", s.findings, nil
}
func (s *spySecurityChecker) CheckOutput(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, choiceIndex int) (string, string, []SecurityFinding, error) {
	return "allow", "", nil, nil
}
func (s *spySecurityChecker) CheckSemanticOnly(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string) ([]SecurityFinding, error) {
	return nil, nil
}
func (s *spySecurityChecker) CheckTriage(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, findings []SecurityFinding) ([]SecurityFinding, error) {
	return findings, nil
}
func (s *spySecurityChecker) CheckInputDetailed(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, contentSource string) (*InputCheckOutcome, error) {
	a, masked, findings, err := s.CheckInput(ctx, envelope, content, messageIndex, messageRole, contentSource)
	if err != nil {
		return nil, err
	}
	return &InputCheckOutcome{Action: a, MaskedContent: masked, Findings: findings}, nil
}
func (s *spySecurityChecker) ApplyContext(ctx context.Context, envelope *modelrouter.RequestEnvelope, rawFindings json.RawMessage, contentSource string) (string, []SecurityFinding, error) {
	return "allow", nil, nil
}

// 合成一个最小 docx（含手机号+身份证文本），返回 data URL base64。
func synthDocxBase64(t *testing.T) string {
	t.Helper()
	// 真实 docx 需 ZIP；这里用 text/plain 块也能验证"附件进入 CheckInput 且开启时阻断"。
	// docx 真实正文提取由 security-engine 负责（gateway 只送字节）。
	return "data:text/plain;base64," + base64Std("联系手机13812345678 证件110101199001010015")
}

func base64Std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// 含 docx（text 代表）附件的 input_file 块消息
func docxAttachmentMessage(t *testing.T) json.RawMessage {
	b64 := synthDocxBase64(t)
	content := `[{"type":"input_file","file_data":{"base64":"` + strings.TrimPrefix(b64, "data:text/plain;base64,") + `","mime_type":"text/plain"},"filename":"secret.txt"}]`
	return json.RawMessage(content)
}

func TestApplyInputSecurity_DocxAttachmentEnabledBlocksAndReachesCheck(t *testing.T) {
	os.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	t.Cleanup(func() { os.Unsetenv("SECURITY_FILE_CONTENT_DLP_ENABLED") })

	spy := &spySecurityChecker{action: "block"}
	h := &ChatCompletionsHandler{
		securityClient: spy,
		auditWriter:    &MockAuditWriter{},
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "r1", TenantID: "tenant_default", ProjectID: "project_default", Model: "m"}
	req := &ChatCompletionRequest{
		Model:    "m",
		Messages: []Message{{Role: "user", Content: docxAttachmentMessage(t)}},
	}
	_, err := h.applyInputSecurity(context.Background(), envelope, req)
	// action=block → applyInputSecurity 返回 error（中断 provider 路径 = provider 调用 0 次）
	if err == nil {
		t.Fatal("docx 含敏感内容开启 DLP 应阻断（返回 error），provider 不应被调用")
	}
	if spy.calls == 0 {
		t.Fatal("CheckInput 未被调用：附件消息没进入检测链路")
	}
	if len(spy.gotAtts) == 0 {
		t.Fatal("附件未进入 CheckInput 的 ctx（附件接线断了）")
	}
	// 证明送进去的是文件附件（含 data_base64）
	if spy.gotAtts[0]["data_base64"] == "" {
		t.Fatalf("CheckInput 收到的附件无 data_base64: %+v", spy.gotAtts[0])
	}
}

// A file cannot be masked. The configured action is "mask", not "block": the
// original file is forwarded and a mask-unavailable alert is recorded.
func TestApplyInputSecurity_FileMaskIsForwardedWithAlert(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")

	spy := &spySecurityChecker{action: "mask"}
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		securityClient: spy,
		auditWriter:    audit,
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "r-file-mask", TenantID: "tenant_default", ProjectID: "project_default", Model: "m"}
	req := &ChatCompletionRequest{
		Model:    "m",
		Messages: []Message{{Role: "user", Content: docxAttachmentMessage(t)}},
	}

	original := req.Messages[0].Content
	if _, err := h.applyInputSecurity(context.Background(), envelope, req); err != nil {
		t.Fatalf("文件附件无法脱敏时应放行原文件并告警，got %v", err)
	}
	if string(req.Messages[0].Content) != string(original) {
		t.Fatal("the original attachment must be forwarded unchanged")
	}
	alerted := false
	for _, event := range audit.SecurityEventWrites {
		alerted = alerted || (event.ActionTaken == "security_audit" && event.MaskUnavailable)
	}
	if !alerted {
		t.Fatalf("mask-unavailable alert missing: %+v", audit.SecurityEventWrites)
	}
}

func TestApplyInputSecurity_AuditOnlyAllowsFileFinding(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")

	spy := &spySecurityChecker{
		action: "audit",
		findings: []SecurityFinding{{
			Type:          "pii",
			Category:      "phone_cn",
			ContentSource: "file_attachment",
		}},
	}
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{SecurityAuditOnly: true},
		securityClient: spy,
		auditWriter:    &MockAuditWriter{},
	}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "r-file-audit-only",
		TenantID:  "tenant_default",
		ProjectID: "project_default",
		Model:     "m",
	}
	req := &ChatCompletionRequest{
		Model:    "m",
		Messages: []Message{{Role: "user", Content: docxAttachmentMessage(t)}},
	}

	if _, err := h.applyInputSecurity(context.Background(), envelope, req); err != nil {
		t.Fatal("audit-only 不能放行命中文件 DLP 的附件")
	}
}

// 审计模式最高优先级：文件类型"阻断"也只记录。
func TestApplyInputSecurity_AuditOnlyRecordsExplicitFileTypePolicy(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")

	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		cfg: &config.Config{SecurityAuditOnly: true},
		securityClient: &spySecurityChecker{
			action: "audit",
			findings: []SecurityFinding{{
				Type:     "file",
				Category: "file_policy_blocked_type",
				RuleID:   "file-policy-blocked-type",
				Action:   "block",
			}},
		},
		auditWriter: audit,
	}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "r-file-explicit-block-audit-only",
		TenantID:  "tenant_default",
		ProjectID: "project_default",
		Model:     "m",
	}
	req := &ChatCompletionRequest{
		Model:    "m",
		Messages: []Message{{Role: "user", Content: docxAttachmentMessage(t)}},
	}

	if _, err := h.applyInputSecurity(context.Background(), envelope, req); err != nil {
		t.Fatalf("audit-only must record, not block, an explicit file type: %v", err)
	}
	if hasSecurityEvent(audit, "security_blocked") || !hasSecurityEvent(audit, "security_audit_only") {
		t.Fatalf("explicit file type must be kept as audit evidence: %+v", audit.SecurityEventWrites)
	}
}

func TestApplyInputSecurity_AuditOnlyAllowsTerminalFileActions(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")

	for _, action := range []string{"deny", "quarantine", "redact"} {
		t.Run(action, func(t *testing.T) {
			audit := &MockAuditWriter{}
			h := &ChatCompletionsHandler{
				cfg: &config.Config{SecurityAuditOnly: true},
				securityClient: &spySecurityChecker{
					action: action,
				},
				auditWriter: audit,
			}
			envelope := &modelrouter.RequestEnvelope{
				RequestID: "r-file-audit-terminal-" + action,
				TenantID:  "tenant_default",
				ProjectID: "project_default",
				Model:     "m",
			}
			req := &ChatCompletionRequest{
				Model:    "m",
				Messages: []Message{{Role: "user", Content: docxAttachmentMessage(t)}},
			}

			if _, err := h.applyInputSecurity(context.Background(), envelope, req); err != nil {
				t.Fatalf("audit-only action=%s must retain and forward the file: %v", action, err)
			}
			if !hasSecurityEvent(audit, "security_audit_only") {
				t.Fatalf("audit-only action=%s was not retained: %+v", action, audit.SecurityEventWrites)
			}
		})
	}
}

func TestApplyInputSecurity_FilenameOnlyFileBlockReachesSecurityChecker(t *testing.T) {
	spy := &spySecurityChecker{action: "block"}
	h := &ChatCompletionsHandler{
		securityClient: spy,
		auditWriter:    &MockAuditWriter{},
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "r-filename-only", TenantID: "tenant_default", ProjectID: "project_default", Model: "m"}
	req := &ChatCompletionRequest{
		Model:    "m",
		Messages: []Message{{Role: "user", Content: json.RawMessage(`[{"type":"file","filename":"report.pdf"}]`)}},
	}

	if _, err := h.applyInputSecurity(context.Background(), envelope, req); err == nil {
		t.Fatal("filename-only blocked file metadata must stop upstream forwarding")
	}
	if spy.calls != 1 || len(spy.gotAtts) != 1 {
		t.Fatalf("filename-only metadata did not reach security checker: calls=%d attachments=%+v", spy.calls, spy.gotAtts)
	}
	if spy.gotAtts[0]["file_name"] != "report.pdf" || spy.gotAtts[0]["content_type"] != "application/pdf" {
		t.Fatalf("filename-only metadata mismatch: %+v", spy.gotAtts[0])
	}
}

func TestApplyInputSecurity_ContentDLPDisabledStillScansAttachmentType(t *testing.T) {
	os.Unsetenv("SECURITY_FILE_CONTENT_DLP_ENABLED")
	spy := &spySecurityChecker{action: "audit"}
	h := &ChatCompletionsHandler{
		securityClient: spy,
		auditWriter:    &MockAuditWriter{},
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "r1", TenantID: "tenant_default", ProjectID: "project_default", Model: "m"}
	// 正文 DLP 关闭只跳过正文提取，文件类型策略仍须拿到原始附件。
	req := &ChatCompletionRequest{
		Model:    "m",
		Messages: []Message{{Role: "user", Content: docxAttachmentMessage(t)}},
	}
	_, err := h.applyInputSecurity(context.Background(), envelope, req)
	if err != nil {
		t.Fatalf("正文 DLP 关闭时的文件类型审计不应阻断: %v", err)
	}
	if spy.calls != 1 {
		t.Fatalf("正文 DLP 关闭时纯附件仍应触发一次类型检查, got %d calls", spy.calls)
	}
	if len(spy.gotAtts) != 1 {
		t.Fatalf("文件类型检查必须收到原始附件, got %+v", spy.gotAtts)
	}
}

func TestApplyInputSecurity_ContentDLPDisabledFileTypeBlockStopsUpload(t *testing.T) {
	os.Unsetenv("SECURITY_FILE_CONTENT_DLP_ENABLED")
	spy := &spySecurityChecker{action: "block"}
	h := &ChatCompletionsHandler{
		securityClient: spy,
		auditWriter:    &MockAuditWriter{},
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "r-file-type-block", TenantID: "tenant_default", ProjectID: "project_default", Model: "m"}
	req := &ChatCompletionRequest{
		Model:    "m",
		Messages: []Message{{Role: "user", Content: docxAttachmentMessage(t)}},
	}

	if _, err := h.applyInputSecurity(context.Background(), envelope, req); err == nil {
		t.Fatal("正文 DLP 关闭时命中文件类型阻断策略仍必须中断上游发送")
	}
	if spy.calls != 1 || len(spy.gotAtts) != 1 {
		t.Fatalf("文件类型阻断必须基于真实附件检查, calls=%d attachments=%+v", spy.calls, spy.gotAtts)
	}
}

func TestApplyInputSecurity_AuditOnlyAttachmentEngineFailureAllows(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	spy := &spySecurityChecker{err: errors.New("engine unavailable")}
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{SecurityAuditOnly: true},
		securityClient: spy,
		auditWriter:    &MockAuditWriter{},
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "r-file-audit-engine-error", TenantID: "tenant_default", ProjectID: "project_default", Model: "m"}
	req := &ChatCompletionRequest{
		Model:    "m",
		Messages: []Message{{Role: "user", Content: docxAttachmentMessage(t)}},
	}

	if _, err := h.applyInputSecurity(context.Background(), envelope, req); err != nil {
		t.Fatalf("审计模式下附件检测引擎异常不得中断业务: %v", err)
	}
	if spy.calls != 1 {
		t.Fatalf("附件引擎异常仍应产生一次审计检查, got %d calls", spy.calls)
	}
}

func TestApplyInputSecurity_PureTextMessageAlwaysChecked(t *testing.T) {
	// 普通文字消息无论 DLP 开关都照常检测（不受文件 DLP 影响）
	os.Unsetenv("SECURITY_FILE_CONTENT_DLP_ENABLED")
	spy := &spySecurityChecker{action: "allow"}
	h := &ChatCompletionsHandler{securityClient: spy, auditWriter: &MockAuditWriter{}}
	envelope := &modelrouter.RequestEnvelope{RequestID: "r1", TenantID: "tenant_default", ProjectID: "project_default", Model: "m"}
	req := &ChatCompletionRequest{Model: "m", Messages: []Message{{Role: "user", Content: jsonQuote("hello text message")}}}
	h.applyInputSecurity(context.Background(), envelope, req)
	if spy.calls == 0 {
		t.Fatal("普通文字消息应照常 CheckInput")
	}
}

// An attachment the engine could not inspect is an inspection anomaly: it is
// recorded (security_check_failed) and forwarded; only a file-type policy the
// administrator set to "禁止发送" blocks a file.
func TestApplyInputSecurity_FileRequestEngineFailureIsRecordedNotBlocked(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	spy := &spySecurityChecker{err: errors.New("engine unavailable")}
	h := &ChatCompletionsHandler{
		securityClient: spy,
		auditWriter:    &MockAuditWriter{},
	}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "r-file-error", TenantID: "tenant_default",
		ProjectID: "project_default", Model: "m",
	}
	req := &ChatCompletionRequest{
		Model: "m",
		Messages: []Message{{
			Role: "user", Content: docxAttachmentMessage(t),
		}},
	}

	audit := h.auditWriter.(*MockAuditWriter)
	if _, err := h.applyInputSecurity(context.Background(), envelope, req); err != nil {
		t.Fatalf("附件检测异常必须放行并记录，got %v", err)
	}
	recorded := false
	for _, ev := range audit.SecurityEventWrites {
		if ev.ActionTaken == "security_check_failed" {
			recorded = true
		}
	}
	if !recorded {
		t.Fatalf("附件检测异常必须留下 security_check_failed 记录，got %#v", audit.SecurityEventWrites)
	}
}
