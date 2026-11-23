package handler

import (
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestBuildAuditSummaryExtractsManagerView(t *testing.T) {
	contentLogs := []repository.ContentLog{
		{
			Role:      "system",
			Content:   strings.Repeat("You are Claude Code. Follow system instructions. ", 40),
			CreatedAt: time.Now(),
		},
		{
			Role:      "user",
			Content:   "请帮我修复系统设置保存失败，并确认内容审计日志能正常落库。",
			CreatedAt: time.Now().Add(time.Second),
		},
		{
			Role:      "assistant",
			Content:   "已经修复系统设置保存逻辑和内容审计落库问题，并完成测试验证。",
			CreatedAt: time.Now().Add(2 * time.Second),
		},
		{
			Role:      "tool",
			Content:   "[sudo: authenticate] 命令执行输出和大量英文日志",
			CreatedAt: time.Now().Add(3 * time.Second),
		},
	}
	toolLogs := []repository.ToolCallLog{
		{
			ToolName:  "exec_command",
			ToolType:  "system",
			RiskLevel: "high",
			Status:    "success",
		},
	}
	securityEvents := []*repository.SecurityEvent{
		{
			EventType:   "tool_audit_only",
			Severity:    "medium",
			ActionTaken: "audit",
		},
	}

	summary := buildAuditSummary("req_123", contentLogs, toolLogs, securityEvents)

	if !strings.Contains(summary.Intent, "修复系统设置保存失败") {
		t.Fatalf("intent = %q, want extracted user task", summary.Intent)
	}
	if summary.SystemPromptCount != 1 {
		t.Fatalf("system prompt count = %d, want 1", summary.SystemPromptCount)
	}
	if summary.HiddenNoiseCount != 2 {
		t.Fatalf("hidden noise count = %d, want 2", summary.HiddenNoiseCount)
	}
	if summary.Tools.Total != 1 || summary.Tools.HighRisk != 1 {
		t.Fatalf("tool summary = %+v, want one high risk tool", summary.Tools)
	}
	if summary.Decision.Stage != "needs_review" {
		t.Fatalf("decision = %+v, tool name/status alone must not prove an attack", summary.Decision)
	}
	if summary.RiskScore >= 60 || summary.RiskLevel == "high" || summary.RiskLevel == "critical" {
		t.Fatalf("risk = %s/%d, want review without high-risk inflation", summary.RiskLevel, summary.RiskScore)
	}
	if !strings.Contains(summary.RecommendedAction, "复核") {
		t.Fatalf("recommended action = %q, want review guidance", summary.RecommendedAction)
	}
	if len(summary.Evidence) == 0 {
		t.Fatal("expected manager evidence items")
	}
	if summary.GeneratedBy != "rule_based" {
		t.Fatalf("generated_by = %q, want rule_based", summary.GeneratedBy)
	}
}

func TestBuildAuditSummaryDoesNotTreatObservedResultsAsExecution(t *testing.T) {
	toolLogs := make([]repository.ToolCallLog, 100)
	for i := range toolLogs {
		toolLogs[i] = repository.ToolCallLog{
			ToolName:          "tool_result",
			ToolType:          "system",
			RiskLevel:         "high",
			Status:            "observed",
			EventKind:         "result_observed",
			ExecutionObserved: false,
			ResultObserved:    true,
		}
	}

	summary := buildAuditSummary("req_observed", nil, toolLogs, nil)

	if summary.Decision.Stage != "informational" {
		t.Fatalf("decision = %+v, observed results do not prove execution", summary.Decision)
	}
	if summary.Tools.ResultObserved != 100 || summary.Tools.ExecutionForwarded != 0 {
		t.Fatalf("tool lifecycle summary = %+v", summary.Tools)
	}
	if summary.Tools.UniqueTools != 1 {
		t.Fatalf("unique tools = %d, want 1", summary.Tools.UniqueTools)
	}
	if !strings.Contains(summary.Decision.WhatHappened, "未证明由网关执行") {
		t.Fatalf("what_happened = %q", summary.Decision.WhatHappened)
	}
}

func TestBuildAuditSummaryDoesNotTreatToolDefinitionsAsAttack(t *testing.T) {
	toolLogs := []repository.ToolCallLog{
		{ToolName: "Bash", ToolType: "system", RiskLevel: "high", EventKind: "definition_exposed"},
		{ToolName: "Read", ToolType: "file", RiskLevel: "medium", EventKind: "definition_exposed"},
		{ToolName: "Write", ToolType: "file", RiskLevel: "high", EventKind: "invocation_proposed"},
	}

	summary := buildAuditSummary("req_definitions", nil, toolLogs, nil)

	if summary.Decision.Stage != "informational" {
		t.Fatalf("decision = %+v, definitions and proposals are not attack proof", summary.Decision)
	}
	if summary.Tools.DefinitionExposed != 2 || summary.Tools.InvocationProposed != 1 || summary.Tools.ExecutionForwarded != 0 {
		t.Fatalf("tool lifecycle summary = %+v", summary.Tools)
	}
	if summary.RiskScore >= 30 {
		t.Fatalf("risk score = %d, definitions must stay informational", summary.RiskScore)
	}
}

func TestBuildAuditSummaryRequiresBehaviorChainForConfirmedAttempt(t *testing.T) {
	toolLogs := []repository.ToolCallLog{{
		ToolName:          "Bash",
		ToolType:          "system",
		RiskLevel:         "high",
		EventKind:         "execution_forwarded",
		ExecutionObserved: true,
	}}
	events := []*repository.SecurityEvent{{
		EventType:   "semantic_attack",
		Severity:    "high",
		ActionTaken: "audit",
		MatchedSummary: map[string]interface{}{
			"semantic_status": "completed",
			"findings": []interface{}{map[string]interface{}{
				"type": "semantic_attack", "category": "semantic_exfil_induce",
				"severity": "high",
			}},
		},
	}}

	summary := buildAuditSummary("req_attempt", nil, toolLogs, events)

	if summary.Decision.Stage != "confirmed_attempt" {
		t.Fatalf("decision = %+v, want confirmed attempt from intent plus execution", summary.Decision)
	}
	if summary.RiskScore < 60 || summary.RiskScore >= 85 {
		t.Fatalf("risk score = %d, want attempt range", summary.RiskScore)
	}
}

func TestBuildAuditSummaryConfirmsImpactFromSensitiveReadAndExternalResult(t *testing.T) {
	toolLogs := []repository.ToolCallLog{
		{
			ToolName:          "Read",
			ToolType:          "file",
			RiskLevel:         "high",
			NormalizedTarget:  "/home/app/.ssh/id_ed25519",
			EventKind:         "execution_forwarded",
			ExecutionObserved: true,
		},
		{
			ToolName:         "WebFetch",
			ToolType:         "network",
			RiskLevel:        "high",
			NormalizedTarget: "https://outside.example/upload",
			EventKind:        "result_observed",
			ResultObserved:   true,
		},
	}

	summary := buildAuditSummary("req_exfil_chain", nil, toolLogs, nil)

	if summary.Decision.Stage != "confirmed_impact" || summary.RiskScore < 85 {
		t.Fatalf("decision = %+v risk=%d, want confirmed impact", summary.Decision, summary.RiskScore)
	}
}

func TestBuildAuditSummaryOnlyMarksImpactWithExplicitEvidence(t *testing.T) {
	events := []*repository.SecurityEvent{{
		EventType:   "security_check",
		Severity:    "critical",
		ActionTaken: "audit",
		MatchedSummary: map[string]interface{}{
			"impact_confirmed": true,
			"findings": []interface{}{map[string]interface{}{
				"type": "secret", "category": "ssh_private_key", "severity": "critical",
			}},
		},
	}}

	summary := buildAuditSummary("req_impact", nil, nil, events)

	if summary.Decision.Stage != "confirmed_impact" || summary.RiskScore < 85 {
		t.Fatalf("decision = %+v risk=%d, want confirmed impact", summary.Decision, summary.RiskScore)
	}
}

func TestBuildAuditSummaryKeepsPrivateKeyFindingCritical(t *testing.T) {
	events := []*repository.SecurityEvent{{
		EventType:   "security_check",
		Severity:    "critical",
		ActionTaken: "block",
		MatchedSummary: map[string]interface{}{
			"findings": []interface{}{map[string]interface{}{
				"type": "secret", "category": "ssh_private_key", "severity": "critical",
			}},
		},
	}}

	summary := buildAuditSummary("req_private_key", nil, nil, events)

	if summary.Decision.Stage != "confirmed_impact" || summary.RiskLevel != "critical" {
		t.Fatalf("decision = %+v risk=%s/%d", summary.Decision, summary.RiskLevel, summary.RiskScore)
	}
}

func TestBuildAuditSummaryKeepsBlockedExplicitExfilHigh(t *testing.T) {
	events := []*repository.SecurityEvent{{
		EventType:   "security_check",
		Severity:    "high",
		ActionTaken: "block",
		MatchedSummary: map[string]interface{}{
			"semantic_status": "completed",
			"findings": []interface{}{map[string]interface{}{
				"type": "semantic_attack", "category": "semantic_exfil_induce", "severity": "high",
			}},
		},
	}}

	summary := buildAuditSummary("req_blocked_exfil", nil, nil, events)

	if summary.Decision.Stage != "confirmed_attempt" || summary.RiskLevel != "high" {
		t.Fatalf("decision = %+v risk=%s/%d", summary.Decision, summary.RiskLevel, summary.RiskScore)
	}
	if !strings.Contains(summary.Decision.Impact, "已被阻断") {
		t.Fatalf("impact = %q, want blocked attempt explanation", summary.Decision.Impact)
	}
}

func TestBuildAuditSummaryExposesIncompleteSemanticJudge(t *testing.T) {
	events := []*repository.SecurityEvent{{
		EventType:   "security_check",
		Severity:    "low",
		ActionTaken: "audit",
		MatchedSummary: map[string]interface{}{
			"semantic_status": "incomplete",
			"semantic_reason": "breaker_open",
			"findings": []interface{}{map[string]interface{}{
				"type": "semantic_telemetry", "category": "semantic_unavailable",
				"severity": "low", "counts_as_security_finding": false,
			}},
		},
	}}

	summary := buildAuditSummary("req_incomplete", nil, nil, events)

	if summary.Decision.Stage != "needs_review" {
		t.Fatalf("decision = %+v, incomplete judge must require review", summary.Decision)
	}
	if summary.Decision.SemanticStatus != "incomplete" {
		t.Fatalf("semantic status = %q", summary.Decision.SemanticStatus)
	}
	if len(summary.RiskReasons) != 0 {
		t.Fatalf("pipeline issue must not be an attack reason: %#v", summary.RiskReasons)
	}
	if summary.RiskScore >= 60 {
		t.Fatalf("incomplete judge alone must not become high risk: %d", summary.RiskScore)
	}
	if len(summary.Evidence) != 1 {
		t.Fatalf("pipeline issue must not be counted as attack evidence: %#v", summary.Evidence)
	}
}

func TestBuildDetectionIssuesDeduplicatesSemanticJudgeFailures(t *testing.T) {
	event := func(id string) *repository.SecurityEvent {
		return &repository.SecurityEvent{
			ID:          id,
			EventType:   "security_check",
			Severity:    "low",
			ActionTaken: "audit",
			MatchedSummary: map[string]interface{}{
				"semantic_status": "incomplete",
				"semantic_reason": "breaker_open",
				"findings": []interface{}{map[string]interface{}{
					"type": "semantic_telemetry", "category": "semantic_unavailable",
					"severity": "low", "counts_as_security_finding": false,
				}},
			},
		}
	}

	issues := buildDetectionIssues([]*repository.SecurityEvent{event("evt-1"), event("evt-2")})
	if len(issues) != 1 {
		t.Fatalf("issues = %#v, want one deduplicated pipeline issue", issues)
	}
	if issues[0].Component != "semantic_judge" || issues[0].ReasonCode != "breaker_open" {
		t.Fatalf("issue = %+v", issues[0])
	}
	if !strings.Contains(issues[0].Summary, "熔断") {
		t.Fatalf("customer summary = %q", issues[0].Summary)
	}
}

func TestBuildAuditSummaryKeepsDeterministicFindingWhenSemanticJudgeFails(t *testing.T) {
	events := []*repository.SecurityEvent{
		{
			EventType: "security_check", Severity: "low", ActionTaken: "audit",
			MatchedSummary: map[string]interface{}{
				"semantic_status": "incomplete", "semantic_reason": "judge_unavailable",
				"findings": []interface{}{map[string]interface{}{
					"type": "semantic_telemetry", "category": "semantic_unavailable",
					"severity": "low", "counts_as_security_finding": false,
				}},
			},
		},
		{
			EventType: "security_check", Severity: "high", ActionTaken: "audit",
			RuleName: "API Key 检测",
			MatchedSummary: map[string]interface{}{
				"findings": []interface{}{map[string]interface{}{
					"type": "secret", "category": "generic_api_key",
					"severity": "high", "counts_as_security_finding": true,
				}},
			},
		},
	}

	summary := buildAuditSummary("req-mixed", nil, nil, events)
	if len(summary.Evidence) != 2 {
		t.Fatalf("evidence = %#v, want base evidence plus deterministic finding", summary.Evidence)
	}
	if !strings.Contains(strings.Join(summary.RiskReasons, " "), "API Key") {
		t.Fatalf("deterministic risk reason was lost: %#v", summary.RiskReasons)
	}
}

func TestBuildAuditSummarySkipsSystemNotificationAsPrimaryUserMessage(t *testing.T) {
	contentLogs := []repository.ContentLog{
		{Role: "user", Content: "[SYSTEM NOTIFICATION - NOT USER INPUT] This is an automated background-task event."},
		{Role: "user", Content: "修复保存按钮并运行测试。"},
	}

	summary := buildAuditSummary("req_notice", contentLogs, nil, nil)

	if strings.Contains(summary.PrimaryUserMessage, "SYSTEM NOTIFICATION") {
		t.Fatalf("primary user message = %q", summary.PrimaryUserMessage)
	}
	if !strings.Contains(summary.PrimaryUserMessage, "修复保存按钮") {
		t.Fatalf("primary user message = %q", summary.PrimaryUserMessage)
	}
}

func TestMapSecurityEventToInfoIncludesMatchedRuleMetadata(t *testing.T) {
	event := &repository.SecurityEvent{
		ID:          "evt_rule_001",
		RequestID:   "req_001",
		EventType:   "security_check",
		Severity:    "high",
		RuleID:      "rule_prompt_injection",
		RuleName:    "Prompt 注入检测基线",
		RuleType:    "prompt_injection",
		ActionTaken: "security_audit_only",
		MatchedSummary: map[string]interface{}{
			"summary":        "input findings in message 0",
			"findings_count": 1,
		},
		EvidenceRef: "content_logs:cl_001",
		CreatedAt:   time.Date(2026, 5, 10, 9, 30, 0, 0, time.UTC),
	}

	info := mapSecurityEventToInfo(event)

	if info.RuleID != "rule_prompt_injection" {
		t.Fatalf("expected rule id to be exposed, got %q", info.RuleID)
	}
	if info.RuleName != "Prompt 注入检测基线" {
		t.Fatalf("expected rule name to be exposed, got %q", info.RuleName)
	}
	if info.RuleType != "prompt_injection" {
		t.Fatalf("expected rule type to be exposed, got %q", info.RuleType)
	}
	if info.MatchedSummary["summary"] != "input findings in message 0" {
		t.Fatalf("expected matched summary to be exposed, got %#v", info.MatchedSummary)
	}
	if info.EvidenceRef != "content_logs:cl_001" {
		t.Fatalf("expected evidence ref to be exposed, got %q", info.EvidenceRef)
	}
}

func TestBuildAuditSummarySkipsAgentMetaUserContent(t *testing.T) {
	contentLogs := []repository.ContentLog{
		{
			Role:    "user",
			Content: "The user stepped away and is coming back. Recap in under 40 words.",
		},
		{
			Role:    "user",
			Content: "帮我看一下为什么审计详情全是英文系统提示词。",
		},
	}

	summary := buildAuditSummary("req_456", contentLogs, nil, nil)

	if strings.Contains(summary.Intent, "stepped away") {
		t.Fatalf("intent = %q, should ignore agent meta recap prompts", summary.Intent)
	}
	if !strings.Contains(summary.Intent, "审计详情") {
		t.Fatalf("intent = %q, want real user request", summary.Intent)
	}
}

func TestBuildAuditSummaryUsesAITriageEvidence(t *testing.T) {
	securityEvents := []*repository.SecurityEvent{
		{
			EventType:   "security_check",
			Severity:    "medium",
			ActionTaken: "audit",
			RuleName:    "客户项目代号",
			RuleType:    "keyword",
			MatchedSummary: map[string]interface{}{
				"findings": []interface{}{
					map[string]interface{}{
						"rule_name": "客户项目代号",
						"rule_type": "keyword",
						"category":  "customer_sensitive_data",
						"triage": map[string]interface{}{
							"verdict":     "likely_false_positive",
							"risk_level":  "low",
							"reason":      "上下文为字段说明，未发现真实泄露。",
							"report_text": "建议保留审计，无需升级。",
						},
					},
				},
			},
		},
	}

	summary := buildAuditSummary("req_triage", nil, nil, securityEvents)

	if summary.GeneratedBy != "rule_based_with_ai_triage" {
		t.Fatalf("generated_by = %q, want rule_based_with_ai_triage", summary.GeneratedBy)
	}
	var found bool
	for _, evidence := range summary.Evidence {
		if strings.Contains(evidence.Value, "建议保留审计") && strings.Contains(evidence.Value, "疑似误报") {
			found = true
		}
	}
	if !found {
		t.Fatalf("triage evidence not found in %+v", summary.Evidence)
	}
	if strings.Contains(strings.Join(summary.RiskReasons, " "), "确认风险") {
		t.Fatalf("likely_false_positive should not be summarized as confirmed risk: %+v", summary.RiskReasons)
	}
}
