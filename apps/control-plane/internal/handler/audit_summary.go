package handler

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

const summaryTextLimit = 180

func buildAuditSummary(requestID string, contentLogs []repository.ContentLog, toolLogs []repository.ToolCallLog, securityEvents []*repository.SecurityEvent) types.AuditSummaryInfo {
	sortedContent := append([]repository.ContentLog(nil), contentLogs...)
	sort.SliceStable(sortedContent, func(i, j int) bool {
		return sortedContent[i].CreatedAt.Before(sortedContent[j].CreatedAt)
	})

	rawCount := len(sortedContent)
	systemPromptCount := 0
	hiddenNoiseCount := 0
	var firstUser, fallbackUser, assistant string
	var contentRiskReasons []string

	for _, item := range sortedContent {
		role := strings.ToLower(strings.TrimSpace(item.Role))
		content := normalizeAuditText(item.Content)
		if content == "" {
			continue
		}

		if role == "system" {
			systemPromptCount++
			hiddenNoiseCount++
			continue
		}
		if role == "tool" {
			hiddenNoiseCount++
			continue
		}

		if role == "user" {
			if fallbackUser == "" {
				fallbackUser = content
			}
			if firstUser == "" && !isAgentMetaPrompt(content) {
				firstUser = content
			}
			contentRiskReasons = append(contentRiskReasons, detectSensitiveContentRisk(content)...)
			continue
		}

		if role == "assistant" && assistant == "" {
			assistant = content
			contentRiskReasons = append(contentRiskReasons, detectSensitiveContentRisk(content)...)
		}
	}

	if firstUser == "" {
		firstUser = fallbackUser
	}

	intent := summarizeIntent(firstUser)
	assistantSummary := summarizeAssistant(assistant)
	toolSummary, toolRiskReasons := summarizeTools(toolLogs)
	eventEvidence, eventRiskReasons, _, hasAITriage := summarizeSecurityEvents(securityEvents)
	riskReasons := uniqueStrings(append(append(toolRiskReasons, eventRiskReasons...), contentRiskReasons...))
	decision, riskScore := buildAuditDecision(toolLogs, securityEvents, contentRiskReasons)
	riskLevel := riskLevelFromScore(riskScore)

	evidence := []types.AuditEvidenceInfo{
		{Label: "原始内容记录", Value: fmt.Sprintf("%d 条，默认隐藏系统/工具噪音 %d 条", rawCount, hiddenNoiseCount), Severity: "low"},
	}
	if toolSummary.Total > 0 {
		evidence = append(evidence, types.AuditEvidenceInfo{Label: "工具行为", Value: toolSummary.Summary, Severity: riskLevel})
	}
	evidence = append(evidence, eventEvidence...)
	if len(evidence) == 0 {
		evidence = append(evidence, types.AuditEvidenceInfo{Label: "请求", Value: requestID, Severity: "low"})
	}

	generatedBy := "rule_based"
	if hasAITriage {
		generatedBy = "rule_based_with_ai_triage"
	}

	return types.AuditSummaryInfo{
		Title:              buildAuditTitle(intent, riskLevel),
		Intent:             intent,
		Outcome:            summarizeOutcome(assistant, securityEvents),
		BusinessSummary:    buildBusinessSummary(intent, assistantSummary, toolSummary, riskLevel),
		RiskLevel:          riskLevel,
		RiskScore:          riskScore,
		RiskReasons:        riskReasons,
		RecommendedAction:  decision.NextAction,
		Tags:               buildTags(toolLogs, securityEvents, contentLogs),
		PrimaryUserMessage: truncateRunes(firstUser, 260),
		AssistantSummary:   assistantSummary,
		SystemPromptCount:  systemPromptCount,
		RawContentCount:    rawCount,
		HiddenNoiseCount:   hiddenNoiseCount,
		Evidence:           evidence,
		Tools:              toolSummary,
		Decision:           decision,
		GeneratedBy:        generatedBy,
	}
}

func normalizeAuditText(text string) string {
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\n", " ")
	return strings.Join(strings.Fields(text), " ")
}

func isAgentMetaPrompt(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	metaPrefixes := []string{
		"[system notification - not user input]",
		"the user stepped away",
		"recap in under",
		"we need continue",
		"continue from the previous",
	}
	for _, prefix := range metaPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return strings.Contains(lower, "<system-reminder>")
}

func summarizeIntent(userText string) string {
	if userText == "" {
		return "未识别到明确的用户业务意图，建议查看原始内容记录。"
	}
	return truncateRunes(userText, summaryTextLimit)
}

func summarizeAssistant(text string) string {
	if text == "" {
		return "未记录到模型回复内容。"
	}
	if containsCJK(text) {
		return truncateRunes(text, summaryTextLimit)
	}
	return fmt.Sprintf("模型返回英文响应，长度约 %d 字符；默认隐藏长原文，可在内容记录中展开查看。", len(text))
}

func summarizeOutcome(assistant string, events []*repository.SecurityEvent) string {
	for _, event := range events {
		if strings.EqualFold(event.ActionTaken, "block") || strings.Contains(strings.ToLower(event.EventType), "blocked") {
			return "请求触发安全策略并被阻断。"
		}
	}
	if assistant != "" {
		return "模型已返回响应，请结合风险结论和工具行为确认是否符合预期。"
	}
	return "请求已记录，但未发现模型回复内容。"
}

func buildBusinessSummary(intent, assistantSummary string, tools types.AuditToolSummaryInfo, riskLevel string) string {
	if tools.Total > 0 {
		return fmt.Sprintf("本次请求围绕“%s”展开，涉及 %s。当前风险等级为%s，模型响应摘要：%s", intent, tools.Summary, riskLevelLabel(riskLevel), assistantSummary)
	}
	return fmt.Sprintf("本次请求围绕“%s”展开。当前风险等级为%s，模型响应摘要：%s", intent, riskLevelLabel(riskLevel), assistantSummary)
}

func summarizeTools(toolLogs []repository.ToolCallLog) (types.AuditToolSummaryInfo, []string) {
	if len(toolLogs) == 0 {
		return types.AuditToolSummaryInfo{Summary: "未记录到工具调用。"}, nil
	}

	typeSet := map[string]struct{}{}
	toolCount := map[string]int{}
	highRisk := 0
	definitionExposed := 0
	invocationProposed := 0
	executionForwarded := 0
	resultObserved := 0
	var reasons []string
	for _, tool := range toolLogs {
		typeSet[toolTypeLabel(tool.ToolType)] = struct{}{}
		toolName := strings.TrimSpace(tool.ToolName)
		if toolName == "" {
			toolName = "未知工具"
		}
		toolCount[toolName]++
		switch strings.ToLower(tool.RiskLevel) {
		case "high", "critical":
			highRisk++
		}
		switch normalizedToolEventKind(tool) {
		case "definition_exposed":
			definitionExposed++
		case "invocation_proposed":
			invocationProposed++
		case "execution_forwarded":
			executionForwarded++
			if strings.EqualFold(tool.RiskLevel, "high") || strings.EqualFold(tool.RiskLevel, "critical") {
				reasons = append(reasons, fmt.Sprintf("已转发%s风险工具执行：%s", riskLevelLabel(tool.RiskLevel), toolName))
			}
		case "result_observed":
			resultObserved++
		}
		if strings.EqualFold(tool.Status, "blocked") && normalizedToolEventKind(tool) == "execution_forwarded" {
			reasons = append(reasons, fmt.Sprintf("已转发的工具行为被阻断：%s", toolName))
		}
	}

	typesList := keysOfSet(typeSet)
	topTools := topKeysByCount(toolCount, 5)
	summary := fmt.Sprintf(
		"共 %d 条工具审计（%d 种工具）：定义出现 %d，建议调用 %d，已转发执行 %d，结果已观察 %d",
		len(toolLogs), len(toolCount), definitionExposed, invocationProposed, executionForwarded, resultObserved,
	)
	if resultObserved > 0 && executionForwarded == 0 {
		summary += "；观察到结果消息，但未证明由网关执行"
	}

	return types.AuditToolSummaryInfo{
		Total:              len(toolLogs),
		UniqueTools:        len(toolCount),
		HighRisk:           highRisk,
		DefinitionExposed:  definitionExposed,
		InvocationProposed: invocationProposed,
		ExecutionForwarded: executionForwarded,
		ResultObserved:     resultObserved,
		Types:              typesList,
		TopTools:           topTools,
		Summary:            summary,
	}, reasons
}

func normalizedToolEventKind(tool repository.ToolCallLog) string {
	kind := strings.ToLower(strings.TrimSpace(tool.EventKind))
	if kind != "" && kind != "legacy_unknown" {
		return kind
	}
	if tool.ExecutionObserved {
		return "execution_forwarded"
	}
	if tool.ResultObserved {
		return "result_observed"
	}
	return "legacy_unknown"
}

func semanticDetectionIssue(event *repository.SecurityEvent) (types.AuditDetectionIssueInfo, bool) {
	if event == nil {
		return types.AuditDetectionIssueInfo{}, false
	}
	for _, finding := range findingsFromMatchedSummary(event.MatchedSummary) {
		category := strings.ToLower(firstNonEmptyAuditSummaryString(
			finding["category"], finding["type"],
		))
		if category != "semantic_unavailable" || findingCountsAsSecuritySignal(finding) {
			continue
		}

		reasonCode := strings.ToLower(firstNonEmptyAuditSummaryString(
			event.MatchedSummary["semantic_reason"],
			finding["semantic_reason"],
			finding["reason"],
		))
		if reasonCode == "" {
			reasonCode = "judge_unavailable"
		}
		issue := types.AuditDetectionIssueInfo{
			Component:  "semantic_judge",
			ReasonCode: reasonCode,
		}
		switch reasonCode {
		case "breaker_open":
			issue.Summary = "语义检测服务当前处于熔断状态，本次语义判定未完成。"
			issue.NextAction = "检查语义检测模型可用性和近期连续失败记录，恢复后重新验证。"
		case "timeout", "judge_timeout":
			issue.Summary = "语义检测服务响应超时，本次语义判定未完成。"
			issue.NextAction = "检查模型延迟、超时阈值和网络连通性，恢复后重新验证。"
		case "judge_unavailable":
			issue.Summary = "语义检测模型当前不可用，本次语义判定未完成。"
			issue.NextAction = "检查语义检测模型路由、健康状态和凭据配置。"
		default:
			issue.Summary = "语义检测链未完成，本次请求只能依据确定性规则和行为证据研判。"
			issue.NextAction = "检查语义检测运行状态，恢复后重新验证。"
		}
		return issue, true
	}
	return types.AuditDetectionIssueInfo{}, false
}

func eventHasCountedSecurityFinding(event *repository.SecurityEvent) bool {
	if event == nil {
		return false
	}
	for _, finding := range findingsFromMatchedSummary(event.MatchedSummary) {
		if findingCountsAsSecuritySignal(finding) {
			return true
		}
	}
	return false
}

func buildDetectionIssues(events []*repository.SecurityEvent) []types.AuditDetectionIssueInfo {
	issues := make([]types.AuditDetectionIssueInfo, 0)
	seen := map[string]struct{}{}
	for _, event := range events {
		issue, ok := semanticDetectionIssue(event)
		if !ok {
			continue
		}
		key := issue.Component + "\x00" + issue.ReasonCode
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		issues = append(issues, issue)
	}
	return issues
}

func summarizeSecurityEvents(events []*repository.SecurityEvent) ([]types.AuditEvidenceInfo, []string, int, bool) {
	var evidence []types.AuditEvidenceInfo
	var reasons []string
	score := 10
	hasAITriage := false

	for _, event := range events {
		if _, isPipelineIssue := semanticDetectionIssue(event); isPipelineIssue &&
			!eventHasCountedSecurityFinding(event) {
			continue
		}
		severity := strings.ToLower(event.Severity)
		action := strings.ToLower(event.ActionTaken)
		label := event.RuleName
		if label == "" {
			label = securityEventLabel(event)
		}
		if label == "" {
			label = "安全事件"
		}
		category := riskCategoryLabel(event.RuleType)
		if category == "" {
			category = riskCategoryFromMatchedSummary(event.MatchedSummary)
		}
		if category == "" {
			category = label
		}
		evidence = append(evidence, types.AuditEvidenceInfo{
			Label:    category,
			Value:    fmt.Sprintf("严重程度 %s，动作 %s", riskLevelLabel(severity), actionLabel(action)),
			Severity: severity,
		})
		for _, triage := range triagesFromMatchedSummary(event.MatchedSummary) {
			hasAITriage = true
			verdict := triageVerdictLabel(fmt.Sprint(triage["verdict"]))
			text := firstNonEmptyAuditSummaryString(triage["report_text"], triage["reason"], triage["evidence_summary"])
			if text == "" {
				text = "AI 复核未给出说明。"
			}
			evidence = append(evidence, types.AuditEvidenceInfo{
				Label:    "AI 复核：" + verdict,
				Value:    fmt.Sprintf("%s：%s", verdict, truncateRunes(text, 220)),
				Severity: strings.ToLower(firstNonEmptyAuditSummaryString(triage["risk_level"], severity, "medium")),
			})
			switch strings.ToLower(fmt.Sprint(triage["verdict"])) {
			case "confirmed_risk":
				reasons = append(reasons, fmt.Sprintf("AI 复核确认风险：%s", label))
			case "needs_review":
				reasons = append(reasons, fmt.Sprintf("AI 复核建议人工复核：%s", label))
			}
		}
		if severity != "" && severity != "low" {
			reasons = append(reasons, fmt.Sprintf("命中%s风险：%s（%s）", riskLevelLabel(severity), category, label))
		}
		switch severity {
		case "critical":
			score += 55
		case "high":
			score += 40
		case "medium":
			score += 20
		case "low":
			score += 5
		}
		if action == "block" {
			score += 30
			reasons = append(reasons, "安全策略执行了阻断动作")
		}
	}

	if score > 100 {
		score = 100
	}
	return evidence, uniqueStrings(reasons), score, hasAITriage
}

func firstNonEmptyAuditSummaryString(values ...interface{}) string {
	for _, value := range values {
		text := strings.TrimSpace(fmt.Sprint(value))
		if text != "" && text != "<nil>" {
			return text
		}
	}
	return ""
}

func triageVerdictLabel(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "confirmed_risk":
		return "确认风险"
	case "likely_false_positive":
		return "疑似误报"
	case "audit_evidence":
		return "审计留证"
	case "needs_review":
		return "需人工复核"
	default:
		return "需人工复核"
	}
}

func triagesFromMatchedSummary(summary map[string]interface{}) []map[string]interface{} {
	if summary == nil {
		return nil
	}
	rawFindings, ok := summary["findings"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0)
	for _, raw := range rawFindings {
		finding, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		switch triage := finding["triage"].(type) {
		case map[string]interface{}:
			out = append(out, triage)
		}
	}
	return out
}

func securityEventLabel(event *repository.SecurityEvent) string {
	switch event.EventType {
	case "security_check":
		return "安全检测"
	case "tool_risk", "tool_call_risk", "tool_audited", "tool_blocked", "tool_audit_only":
		return "工具风险"
	case "model_policy":
		return "模型策略"
	case "quota":
		return "额度控制"
	default:
		return event.EventType
	}
}

func findingString(finding map[string]interface{}, key string) string {
	if finding == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(finding[key]))
}

func findingBool(finding map[string]interface{}, key string) bool {
	if finding == nil {
		return false
	}
	switch value := finding[key].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true")
	default:
		return strings.EqualFold(strings.TrimSpace(fmt.Sprint(value)), "true")
	}
}

func findingPriority(finding map[string]interface{}) int {
	if finding == nil {
		return 0
	}
	score := 0
	switch strings.ToLower(findingString(finding, "action")) {
	case "block", "blocked", "reply", "quarantine":
		score += 80
	case "mask":
		score += 50
	case "alert", "audit":
		score += 20
	}
	switch strings.ToLower(findingString(finding, "severity")) {
	case "critical":
		score += 60
	case "high":
		score += 45
	case "medium":
		score += 20
	case "low":
		score += 5
	}
	category := strings.ToLower(findingString(finding, "category"))
	findingType := strings.ToLower(findingString(finding, "type"))
	if findingType == "secret" || strings.Contains(category, "key") || strings.Contains(category, "secret") || strings.Contains(category, "token") || strings.Contains(category, "password") {
		score += 15
	}
	if findingType == "file" || findingType == "tool" || findingType == "code_config" {
		score += 10
	}
	return score
}

func primaryFindingFromMatchedSummary(summary map[string]interface{}) map[string]interface{} {
	if summary == nil {
		return nil
	}
	rawFindings, ok := summary["findings"].([]interface{})
	if !ok {
		return nil
	}
	var best map[string]interface{}
	bestScore := -1
	for _, raw := range rawFindings {
		finding, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		score := findingPriority(finding)
		if best == nil || score > bestScore {
			best = finding
			bestScore = score
		}
	}
	return best
}

func riskCategoryFromMatchedSummary(summary map[string]interface{}) string {
	if summary == nil {
		return ""
	}
	if category, ok := summary["category"].(string); ok {
		return riskCategoryLabel(category)
	}
	primary := primaryFindingFromMatchedSummary(summary)
	if primary != nil {
		if category := findingString(primary, "category"); category != "" {
			return riskCategoryLabel(category)
		}
		if findingType := findingString(primary, "type"); findingType != "" {
			return riskCategoryLabel(findingType)
		}
	}
	return ""
}

func buildAuditDecision(toolLogs []repository.ToolCallLog, events []*repository.SecurityEvent, contentReasons []string) (types.AuditDecisionInfo, int) {
	semanticStatus := "not_recorded"
	hasSecuritySignal := false
	hasHighSignal := false
	hasCompletedSemanticIntent := false
	hasExplicitImpact := len(contentReasons) > 0
	hasExplicitBlockedAttempt := false
	hasLikelyFalsePositive := false
	executionForwarded := false
	sensitiveTargetForwarded := false
	externalResultObserved := false
	resultObserved := false

	for _, tool := range toolLogs {
		kind := normalizedToolEventKind(tool)
		switch kind {
		case "execution_forwarded":
			executionForwarded = true
			if isSensitiveToolTarget(tool.NormalizedTarget, tool.Parameters) {
				sensitiveTargetForwarded = true
			}
		case "result_observed":
			resultObserved = true
			if isExternalNetworkTool(tool) {
				externalResultObserved = true
			}
		}
	}

	for _, event := range events {
		summary := event.MatchedSummary
		eventSemanticStatus := strings.ToLower(firstNonEmptyAuditSummaryString(summary["semantic_status"]))
		switch eventSemanticStatus {
		case "incomplete":
			semanticStatus = "incomplete"
		case "completed":
			if semanticStatus != "incomplete" {
				semanticStatus = "completed"
			}
		case "not_run", "skipped":
			if semanticStatus == "not_recorded" {
				semanticStatus = "not_run"
			}
		}

		if auditSummaryBool(summary, "impact_confirmed") || auditSummaryBool(summary, "destructive_effect_confirmed") {
			hasExplicitImpact = true
		}

		eventHasExplicitAttack := false
		for _, finding := range findingsFromMatchedSummary(summary) {
			if !findingCountsAsSecuritySignal(finding) {
				continue
			}
			hasSecuritySignal = true
			severity := strings.ToLower(firstNonEmptyAuditSummaryString(finding["severity"], event.Severity))
			if severity == "high" || severity == "critical" {
				hasHighSignal = true
			}
			category := strings.ToLower(firstNonEmptyAuditSummaryString(finding["category"], finding["type"]))
			if isConfirmedSensitiveMaterial(category, finding) {
				hasExplicitImpact = true
			}
			if isExplicitAttackCategory(category) {
				eventHasExplicitAttack = true
			}
			for _, triage := range triagesFromFinding(finding) {
				if strings.EqualFold(firstNonEmptyAuditSummaryString(triage["verdict"]), "likely_false_positive") {
					hasLikelyFalsePositive = true
				}
			}
		}

		severity := strings.ToLower(event.Severity)
		if severity == "medium" || severity == "high" || severity == "critical" {
			hasSecuritySignal = true
		}
		if severity == "high" || severity == "critical" {
			hasHighSignal = true
		}
		if eventSemanticStatus == "completed" && eventHasExplicitAttack {
			hasCompletedSemanticIntent = true
		}
		if strings.EqualFold(event.ActionTaken, "block") && eventHasExplicitAttack {
			hasExplicitBlockedAttempt = true
		}
	}

	if sensitiveTargetForwarded && externalResultObserved {
		hasExplicitImpact = true
	}

	stage := "informational"
	score := 12
	whatHappened := "记录到常规模型或工具审计信息，未形成可验证的攻击行为链。"
	whyRisky := "当前证据不足以证明存在攻击。"
	impact := "未发现已确认的安全影响。"
	nextAction := "无需升级安全事件，保留审计记录即可。"

	switch {
	case hasExplicitImpact:
		stage = "confirmed_impact"
		score = 92
		whatHappened = "检测到明确敏感材料或完整的敏感目标读取与外部结果链。"
		whyRisky = "证据已达到实际影响门槛，不是仅凭工具名称或关键词推断。"
		impact = "已确认存在敏感数据暴露或同等级安全影响。"
		nextAction = "建议立即复核证据、处置相关凭据，并确认是否需要回滚或隔离。"
	case hasExplicitBlockedAttempt:
		stage = "confirmed_attempt"
		score = 78
		whatHappened = "检测到明确攻击意图，且安全策略执行了阻断。"
		whyRisky = "攻击目标和处置动作均有结构化检测证据。"
		impact = "攻击尝试已被阻断，尚无证据表明造成实际影响。"
		nextAction = "建议复核攻击来源和阻断证据，确认是否需要收紧策略。"
	case semanticStatus != "incomplete" && hasCompletedSemanticIntent && executionForwarded:
		stage = "confirmed_attempt"
		score = 72
		whatHappened = "语义检测识别到明确攻击意图，并观察到工具执行被转发。"
		whyRisky = "攻击意图与可执行行为形成了证据链。"
		impact = "已确认攻击尝试，尚未确认造成实际影响。"
		nextAction = "建议安全或研发负责人复核工具目标和执行结果。"
	case semanticStatus == "incomplete":
		stage = "needs_review"
		score = 45
		whatHappened = "语义裁判未完成，当前只有部分规则或行为信号。"
		whyRisky = "检测链不完整，不能据此确认攻击，也不能直接忽略。"
		impact = "未确认实际影响。"
		nextAction = "建议复核原始命中，并检查语义裁判超时、熔断或模型可用性。"
	case hasSecuritySignal && !hasLikelyFalsePositive:
		stage = "needs_review"
		score = 42
		whatHappened = "检测到需要核实的安全信号，但尚未形成完整行为证据链。"
		whyRisky = "单个检测命中可能是真实风险，也可能是开发上下文误报。"
		impact = "未确认实际影响。"
		nextAction = "建议复核命中原文、工具生命周期和目标对象后再处置。"
	case resultObserved && !executionForwarded:
		whatHappened = "观察到结果消息，但未证明由网关执行。"
		whyRisky = "结果消息只能作为审计线索，不能反推工具已经执行。"
	case hasHighSignal:
		stage = "needs_review"
		score = 42
	}

	return types.AuditDecisionInfo{
		Stage:          stage,
		SemanticStatus: semanticStatus,
		WhatHappened:   whatHappened,
		WhyRisky:       whyRisky,
		Impact:         impact,
		NextAction:     nextAction,
	}, score
}

func findingsFromMatchedSummary(summary map[string]interface{}) []map[string]interface{} {
	if summary == nil {
		return nil
	}
	rawFindings, ok := summary["findings"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(rawFindings))
	for _, raw := range rawFindings {
		if finding, ok := raw.(map[string]interface{}); ok {
			out = append(out, finding)
		}
	}
	return out
}

func triagesFromFinding(finding map[string]interface{}) []map[string]interface{} {
	triage, ok := finding["triage"].(map[string]interface{})
	if !ok {
		return nil
	}
	return []map[string]interface{}{triage}
}

func findingCountsAsSecuritySignal(finding map[string]interface{}) bool {
	value, exists := finding["counts_as_security_finding"]
	if !exists {
		return true
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}

func auditSummaryBool(summary map[string]interface{}, key string) bool {
	if summary == nil {
		return false
	}
	switch value := summary[key].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true")
	default:
		return false
	}
}

func isExplicitAttackCategory(category string) bool {
	category = strings.ToLower(strings.TrimSpace(category))
	return strings.Contains(category, "exfil") ||
		strings.Contains(category, "data_leak") ||
		strings.Contains(category, "instruction_override") ||
		strings.Contains(category, "jailbreak") ||
		strings.Contains(category, "system_command") ||
		strings.Contains(category, "privilege_escalation") ||
		strings.Contains(category, "data_exfil")
}

func isConfirmedSensitiveMaterial(category string, finding map[string]interface{}) bool {
	if findingBool(finding, "impact_confirmed") {
		return true
	}
	category = strings.ToLower(category)
	return strings.Contains(category, "ssh_private_key") ||
		strings.Contains(category, "private_key_material")
}

func isSensitiveToolTarget(target string, parameters map[string]interface{}) bool {
	text := strings.ToLower(strings.TrimSpace(target + " " + fmt.Sprint(parameters)))
	sensitiveMarkers := []string{"/.ssh/", "id_rsa", "id_ed25519", "/.aws/", ".env", "credentials", "secret", "private_key"}
	for _, marker := range sensitiveMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func isExternalNetworkTool(tool repository.ToolCallLog) bool {
	text := strings.ToLower(strings.TrimSpace(tool.ToolType + " " + tool.ToolName + " " + tool.NormalizedTarget))
	markers := []string{"network", "webfetch", "websearch", "curl", "wget", "http://", "https://"}
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func riskLevelFromScore(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

func recommendedAction(level string, reasons []string) string {
	switch level {
	case "critical":
		return "建议立即复核该会话，确认是否需要禁用密钥、回滚操作或升级安全策略。"
	case "high":
		return "建议安全或研发负责人复核该请求，确认工具行为和输出内容是否符合授权范围。"
	case "medium":
		return "建议抽样复核，关注命中的安全事件和工具调用证据。"
	default:
		if len(reasons) == 0 {
			return "未发现明显风险，可保留审计记录用于追溯。"
		}
		return "风险较低，建议保留审计记录并按需复核。"
	}
}

func buildTags(toolLogs []repository.ToolCallLog, events []*repository.SecurityEvent, contentLogs []repository.ContentLog) []string {
	tagSet := map[string]struct{}{}
	for _, tool := range toolLogs {
		tagSet["工具调用"] = struct{}{}
		tagSet[toolTypeLabel(tool.ToolType)] = struct{}{}
		if strings.EqualFold(tool.RiskLevel, "high") || strings.EqualFold(tool.RiskLevel, "critical") {
			tagSet["高危工具"] = struct{}{}
		}
	}
	for _, event := range events {
		if event.EventType != "" {
			tagSet["安全事件"] = struct{}{}
		}
		if strings.EqualFold(event.ActionTaken, "block") {
			tagSet["已阻断"] = struct{}{}
		}
	}
	for _, content := range contentLogs {
		if strings.EqualFold(content.Role, "system") {
			tagSet["含系统提示词"] = struct{}{}
		}
	}
	if len(tagSet) == 0 {
		tagSet["常规请求"] = struct{}{}
	}
	return keysOfSet(tagSet)
}

func buildAuditTitle(intent, riskLevel string) string {
	title := truncateRunes(intent, 32)
	if title == "" {
		title = "未识别业务意图"
	}
	return fmt.Sprintf("%s · %s", title, riskLevelLabel(riskLevel))
}

func detectSensitiveContentRisk(text string) []string {
	lower := strings.ToLower(text)
	var reasons []string
	if strings.Contains(lower, "-----begin ") && strings.Contains(lower, " private key-----") {
		reasons = append(reasons, "内容中包含完整私钥材料")
	}
	return uniqueStrings(reasons)
}

func toolTypeLabel(toolType string) string {
	switch strings.ToLower(toolType) {
	case "file":
		return "文件操作"
	case "network":
		return "网络访问"
	case "database":
		return "数据库访问"
	case "mcp":
		return "MCP 工具"
	case "system":
		return "系统命令"
	default:
		if toolType == "" {
			return "未知工具"
		}
		return toolType
	}
}

func riskCategoryLabel(category string) string {
	switch strings.ToLower(category) {
	case "prompt_injection":
		return "Prompt 注入"
	case "content_safety":
		return "内容安全"
	case "agent_detect":
		return "智能体行为"
	case "pii", "phone_cn", "id_card_cn", "bank_card_cn", "email":
		return "个人信息泄露"
	case "secret", "aws_secret_key", "aws_access_key", "github_token", "openai_key", "anthropic_key", "jwt_token", "generic_api_key", "ssh_private_key":
		return "敏感凭据泄露"
	case "data_leak":
		return "数据泄露"
	case "prompt_leak":
		return "提示词泄露"
	case "code_security":
		return "代码安全"
	case "code_config", "env_file", "config_file":
		return "配置文件风险"
	case "fraud_detect":
		return "欺诈风险"
	case "dos_protection":
		return "资源耗尽"
	case "plugin_security":
		return "插件/MCP 风险"
	case "illegal_trade":
		return "违规交易"
	case "copyright_protect":
		return "版权风险"
	case "rag_security":
		return "RAG 风险"
	case "supply_chain":
		return "供应链风险"
	case "tool_call", "tool_risk":
		return "工具风险"
	default:
		if strings.Contains(category, "key") || strings.Contains(category, "secret") || strings.Contains(category, "token") || strings.Contains(category, "password") {
			return "敏感凭据泄露"
		}
		if strings.Contains(category, "phone") || strings.Contains(category, "card") || strings.Contains(category, "email") || strings.Contains(category, "id_card") {
			return "个人信息泄露"
		}
		if strings.Contains(category, "classified") || strings.Contains(category, "sensitive") || strings.Contains(category, "leak") {
			return "数据泄露"
		}
		return category
	}
}

func riskLevelLabel(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	default:
		if level == "" {
			return "未知"
		}
		return level
	}
}

func actionLabel(action string) string {
	switch strings.ToLower(action) {
	case "block":
		return "阻断"
	case "mask":
		return "脱敏"
	case "audit":
		return "审计"
	case "allow":
		return "放行"
	default:
		if action == "" {
			return "未记录"
		}
		return action
	}
}

func containsCJK(text string) bool {
	for _, r := range text {
		if r >= '\u4e00' && r <= '\u9fff' {
			return true
		}
	}
	return false
}

func truncateRunes(text string, limit int) string {
	if limit <= 0 || utf8.RuneCountInString(text) <= limit {
		return text
	}
	runes := []rune(text)
	return string(runes[:limit]) + "..."
}

func keysOfSet(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func topKeysByCount(counts map[string]int, limit int) []string {
	type entry struct {
		key   string
		count int
	}
	entries := make([]entry, 0, len(counts))
	for key, count := range counts {
		entries = append(entries, entry{key: key, count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count == entries[j].count {
			return entries[i].key < entries[j].key
		}
		return entries[i].count > entries[j].count
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	result := make([]string, len(entries))
	for i, item := range entries {
		result[i] = item.key
	}
	return result
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	var result []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
