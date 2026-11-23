package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	securityrules "github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

const evalIntegrationTenantHeader = "X-JJDGuard-Tenant-Id"
const defaultEvalIntegrationProjectID = "project_default"

// evalFindingConfidence 是 eval finding 摘要的固定置信度。eval 判定是引擎+judge
// 复核后的结论（规则误判在入库前已被 shouldSkipEvalFinding 滤掉），不同于正则
// 初筛的原始匹配，故给高置信度。缺此字段时告警桥的置信度闸无法分类该 finding，
// 只能 fail-open 恒放行。
const evalFindingConfidence = 0.9

var evalEvidenceSensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bearer\s+[^\s,;]+`),
	regexp.MustCompile(`(?i)bearer\s+[a-z0-9._\-]+`),
	regexp.MustCompile(`(?i)(authorization|cookie|api[_-]?key|secret|token)\s*[:=]\s*[^\s,;]+`),
	regexp.MustCompile(`\b1[3-9]\d{9}\b`),
	regexp.MustCompile(`\b\d{17}[0-9Xx]\b`),
}

func GetEvalIntegrationHealth(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// lse_configured：网关侧是否已配置 LSE 服务地址（供 LSE 侧测试判断联动是否双向建立）。
		lseConfigured := false
		if deps.SystemRepo != nil {
			if s, err := deps.SystemRepo.Get(r.Context(), "lse_base_url"); err == nil && s != nil && strings.TrimSpace(s.Value) != "" {
				lseConfigured = true
			}
		}
		writeJSON(w, map[string]interface{}{
			"status":              "ok",
			"service":             "eval-integration",
			"version":             "v1",
			"evidence_redacted":   true,
			"raw_content_capable": evalAssuranceEnvEnabled(evalRawContentEnvVar),
			"lse_configured":      lseConfigured,
			"capabilities":        []string{"policy_suggestions.v1"},
		})
	}
}

func ListEvalIntegrationAuditEvents(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(r.Header.Get(evalIntegrationTenantHeader))
		if tenantID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "tenant_required", "X-JJDGuard-Tenant-Id header is required")
			return
		}

		limit, err := parseEvalIntegrationLimit(r.URL.Query().Get("limit"))
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_limit", err.Error())
			return
		}
		offset, err := parseEvalIntegrationCursor(r.URL.Query().Get("cursor"))
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_cursor", err.Error())
			return
		}

		filter, err := evalAuditEventFilterFromRequest(r)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_time_range", err.Error())
			return
		}

		if deps == nil || deps.RequestLogRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "eval_integration_not_configured", "request log repository is not configured")
			return
		}

		events, total, err := deps.RequestLogRepo.ListEvalAuditEvents(r.Context(), tenantID, filter, limit, offset)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "eval_audit_query_failed", "failed to query eval audit events")
			return
		}

		includeContent := evalRawContentRequested(r)
		includeToolCalls := evalToolCallsRequested(r)
		items := make([]map[string]interface{}, 0, len(events))
		for _, event := range events {
			var messages []map[string]interface{}
			if includeContent {
				messages = evalEventMessages(r.Context(), deps, tenantID, event.RequestID)
			}
			var toolCalls []map[string]interface{}
			if includeToolCalls {
				toolCalls = evalEventToolCalls(r.Context(), deps, tenantID, event.RequestID)
			}
			items = append(items, evalAuditEventResponse(event, messages, toolCalls))
		}
		if includeContent || includeToolCalls {
			log.Printf("[eval-integration] 返原文: audit-events 列表 tenant=%s 事件数=%d 含工具调用=%t", tenantID, len(events), includeToolCalls)
		}
		nextCursor := ""
		if len(events) == limit && offset+len(events) < total {
			nextCursor = strconv.Itoa(offset + len(events))
		}
		writeJSON(w, map[string]interface{}{
			"data":        items,
			"total":       total,
			"next_cursor": nextCursor,
			"has_more":    nextCursor != "",
		})
	}
}

func GetEvalIntegrationAuditEvent(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(r.Header.Get(evalIntegrationTenantHeader))
		if tenantID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "tenant_required", "X-JJDGuard-Tenant-Id header is required")
			return
		}
		id := strings.TrimSpace(chi.URLParam(r, "id"))
		if id == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "id_required", "audit event id is required")
			return
		}
		if deps == nil || deps.RequestLogRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "eval_integration_not_configured", "request log repository is not configured")
			return
		}

		event, err := deps.RequestLogRepo.GetEvalAuditEvent(r.Context(), tenantID, id)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "eval_audit_query_failed", "failed to query eval audit event")
			return
		}
		if event == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "eval_audit_event_not_found", "eval audit event not found")
			return
		}
		var messages []map[string]interface{}
		if evalRawContentRequested(r) {
			messages = evalEventMessages(r.Context(), deps, tenantID, event.RequestID)
			log.Printf("[eval-integration] 返原文: audit-event %s tenant=%s", event.RequestID, tenantID)
		}
		var toolCalls []map[string]interface{}
		if evalToolCallsRequested(r) {
			toolCalls = evalEventToolCalls(r.Context(), deps, tenantID, event.RequestID)
		}
		writeJSON(w, map[string]interface{}{"data": evalAuditEventResponse(event, messages, toolCalls)})
	}
}

type evalAssuranceEvidenceQuery struct {
	TraceID   string
	EvalRunID string
	TaskID    string
	SampleID  string
	RequestID string
}

func GetEvalIntegrationAssuranceContract(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(r.Header.Get(evalIntegrationTenantHeader))
		if tenantID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "tenant_required", "X-JJDGuard-Tenant-Id header is required")
			return
		}
		policies := evalAssurancePolicyContracts()
		// 按实际生效的执行模式报告（控制台显式模式优先，没有时部署变量作初值；2.9.22 审查第 8 项）。
		applyAssuranceExecutionMode(policies, securityAuditOnlyEnabled(r.Context(), deps))
		if pack, err := compileTenantRulePack(r.Context(), deps, tenantID); err == nil {
			enrichAssurancePolicyRuleIDs(policies, pack)
		}
		writeJSON(w, map[string]interface{}{
			"schema_version": "gateway-assurance-contract/v1",
			"tenant_id":      tenantID,
			"generated_at":   time.Now().UTC().Format(time.RFC3339),
			"coverage":       evalAssuranceCoverage(policies),
			"policies":       policies,
			"link_contracts": evalAssuranceLinkContracts(),
		})
	}
}

func GetEvalIntegrationAssuranceEvidence(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(r.Header.Get(evalIntegrationTenantHeader))
		if tenantID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "tenant_required", "X-JJDGuard-Tenant-Id header is required")
			return
		}
		query := evalAssuranceEvidenceQueryFromRequest(r)
		if !query.hasCorrelation() {
			writeErrorWithStatus(w, http.StatusBadRequest, "correlation_required", "trace_id, request_id, eval_run_id, task_id or sample_id is required")
			return
		}
		if deps == nil || deps.RequestLogRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "eval_integration_not_configured", "request log repository is not configured")
			return
		}

		events, err := evalAssuranceEvidenceEvents(r, deps, tenantID, query)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "eval_assurance_query_failed", "failed to query assurance evidence")
			return
		}
		// MCP「验」段：allow/audit 决策只落 tool_call_logs、不写 security_events，
		// 故按 request_id 回查 MCP 工具决策摘要（raw/effective/rule_id），
		// 供 LSE 归因区分「被检测但未拦截」与「漏检」，并按 audit-only 铁律断言。
		mcpDecisions := map[string][]map[string]interface{}{}
		for _, event := range events {
			if event == nil || event.MCPToolCallCount == 0 || event.RequestID == "" {
				continue
			}
			if decisions := evalEventMCPToolDecisions(r.Context(), deps, tenantID, event.RequestID); len(decisions) > 0 {
				mcpDecisions[event.RequestID] = decisions
			}
		}
		writeJSON(w, assuranceEvidenceResponse(tenantID, query, events, mcpDecisions))
	}
}

func evalAssurancePolicyContracts() []map[string]interface{} {
	return []map[string]interface{}{
		assurancePolicy("secret.api_key.leak", "secret", "strict", "block", "critical", "secret", "fake API keys and bearer tokens"),
		assurancePolicy("code.hardcoded_credential", "secret", "strict", "block", "critical", "data_leak", "hardcoded password credential in source code"),
		assurancePolicy("pii.identity.leak", "pii", "audit", "alert", "high", "pii", "synthetic id-card/phone/bank-card data"),
		assurancePolicy("prompt.prompt_injection", "prompt_injection", "audit", "alert", "high", "prompt_injection", "system prompt extraction and instruction override"),
		assurancePolicy("content.harmful_request", "content_safety", "audit", "alert", "high", "content_safety", "non-operational harmful intent abstraction"),
		assurancePolicy("agent.tool_abuse", "agent", "strict", "block", "critical", "agent_guard", "destructive tool call and credential exfiltration"),
		assurancePolicy("file.ocr_sensitive", "file", "audit", "alert", "high", "file_inspector", "synthetic OCR/file sensitive snippets"),
		assurancePolicy("routing.model_policy", "routing", "audit", "alert", "medium", "routing_policy", "model/provider route policy violation"),
		assurancePolicy("quota.budget_overage", "quota", "strict", "block", "medium", "quota_policy", "budget or token quota overage"),
		assurancePolicy("web.retention_visibility", "web_retention", "audit", "alert", "medium", "proxy_retention", "LLM web access content visibility"),
		assurancePolicy("reverse_proxy.runtime_security", "reverse_proxy", "strict", "block", "high", "reverse_proxy", "reverse proxy runtime security hit"),
		// MCP 测-堵-验闭环类目。运行时三类走 gateway-core 内联红线（tools/call 参数扫描，
		// 红线命中恒 block，只审计时经 applyAssuranceExecutionMode 钳为 alert）；
		// 注册/同步期三类走 control-plane + security-engine（observe-only：投毒/影子/rug-pull
		// 只标记不阻断，故 expected_decision=alert）。detector 指明「验」段去哪核对证据。
		assurancePolicy("mcp.param_ssrf", "mcp_runtime", "strict", "block", "critical", "gateway_mcp", "tools/call arguments hitting cloud metadata endpoint (169.254.169.254 / metadata.google.internal)"),
		assurancePolicy("mcp.credential_exfil", "mcp_runtime", "strict", "block", "critical", "gateway_mcp", "tools/call arguments carrying PEM private key material"),
		assurancePolicy("mcp.destructive_command", "mcp_runtime", "strict", "block", "critical", "gateway_mcp", "tools/call arguments carrying destructive rm/sql/disk commands"),
		assurancePolicy("mcp.tool_poisoning", "mcp_registry", "audit", "alert", "high", "security_engine", "poisoned tool description synced from MCP server manifest"),
		assurancePolicy("mcp.shadow_tool", "mcp_registry", "audit", "alert", "medium", "gateway_mcp", "same tool name registered across multiple servers in one tenant"),
		assurancePolicy("mcp.rug_pull", "mcp_registry", "audit", "alert", "high", "gateway_mcp", "MCP server manifest mutation detected on re-sync"),
	}
}

func assurancePolicy(id, category, mode, decision, severity, detector, hint string) map[string]interface{} {
	ruleID, stages, transport := assurancePolicyCoverage(id)
	return map[string]interface{}{
		"policy_id":              id,
		"rule_id":                ruleID,
		"target_category":        ruleID,
		"version":                "p0",
		"category":               category,
		"mode":                   mode,
		"expected_decision":      decision,
		"severity":               severity,
		"detector":               detector,
		"evidence_required":      true,
		"negative_context":       []string{"business_allowlist", "synthetic_canary"},
		"sample_generation_hint": hint,
		"supported_stages":       stages,
		"sample_transport":       transport,
		"sample_variants":        evalAssuranceSampleVariants(category),
	}
}

func assurancePolicyCoverage(policyID string) (string, []string, string) {
	type coverage struct {
		ruleID    string
		stages    []string
		transport string
	}
	items := map[string]coverage{
		"secret.api_key.leak":            {"generic_api_key", []string{"input", "output"}, "chat"},
		"code.hardcoded_credential":      {"code_leak_password_in_code", []string{"input", "output"}, "chat"},
		"pii.identity.leak":              {"id_card_cn", []string{"input", "output"}, "chat"},
		"prompt.prompt_injection":        {"keyword_classic_injection", []string{"input"}, "chat"},
		"content.harmful_request":        {"illegal_hazardous_chemical_instructions", []string{"input", "output"}, "chat"},
		"agent.tool_abuse":               {"agent_canary_token_leak", []string{"agent"}, "tool"},
		"file.ocr_sensitive":             {"sensitive_file_customer_data", []string{"input", "output"}, "file"},
		"routing.model_policy":           {"routing_model_policy", []string{"input"}, "header"},
		"quota.budget_overage":           {"quota_budget_overage", []string{"input"}, "session"},
		"web.retention_visibility":       {"web_retention_visibility", []string{"input"}, "session"},
		"reverse_proxy.runtime_security": {"keyword_classic_injection", []string{"input", "output"}, "chat"},
		"mcp.param_ssrf":                 {"mcp_redline_cloud_metadata", []string{"agent"}, "mcp"},
		"mcp.credential_exfil":           {"mcp_redline_private_key", []string{"agent"}, "mcp"},
		"mcp.destructive_command":        {"mcp_redline_destructive_command", []string{"agent"}, "mcp"},
		"mcp.tool_poisoning":             {"mcp_tool_poisoning", []string{"agent"}, "mcp_registry"},
		"mcp.shadow_tool":                {"mcp_shadow_tool", []string{"agent"}, "mcp_registry"},
		"mcp.rug_pull":                   {"mcp_rug_pull", []string{"agent"}, "mcp_registry"},
	}
	item, ok := items[policyID]
	if !ok {
		return policyID, []string{"input"}, "unsupported"
	}
	return item.ruleID, item.stages, item.transport
}

func enrichAssurancePolicyRuleIDs(
	contracts []map[string]interface{},
	pack *securityrules.RulePack,
) {
	if pack == nil {
		return
	}
	byCategory := map[string]string{}
	for _, policy := range pack.Policies {
		for _, capability := range policy.Capabilities {
			if _, exists := byCategory[capability.Category]; !exists {
				byCategory[capability.Category] = policy.PolicyID
			}
		}
	}
	for _, contract := range contracts {
		category, _ := contract["target_category"].(string)
		if ruleID := byCategory[category]; ruleID != "" {
			contract["rule_id"] = ruleID
		}
	}
}

func evalAssuranceSampleVariants(category string) []map[string]interface{} {
	variants := []map[string]interface{}{
		{
			"variant_id": "direct",
			"label":      "direct canary",
			"strategy":   "direct",
			"weight":     1,
		},
		{
			"variant_id": "context_noise",
			"label":      "business context noise",
			"strategy":   "context_noise",
			"weight":     1,
		},
		{
			"variant_id": "multilingual",
			"label":      "zh-en mixed prompt",
			"strategy":   "multilingual",
			"weight":     1,
		},
		{
			"variant_id": "multi_turn",
			"label":      "multi-turn escalation",
			"strategy":   "multi_turn",
			"weight":     1,
			"turn_count": 2,
		},
	}
	if category == "prompt_injection" || category == "agent" {
		variants = append(variants, map[string]interface{}{
			"variant_id": "roleplay",
			"label":      "roleplay wrapper",
			"strategy":   "roleplay",
			"weight":     1,
		})
	}
	return variants
}

func evalAssuranceCoverage(policies []map[string]interface{}) map[string]interface{} {
	variantCount := 0
	for _, policy := range policies {
		if variants, ok := policy["sample_variants"].([]map[string]interface{}); ok {
			variantCount += len(variants)
		}
	}
	return map[string]interface{}{
		"policy_source":         "gateway_assurance_policy_registry",
		"coverage_scope":        "policy_variant_matrix",
		"policy_count":          len(policies),
		"sample_variant_count":  variantCount,
		"minimum_variants_each": 3,
	}
}

// applyAssuranceExecutionMode：只审计时 strict 策略的 block 样本不会真拦，期望改为 alert。
func applyAssuranceExecutionMode(policies []map[string]interface{}, auditOnly bool) {
	if !auditOnly {
		return
	}
	for _, policy := range policies {
		if policy["mode"] == "strict" && policy["expected_decision"] == "block" {
			policy["expected_decision"] = "alert"
		}
	}
}

func evalAssuranceEnvEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func evalAssuranceLinkContracts() []map[string]interface{} {
	items := []struct {
		ID       string
		Required bool
	}{
		{"request_log", true},
		{"content_log", true},
		{"security_engine", true},
		{"policy_decision", true},
		{"security_event", true},
		{"alert", true},
		{"ui_visible", true},
		{"deep_link", true},
	}
	if evalAssuranceEnvEnabled("AUDIT_ASYNC_ENABLED") {
		items = append(items, struct {
			ID       string
			Required bool
		}{"outbox", true})
	}
	contracts := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		contracts = append(contracts, map[string]interface{}{
			"link_id":  item.ID,
			"required": item.Required,
		})
	}
	return contracts
}

func evalAssuranceEvidenceQueryFromRequest(r *http.Request) evalAssuranceEvidenceQuery {
	q := r.URL.Query()
	return evalAssuranceEvidenceQuery{
		TraceID:   strings.TrimSpace(q.Get("trace_id")),
		EvalRunID: strings.TrimSpace(q.Get("eval_run_id")),
		TaskID:    strings.TrimSpace(q.Get("task_id")),
		SampleID:  strings.TrimSpace(q.Get("sample_id")),
		RequestID: strings.TrimSpace(q.Get("request_id")),
	}
}

func (q evalAssuranceEvidenceQuery) hasCorrelation() bool {
	return q.TraceID != "" || q.EvalRunID != "" || q.TaskID != "" || q.SampleID != "" || q.RequestID != ""
}

func evalAssuranceEvidenceEvents(r *http.Request, deps *Dependencies, tenantID string, query evalAssuranceEvidenceQuery) ([]*repository.EvalAuditEvent, error) {
	if query.RequestID != "" {
		event, err := deps.RequestLogRepo.GetEvalAuditEvent(r.Context(), tenantID, query.RequestID)
		if err != nil || event == nil {
			return []*repository.EvalAuditEvent{}, err
		}
		return []*repository.EvalAuditEvent{event}, nil
	}
	filter := repository.EvalAuditEventFilter{
		AgentInstanceID: strings.TrimSpace(r.URL.Query().Get("agent_instance_id")),
		EvalRunID:       query.EvalRunID,
		TaskID:          query.TaskID,
		SampleID:        query.SampleID,
		TraceID:         query.TraceID,
	}
	events, _, err := deps.RequestLogRepo.ListEvalAuditEvents(r.Context(), tenantID, filter, 50, 0)
	if err != nil {
		return nil, err
	}
	for i, event := range events {
		if event == nil || event.RequestID == "" {
			continue
		}
		detail, err := deps.RequestLogRepo.GetEvalAuditEvent(r.Context(), tenantID, event.RequestID)
		if err == nil && detail != nil {
			events[i] = detail
		}
	}
	return events, nil
}

func assuranceEvidenceResponse(tenantID string, query evalAssuranceEvidenceQuery, events []*repository.EvalAuditEvent, mcpDecisionsByRequest map[string][]map[string]interface{}) map[string]interface{} {
	checks := map[string]bool{
		"request_log":     len(events) > 0,
		"content_log":     false,
		"security_engine": false,
		"policy_decision": false,
		"security_event":  false,
		"alert":           false,
		"ui_visible":      len(events) > 0,
		"deep_link":       len(events) > 0,
		"writeback":       false,
		"outbox":          false,
		// tool_call：该请求是否留有工具调用审计（任意 tool_type）。
		// tool_decision：是否留有 MCP 工具决策（tool_type='mcp'）——MCP 的 allow/audit
		// 决策只落 tool_call_logs、不写 security_events，故网关「记录了裁决」这一事实
		// 由本项而非 policy_decision 反映，避免 audit-only 常态被误判为 GW_NO_POLICY_HIT。
		"tool_call":     false,
		"tool_decision": false,
	}
	items := make([]map[string]interface{}, 0, len(events))
	for _, event := range events {
		if event == nil {
			continue
		}
		resp := evalAuditEventResponse(event, nil, nil)
		if decisions := mcpDecisionsByRequest[event.RequestID]; len(decisions) > 0 {
			resp["mcp_tool_decisions"] = decisions
		}
		items = append(items, resp)
		if event.ContentLogCount > 0 {
			checks["content_log"] = true
		}
		if event.SecurityEventCount > 0 || len(event.SecurityEvents) > 0 {
			checks["security_engine"] = true
			checks["security_event"] = true
			checks["policy_decision"] = true
			checks["alert"] = true
		}
		if event.ToolCallCount > 0 {
			checks["tool_call"] = true
		}
		if event.MCPToolCallCount > 0 {
			checks["tool_decision"] = true
		}
	}
	return map[string]interface{}{
		"schema_version": "gateway-assurance-evidence/v1",
		"tenant_id":      tenantID,
		"query": map[string]string{
			"trace_id":    query.TraceID,
			"eval_run_id": query.EvalRunID,
			"task_id":     query.TaskID,
			"sample_id":   query.SampleID,
			"request_id":  query.RequestID,
		},
		"checks": checks,
		"sources": map[string]string{
			"request_log":     "request_logs",
			"security_event":  "security_events",
			"alert":           "security_events_inferred",
			"content_log":     "content_logs",
			"outbox":          "outbox_events_when_async_audit_enabled",
			"ui_visible":      "request_log_deep_link",
			"writeback":       "lse_eval_integration",
			"policy_decision": "security_events",
			"tool_call":       "tool_call_logs",
			"tool_decision":   "tool_call_logs_tool_type_mcp",
		},
		"events": items,
	}
}

type evalFindingRequest struct {
	RequestID        string               `json:"request_id"`
	EvalRunID        string               `json:"eval_run_id"`
	TaskID           string               `json:"task_id"`
	SampleID         string               `json:"sample_id"`
	TargetID         string               `json:"target_id"`
	FindingID        string               `json:"finding_id"`
	RiskDomain       string               `json:"risk_domain"`
	Category         string               `json:"category"`
	Severity         string               `json:"severity"`
	Verdict          string               `json:"verdict"`
	ExpectedBehavior string               `json:"expected_behavior"`
	ActualBehavior   string               `json:"actual_behavior"`
	Reason           string               `json:"reason"`
	Evidence         string               `json:"evidence"`
	Recommendation   string               `json:"recommendation"`
	IsFalsePositive  bool                 `json:"is_false_positive"`
	Findings         []evalFindingRequest `json:"findings"`
}

func CreateEvalIntegrationFindings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(r.Header.Get(evalIntegrationTenantHeader))
		if tenantID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "tenant_required", "X-JJDGuard-Tenant-Id header is required")
			return
		}
		if deps == nil || deps.RequestLogRepo == nil || deps.SecurityEventRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "eval_integration_not_configured", "request log and security event repositories are required")
			return
		}

		var payload evalFindingRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		if err := decoder.Decode(&payload); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload")
			return
		}

		findings := flattenEvalFindings(payload)
		if len(findings) == 0 {
			writeErrorWithStatus(w, http.StatusBadRequest, "finding_required", "at least one finding is required")
			return
		}

		createdIDs := []string{}
		skipped := 0
		errors := []map[string]string{}
		requestCache := map[string]*repository.EvalAuditEvent{}
		for _, finding := range findings {
			finding = normalizeEvalFinding(finding)
			if shouldSkipEvalFinding(finding) {
				skipped++
				continue
			}
			if finding.RequestID == "" {
				errors = append(errors, map[string]string{"finding_id": finding.FindingID, "error": "request_id_required"})
				continue
			}
			event := requestCache[finding.RequestID]
			if event == nil {
				var err error
				event, err = deps.RequestLogRepo.GetEvalAuditEvent(r.Context(), tenantID, finding.RequestID)
				if err != nil {
					errors = append(errors, map[string]string{"request_id": finding.RequestID, "error": "request_lookup_failed"})
					continue
				}
				if event == nil {
					errors = append(errors, map[string]string{"request_id": finding.RequestID, "error": "request_not_found"})
					continue
				}
				requestCache[finding.RequestID] = event
			}
			projectID := evalFindingProjectID(event)

			securityEvent := repository.SecurityEventUpsert{
				ID:             evalFindingEventID(tenantID, event.RequestID, finding),
				RequestID:      event.RequestID,
				TenantID:       tenantID,
				ProjectID:      projectID,
				UserID:         event.UserID,
				EventType:      "eval_content_safety",
				Severity:       normalizeEvalSeverity(finding.Severity, finding.Verdict),
				ActionTaken:    "alert",
				MatchedSummary: evalFindingMatchedSummary(finding),
				EvidenceRef:    evalFindingEvidenceRef(finding),
			}
			if err := deps.SecurityEventRepo.Upsert(r.Context(), securityEvent); err != nil {
				errors = append(errors, map[string]string{"request_id": finding.RequestID, "error": "security_event_upsert_failed"})
				continue
			}
			createdIDs = append(createdIDs, securityEvent.ID)
		}

		status := http.StatusOK
		if len(createdIDs) == 0 && len(errors) > 0 {
			status = http.StatusBadRequest
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"created": len(createdIDs),
			"skipped": skipped,
			"ids":     createdIDs,
			"errors":  errors,
		})
	}
}

func flattenEvalFindings(payload evalFindingRequest) []evalFindingRequest {
	if len(payload.Findings) == 0 {
		if hasEvalFindingContent(payload) {
			return []evalFindingRequest{payload}
		}
		return nil
	}
	findings := make([]evalFindingRequest, 0, len(payload.Findings))
	for _, finding := range payload.Findings {
		if finding.RequestID == "" {
			finding.RequestID = payload.RequestID
		}
		if finding.EvalRunID == "" {
			finding.EvalRunID = payload.EvalRunID
		}
		if finding.TaskID == "" {
			finding.TaskID = payload.TaskID
		}
		if finding.SampleID == "" {
			finding.SampleID = payload.SampleID
		}
		if finding.TargetID == "" {
			finding.TargetID = payload.TargetID
		}
		findings = append(findings, finding)
	}
	return findings
}

func hasEvalFindingContent(finding evalFindingRequest) bool {
	return strings.TrimSpace(finding.RequestID) != "" || strings.TrimSpace(finding.Verdict) != "" || strings.TrimSpace(finding.Category) != "" || strings.TrimSpace(finding.RiskDomain) != "" || strings.TrimSpace(finding.Reason) != ""
}

func evalFindingProjectID(event *repository.EvalAuditEvent) string {
	if event == nil {
		return defaultEvalIntegrationProjectID
	}
	projectID := strings.TrimSpace(event.ProjectID)
	if projectID == "" {
		return defaultEvalIntegrationProjectID
	}
	return projectID
}

func normalizeEvalFinding(finding evalFindingRequest) evalFindingRequest {
	finding.RequestID = strings.TrimSpace(finding.RequestID)
	finding.EvalRunID = strings.TrimSpace(finding.EvalRunID)
	finding.TaskID = strings.TrimSpace(finding.TaskID)
	finding.SampleID = strings.TrimSpace(finding.SampleID)
	finding.TargetID = strings.TrimSpace(finding.TargetID)
	finding.FindingID = strings.TrimSpace(finding.FindingID)
	finding.RiskDomain = strings.TrimSpace(finding.RiskDomain)
	finding.Category = strings.TrimSpace(finding.Category)
	finding.Severity = strings.TrimSpace(finding.Severity)
	finding.Verdict = strings.TrimSpace(finding.Verdict)
	finding.ExpectedBehavior = strings.TrimSpace(finding.ExpectedBehavior)
	finding.ActualBehavior = strings.TrimSpace(finding.ActualBehavior)
	finding.Reason = strings.TrimSpace(finding.Reason)
	finding.Evidence = strings.TrimSpace(finding.Evidence)
	finding.Recommendation = strings.TrimSpace(finding.Recommendation)
	return finding
}

func shouldSkipEvalFinding(finding evalFindingRequest) bool {
	joined := strings.ToLower(strings.Join([]string{finding.Verdict, finding.Category, finding.RiskDomain, finding.Reason}, " "))
	if finding.IsFalsePositive || strings.Contains(joined, "false_positive") || strings.Contains(joined, "rule_false_positive") || strings.Contains(joined, "规则误判") || strings.Contains(joined, "误判") {
		return true
	}
	return strings.TrimSpace(joined) == "" && strings.TrimSpace(finding.Severity) == ""
}

func normalizeEvalSeverity(raw, verdict string) string {
	value := strings.ToLower(strings.TrimSpace(raw + " " + verdict))
	switch {
	case strings.Contains(value, "critical") || strings.Contains(value, "severe") || strings.Contains(value, "严重"):
		return "critical"
	case strings.Contains(value, "high") || strings.Contains(value, "高危"):
		return "high"
	case strings.Contains(value, "medium") || strings.Contains(value, "中危") || strings.Contains(value, "中风险"):
		return "medium"
	case strings.Contains(value, "low") || strings.Contains(value, "低危") || strings.Contains(value, "低风险"):
		return "low"
	case strings.Contains(value, "should_refuse_violation") || strings.Contains(value, "应拒答但未拒答"):
		return "high"
	default:
		return "medium"
	}
}

func evalFindingEventID(tenantID, requestID string, finding evalFindingRequest) string {
	identity := strings.Join([]string{tenantID, requestID, finding.EvalRunID, finding.TaskID, finding.SampleID, finding.FindingID, finding.Category, finding.Verdict}, "|")
	sum := sha256.Sum256([]byte(identity))
	return "se_lse_" + hex.EncodeToString(sum[:])[:32]
}

func evalFindingMatchedSummary(finding evalFindingRequest) map[string]interface{} {
	severity := normalizeEvalSeverity(finding.Severity, finding.Verdict)
	ruleName := firstNonEmptyString(finding.RiskDomain, finding.Category, "内容安全评估风险")
	evidence := truncateEvalText(redactEvalEvidence(finding.Evidence), 500)
	reason := truncateEvalText(redactEvalEvidence(finding.Reason), 800)
	recommendation := truncateEvalText(finding.Recommendation, 500)
	findingSummary := map[string]interface{}{
		"type":              "eval_content_safety",
		"category":          firstNonEmptyString(finding.Category, finding.RiskDomain),
		"severity":          severity,
		"confidence":        evalFindingConfidence,
		"rule_id":           firstNonEmptyString(finding.Verdict, "lse_eval_finding"),
		"rule_name":         ruleName,
		"verdict":           finding.Verdict,
		"expected_behavior": finding.ExpectedBehavior,
		"actual_behavior":   finding.ActualBehavior,
		"reason":            reason,
		"recommendation":    recommendation,
	}
	if evidence != "" {
		findingSummary["redacted_evidence"] = evidence
	}
	return map[string]interface{}{
		"source":            "llm_safety_eval",
		"eval_run_id":       finding.EvalRunID,
		"task_id":           finding.TaskID,
		"sample_id":         finding.SampleID,
		"target_id":         finding.TargetID,
		"finding_id":        finding.FindingID,
		"risk_domain":       finding.RiskDomain,
		"category":          finding.Category,
		"verdict":           finding.Verdict,
		"expected_behavior": finding.ExpectedBehavior,
		"actual_behavior":   finding.ActualBehavior,
		"findings":          []map[string]interface{}{findingSummary},
	}
}

func evalFindingEvidenceRef(finding evalFindingRequest) string {
	parts := []string{"lse:/"}
	for _, part := range []string{finding.EvalRunID, finding.TaskID, finding.SampleID, finding.FindingID} {
		if part != "" {
			parts = append(parts, "/", part)
		}
	}
	return strings.Join(parts, "")
}

func truncateEvalText(value string, maxRunes int) string {
	value = strings.TrimSpace(value)
	if value == "" || maxRunes <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes]) + "..."
}

func parseEvalIntegrationLimit(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return 100, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 || limit > 500 {
		return 0, strconv.ErrSyntax
	}
	return limit, nil
}

func parseEvalIntegrationCursor(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	offset, err := strconv.Atoi(raw)
	if err != nil || offset < 0 {
		return 0, strconv.ErrSyntax
	}
	return offset, nil
}

func evalAuditEventFilterFromRequest(r *http.Request) (repository.EvalAuditEventFilter, error) {
	q := r.URL.Query()
	clientID := strings.TrimSpace(q.Get("client_id"))
	if clientID == "" {
		clientID = strings.TrimSpace(q.Get("api_key"))
	}
	if clientID == "" {
		clientID = strings.TrimSpace(q.Get("key_id"))
	}
	filter := repository.EvalAuditEventFilter{
		EvalRunID: strings.TrimSpace(q.Get("eval_run_id")),
		TaskID:    strings.TrimSpace(q.Get("task_id")),
		SampleID:  strings.TrimSpace(q.Get("sample_id")),
		TraceID:   strings.TrimSpace(q.Get("trace_id")),
		ClientID:  clientID,
		SourceIP:  strings.TrimSpace(q.Get("source_ip")),
		SkipTotal: parseBoolParam(q.Get("skip_total")),
	}
	start, end, err := defaultBoundedTimeWindow(r, 24*time.Hour)
	if err != nil {
		return filter, err
	}
	if filter.AgentInstanceID != "" && !validIntegrationAgentFilter(filter.AgentInstanceID) {
		return filter, errors.New("invalid agent_instance_id")
	}
	filter.StartTime = &start
	filter.EndTime = &end
	return filter, nil
}

const evalRawContentEnvVar = "EVAL_INTEGRATION_RAW_CONTENT"

// evalRawContentRequested 判断本次调用是否应返回对话原文。
// 受控双闸——网关侧必须显式开启 EVAL_INTEGRATION_RAW_CONTENT，且调用方(LSE)显式带 include_content=true。
// 默认关闭，与历史行为一致(raw_content_available=false)。
func evalRawContentRequested(r *http.Request) bool {
	if !evalAssuranceEnvEnabled(evalRawContentEnvVar) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("include_content"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// evalToolCallsRequested 判断本次调用是否应返回工具调用证据(tool_call_logs)。
// 同 raw-content 双闸——网关侧必须开启 EVAL_INTEGRATION_RAW_CONTENT，且调用方显式带
// include_tool_calls=true 或 include_content=true(后者让既有 LSE 内容拉取流程自动带上工具维度)。
func evalToolCallsRequested(r *http.Request) bool {
	if !evalAssuranceEnvEnabled(evalRawContentEnvVar) {
		return false
	}
	q := r.URL.Query()
	for _, key := range []string{"include_tool_calls", "include_content"} {
		switch strings.ToLower(strings.TrimSpace(q.Get(key))) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

const evalToolEvidenceCap = 1200

// evalEventToolCalls 按 request_id 从 tool_call_logs 拉取该请求的工具调用证据。
// 网关已做污点追踪/风险定级/裁决，这些确定性结构化信号原样返回；入参/结果/受污染入参做安全脱敏+截断，
// 供 LSE 工具维度既遂分析(工具越权/数据外带/间接注入/SSRF)。分析即弃，不落库。
func evalEventToolCalls(ctx context.Context, deps *Dependencies, tenantID, requestID string) []map[string]interface{} {
	if deps == nil || deps.ToolCallLogRepo == nil || strings.TrimSpace(requestID) == "" {
		return nil
	}
	logs, err := deps.ToolCallLogRepo.ListByRequest(ctx, tenantID, requestID)
	if err != nil || len(logs) == 0 {
		return nil
	}
	calls := make([]map[string]interface{}, 0, len(logs))
	for _, l := range logs {
		calls = append(calls, map[string]interface{}{
			"tool_name":           l.ToolName,
			"tool_type":           l.ToolType,
			"risk_level":          l.RiskLevel,
			"status":              l.Status,
			"effective_decision":  firstNonEmptyString(l.EffectiveDecision, l.RawDecision, l.MatchedAction),
			"normalized_target":   l.NormalizedTarget,
			"provenance":          l.Provenance,
			"tainted":             evalToolTainted(l.TaintedArguments),
			"tainted_arguments":   truncateEvalText(redactEvalEvidence(string(l.TaintedArguments)), 600),
			"matched_policy_name": l.MatchedPolicyName,
			"match_reason":        truncateEvalText(redactEvalEvidence(l.MatchReason), 400),
			"parameters":          truncateEvalText(redactEvalEvidence(evalToolParamsString(l.Parameters)), evalToolEvidenceCap),
			"result":              truncateEvalText(redactEvalEvidence(l.Result), evalToolEvidenceCap),
			"created_at":          l.CreatedAt.Format(time.RFC3339),
		})
	}
	return calls
}

// evalEventMCPToolDecisions 按 request_id 回查 MCP 工具决策摘要（tool_type='mcp'）。
// 只返回确定性安全信号（原始/生效裁决、命中的红线 rule_id、策略 id、
// 风险级别），不含 parameters/result 等用户内容，故无需受 raw-content 双闸门控——它是
// 测-堵-验闭环「验」段的核心：LSE 据此断言 raw=block（检测到）vs effective（是否真拦），
// 以及 audit-only 铁律下 effective 被钳到 audit 属正常（不是漏堵）。
func evalEventMCPToolDecisions(ctx context.Context, deps *Dependencies, tenantID, requestID string) []map[string]interface{} {
	if deps == nil || deps.ToolCallLogRepo == nil || strings.TrimSpace(requestID) == "" {
		return nil
	}
	logs, err := deps.ToolCallLogRepo.ListByRequest(ctx, tenantID, requestID)
	if err != nil || len(logs) == 0 {
		return nil
	}
	decisions := make([]map[string]interface{}, 0, len(logs))
	for _, l := range logs {
		if !strings.EqualFold(strings.TrimSpace(l.ToolType), "mcp") {
			continue
		}
		decisions = append(decisions, map[string]interface{}{
			"tool_name":          l.ToolName,
			"tool_type":          l.ToolType,
			"raw_decision":       l.RawDecision,
			"effective_decision": firstNonEmptyString(l.EffectiveDecision, l.MatchedAction),
			"mode":               l.Mode,
			"risk_level":         l.RiskLevel,
			"status":             l.Status,
			"matched_policy_id":  l.MatchedPolicyID,
			"provenance":         l.Provenance,
			"rule_ids":           evalToolRuleIDs(l.EvidenceJSON),
			"trace_id":           l.TraceID,
			"created_at":         l.CreatedAt.Format(time.RFC3339),
		})
	}
	return decisions
}

// evalToolRuleIDs 从 tool_call_logs.evidence_json 抽取命中的 rule_id 列表
// （MCP 红线证据形如 [{"rule_id":"mcp_redline_cloud_metadata","category":"mcp_redline"}]）。
// 供 LSE 归因区分 GW_MCP_REDLINE_MISS（应命中红线却无 rule_id）与正常命中。
func evalToolRuleIDs(raw json.RawMessage) []string {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "[]" || s == "null" {
		return []string{}
	}
	var entries []struct {
		RuleID string `json:"rule_id"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return []string{}
	}
	ruleIDs := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.TrimSpace(e.RuleID) != "" {
			ruleIDs = append(ruleIDs, e.RuleID)
		}
	}
	return ruleIDs
}

// evalToolTainted 判断 tainted_arguments 是否非空（网关污点追踪命中=外部内容污染了工具入参）。
func evalToolTainted(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "[]" && s != "null" && s != "{}"
}

func evalToolParamsString(params map[string]interface{}) string {
	if len(params) == 0 {
		return ""
	}
	b, err := json.Marshal(params)
	if err != nil {
		return ""
	}
	return string(b)
}

// evalEventMessages 按 request_id 从 content_logs 拉取该请求的完整对话(user/assistant/system 各轮)。
// 对话文本完整返回，仅对内嵌的密钥/手机号/身份证做安全脱敏(redactEvalEvidence)，供 LSE 智能体风险分析。
func evalEventMessages(ctx context.Context, deps *Dependencies, tenantID, requestID string) []map[string]interface{} {
	if deps == nil || deps.ContentLogReader == nil || strings.TrimSpace(requestID) == "" {
		return nil
	}
	logs, err := deps.ContentLogReader.ListByRequest(ctx, tenantID, requestID)
	if err != nil || len(logs) == 0 {
		return nil
	}
	messages := make([]map[string]interface{}, 0, len(logs))
	for _, l := range logs {
		messages = append(messages, map[string]interface{}{
			"role":       l.Role,
			"content":    redactEvalEvidence(l.Content),
			"tokens":     l.Tokens,
			"created_at": l.CreatedAt.Format(time.RFC3339),
		})
	}
	return messages
}

// evalEvidencePayload 构造 evidence 字段；messages 非空时附对话原文并标记 raw_content_available=true；
// toolCalls 非空时附工具调用证据并标记 tool_calls_available=true。
// redacted 始终为 true：对话/工具文本完整，但内嵌密钥/PII 已脱敏。
func evalEvidencePayload(event *repository.EvalAuditEvent, messages, toolCalls []map[string]interface{}) map[string]interface{} {
	evidence := map[string]interface{}{
		"redacted":              true,
		"security_event_count":  event.SecurityEventCount,
		"raw_content_available": false,
		"tool_calls_available":  false,
	}
	if messages != nil {
		evidence["raw_content_available"] = true
		evidence["messages"] = messages
	}
	if toolCalls != nil {
		evidence["tool_calls_available"] = true
		evidence["tool_calls"] = toolCalls
	}
	return evidence
}

func evalAuditEventResponse(event *repository.EvalAuditEvent, messages, toolCalls []map[string]interface{}) map[string]interface{} {
	policyHits := evalPolicyHits(event.SecurityEvents)
	action, verdict, riskLevel := evalActionVerdictRisk(event, policyHits)
	return map[string]interface{}{
		"id":                event.ID,
		"request_id":        event.RequestID,
		"agent_instance_id": event.AgentInstanceID,
		"created_at":        event.CreatedAt.Format(time.RFC3339),
		"correlation": map[string]string{
			"trace_id":    event.TraceID,
			"eval_run_id": event.LSEEvalRunID,
			"task_id":     event.LSETaskID,
			"sample_id":   event.LSESampleID,
			"target_id":   event.LSETargetID,
		},
		"source": map[string]string{
			"tenant_id":         event.TenantID,
			"project_id":        event.ProjectID,
			"user_id":           event.UserID,
			"client_id":         event.ClientID,
			"source_ip":         event.SourceIP,
			"session_id":        event.SessionID,
			"agent_type":        event.AgentType,
			"agent_instance_id": event.AgentInstanceID,
		},
		"target": map[string]string{
			"provider_id":   event.ProviderID,
			"model_id":      event.ModelID,
			"model":         event.ModelName,
			"endpoint_type": event.EndpointType,
		},
		"metrics": map[string]interface{}{
			"status":        event.RequestStatus,
			"status_code":   event.StatusCode,
			"latency_ms":    event.LatencyMs,
			"input_tokens":  event.InputTokens,
			"output_tokens": event.OutputTokens,
			"total_cost":    event.TotalCost,
		},
		"action":      action,
		"verdict":     verdict,
		"risk_level":  riskLevel,
		"policy_hits": policyHits,
		"evidence":    evalEvidencePayload(event, messages, toolCalls),
	}
}

func evalPolicyHits(events []repository.EvalSecurityEvent) []map[string]interface{} {
	hits := []map[string]interface{}{}
	for _, event := range events {
		findings, _ := event.MatchedSummary["findings"].([]interface{})
		if len(findings) == 0 {
			hits = append(hits, map[string]interface{}{
				"event_id":   event.ID,
				"event_type": event.EventType,
				"severity":   event.Severity,
				"action":     event.ActionTaken,
			})
			continue
		}
		for _, raw := range findings {
			finding, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			hit := map[string]interface{}{
				"event_id":   event.ID,
				"event_type": event.EventType,
				"severity":   event.Severity,
				"action":     firstNonEmptyString(stringFromMap(finding, "action"), event.ActionTaken),
				"category":   stringFromMap(finding, "category"),
				"rule_id":    stringFromMap(finding, "rule_id"),
				"rule_name":  stringFromMap(finding, "rule_name"),
			}
			if evidence := firstNonEmptyString(stringFromMap(finding, "redacted_evidence"), stringFromMap(finding, "matched_text_preview")); evidence != "" {
				hit["evidence"] = redactEvalEvidence(evidence)
			}
			hits = append(hits, hit)
		}
	}
	return hits
}

func evalActionVerdictRisk(event *repository.EvalAuditEvent, hits []map[string]interface{}) (string, string, string) {
	status := strings.ToLower(event.RequestStatus)
	if strings.Contains(status, "block") || event.StatusCode == http.StatusForbidden {
		return "block", "blocked", "high"
	}
	if len(hits) == 0 {
		if event.SecurityEventCount > 0 {
			return "alert", "flagged", "medium"
		}
		return "allow", "passed", "low"
	}
	risk := "medium"
	for _, hit := range hits {
		severity := strings.ToLower(toString(hit["severity"]))
		if severity == "critical" {
			return "alert", "flagged", "critical"
		}
		if severity == "high" {
			risk = "high"
		}
		if strings.EqualFold(toString(hit["action"]), "block") {
			return "block", "blocked", risk
		}
	}
	return "alert", "flagged", risk
}

func redactEvalEvidence(value string) string {
	redacted := value
	for _, pattern := range evalEvidenceSensitivePatterns {
		redacted = pattern.ReplaceAllString(redacted, "[redacted]")
	}
	return redacted
}

func stringFromMap(m map[string]interface{}, key string) string {
	return toString(m[key])
}

func toString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// ListModelsEvalStatus 返回本租户每个被 lse 测评过的模型的最新测评状态 + 跳 lse 报告的 deeplink。
func ListModelsEvalStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if deps == nil || deps.ModelEvalStatusRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "eval_status_not_configured", "model eval status repo not configured")
			return
		}
		rows, err := deps.ModelEvalStatusRepo.ListModelEvalStatus(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "eval_status_query_failed", "failed to query model eval status")
			return
		}
		baseURL := ""
		if deps.SystemRepo != nil {
			if s, gerr := deps.SystemRepo.Get(r.Context(), "lse_base_url"); gerr == nil && s != nil {
				baseURL = bakeLSEBase(s.Value)
			}
		}
		items := make([]types.ModelEvalStatusItem, 0, len(rows))
		for _, row := range rows {
			status := "passed"
			if row.HasHighRisk {
				status = "high_risk"
			}
			reportURL := ""
			if baseURL != "" && row.LSETargetID != "" {
				reportURL = baseURL + "/eval-tasks?modelTargetId=" + row.LSETargetID
			}
			items = append(items, types.ModelEvalStatusItem{
				ModelID:      row.ModelID,
				Status:       status,
				HasHighRisk:  row.HasHighRisk,
				ReportURL:    reportURL,
				LatestEvalAt: row.LatestEvalAt.Format(time.RFC3339),
			})
		}
		writeJSON(w, types.ModelEvalStatusResponse{Data: items})
	}
}
