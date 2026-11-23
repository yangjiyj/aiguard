package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/alertevidence"
)

// blockIdentifierPattern limits prefix matching to ASCII identifiers
// (evt_/op_/request/trace ids), never free-text rule names.
var blockIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

// blockingSecurityActions are the action_taken values every data plane writes
// when it actually stopped traffic: the gateway protocols, the reverse proxy
// (security_blocked), AgentGuard tool calls (tool_attempt_blocked legacy value;
// the current value is block/confirm after the action_taken misalignment fix),
// tool definitions (tool_blocked), and the forward proxy (block).
const blockingSecurityActionsSQL = `('block','confirm','security_blocked','stream_blocked','tool_attempt_blocked','tool_blocked')`

// SecurityBlockRecord is one blocked request as the console's 阻断记录 shows
// it: what was stopped, by which configured rule, on what matched detail, and
// every identifier an agent-side notice may carry.
type SecurityBlockRecord struct {
	BlockID      string    `json:"block_id"`
	CreatedAt    time.Time `json:"created_at"`
	RequestID    string    `json:"request_id"`
	TraceID      string    `json:"trace_id,omitempty"`
	OperationID  string    `json:"operation_id,omitempty"`
	TenantID     string    `json:"tenant_id"`
	ProjectID    string    `json:"project_id,omitempty"`
	ProjectName  string    `json:"project_name,omitempty"`
	UserID       string    `json:"user_id,omitempty"`
	UserName     string    `json:"user_name,omitempty"`
	Model        string    `json:"model,omitempty"`
	AgentType    string    `json:"agent_type,omitempty"`
	EndpointType string    `json:"endpoint_type,omitempty"`
	SourceIP     string    `json:"source_ip,omitempty"`
	Source       string    `json:"source"`
	EventType    string    `json:"event_type"`
	ActionTaken  string    `json:"action_taken"`
	Severity     string    `json:"severity"`
	Stage        string    `json:"stage,omitempty"`
	Layer        string    `json:"layer"`
	Reason       string    `json:"reason"`
	RuleID       string    `json:"rule_id,omitempty"`
	RuleName     string    `json:"rule_name,omitempty"`
	Category     string    `json:"category,omitempty"`
	Detail       string    `json:"detail,omitempty"`
	// RawEvidence、EvidenceContext 是阻断所依据命中的原文片段和不打码前后文（2.9.22 起入库）。
	// 只在详情、溯源里给有内容证据权限的角色返回（见 handler 的 blockRecordForViewer），列表一律不返回。
	RawEvidence     string `json:"raw_evidence,omitempty"`
	EvidenceContext string `json:"evidence_context,omitempty"`
	// RawEvidenceTruncated 表示 RawEvidence 是被截断的原文（单条超过 4096 字），与 RawEvidence 同源、同权限：
	// 只在详情、溯源里给有内容证据权限的角色返回，控制台据此显示“（已截断）”。
	RawEvidenceTruncated bool `json:"raw_evidence_truncated,omitempty"`
	// RawEvidenceOmitted 表示依据的命中因事件原文总量超限没有存原文（哈希照存），需要从留存回捞；不是敏感信息，各角色都返回。
	RawEvidenceOmitted bool   `json:"raw_evidence_omitted,omitempty"`
	Basis              string `json:"basis"`
	// Explanation 说明这次调用为什么危险；只在网关写入了可靠的风险原因时才有值。
	Explanation   string `json:"explanation,omitempty"`
	Summary       string `json:"summary,omitempty"`
	RequestStatus string `json:"request_status,omitempty"`
	HTTPStatus    int    `json:"http_status,omitempty"`
	// PolicyLink 是控制台“命中规则”的跳转目标。
	PolicyLink *PolicyLink `json:"policy_link,omitempty"`

	// 智能分析（语义裁判）拦截时的裁判置信度与拦截阈值，其它拦截为空。
	SemanticConfidence         *float64 `json:"semantic_confidence,omitempty"`
	SemanticBlockMinConfidence *float64 `json:"semantic_block_min_confidence,omitempty"`
}

type SecurityBlockRecordFilter struct {
	// Query matches any identifier exactly (block/event id, request id, trace
	// id, operation id, tool public event id, rule id) and rule names by
	// substring. Identifiers copied from a screenshot with a truncated or
	// explicitly marked truncated tail (… or ...) match on its full prefix of 12+ characters.
	Query      string
	From       time.Time
	To         time.Time
	Layer      string
	ProjectIDs []string
	Limit      int
	Offset     int
}

func buildSecurityBlockRecordWhere(tenantID string, filter SecurityBlockRecordFilter) (string, []any) {
	args := []any{tenantID}
	where := []string{
		"se.tenant_id = $1",
		"se.action_taken IN " + blockingSecurityActionsSQL,
		"se.event_type <> 'security_check_failed'",
		// Skill 调用被拦截时，同一请求另有一条带命令与依据的工具调用阻断记录；控制面写的
		// skill_invocation_risk 只是它的观察副本，列表里不再重复列出（按编号仍可直接打开）。
		`NOT (se.event_type = 'skill_invocation_risk' AND EXISTS (
			SELECT 1 FROM security_events tool
			WHERE tool.tenant_id = se.tenant_id AND tool.request_id = se.request_id
			  AND tool.event_type = 'tool_attempt_blocked' AND tool.action_taken IN ` + blockingSecurityActionsSQL + `
		))`,
	}
	if !filter.From.IsZero() {
		args = append(args, filter.From)
		where = append(where, fmt.Sprintf("se.created_at >= $%d", len(args)))
	}
	if !filter.To.IsZero() {
		args = append(args, filter.To)
		where = append(where, fmt.Sprintf("se.created_at < $%d", len(args)))
	}
	if len(filter.ProjectIDs) > 0 {
		args = append(args, filter.ProjectIDs)
		where = append(where, fmt.Sprintf("se.project_id = ANY($%d)", len(args)))
	}
	if layer := strings.TrimSpace(filter.Layer); layer != "" {
		args = append(args, layer)
		where = append(where, fmt.Sprintf("COALESCE(se.matched_summary->'block'->>'layer', '') = $%d", len(args)))
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		args = append(args, query)
		exact := len(args)
		args = append(args, "%"+escapePostgresLikeLiteral(query)+"%")
		like := len(args)
		prefix := ""
		truncatedPrefix := strings.TrimSuffix(strings.TrimSuffix(query, "..."), "…")
		if truncatedPrefix != query && len(truncatedPrefix) >= 12 && blockIdentifierPattern.MatchString(truncatedPrefix) {
			args = append(args, escapePostgresLikeLiteral(truncatedPrefix)+"%")
			prefix = fmt.Sprintf(`
				OR se.id LIKE $%[1]d ESCAPE E'\\'
				OR se.request_id LIKE $%[1]d ESCAPE E'\\'
				OR COALESCE(rl.trace_id, '') LIKE $%[1]d ESCAPE E'\\'
				OR COALESCE(se.matched_summary->'block'->>'block_id', '') LIKE $%[1]d ESCAPE E'\\'
				OR COALESCE(se.matched_summary->'block'->>'operation_id', '') LIKE $%[1]d ESCAPE E'\\'
				OR EXISTS (
					SELECT 1 FROM tool_call_logs t
					WHERE t.tenant_id = se.tenant_id AND t.request_id = se.request_id
					  AND (COALESCE(t.operation_id, '') LIKE $%[1]d ESCAPE E'\\' OR COALESCE(t.public_event_id, '') LIKE $%[1]d ESCAPE E'\\')
				)`, len(args))
		}
		where = append(where, fmt.Sprintf(`(
			se.id = $%[1]d
			OR COALESCE(se.matched_summary->'block'->>'block_id', '') = $%[1]d
			OR se.request_id = $%[1]d
			OR COALESCE(rl.trace_id, '') = $%[1]d
			OR COALESCE(se.matched_summary->'block'->>'operation_id', '') = $%[1]d
			OR COALESCE(se.matched_summary->'block'->>'rule_id', se.matched_summary->>'rule_id', se.rule_id, '') = $%[1]d
			OR COALESCE(se.matched_summary->'block'->>'rule_name', se.matched_summary->>'rule_name', '') ILIKE $%[2]d ESCAPE E'\\'
			OR EXISTS (
				SELECT 1 FROM tool_call_logs t
				WHERE t.tenant_id = se.tenant_id AND t.request_id = se.request_id
				  AND (t.operation_id = $%[1]d OR t.public_event_id = $%[1]d OR t.trace_id = $%[1]d)
			)%[3]s
		)`, exact, like, prefix))
	}
	return strings.Join(where, " AND "), args
}

const securityBlockRecordSelect = `
	SELECT se.id, se.created_at, se.request_id, se.tenant_id,
	       COALESCE(se.project_id, ''), COALESCE(p.name, ''),
	       COALESCE(se.user_id, ''), COALESCE(u.username, ''),
	       se.event_type, se.action_taken, se.severity,
	       COALESCE(se.rule_id, ''), COALESCE(r.name, ''),
	       COALESCE(se.matched_summary, '{}'::jsonb),
	       COALESCE(rl.trace_id, ''), COALESCE(m.model_name, ''),
	       COALESCE(rl.agent_type, ''), COALESCE(rl.endpoint_type, ''),
	       COALESCE(rl.source_ip, ''), COALESCE(rl.request_status, ''),
	       COALESCE(rl.upstream_status_code, 0),
	       COALESCE((
	           SELECT t.operation_id FROM tool_call_logs t
	           WHERE t.tenant_id = se.tenant_id AND t.request_id = se.request_id
	             AND t.event_type = 'tool_attempt_blocked'
	           ORDER BY t.created_at LIMIT 1
	       ), ''),
	       ARRAY(
	           SELECT r.id FROM rules r
	           JOIN rule_sets rs ON rs.id = r.rule_set_id
	           WHERE r.id = ANY(
	               ARRAY[se.matched_summary->'block'->>'rule_id', se.matched_summary->>'rule_id',
	                     se.matched_summary->'primary_finding'->>'rule_id', se.rule_id]::text[]
	               || ARRAY(
	                   SELECT f->>'rule_id'
	                   FROM jsonb_array_elements(CASE WHEN jsonb_typeof(se.matched_summary->'findings') = 'array'
	                                                  THEN se.matched_summary->'findings' ELSE '[]'::jsonb END) f
	                   WHERE jsonb_typeof(f) = 'object'
	               ))
	             AND rs.published = TRUE
	             AND ` + ruleNotDeletedSQL + `
	             AND (rs.tenant_id = se.tenant_id OR (rs.tenant_id = '` + SystemTenantID + `' AND rs.source_type = 'builtin'))
	       )
	FROM security_events se
	LEFT JOIN request_logs rl ON rl.tenant_id = se.tenant_id AND rl.request_id = se.request_id
	LEFT JOIN projects p ON p.id = se.project_id
	LEFT JOIN users u ON u.id = se.user_id
	LEFT JOIN rules r ON r.id = se.rule_id
	LEFT JOIN models m ON m.id = rl.model_id`

// ListBlockRecords returns the tenant's blocked requests, newest first.
func (r *SecurityEventRepository) ListBlockRecords(ctx context.Context, tenantID string, filter SecurityBlockRecordFilter) ([]SecurityBlockRecord, int, error) {
	if filter.Limit <= 0 || filter.Limit > 200 {
		filter.Limit = 50
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	where, args := buildSecurityBlockRecordWhere(tenantID, filter)
	query := fmt.Sprintf(`%s WHERE %s ORDER BY se.created_at DESC, se.id DESC LIMIT $%d OFFSET $%d`,
		securityBlockRecordSelect, where, len(args)+1, len(args)+2)
	rows, err := r.db.Query(ctx, query, append(append([]any{}, args...), filter.Limit, filter.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list block records: %w", err)
	}
	defer rows.Close()
	records := []SecurityBlockRecord{}
	for rows.Next() {
		record, err := scanSecurityBlockRecord(rows)
		if err != nil {
			return nil, 0, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var total int
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*) FROM security_events se
		LEFT JOIN request_logs rl ON rl.tenant_id = se.tenant_id AND rl.request_id = se.request_id
		WHERE %s`, where)
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count block records: %w", err)
	}
	return records, total, nil
}

// GetBlockRecord returns one block by its block number (the event id).
func (r *SecurityEventRepository) GetBlockRecord(ctx context.Context, tenantID, blockID string) (*SecurityBlockRecord, error) {
	row := r.db.QueryRow(ctx, securityBlockRecordSelect+`
		WHERE se.tenant_id = $1 AND (se.id = $2 OR se.matched_summary->'block'->>'block_id' = $2)
		  AND se.event_type <> 'security_check_failed'
		  AND se.action_taken IN `+blockingSecurityActionsSQL+`
		ORDER BY (se.id = $2) DESC, se.created_at DESC, se.id DESC LIMIT 1`, tenantID, strings.TrimSpace(blockID))
	record, err := scanSecurityBlockRecord(row)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

type securityBlockRecordScanner interface {
	Scan(dest ...any) error
}

func scanSecurityBlockRecord(row securityBlockRecordScanner) (SecurityBlockRecord, error) {
	var record SecurityBlockRecord
	var matchedJSON []byte
	var ruleID, ruleName, toolOperationID string
	var existingRuleIDs []string
	if err := row.Scan(
		&record.BlockID, &record.CreatedAt, &record.RequestID, &record.TenantID,
		&record.ProjectID, &record.ProjectName, &record.UserID, &record.UserName,
		&record.EventType, &record.ActionTaken, &record.Severity,
		&ruleID, &ruleName, &matchedJSON,
		&record.TraceID, &record.Model, &record.AgentType, &record.EndpointType,
		&record.SourceIP, &record.RequestStatus, &record.HTTPStatus, &toolOperationID, &existingRuleIDs,
	); err != nil {
		return SecurityBlockRecord{}, err
	}
	summary := map[string]any{}
	_ = json.Unmarshal(matchedJSON, &summary)
	finalRuleID := blockFinalRuleID(summary, ruleID)
	projectSecurityBlockAttribution(&record, summary, ruleID, ruleName, toolOperationID)
	ruleExists := false
	for _, id := range existingRuleIDs {
		if id != "" && id == finalRuleID {
			ruleExists = true
		}
	}
	record.PolicyLink = blockPolicyLink(&record, summary, ruleID, ruleExists)
	return record, nil
}

// projectSecurityBlockAttribution fills the console fields from the
// attribution the data plane persisted (matched_summary.block); events written
// before that attribution existed fall back to their primary finding.
func projectSecurityBlockAttribution(record *SecurityBlockRecord, summary map[string]any, ruleID, ruleName, toolOperationID string) {
	block, _ := summary["block"].(map[string]any)
	primary, _ := summary["primary_finding"].(map[string]any)
	blocking := blockingFindingFromSummary(summary)
	pick := func(values ...string) string {
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
		return ""
	}
	str := func(source map[string]any, key string) string {
		if source == nil {
			return ""
		}
		value, _ := source[key].(string)
		return value
	}
	record.Stage = pick(str(summary, "stage"), str(blocking, "matched_location"))
	record.Summary = str(summary, "summary")
	record.Source = pick(str(summary, "source"), "gateway")
	record.RuleID = pick(str(block, "rule_id"), str(blocking, "rule_id"), str(summary, "rule_id"), ruleID)
	record.RuleName = pick(str(block, "rule_name"), str(blocking, "rule_name"), str(summary, "rule_name"), ruleName)
	record.Category = pick(str(block, "category"), str(blocking, "category"), str(summary, "category"), str(primary, "category"))
	record.Detail = pick(str(block, "detail"), str(blocking, "redacted_evidence"), str(blocking, "matched_text_preview"),
		str(primary, "redacted_evidence"), str(primary, "matched_text_preview"))
	record.OperationID = pick(str(block, "operation_id"), toolOperationID)
	record.Layer = pick(str(block, "layer"), legacyBlockLayer(record))
	record.Reason = pick(str(block, "reason"), legacyBlockReason(record.Layer))
	record.Basis = pick(str(block, "basis"), legacyBlockBasis(record, blocking))
	projectSemanticBlock(record, block, summary)
	detailTruncated, _ := block["detail_truncated"].(bool)
	record.Detail = fullerBlockDetail(record.Detail, detailTruncated, str(blocking, "redacted_evidence"), str(primary, "redacted_evidence"))
	// 命中原文取自阻断所依据的那条命中（没有时用主命中），与 detail 的来源一致；接口层按内容证据权限决定是否返回。
	evidence := blocking
	if evidence == nil && primary != nil {
		evidence = primaryFindingEvidence(summary, primary)
	}
	record.RawEvidence, record.EvidenceContext = str(evidence, alertevidence.FieldRawEvidence), str(evidence, alertevidence.FieldEvidenceContext)
	record.RawEvidenceTruncated, _ = evidence[alertevidence.FieldRawEvidenceTruncated].(bool)
	record.RawEvidenceOmitted, _ = evidence[alertevidence.FieldRawEvidenceOmitted].(bool)
	explainSkillInvocationBlock(record, summary)
	explainAgentToolBlock(record, block, blocking)
}

// projectSemanticBlock：策略「智能分析命中时=拦截」触发的拦截，依据取引擎写进事件的
// 「智能分析高置信拦截：…」文案并带上置信度与阈值。只在能确认「网关选中的拦截原因就是这条语义
// 拦截」时才改：网关写了 block.semantic_enforced=true；或旧记录（11a50f1d8 网关，无标记）的依据
// 恰好是用该语义 finding 规则名拼出的「规则『…』的处置动作为阻断」。两种情况都要求记录的规则名与
// 类别和该语义 finding 一致，避免同一请求里手机号等其它规则拦截时被误改。
func projectSemanticBlock(record *SecurityBlockRecord, block, summary map[string]any) {
	semantic := semanticBlockedFindingFor(record, summary)
	if semantic == nil {
		return
	}
	ruleName, _ := semantic["rule_name"].(string)
	marked, _ := block["semantic_enforced"].(bool)
	legacy := strings.TrimSpace(record.Basis) == fmt.Sprintf("规则「%s」的处置动作为阻断", strings.TrimSpace(ruleName))
	if !marked && !legacy {
		return
	}
	triage, _ := semantic["triage"].(map[string]any)
	number := func(key string) *float64 {
		for _, source := range []map[string]any{block, triage} {
			if value, ok := source[key].(float64); ok {
				return &value
			}
		}
		return nil
	}
	record.SemanticConfidence = number("semantic_confidence")
	record.SemanticBlockMinConfidence = number("semantic_block_min_confidence")
	if strings.HasPrefix(strings.TrimSpace(record.Basis), semanticBlockBasisPrefix) {
		return
	}
	reason, _ := semantic["evidence_reason"].(string)
	for _, part := range strings.Split(reason, "；") {
		if part = strings.TrimSpace(part); strings.HasPrefix(part, semanticBlockBasisPrefix) {
			record.Basis = part
			return
		}
	}
	if record.SemanticConfidence != nil && record.SemanticBlockMinConfidence != nil {
		record.Basis = fmt.Sprintf("%s置信度 %.2f ≥ 阈值 %.2f", semanticBlockBasisPrefix,
			*record.SemanticConfidence, *record.SemanticBlockMinConfidence)
		return
	}
	record.Basis = "智能分析高置信拦截"
}

// semanticBlockedFindingFor 找规则名与类别都与记录一致、且被智能分析拦截的语义 finding。
func semanticBlockedFindingFor(record *SecurityBlockRecord, summary map[string]any) map[string]any {
	findings, _ := summary["findings"].([]any)
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		triage, _ := finding["triage"].(map[string]any)
		if enforcement, _ := triage["semantic_enforcement"].(string); enforcement != "blocked" {
			continue
		}
		ruleName, _ := finding["rule_name"].(string)
		category, _ := finding["category"].(string)
		if strings.TrimSpace(ruleName) == record.RuleName && strings.TrimSpace(category) == record.Category {
			return finding
		}
	}
	return nil
}

// semanticBlockBasisPrefix 与安全引擎 semantic_enforcement 写进 evidence_reason 的拦截文案一致。
const semanticBlockBasisPrefix = "智能分析高置信拦截："

func blockingFindingFromSummary(summary map[string]any) map[string]any {
	findings, _ := summary["findings"].([]any)
	var fallback map[string]any
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if fallback == nil {
			fallback = finding
		}
		switch strings.ToLower(fmt.Sprint(finding["action"])) {
		case "block", "quarantine", "deny", "blocked":
			return finding
		}
	}
	if primary, ok := summary["primary_finding"].(map[string]any); ok {
		return primaryFindingEvidence(summary, primary)
	}
	return fallback
}

// primaryFindingEvidence 返回主命中对应的 findings 条目：2.9.22 起 primary_finding 不再复制原文，
// 用 findings_index 指向 findings 里的那一条。没有引用或引用无效时返回 primary 本身（旧数据整条复制过）。
func primaryFindingEvidence(summary, primary map[string]any) map[string]any {
	if finding := PrimaryFindingByIndex(summary); finding != nil {
		return finding
	}
	return primary
}

func legacyBlockLayer(record *SecurityBlockRecord) string {
	switch {
	// action_taken 改记真实处置动作后（gateway 不再把事件类型串错位写入
	// action_taken），工具阻断记录按 event_type 识别；旧数据 action_taken
	// 仍是 tool_attempt_blocked，两个条件都保留。
	case record.EventType == "tool_attempt_blocked" || record.ActionTaken == "tool_attempt_blocked":
		if record.Category == "destructive_change" {
			return "destructive_operation"
		}
		return "agent_tool"
	case record.ActionTaken == "tool_blocked":
		return "tool_definition"
	case record.Category == "restricted_file_access":
		return "restricted_file"
	case strings.HasPrefix(record.Category, "file_"):
		return "file"
	case record.Stage == "output" || record.ActionTaken == "stream_blocked":
		return "output_content"
	default:
		return "input_content"
	}
}

func legacyBlockReason(layer string) string {
	switch layer {
	case "output_content":
		return "模型输出命中安全规则"
	case "tool_arguments":
		return "工具调用参数命中安全规则"
	case "file":
		return "附件命中文件策略"
	case "restricted_file":
		return "访问了受限文件"
	case "tool_definition":
		return "请求携带的工具被工具策略禁止"
	case "destructive_operation":
		return "模型准备调用删除或破坏性工具"
	case "agent_tool":
		return "智能体工具调用被行为策略阻断"
	default:
		return "输入内容命中安全规则"
	}
}

func legacyBlockBasis(record *SecurityBlockRecord, blocking map[string]any) string {
	if record.Layer == "destructive_operation" {
		return "策略中心「智能体行为 → 删除与破坏」动作为阻断"
	}
	if record.RuleName != "" {
		return fmt.Sprintf("规则「%s」的处置动作为阻断", record.RuleName)
	}
	if action, _ := blocking["action"].(string); action != "" {
		return "命中规则的处置动作为" + action
	}
	return "控制台策略配置为阻断"
}
