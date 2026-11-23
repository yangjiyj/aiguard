package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/aicontentlabel"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
)

// A block must be explainable from both ends: the agent that was stopped
// receives a notice naming the rule, the matched detail, and a block number,
// and the same block number is the id of the security_events row the console
// lists under 阻断记录. The per-request ledger below is the join: every audit
// writer notes the first blocking event it persists, and every block response
// renders its notice from that note.

const (
	blockResponseModeError   = "error"
	blockResponseModeMessage = "message"

	blockResponseModeSettingKey   = "security_block_response_mode"
	blockNoticeTemplateSettingKey = "security_block_notice_template"
	maxBlockNoticeTemplateRunes   = 2000
	maxBlockNoticeDetailRunes     = 120
	maxBlockRecordDetailRunes     = 2000
	blockNoticeSettingsCacheTTL   = 30 * time.Second
)

// DefaultBlockNoticeTemplate is shown to agents unless an administrator saves
// a custom template. A line whose placeholders all resolve empty is dropped.
const DefaultBlockNoticeTemplate = "【JJDGuard 安全网关】本次请求已被安全策略阻断。\n" +
	"阻断原因：{reason}\n" +
	"命中规则：{rule}\n" +
	"命中内容：{detail}\n" +
	"阻断编号：{block_id}\n" +
	"请求 ID：{request_id}\n" +
	"操作编号：{operation_id}\n" +
	"如需核查，请联系管理员并提供阻断编号或请求 ID（管理后台「风险处理 → 阻断记录」可查）。"

// Recognize only the exact previous stock template. Modified company wording
// remains custom; this compatibility path does not write system settings.
const legacyDefaultBlockNoticeTemplate = "【JJDGuard 安全网关】本次请求已被安全策略阻断。\n" +
	"阻断原因：{reason}\n" +
	"命中规则：{rule}\n" +
	"命中内容：{detail}\n" +
	"阻断编号：{block_id}\n" +
	"操作编号：{operation_id}\n" +
	"如需放行，请联系管理员并提供阻断编号（管理后台「安全护栏 → 阻断记录」可查）。"

func normalizeBlockNoticeTemplate(template string) string {
	trimmed := strings.TrimSpace(template)
	if trimmed == "" || trimmed == legacyDefaultBlockNoticeTemplate || ValidateBlockNoticeTemplate(template) != nil {
		return DefaultBlockNoticeTemplate
	}
	return template
}

// BlockNoticePlaceholders lists every placeholder a template may use.
var BlockNoticePlaceholders = []string{"{reason}", "{rule}", "{detail}", "{block_id}", "{operation_id}", "{request_id}"}

type blockLedgerKey struct{}
type blockOperationKey struct{}
type maskUnavailableKey struct{}

type blockLedger struct {
	mu    sync.Mutex
	entry *blockAttribution
}

// blockAttribution is what a block is traced back to. It is also persisted
// as matched_summary.block on the security event.
type blockAttribution struct {
	BlockID  string `json:"block_id"`
	Layer    string `json:"layer"`
	Reason   string `json:"reason"`
	RuleID   string `json:"rule_id,omitempty"`
	RuleName string `json:"rule_name,omitempty"`
	Category string `json:"category,omitempty"`
	Severity string `json:"severity,omitempty"`
	Detail   string `json:"detail,omitempty"`
	// DetailTruncated 标明 Detail 超过落库上限被截断（末尾补 …）。控制面只在有这个标记时用 finding 里的
	// 完整脱敏证据补全，不按“以 … 结尾”去猜：命令本身可能以 … 结尾。
	DetailTruncated bool `json:"detail_truncated,omitempty"`
	// NoticeDetail 只用于渲染阻断提示，不落库。
	NoticeDetail string `json:"-"`
	Basis        string `json:"basis,omitempty"`
	OperationID  string `json:"operation_id,omitempty"`
	RequestID    string `json:"request_id,omitempty"`
	// Cause 是智能体工具调用阻断的真实处置原因（安全底线、配置规则、高风险判定等），
	// RiskReason 是分析器给出的风险原因；控制台据此生成依据与风险说明。
	Cause      string `json:"cause,omitempty"`
	RiskReason string `json:"risk_reason,omitempty"`
	// ManagedBehavior 是命中的智能体托管行为键（policy-center-<key> 去掉前缀，如 system_command），
	// 控制台据此跳到对应的策略；非托管行为不写。托管编号本身不写进 RuleID（不外露内部代号，也不是 rules 表外键）。
	ManagedBehavior string `json:"managed_behavior,omitempty"`
	// ProtectionItem 是决定（或参与）这次处置的防护项键（注册表键，如 agent.ssh_private_key、
	// agent.high_risk_without_rule）。控制台优先按它定位配置；risk_reason 可能是更强的
	// 非防护项原因（例如 command_not_allowlisted），只看它会找不到对应的防护项。
	ProtectionItem string `json:"protection_item,omitempty"`
	// ExceptionEligible 仅 cause 为 analyzer_high_risk_block 或 protection_item 时写：此次阻断
	// 能否被放行例外改变（2.9.22 起没有让网关忽略例外的安全底线，两者都为 true）。
	// 指针以区分「不适用」与 false。
	ExceptionEligible *bool `json:"exception_eligible,omitempty"`
	// 智能分析（语义裁判）拦截时的裁判置信度与拦截阈值，其它拦截不写。
	SemanticConfidence         *float64 `json:"semantic_confidence,omitempty"`
	SemanticBlockMinConfidence *float64 `json:"semantic_block_min_confidence,omitempty"`
	// SemanticEnforced 显式标明本次选中的拦截原因是智能分析拦截；阻断记录读取侧只信这个标记。
	SemanticEnforced bool `json:"semantic_enforced,omitempty"`
}

// blockOperation carries what AgentGuard knows about a blocked tool call to
// the audit writer that persists the tool_attempt_blocked event.
type blockOperation struct {
	OperationID string
	Layer       string
	Reason      string
	RuleID      string
	RuleName    string
	Basis       string
	Detail      string
	// NoticeDetail 是写进阻断提示的命中内容；为空时用 Detail。删除与破坏操作的提示直接用 Detail 里的命令骨架。
	NoticeDetail string
	Cause        string
	RiskReason   string
	// ManagedBehavior、ProtectionItem、ExceptionEligible 同 blockAttribution 同名字段。
	ManagedBehavior   string
	ProtectionItem    string
	ExceptionEligible *bool
}

func withBlockLedger(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Value(blockLedgerKey{}).(*blockLedger); ok {
		return ctx
	}
	return withRequestRedaction(context.WithValue(ctx, blockLedgerKey{}, &blockLedger{}))
}

func blockLedgerFromContext(ctx context.Context) *blockLedger {
	if ctx == nil {
		return nil
	}
	ledger, _ := ctx.Value(blockLedgerKey{}).(*blockLedger)
	return ledger
}

func withBlockOperation(ctx context.Context, operation blockOperation) context.Context {
	return context.WithValue(ctx, blockOperationKey{}, operation)
}

func withMaskUnavailable(ctx context.Context) context.Context {
	return context.WithValue(ctx, maskUnavailableKey{}, true)
}

// markMaskUnavailable records on the request log that a configured mask could
// not be applied and the original content was forwarded with an alert.
func markMaskUnavailable(result *AuditResult) *AuditResult {
	if result == nil {
		result = &AuditResult{OutputFindings: []map[string]interface{}{}}
	}
	if result.ResponseMetadata == nil {
		result.ResponseMetadata = map[string]interface{}{}
	}
	result.ResponseMetadata["mask_unavailable"] = true
	if result.OutputAction == "" || result.OutputAction == "allow" || result.OutputAction == "mask" {
		result.OutputAction = "audit"
	}
	return result
}

func isBlockingSecurityAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	// "block"/"confirm" 是 AgentGuard 工具链在 action_taken 错位修复后的取值
	// （真实处置动作）；tool_attempt_blocked 是历史数据的旧值（曾错位承载事件
	// 类型），保留以免存量阻断事件的归因回查失效。
	case "security_blocked", "stream_blocked", "tool_attempt_blocked", "tool_blocked", "block", "confirm":
		return true
	default:
		return false
	}
}

// annotateSecurityEventBlock is called by every audit writer once the event id
// is fixed. Blocking events get matched_summary.block and are noted in the
// request ledger; mask-unavailable alerts are labelled as such.
func annotateSecurityEventBlock(ctx context.Context, envelope *modelrouter.RequestEnvelope, eventID string, findings []SecurityFinding, actionTaken, summary string, matchedSummary map[string]interface{}) {
	if matchedSummary == nil {
		return
	}
	if unavailable, _ := ctx.Value(maskUnavailableKey{}).(bool); unavailable {
		matchedSummary["mask_unavailable"] = true
		matchedSummary["decision_basis"] = "规则动作为脱敏，但该内容无法安全脱敏，已按原文放行并告警"
	}
	if !isBlockingSecurityAction(actionTaken) {
		return
	}
	attribution := deriveBlockAttribution(ctx, eventID, findings, actionTaken, summary)
	if envelope != nil {
		attribution.RequestID = envelope.RequestID
	}
	matchedSummary["block"] = attribution
	if ledger := blockLedgerFromContext(ctx); ledger != nil {
		ledger.mu.Lock()
		if ledger.entry == nil {
			copied := attribution
			ledger.entry = &copied
		}
		ledger.mu.Unlock()
	}
}

func deriveBlockAttribution(ctx context.Context, eventID string, findings []SecurityFinding, actionTaken, summary string) blockAttribution {
	attribution := blockAttribution{BlockID: eventID}
	stage := securityEventStageFromContext(ctx)
	if operation, ok := ctx.Value(blockOperationKey{}).(blockOperation); ok {
		attribution.OperationID = operation.OperationID
		attribution.Layer = operation.Layer
		attribution.Reason = operation.Reason
		attribution.RuleID = operation.RuleID
		attribution.RuleName = operation.RuleName
		attribution.Basis = operation.Basis
		attribution.Detail, attribution.DetailTruncated = boundedRecordText(operation.Detail)
		attribution.NoticeDetail, _ = boundedRecordText(operation.NoticeDetail)
		attribution.Cause = operation.Cause
		attribution.RiskReason = operation.RiskReason
		attribution.ManagedBehavior = operation.ManagedBehavior
		attribution.ProtectionItem = operation.ProtectionItem
		attribution.ExceptionEligible = operation.ExceptionEligible
	}
	blocking, hasBlocking := blockingSecurityFinding(findings)
	if hasBlocking {
		finding := blocking
		if attribution.RuleID == "" {
			attribution.RuleID = firstNonEmptyString(finding.RuleID, finding.SourceRuleID, finding.PolicyCode)
		}
		if attribution.RuleName == "" {
			attribution.RuleName = finding.RuleName
		}
		attribution.Category = finding.Category
		attribution.Severity = finding.Severity
		if attribution.Detail == "" {
			attribution.Detail, attribution.DetailTruncated = boundedRecordText(firstNonEmptyString(finding.RedactedEvidence, finding.MatchedTextPreview))
		}
		if attribution.Basis == "" {
			attribution.Basis = findingBlockBasis(finding)
		}
		if isSemanticEnforcedBlock(finding) {
			attribution.SemanticEnforced = true
			attribution.SemanticConfidence = triageFloat(finding.Triage, "semantic_confidence")
			attribution.SemanticBlockMinConfidence = triageFloat(finding.Triage, "semantic_block_min_confidence")
		}
		if stage == "" {
			stage = finding.MatchedLocation
		}
	}
	if attribution.Layer == "" {
		attribution.Layer = blockLayer(actionTaken, stage, findings, summary)
	}
	if attribution.NoticeDetail == "" && hasBlocking {
		attribution.NoticeDetail = contentNoticeDetail(attribution.Layer, blocking)
	}
	if attribution.Reason == "" {
		attribution.Reason = blockLayerReason(attribution.Layer)
	}
	if attribution.Basis == "" {
		attribution.Basis = "控制台策略配置为阻断"
	}
	return attribution
}

// contentNoticeDetail 是内容规则阻断时写进提示的命中内容（规格 4.7）：
//   - 输入阶段且有明确命中位置：使用者自己发来的原文片段，换行压成空格；
//   - 模型输出阶段：沿用旧打码，不回显被拦下的内容；
//   - 其它（AI 判断、上下文类）：返回空串，提示沿用 Detail 里的说明文字。
func contentNoticeDetail(layer string, finding SecurityFinding) string {
	switch layer {
	case "input_content":
		if strings.EqualFold(strings.TrimSpace(finding.EvidenceKind), "literal") && isUserAuthoredContentSource(finding.ContentSource) {
			return flattenNoticeFragment(finding.RawEvidence)
		}
	case "output_content":
		return strings.TrimSpace(finding.MatchedTextPreview)
	}
	return ""
}

// isUserAuthoredContentSource 判断命中是否出在“使用者自己发的消息”里：当前最新一条用户消息（user）、
// 历史用户消息（user_history）、反向代理按协议解析出的用户输入（verified_user_input）。
// 系统提示、开发者指令、工具定义、工具结果、检索与网页内容、附件、历史助手消息、模型输出，以及来源为空的，
// 都不是使用者自己写的，它们的原文不回显给使用者。
func isUserAuthoredContentSource(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "user", "user_history", "verified_user_input":
		return true
	}
	return false
}

// flattenNoticeFragment 把命中的原文片段整理成可放进提示的一行：空白（含换行、制表符）压成单个空格，
// 去掉其余控制字符（Cc）和格式控制符（Cf，含双向排版控制符、零宽字符），避免扰乱提示的显示。
func flattenNoticeFragment(value string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.Is(unicode.Cc, r), unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, value)
	return strings.Join(strings.Fields(cleaned), " ")
}

// retainedNoticeAttribution 返回写入内容留存的那份提示所用的归因：输入阶段去掉原文片段，
// 让提示回落到可读命中内容。被阻断的原文只能存在原文留证里，不进 content_logs。
func retainedNoticeAttribution(attribution blockAttribution) blockAttribution {
	if attribution.Layer == "input_content" {
		attribution.NoticeDetail = ""
	}
	return attribution
}

// blockingSecurityFinding prefers the finding whose own action is a block;
// that is the rule an administrator must change to let the request through.
func blockingSecurityFinding(findings []SecurityFinding) (SecurityFinding, bool) {
	index, ok := blockingSecurityFindingIndex(findings)
	if !ok {
		return SecurityFinding{}, false
	}
	return findings[index], true
}

// blockingSecurityFindingIndex 返回阻断归因所依据的命中下标：阻断动作的命中里取主命中，没有时退回全部命中的主命中。
func blockingSecurityFindingIndex(findings []SecurityFinding) (int, bool) {
	var indexes []int
	var blocking []SecurityFinding
	for index, finding := range findings {
		if isBlockingFindingAction(finding.Action) {
			indexes = append(indexes, index)
			blocking = append(blocking, finding)
		}
	}
	if best, ok := dominantSecurityFindingIndex(blocking, false); ok {
		return indexes[best], true
	}
	if best, ok := dominantSecurityFindingIndex(findings, true); ok {
		return best, true
	}
	return dominantSecurityFindingIndex(findings, false)
}

func isBlockingFindingAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "quarantine", "deny", "blocked":
		return true
	}
	return false
}

// semanticBlockBasisPrefix 是安全引擎 semantic_enforcement 写进 evidence_reason 的拦截文案开头：
// 「智能分析高置信拦截：{类别}，置信度 0.90 ≥ 阈值 0.85」。
const semanticBlockBasisPrefix = "智能分析高置信拦截："

// isSemanticEnforcedBlock：由策略「智能分析命中时=拦截」触发的拦截（引擎闸门标记 blocked）。
func isSemanticEnforcedBlock(finding SecurityFinding) bool {
	value, _ := finding.Triage["semantic_enforcement"].(string)
	return value == "blocked"
}

func triageFloat(triage map[string]any, key string) *float64 {
	switch value := triage[key].(type) {
	case float64:
		return &value
	case float32:
		converted := float64(value)
		return &converted
	}
	return nil
}

// semanticBlockBasis 沿用引擎写进事件的拦截文案；缺失时按 triage 数值生成同格式文案。
func semanticBlockBasis(finding SecurityFinding) string {
	for _, part := range strings.Split(finding.EvidenceReason, "；") {
		if part = strings.TrimSpace(part); strings.HasPrefix(part, semanticBlockBasisPrefix) {
			return part
		}
	}
	confidence := triageFloat(finding.Triage, "semantic_confidence")
	threshold := triageFloat(finding.Triage, "semantic_block_min_confidence")
	if confidence != nil && threshold != nil {
		return fmt.Sprintf("%s置信度 %.2f ≥ 阈值 %.2f", semanticBlockBasisPrefix, *confidence, *threshold)
	}
	return "智能分析高置信拦截"
}

func findingBlockBasis(finding SecurityFinding) string {
	name := strings.TrimSpace(finding.RuleName)
	switch {
	case isSemanticEnforcedBlock(finding):
		return semanticBlockBasis(finding)
	case finding.Type == "file" || strings.HasPrefix(finding.Category, "file_"):
		return "文件策略：禁止发送"
	case finding.Category == "restricted_file_access":
		return "受限文件：配置为阻断"
	case name != "":
		return fmt.Sprintf("规则「%s」的处置动作为阻断", name)
	default:
		return "规则处置动作为阻断"
	}
}

func blockLayer(actionTaken, stage string, findings []SecurityFinding, summary string) string {
	lowerSummary := strings.ToLower(summary)
	switch {
	case actionTaken == "tool_attempt_blocked":
		return "agent_tool"
	case actionTaken == "tool_blocked":
		return "tool_definition"
	case strings.Contains(lowerSummary, "file type") || strings.Contains(lowerSummary, "file attachment"):
		return "file"
	case strings.Contains(lowerSummary, "restricted file"):
		return "restricted_file"
	case strings.Contains(lowerSummary, "tool arguments"):
		return "tool_arguments"
	}
	for _, finding := range findings {
		if finding.Category == "restricted_file_access" {
			return "restricted_file"
		}
	}
	if stage == "output" || actionTaken == "stream_blocked" {
		return "output_content"
	}
	return "input_content"
}

func blockLayerReason(layer string) string {
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
	case "mcp_tool":
		return "MCP 工具调用被权限策略阻断"
	default:
		return "输入内容命中安全规则"
	}
}

// boundedNoticeText 限制阻断提示里命中内容的长度。超长时保留开头和结尾、省略中间：
// 命令里最危险的部分常在管道末端（如「… | git credential fill」），只留开头会把它截掉。
func boundedNoticeText(value string) string {
	value = strings.TrimSpace(value)
	if utf8.RuneCountInString(value) <= maxBlockNoticeDetailRunes {
		return value
	}
	runes := []rune(value)
	head := maxBlockNoticeDetailRunes * 3 / 5
	tail := maxBlockNoticeDetailRunes - head
	return string(runes[:head]) + " … " + string(runes[len(runes)-tail:])
}

// boundedRecordText 是阻断记录（matched_summary.block.detail）保存的命中内容：已脱敏的完整文本，
// 只防极端长度，第二个返回值标明是否截断；阻断提示另行限长。
func boundedRecordText(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if utf8.RuneCountInString(value) <= maxBlockRecordDetailRunes {
		return value, false
	}
	return string([]rune(value)[:maxBlockRecordDetailRunes]) + "…", true
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// ---- settings ----

type blockNoticeSettings struct {
	Mode     string
	Template string
}

type blockNoticeSettingsCache struct {
	mu    sync.Mutex
	value *blockNoticeSettings
}

func normalizeBlockResponseMode(raw string) string {
	if strings.EqualFold(strings.TrimSpace(raw), blockResponseModeMessage) {
		return blockResponseModeMessage
	}
	return blockResponseModeError
}

// ValidateBlockNoticeTemplate is shared with the control plane's contract:
// bounded length and only the documented placeholders.
func ValidateBlockNoticeTemplate(template string) error {
	if utf8.RuneCountInString(template) > maxBlockNoticeTemplateRunes {
		return fmt.Errorf("阻断提示模板不能超过 %d 个字符", maxBlockNoticeTemplateRunes)
	}
	rest := template
	for {
		start := strings.Index(rest, "{")
		if start < 0 {
			return nil
		}
		end := strings.Index(rest[start:], "}")
		if end < 0 {
			return nil
		}
		token := rest[start : start+end+1]
		known := false
		for _, placeholder := range BlockNoticePlaceholders {
			if token == placeholder {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("阻断提示模板包含未知占位符 %s", token)
		}
		rest = rest[start+end+1:]
	}
}

// BlockNoticeSettings returns the last settings loaded by the background
// refresher (StartBlockNoticeRefresh). It never calls the control plane on the
// request path; before the first load the default error-mode notice is used.
func (c *ToolRiskClient) BlockNoticeSettings(_ context.Context) blockNoticeSettings {
	fallback := blockNoticeSettings{Mode: blockResponseModeError, Template: DefaultBlockNoticeTemplate}
	if c == nil {
		return fallback
	}
	c.blockNoticeCache.mu.Lock()
	defer c.blockNoticeCache.mu.Unlock()
	if c.blockNoticeCache.value == nil {
		return fallback
	}
	return *c.blockNoticeCache.value
}

// refreshBlockNoticeSettings keeps the last good settings when the control
// plane is unreachable.
func (c *ToolRiskClient) refreshBlockNoticeSettings(ctx context.Context) error {
	settings, labels, cache, err := c.fetchSystemSettingsForGateway(ctx)
	if err != nil {
		return err
	}
	c.setBlockNoticeSettings(settings)
	c.setAIContentLabelSettings(labels)
	c.setResponseCacheSettings(cache)
	return nil
}

// StartBlockNoticeRefresh loads the console's block-notice settings now and
// then every interval.
func (c *ToolRiskClient) StartBlockNoticeRefresh(ctx context.Context, interval time.Duration) {
	if c == nil {
		return
	}
	if interval <= 0 {
		interval = blockNoticeSettingsCacheTTL
	}
	go func() {
		refresh := func() {
			refreshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_ = c.refreshBlockNoticeSettings(refreshCtx)
		}
		refresh()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()
}

func (c *ToolRiskClient) setBlockNoticeSettings(settings blockNoticeSettings) {
	settings.Template = normalizeBlockNoticeTemplate(settings.Template)
	c.blockNoticeCache.mu.Lock()
	defer c.blockNoticeCache.mu.Unlock()
	c.blockNoticeCache.value = &settings
}

func (c *ToolRiskClient) fetchBlockNoticeSettings(ctx context.Context) (blockNoticeSettings, error) {
	settings, _, _, err := c.fetchSystemSettingsForGateway(ctx)
	return settings, err
}

// fetchSystemSettingsForGateway 拉一次控制面系统设置，解析阻断提示、AI 生成内容标识与响应缓存配置。
func (c *ToolRiskClient) fetchSystemSettingsForGateway(ctx context.Context) (blockNoticeSettings, aicontentlabel.Settings, responseCacheSettings, error) {
	labels := aicontentlabel.DefaultSettings()
	endpoint := fmt.Sprintf("%s/admin/v1/internal/system/settings", strings.TrimRight(c.controlPlaneURL, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return blockNoticeSettings{}, labels, responseCacheSettings{}, err
	}
	if c.internalAPISecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return blockNoticeSettings{}, labels, responseCacheSettings{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return blockNoticeSettings{}, labels, responseCacheSettings{}, fmt.Errorf("control-plane returned status %d", resp.StatusCode)
	}
	var values map[string]string
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&values); err != nil {
		return blockNoticeSettings{}, labels, responseCacheSettings{}, err
	}
	settings := blockNoticeSettings{
		Mode:     normalizeBlockResponseMode(values[blockResponseModeSettingKey]),
		Template: DefaultBlockNoticeTemplate,
	}
	settings.Template = normalizeBlockNoticeTemplate(values[blockNoticeTemplateSettingKey])
	return settings, aicontentlabel.ParseSettings(values), parseResponseCacheSettings(values), nil
}

// ---- rendering ----

// securityBlockNotice is the rendered notice for the current request's block.
type securityBlockNotice struct {
	Mode string
	Text string
	// RetainedText 是写入内容留存等持久化去向的副本，不含命中原文片段。
	RetainedText string
	Attribution  blockAttribution
}

func (h *ChatCompletionsHandler) securityBlockNotice(ctx context.Context, envelope *modelrouter.RequestEnvelope, fallbackReason string) securityBlockNotice {
	settings := blockNoticeSettings{Mode: blockResponseModeError, Template: DefaultBlockNoticeTemplate}
	if h != nil && h.toolRiskClient != nil {
		settings = h.toolRiskClient.BlockNoticeSettings(ctx)
	}
	attribution := blockAttribution{Reason: firstNonEmptyString(fallbackReason, "请求命中安全策略")}
	if ledger := blockLedgerFromContext(ctx); ledger != nil {
		ledger.mu.Lock()
		if ledger.entry != nil {
			attribution = *ledger.entry
		}
		ledger.mu.Unlock()
	}
	if attribution.RequestID == "" && envelope != nil {
		attribution.RequestID = envelope.RequestID
	}
	return securityBlockNotice{
		Mode:         settings.Mode,
		Text:         renderBlockNotice(settings.Template, attribution),
		RetainedText: renderBlockNotice(settings.Template, retainedNoticeAttribution(attribution)),
		Attribution:  attribution,
	}
}

func renderBlockNotice(template string, attribution blockAttribution) string {
	template = normalizeBlockNoticeTemplate(template)
	rule := attribution.RuleName
	if attribution.RuleID != "" && attribution.RuleID != attribution.RuleName {
		if rule != "" {
			rule += "（" + attribution.RuleID + "）"
		} else {
			rule = attribution.RuleID
		}
	}
	values := map[string]string{
		"{reason}":       attribution.Reason,
		"{rule}":         rule,
		"{detail}":       boundedNoticeText(firstNonEmptyString(attribution.NoticeDetail, attribution.Detail)),
		"{block_id}":     attribution.BlockID,
		"{operation_id}": attribution.OperationID,
		"{request_id}":   attribution.RequestID,
	}
	lines := strings.Split(template, "\n")
	rendered := make([]string, 0, len(lines))
	for _, line := range lines {
		hasPlaceholder, hasValue := false, false
		for _, placeholder := range BlockNoticePlaceholders {
			if strings.Contains(line, placeholder) {
				hasPlaceholder = true
				if values[placeholder] != "" {
					hasValue = true
				}
				line = strings.ReplaceAll(line, placeholder, values[placeholder])
			}
		}
		if hasPlaceholder && !hasValue {
			continue
		}
		rendered = append(rendered, line)
	}
	text := strings.TrimSpace(strings.Join(rendered, "\n"))
	// Custom notices keep their wording, but must still carry a searchable key.
	for _, key := range []struct{ label, value string }{
		{"阻断编号：", attribution.BlockID}, {"请求 ID：", attribution.RequestID},
	} {
		if key.value != "" && !strings.Contains(text, key.value) {
			if text != "" {
				text += "\n"
			}
			text += key.label + key.value
		}
	}
	return text
}

// setBlockNoticeHeaders exposes the block number to programmatic clients in
// both response modes.
func setBlockNoticeHeaders(w http.ResponseWriter, notice securityBlockNotice) {
	if notice.Attribution.RequestID != "" {
		w.Header().Set("X-Request-ID", notice.Attribution.RequestID)
		w.Header().Set("X-JJDGuard-Request-ID", notice.Attribution.RequestID)
	}
	if notice.Attribution.BlockID != "" {
		w.Header().Set("X-JJDGuard-Block-ID", notice.Attribution.BlockID)
	}
	if notice.Attribution.OperationID != "" {
		w.Header().Set("X-JJDGuard-Operation-ID", notice.Attribution.OperationID)
	}
}

// writeChatBlockResponse answers a blocked Chat Completions request. In
// "message" mode the notice is an ordinary assistant reply (HTTP 200) so every
// OpenAI-compatible agent shows it; in "error" mode it is a 403 whose message
// is the notice.
func (h *ChatCompletionsHandler) writeChatBlockResponse(ctx context.Context, w http.ResponseWriter, envelope *modelrouter.RequestEnvelope, requestID string, stream bool, notice securityBlockNotice) {
	setBlockNoticeHeaders(w, notice)
	setSecurityActionHeader(w, "block", securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
	if notice.Mode != blockResponseModeMessage {
		if stream {
			writeSSEError(w, requestID, "security_blocked", notice.Text)
			return
		}
		writeErrorResponse(w, "security_blocked", notice.Text, requestID)
		return
	}
	model := ""
	if envelope != nil {
		model = envelope.Model
	}
	id := "chatcmpl-" + requestID
	created := time.Now().Unix()
	if !stream {
		body, _ := json.Marshal(ChatCompletionResponse{
			ID: id, Object: "chat.completion", Created: created, Model: model,
			Choices: []Choice{{Index: 0, Message: ChoiceMessage{Role: "assistant", Content: notice.Text}, FinishReason: "stop"}},
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		writeGatewayJSONBody(w, body)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	chunk, _ := json.Marshal(SSEChunk{
		ID: id, Object: "chat.completion.chunk", Created: created, Model: model,
		Choices: []SSEChoice{{Index: 0, Delta: SSEDelta{Role: "assistant", Content: notice.Text}, FinishReason: "stop"}},
	})
	writeSSEData(w, string(chunk))
	writeSSEData(w, "[DONE]")
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// liveChatBlockPayloads returns the frames that close an already-started
// Chat Completions stream after a block.
func liveChatBlockPayloads(requestID, model string, notice securityBlockNotice) [][]byte {
	if notice.Mode != blockResponseModeMessage {
		payload, _ := json.Marshal(map[string]interface{}{"error": map[string]interface{}{
			"message": notice.Text, "type": "security_error", "code": "security_blocked",
			"block_id":     notice.Attribution.BlockID,
			"request_id":   notice.Attribution.RequestID,
			"operation_id": notice.Attribution.OperationID,
		}})
		return [][]byte{payload}
	}
	chunk, _ := json.Marshal(SSEChunk{
		ID: "chatcmpl-" + requestID, Object: "chat.completion.chunk", Created: time.Now().Unix(), Model: model,
		Choices: []SSEChoice{{Index: 0, Delta: SSEDelta{Content: "\n\n" + notice.Text}, FinishReason: "stop"}},
	})
	return [][]byte{chunk, []byte("[DONE]")}
}

// forgetBlockRecord prevents a failed durable write from advertising a phantom
// block number. The request ID remains available for request-log correlation.
func forgetBlockRecord(ctx context.Context, eventID string) {
	if ledger := blockLedgerFromContext(ctx); ledger != nil {
		ledger.mu.Lock()
		if ledger.entry != nil && ledger.entry.BlockID == eventID {
			ledger.entry = nil
		}
		ledger.mu.Unlock()
	}
}

// requestBlockAttribution copies the join key for the finalized request log.
func requestBlockAttribution(ctx context.Context) *blockAttribution {
	if ledger := blockLedgerFromContext(ctx); ledger != nil {
		ledger.mu.Lock()
		defer ledger.mu.Unlock()
		if ledger.entry != nil {
			copied := *ledger.entry
			return &copied
		}
	}
	return nil
}

// blockRecorded reports whether this request already persisted a block event.
func blockRecorded(ctx context.Context) bool {
	ledger := blockLedgerFromContext(ctx)
	if ledger == nil {
		return false
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	return ledger.entry != nil
}

// blockNoticeForResponse guarantees that every response answered as blocked
// has a persisted block record, then renders the notice for it.
func (h *ChatCompletionsHandler) blockNoticeForResponse(ctx context.Context, envelope *modelrouter.RequestEnvelope, stage, summary string) securityBlockNotice {
	if h != nil && h.auditWriter != nil && envelope != nil && !blockRecorded(ctx) {
		h.auditWriter.WriteSecurityEvent(withSecurityEventStage(ctx, stage), envelope, nil, "security_blocked", summary)
	}
	return h.securityBlockNotice(ctx, envelope, "")
}

// blockHTTPStatus is the status logged and returned for a blocked response.
func blockHTTPStatus(notice securityBlockNotice) int {
	if notice.Mode == blockResponseModeMessage {
		return http.StatusOK
	}
	return http.StatusForbidden
}

// writeResponsesBlockResponse answers a blocked /v1/responses request in the
// Responses shape, as an assistant message or as an error.
func (h *ResponsesHandler) writeResponsesBlockResponse(w http.ResponseWriter, chatHandler *ChatCompletionsHandler, envelope *modelrouter.RequestEnvelope, requestID string, stream bool, notice securityBlockNotice) {
	ctx := context.Background()
	setBlockNoticeHeaders(w, notice)
	setSecurityActionHeader(w, "block", securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
	if notice.Mode == blockResponseModeMessage && chatHandler != nil && envelope != nil {
		response := h.transformChatToResponsesResponse(chatHandler.buildSecurityReplyBody(envelope, notice.Text), requestID)
		if stream {
			_ = writeResponsesStream(w, response)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
		return
	}
	writeNativeResponsesError(w, stream, requestID, "security_blocked", notice.Text)
}

// writeMessagesBlockResponse answers a blocked Anthropic Messages request.
func writeMessagesBlockResponse(w http.ResponseWriter, headerEnabled bool, requestID, model string, stream bool, notice securityBlockNotice) {
	setBlockNoticeHeaders(w, notice)
	setSecurityActionHeader(w, "block", headerEnabled)
	if notice.Mode == blockResponseModeMessage {
		writeNativeMessagesSecurityReply(w, requestID, model, notice.Text, stream)
		return
	}
	writeAnthropicMessagesError(w, http.StatusForbidden, "permission_error", notice.Text, requestID)
}
