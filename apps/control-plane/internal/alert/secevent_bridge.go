package alert

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alertconfig"
	"github.com/yangjiyj/aiguard/packages/shared-go/alertevidence"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// secEventBatchSize bounds how many unalerted events one RunOnce drains.
const secEventBatchSize = 200

// defaultInboxMinConfidence is the confidence floor below which a passive
// (audit-only) security event is recorded in security_events but NOT raised as
// an actionable inbox alert. The detection engine assigns low confidence to
// matches it already suspects are false — e.g. a bank-card / id-card shaped
// number that fails its checksum scores 0.30 — so surfacing those as alerts is
// pure noise. Tunable via SECEVENT_INBOX_MIN_CONFIDENCE; set to 0 to disable
// the gate and surface every high/critical event (legacy behaviour).
const defaultInboxMinConfidence = 0.5

// defaultInboxDedup controls whether repeated identical leaks are folded onto a
// single actionable inbox alert (carrying an occurrence count + last-seen time)
// instead of one row per request. The home data showed ~40:1 duplication
// (13078 findings → 330 distinct leaks; 344 secret alerts → 63 unique secrets),
// so dedup — not filtering — is the primary flood control. Disable with
// SECEVENT_INBOX_DEDUP=off to restore one-row-per-event (legacy behaviour).
const defaultInboxDedup = true

// secEventMinConfidence reads the inbox confidence floor from the environment,
// falling back to the default on an empty or malformed value.
func secEventMinConfidence() float64 {
	v := os.Getenv("SECEVENT_INBOX_MIN_CONFIDENCE")
	if v == "" {
		return defaultInboxMinConfidence
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		log.Printf("[secevent] invalid SECEVENT_INBOX_MIN_CONFIDENCE=%q, using default %.2f", v, defaultInboxMinConfidence)
		return defaultInboxMinConfidence
	}
	return f
}

// secEventSuppressCategories reads the comma-separated set of finding categories
// that are treated as expected baseline traffic for this gateway and kept out of
// the actionable inbox (they remain in security_events as evidence). This is a
// deployment policy, not a code decision: for an AI-IDE gateway env_file
// openai_key / config_file matches are real but routine, while for another
// deployment they may be incidents. Empty (the default) suppresses nothing by
// category. Configure via SECEVENT_INBOX_SUPPRESS_CATEGORIES, e.g.
// "env_file,config_file,openai_key,generic_api_key".
func secEventSuppressCategories() map[string]bool {
	v := os.Getenv("SECEVENT_INBOX_SUPPRESS_CATEGORIES")
	set := map[string]bool{}
	for _, c := range strings.Split(v, ",") {
		if c = strings.TrimSpace(c); c != "" {
			set[c] = true
		}
	}
	return set
}

// secEventSuppressSources lists matched.source tags whose events are baseline
// noise for the actionable inbox — typically offline/non-runtime pipelines (e.g.
// "llm_safety_eval", whose LLM-judge verdicts are mis-routed into the runtime
// queue). Like category suppression this is deployment policy, not a code
// decision: such events are still fully recorded in security_events as evidence;
// (secrets/PII) always overrides this and surfaces regardless of source. Empty
// (the default) suppresses nothing by source. Configure via
// SECEVENT_INBOX_SUPPRESS_SOURCES, e.g. "llm_safety_eval".
func secEventSuppressSources() map[string]bool {
	v := os.Getenv("SECEVENT_INBOX_SUPPRESS_SOURCES")
	set := map[string]bool{}
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			set[s] = true
		}
	}
	return set
}

// secEventDedupEnabled reports whether occurrence dedup is on. Default on;
// SECEVENT_INBOX_DEDUP=off|false|0|no restores one-row-per-event.
func secEventDedupEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SECEVENT_INBOX_DEDUP"))) {
	case "off", "false", "0", "no":
		return false
	}
	return defaultInboxDedup
}

// defaultFPDispositionSuppressDays 是「标记误报→同组静默」的有效期（天）。
// 运营在告警组上做出 false_positive 处置后，同 group_key 的后续事件在有效期内
// 不再进收件箱/不通知/不再开新告警组（security_events 照常留证、MarkAlerted 照常、
// 故默认启用；SECEVENT_FP_DISPOSITION_SUPPRESS_DAYS=0 关闭。
const defaultFPDispositionSuppressDays = 30

// secEventFPSuppressDays 读取误报处置静默有效期（天），非法/负值回落默认 30。
func secEventFPSuppressDays() int {
	v := strings.TrimSpace(os.Getenv("SECEVENT_FP_DISPOSITION_SUPPRESS_DAYS"))
	if v == "" {
		return defaultFPDispositionSuppressDays
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		log.Printf("[secevent] invalid SECEVENT_FP_DISPOSITION_SUPPRESS_DAYS=%q, using default %d", v, defaultFPDispositionSuppressDays)
		return defaultFPDispositionSuppressDays
	}
	return n
}

// secEventRuleDailyLimit 读取单规则（维度）每日逐条告警上限。默认 0=关闭，
// 完全不改变现有行为；非法值同样回落 0（宁可不聚合也不误折叠）。
func secEventRuleDailyLimit() int {
	v := strings.TrimSpace(os.Getenv("SECEVENT_RULE_DAILY_LIMIT"))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		log.Printf("[secevent] invalid SECEVENT_RULE_DAILY_LIMIT=%q, feature stays off", v)
		return 0
	}
	return n
}

// secEventSecretNoveltyEnabled 读取 secret 首见告警开关，默认关（不改变现有行为）。
func secEventSecretNoveltyEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SECEVENT_SECRET_NOVELTY_ENABLED"))) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// secEventSource supplies high/critical security events that have not yet been
// alerted, and marks a batch as alerted. Satisfied by *repository.SecurityEventRepository.
type secEventSource interface {
	ListUnalerted(ctx context.Context, limit int) ([]*repository.SecurityEvent, error)
	MarkAlerted(ctx context.Context, ids []string) error
}

// secInboxPusher drops an item into the in-app alert inbox. Satisfied by *InboxService.
// UpsertByGroup folds an event onto an existing unread alert sharing groupKey
// (returning created=false), or opens a new alert (created=true).
type secInboxPusher interface {
	Push(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL string) error
	UpsertByGroup(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL, groupKey string) (bool, error)
}

type secAlertGrouper interface {
	UpsertOpen(ctx context.Context, input repository.AlertGroupUpsertInput) (*repository.AlertGroup, bool, error)
}

// secGroupCounterSink 把事件回填进组并幂等重算主指标（P1-D 契约第 6 条）。
// 由 *repository.AlertGroupRepository 满足。桥是 at-least-once：一律 COUNT(DISTINCT) 重算，
// 绝不增量 +1（重投会重复计数）。
type secGroupCounterSink interface {
	AttachEvent(ctx context.Context, tenantID, eventID, groupID string) error
	RecalcCounters(ctx context.Context, tenantID, groupID string) (int, int, error)
}

// secFPDispositionSource 提供「有效期内被人工处置为误报」的告警组 group_key 集合
// （按租户分组，含已关闭组）。由 *repository.AlertGroupRepository 满足。
type secFPDispositionSource interface {
	ListFalsePositiveGroupKeys(ctx context.Context, tenantIDs []string, since time.Time) (map[string]map[string]bool, error)
}

// secRuleDailyCounter 按「租户×日×维度」统计 security_events 当日可告警事件数。
// DB 锚定（照 anomaly scanner 先例），不搞内存计数器。由 *repository.SecurityEventRepository 满足。
type secRuleDailyCounter interface {
	CountAlertableDaily(ctx context.Context, tenantIDs []string, from, to time.Time) ([]repository.SecurityEventRuleDailyCount, error)
}

// secSecretNoveltySink 幂等登记「密钥指纹×目的地」首见对，返回本次新对数。
// 由 *repository.SecretFlowFirstSeenRepository 满足。
type secSecretNoveltySink interface {
	MarkSeen(ctx context.Context, tenantID string, pairs []repository.SecretFlowPair) (int, error)
}

// secNotifier fans an alert out to a tenant's configured external channels
// (email/webhook/dingtalk). Satisfied by *notify.Dispatcher. It is a no-op when
// the tenant has no enabled channels.
type secNotifier interface {
	Dispatch(ctx context.Context, tenantID, severity, title string, body map[string]any) error
}

// SecEventBridge closes the P0-2 gap: security events were written to the
// database (by the gateway/proxy/permission data planes) but never surfaced as
// alerts. It polls unalerted high/critical events, records each in the alert
// inbox, and fans it out to any external notify channels the tenant configured.
//
// It mirrors the anomaly scanner pattern but operates on security_events. Its
// dependencies are narrow interfaces so RunOnce is unit-testable with fakes —
// the DB-integration path is exercised separately.
//
// Not every high/critical event is alert-worthy, and the same leak recurs many
// times. security_events is the graded evidence log and keeps everything; the
// inbox is the actionable queue. Two controls keep it actionable: a confidence
// category gate (shouldSurface) drops low-signal detector noise, and occurrence
// dedup (eventGroupKey + UpsertByGroup) folds repeats of the same leak onto one
// alert. Neither weakens evidence retention.
type SecEventBridge struct {
	src                secEventSource
	inbox              secInboxPusher
	notifier           secNotifier
	groups             secAlertGrouper
	minConfidence      float64
	suppressCategories map[string]bool
	suppressSources    map[string]bool
	dedup              bool
	// fpDispositions/fpSuppressDays：误报处置静默（P1-2）。组被处置为 false_positive 后，
	// 同 group_key 的后续事件在有效期内不进收件箱/不通知；0 天=关闭。
	fpDispositions secFPDispositionSource
	fpSuppressDays int
	// dailyCounter/ruleDailyLimit：高频规则日聚合（P1-1）。单维度当日超上限后改投日聚合卡；
	// 0=关闭（默认，不改变现有行为）。
	dailyCounter   secRuleDailyCounter
	ruleDailyLimit int
	// secretSink/secretNovelty：secret 首见告警（P2-3）。重复 (指纹,目的地) 折叠，
	// 新对照常提升；默认关。
	secretSink    secSecretNoveltySink
	secretNovelty bool
	// groupCounters：P1-D 主指标（独立事发/涉及人数）。nil=不回填不重算（行为回退旧版）。
	groupCounters secGroupCounterSink
	// trustedDev：可信开发主体分流策略。nil=每次按环境变量解析（运算符改清单不用重启）；
	// 测试注入固定策略，避免结果受开发机环境变量影响。
	trustedDev *trustedDevConfig
	// runMu serializes startup and scheduled drains in-process. Each event is
	// still marked only after durable inbox/group work, so retries remain idempotent.
	runMu sync.Mutex
}

// NewSecEventBridge wires the bridge to its event source, the alert inbox, and
// the external notify dispatcher. notifier may be nil (external fan-out skipped).
func NewSecEventBridge(src secEventSource, inbox secInboxPusher, notifier secNotifier) *SecEventBridge {
	return &SecEventBridge{
		src:                src,
		inbox:              inbox,
		notifier:           notifier,
		minConfidence:      secEventMinConfidence(),
		suppressCategories: secEventSuppressCategories(),
		suppressSources:    secEventSuppressSources(),
		dedup:              secEventDedupEnabled(),
		fpSuppressDays:     secEventFPSuppressDays(),
		ruleDailyLimit:     secEventRuleDailyLimit(),
		secretNovelty:      secEventSecretNoveltyEnabled(),
	}
}

func (b *SecEventBridge) WithAlertGroups(groups secAlertGrouper) *SecEventBridge {
	if b == nil {
		return nil
	}
	b.groups = groups
	return b
}

// WithFPDispositions 接入误报处置组集合来源（通常与 WithAlertGroups 同一个仓库实例）。
func (b *SecEventBridge) WithFPDispositions(src secFPDispositionSource) *SecEventBridge {
	if b == nil {
		return nil
	}
	b.fpDispositions = src
	return b
}

// WithRuleDailyCounts 接入当日规则计数来源（通常是 SecurityEventRepository 本尊）。
func (b *SecEventBridge) WithRuleDailyCounts(c secRuleDailyCounter) *SecEventBridge {
	if b == nil {
		return nil
	}
	b.dailyCounter = c
	return b
}

// WithSecretNovelty 接入 secret 首见登记表。
func (b *SecEventBridge) WithSecretNovelty(s secSecretNoveltySink) *SecEventBridge {
	if b == nil {
		return nil
	}
	b.secretSink = s
	return b
}

// WithGroupCounters 接入事件回填与主指标重算（通常与 WithAlertGroups 同一个仓库实例）。
func (b *SecEventBridge) WithGroupCounters(c secGroupCounterSink) *SecEventBridge {
	if b == nil {
		return nil
	}
	b.groupCounters = c
	return b
}

// isEnforcementAction reports whether the data plane took a user-visible action
// on the request. Such events are always surfaced regardless of confidence:
// something actually happened to the traffic, so it must be auditable as an
// alert. Only passive (audit/allow) events are eligible for confidence gating.
func isEnforcementAction(action string) bool {
	switch action {
	case "block", "reply", "deny", "redact", "mask", "rewrite":
		return true
	}
	normalized := strings.ToLower(strings.TrimSpace(action))
	return strings.Contains(normalized, "blocked") ||
		strings.Contains(normalized, "replied") ||
		strings.Contains(normalized, "masked") ||
		strings.Contains(normalized, "redacted")
}

// isDataPlaneEnforcedEvent reports whether the data plane actually held or
// blocked the traffic: a tool call parked for confirmation, a blocked tool
// attempt, or any event whose action / effective decision is confirm or block.
// isEnforcementAction alone does not recognise "confirm" nor the
// tool_attempt_blocked event type, so a held Skill call whose finding carried
// confidence 0 fell through to the confidence gate and was silently dropped.
func isDataPlaneEnforcedEvent(ev *repository.SecurityEvent) bool {
	if ev == nil {
		return false
	}
	if ev.EventType == "tool_attempt_blocked" || isEnforcementAction(ev.ActionTaken) {
		return true
	}
	if isEnforcementDecision(ev.ActionTaken) {
		return true
	}
	decision, _ := ev.MatchedSummary["effective_decision"].(string)
	return isEnforcementDecision(decision)
}

func isEnforcementDecision(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "confirm", "block":
		return true
	}
	return false
}

// isPassivePureSemanticEvent identifies inference-only prompt/jailbreak
// signals that caused no enforcement and carry no independent deterministic
// evidence. They remain in security_events for the instruction-evidence view,
// but must not become actionable alerts because a classifier authored a high
// severity or confidence.
func isPassivePureSemanticEvent(ev *repository.SecurityEvent, findingsRaw []any) bool {
	if ev == nil || isEnforcementAction(ev.ActionTaken) || len(findingsRaw) == 0 {
		return false
	}
	// 二次裁判已确认真实风险时，纯语义事件也必须进入告警收件箱。
	// 只有未确认的被动语义证据才保持 evidence-only。
	if eventReviewState(ev) == "confirmed_risk" {
		return false
	}
	for _, raw := range findingsRaw {
		finding, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		findingType, _ := finding["type"].(string)
		category, _ := finding["category"].(string)
		if findingType != "" && findingType != "semantic_attack" && findingType != "semantic_telemetry" {
			return false
		}
		if findingType == "" && !strings.HasPrefix(category, "semantic_") {
			return false
		}
	}
	return true
}

// isPassiveObservationOnlyEvent identifies events whose detection layer
// explicitly marked every finding as technical evidence rather than a security
// finding. Enforcement still wins: if traffic was blocked or rewritten, the
// operational event remains visible even when detector metadata is malformed.
// isPassiveAgentBehaviorOnlyEvent identifies ordinary agent/client inventory
// signals. They are behavior-governance evidence, not actionable security alerts,
// unless traffic was enforced, the event was confirmed, or any finding is a
// deterministic redline / non-agent security finding.
func isPassiveAgentBehaviorOnlyEvent(ev *repository.SecurityEvent, findingsRaw []any) bool {
	if ev == nil || isEnforcementAction(ev.ActionTaken) || eventReviewState(ev) == "confirmed_risk" || len(findingsRaw) == 0 {
		return false
	}
	if isRedline(ev) {
		return false
	}
	for _, raw := range findingsRaw {
		finding, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		ruleType, _ := finding["rule_type"].(string)
		if strings.ToLower(strings.TrimSpace(ruleType)) != "agent_detect" {
			return false
		}
		category, _ := finding["category"].(string)
		category = strings.ToLower(strings.TrimSpace(category))
		if !strings.HasPrefix(category, "agent_") || strings.HasPrefix(category, "agent_canary") {
			return false
		}
	}
	return true
}

func isPassiveObservationOnlyEvent(ev *repository.SecurityEvent, findingsRaw []any) bool {
	if ev == nil || isEnforcementAction(ev.ActionTaken) || len(findingsRaw) == 0 {
		return false
	}
	for _, raw := range findingsRaw {
		finding, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		findingType, _ := finding["type"].(string)
		category, _ := finding["category"].(string)
		if findingType == "secret" || findingType == "data_leak" ||
			findingType == "file" || strings.HasPrefix(category, "agent_canary") {
			return false
		}
		counts, present := finding["counts_as_security_finding"].(bool)
		if !present || counts {
			return false
		}
	}
	return true
}

// toFloat coerces a JSON-decoded numeric value to float64. json.Unmarshal into
// interface{} yields float64, but int forms are tolerated for robustness.
func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// isNoiseFinding classifies a single finding for inbox-gating purposes. It
// returns (noise, classifiable): a finding is noise when its category is an
// explicitly configured baseline category, or when its confidence is below the
// floor. classifiable is false when neither lever applies (no matching category
// and no usable confidence) — the caller then fails open on that finding.
func (b *SecEventBridge) isNoiseFinding(fm map[string]any) (noise bool, classifiable bool) {
	if cat, _ := fm["category"].(string); cat != "" && b.suppressCategories[cat] {
		return true, true // explicitly baselined for this gateway
	}
	c, ok := toFloat(fm["confidence"])
	if !ok {
		return false, false // no confidence and not a baseline category
	}
	if c < b.minConfidence {
		return true, true
	}
	return false, true
}

// shouldSurface reports whether a security event warrants an inbox alert, with a
// reason used only for the suppression log. The event is recorded in
// security_events regardless; this gate decides only whether to ALSO raise an
// actionable alert.
//
// It fails OPEN: anything it cannot confidently classify as low-signal noise is
// surfaced. It surfaces when both levers are off, when the data plane took an
// enforcement action, when any finding is a deterministic redline, when findings can't be
// parsed, and when any finding is signal (or unclassifiable). It suppresses only
// when EVERY finding is classifiable noise (baseline category or sub-floor
// confidence) — so a real high-confidence leak riding alongside baseline noise
// still surfaces.
func (b *SecEventBridge) shouldSurface(ev *repository.SecurityEvent) (bool, string) {
	if ev != nil && ev.EventType == "security_inspection_completed" {
		return false, "completed inspection telemetry"
	}
	if isUpgradeSelfTestEvent(ev) {
		return false, reasonUpgradeSelfTest
	}
	if ev != nil && alertTypeForSecurityEvent(ev) == "runtime_fault" {
		if isSemanticBudgetFault(ev) {
			return false, reasonSemanticBudgetFault
		}
		return true, ""
	}
	if ev != nil {
		switch strings.ToLower(strings.TrimSpace(ev.ActionTaken)) {
		case "security_check_failed", "security_output_check_failed":
			return false, "security detection pipeline issue is operational telemetry"
		}
	}
	reviewState := effectiveReviewState(ev)
	if isVerifiedContentEvent(ev) {
		switch reviewState {
		case "review_pending":
			return false, reasonReviewPending
		case "unavailable", "needs_review":
			return true, ""
		}
	}
	// 数据面已实际执法（拦截 / 等待确认）：真实发生的处置必须可审计，排在低信号、
	// triage 误报压制、例外抑制之前。运营遥测排除与 review_pending 的既有语义在上面，不受影响。
	if isDataPlaneEnforcedEvent(ev) {
		return true, ""
	}
	findingsRaw, findingsOK := ev.MatchedSummary["findings"].([]any)
	if isRedline(ev) {
		return true, ""
	}
	if isPassiveObservationOnlyEvent(ev, findingsRaw) {
		return false, reasonObservationOnly
	}
	if isPassiveAgentBehaviorOnlyEvent(ev, findingsRaw) {
		return false, reasonAgentBehaviorOnly
	}

	if b.minConfidence <= 0 && len(b.suppressCategories) == 0 && len(b.suppressSources) == 0 {
		return true, "" // gate fully disabled
	}
	// Source baseline: events from a configured non-runtime source (e.g. an
	// offline LLM-judge eval pipeline mis-routed into the runtime queue) are kept
	// out of the actionable inbox but remain in security_events as evidence. The
	// surfaces. This check precedes the findings fail-open below: source lives at
	// the top level of matched_summary and does not depend on the findings array,
	// baseline holds.
	if len(b.suppressSources) > 0 {
		if src, _ := ev.MatchedSummary["source"].(string); src != "" && b.suppressSources[src] {
			return false, fmt.Sprintf("source %q baselined out of inbox", src)
		}
	}

	if !findingsOK || len(findingsRaw) == 0 {
		return true, "" // no structured findings → can't assess → fail open
	}
	if isPassivePureSemanticEvent(ev, findingsRaw) {
		return false, reasonPassiveSemantic
	}

	// L5：LLM triage 误报压制。某 finding 被异步裁判确认为 likely_false_positive 且非
	// 事实暴露类即使被标 FP 也照常提升。一旦发现任一非 FP 信号 finding，整事件照常提升
	if allTriageSuppressible(findingsRaw) {
		return false, reasonTriageSuppressed
	}

	// 例外抑制闸（与 L5 triage 闸并列，custom 规则用）：finding 带 exception_id 说明数据面
	if allExceptionSuppressible(findingsRaw) {
		return false, reasonExceptionSuppressed
	}

	noiseCats := map[string]bool{}
	for _, raw := range findingsRaw {
		fm, ok := raw.(map[string]any)
		if !ok {
			return true, "" // unexpected shape → fail open
		}
		noise, classifiable := b.isNoiseFinding(fm)
		if !classifiable || !noise {
			return true, "" // a signal (or unclassifiable) finding → surface
		}
		if cat, _ := fm["category"].(string); cat != "" {
			noiseCats[cat] = true
		}
	}

	// Every finding was classifiable noise.
	cats := make([]string, 0, len(noiseCats))
	for c := range noiseCats {
		cats = append(cats, c)
	}
	return false, fmt.Sprintf("all findings baseline/low-confidence (categories=%v)", cats)
}

// was once dispositioned false_positive would silence real exfil for the whole
// suppression window.
func hasCanary(findingsRaw []any) bool {
	for _, raw := range findingsRaw {
		if fm, ok := raw.(map[string]any); ok {
			if cat, _ := fm["category"].(string); strings.HasPrefix(cat, "agent_canary") {
				return true
			}
		}
	}
	return false
}

// eventStage returns the event's pipeline stage (input/output/tool) from
// matched_summary, or "" when absent.
func eventStage(ev *repository.SecurityEvent) string {
	s, _ := ev.MatchedSummary["stage"].(string)
	return s
}

// isRedline reports whether an event carries a signal that must NEVER be
func eventReviewState(ev *repository.SecurityEvent) string {
	if ev == nil {
		return ""
	}
	if state, _ := ev.MatchedSummary["review_state"].(string); strings.TrimSpace(state) != "" {
		return strings.ToLower(strings.TrimSpace(state))
	}
	findingsRaw, _ := ev.MatchedSummary["findings"].([]any)
	for _, raw := range findingsRaw {
		fm, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		triage, _ := fm["triage"].(map[string]any)
		if state, _ := fm["review_state"].(string); strings.TrimSpace(state) != "" {
			return strings.ToLower(strings.TrimSpace(state))
		}

		if state, _ := triage["review_state"].(string); strings.TrimSpace(state) != "" {
			return strings.ToLower(strings.TrimSpace(state))
		}
		if verdict, _ := triage["verdict"].(string); strings.TrimSpace(verdict) != "" {
			return strings.ToLower(strings.TrimSpace(verdict))
		}
	}
	return ""
}

func isVerifiedContentEvent(ev *repository.SecurityEvent) bool {
	if ev == nil {
		return false
	}
	source, _ := ev.MatchedSummary["content_source"].(string)
	if source == "verified_user_input" || source == "verified_final_output" {
		return true
	}
	findings, _ := ev.MatchedSummary["findings"].([]any)
	for _, raw := range findings {
		if finding, ok := raw.(map[string]any); ok {
			source, _ = finding["content_source"].(string)
			if source == "verified_user_input" || source == "verified_final_output" {
				return true
			}
		}
	}
	return false
}

func pendingReviewExpired(ev *repository.SecurityEvent) bool {
	if ev == nil || ev.CreatedAt.IsZero() {
		return false
	}
	return time.Since(ev.CreatedAt.UTC()) >= alertconfig.ReviewPendingTimeout()
}

func effectiveReviewState(ev *repository.SecurityEvent) string {
	state := eventReviewState(ev)
	if state == "review_pending" && pendingReviewExpired(ev) {
		return "needs_review"
	}
	return state
}

func effectiveSeverityForEvent(ev *repository.SecurityEvent) string {
	state := effectiveReviewState(ev)
	if isVerifiedContentEvent(ev) && (state == "review_pending" || state == "unavailable" || state == "needs_review") {
		return "medium"
	}
	if severity, _ := ev.MatchedSummary["effective_severity"].(string); normalizeEffectiveSeverity(severity) != "" {
		return normalizeEffectiveSeverity(severity)
	}
	return normalizeEffectiveSeverity(ev.Severity)
}

// suppressed, silenced, downgraded, or auto-closed: an enforcement action, a
// It bypasses EVERY suppression path (fp-silence, source baseline, triage,
// exception, low-confidence noise, daily-agg, secret-novelty), not just the
func isRedline(ev *repository.SecurityEvent) bool {
	if isEnforcementAction(ev.ActionTaken) {
		return true
	}
	findingsRaw, _ := ev.MatchedSummary["findings"].([]any)
	if hasCanary(findingsRaw) {
		return true
	}
	// Deterministic secret leakage and verified PII/data-leak evidence are red
	// lines: never turn a previous group disposition into a future blind spot.
	for _, raw := range findingsRaw {
		fm, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := fm["type"].(string)
		if typ == "secret" {
			return true
		}
		if typ == "data_leak" {
			if verified, _ := fm["verified_fact"].(bool); verified {
				return true
			}
			if source, _ := fm["content_source"].(string); source == "verified_final_output" {
				return true
			}
		}
	}
	return false
}

// severityRank orders authored severities so the dominant finding (and thus the
// class signature) is picked by impact-if-true, tie-broken by confidence.
var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// lifecycleFields are the P0-A situational/lifecycle columns computed for an
// alert group from its source event.
type lifecycleFields struct {
	effectiveSeverity string
	dispositionClass  string
	classKey          string
	isCanary          bool
	stage             string
	// triageRoute is non-nil when the event was routed to observation by the
	// trusted-development rule. RunOnce copies it into the group body.
	triageRoute *trustedDevRoute
}

// findingCountsAsSecurityFinding reports whether a detector finding is actionable.
func findingCountsAsSecurityFinding(fm map[string]any) bool {
	value, present := fm["counts_as_security_finding"]
	if !present {
		return true
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return !strings.EqualFold(strings.TrimSpace(v), "false")
	default:
		return true
	}
}

// dominantCategory returns the category of the highest-severity finding
// (tie-break: highest confidence). Falls back to the event type when no finding
// carries a category, so the class signature is never empty.
// dominantFinding is the single source for the displayed rule, category and
// representative evidence. Informational/telemetry findings cannot claim an
// actionable finding's severity. Ties are deterministic across detector order.
// dominantFinding 是告警正文与外发里的主命中：事件带 primary_finding.findings_index 时直接按它取
// （与数据面选出的主命中一致，取到的是带原文的 findings 条目），旧事件再按严重度等规则重选。
func dominantFinding(ev *repository.SecurityEvent) map[string]any {
	if ev == nil {
		return nil
	}
	if finding := repository.PrimaryFindingByIndex(ev.MatchedSummary); finding != nil {
		return finding
	}
	return repository.DominantSecurityFinding(ev.MatchedSummary)
}

func dominantCategory(ev *repository.SecurityEvent) string {
	if cat, _ := dominantFinding(ev)["category"].(string); cat != "" {
		return cat
	}
	return ev.EventType
}

func attributedEvent(ev *repository.SecurityEvent) *repository.SecurityEvent {
	fm := dominantFinding(ev)
	if fm == nil {
		return ev
	}
	result := *ev
	if sev, _ := fm["severity"].(string); normalizeEffectiveSeverity(sev) != "" {
		result.Severity = normalizeEffectiveSeverity(sev)
	}
	result.RuleName, _ = fm["rule_name"].(string)
	if result.RuleName == "" {
		result.RuleName, _ = fm["category"].(string)
	}
	result.RuleType, _ = fm["type"].(string)
	return &result
}

// normalizeEffectiveSeverity keeps only the values allowed by the
// alert_groups.effective_severity CHECK (low/medium/high/critical); anything
// else (info/warning/empty) maps to "" so the column stays NULL.
func normalizeEffectiveSeverity(sev string) string {
	switch sev {
	case "low", "medium", "high", "critical":
		return sev
	}
	return ""
}

// computeLifecycleFields derives the P0-A situational/lifecycle fields for an
// event's alert group. In P0-A effective_severity is a pass-through of the
// authored severity (context-aware recompute lives in the detection layer,
// P0-B/P2); disposition_class is action_required for red-line or high/critical
// events and informational otherwise; principal_key is deferred to P1-C.
// hasCorroboration 报告 findings 是否带有佐证型高价值信号（身份证 / secret / data_leak），
// 用于把 bank_card_cn 这类 ≥90% 误报的 PII 类留在需行动：卡号旁边有身份证或密钥，
// 是真实的组合泄露，而非随机数字串。
func hasCorroboration(findingsRaw []any) bool {
	for _, raw := range findingsRaw {
		if fm, ok := raw.(map[string]any); ok {
			if cat, _ := fm["category"].(string); cat == "id_card_cn" {
				return true
			}
			if t, _ := fm["type"].(string); t == "secret" || t == "data_leak" {
				return true
			}
		}
	}
	return false
}

// alertDomainForSecurityEvent 把安全事件归入风险域（迁移 941）：
// skill_ 前缀 → skill；mcp_ 前缀或 matched_summary 带 MCP 服务标识（server_id /
// mcp_server_id，或 source=gateway_mcp）→ mcp；tool_ 前缀 → tool；访问治理枚举 →
// access；运行故障 → system；其余（proxy_*、security_check*、semantic、data/file 等）
// → content。MCP 网关写入的 tool_attempt_blocked/tool_execution_risk 事件带
// source=gateway_mcp，因此先于 tool_ 前缀命中 mcp 域。
func alertDomainForSecurityEvent(ev *repository.SecurityEvent) string {
	if ev == nil {
		return "content"
	}
	eventType := strings.ToLower(strings.TrimSpace(ev.EventType))
	if strings.HasPrefix(eventType, "skill_") {
		return "skill"
	}
	if strings.HasPrefix(eventType, "mcp_") ||
		summaryKeyNonEmpty(ev.MatchedSummary, "mcp_server_id") ||
		summaryKeyNonEmpty(ev.MatchedSummary, "server_id") ||
		strings.TrimSpace(summaryString(ev.MatchedSummary, "source")) == "gateway_mcp" {
		return "mcp"
	}
	if strings.HasPrefix(eventType, "tool_") {
		return "tool"
	}
	switch eventType {
	case "access_denied", "model_policy", "quota", "proxy_auth_denied", "proxy_access_denied":
		return "access"
	case "security_mode_changed":
		return "system"
	}
	if alertTypeForSecurityEvent(ev) == "runtime_fault" {
		return "system"
	}
	return "content"
}

func summaryKeyNonEmpty(summary map[string]any, key string) bool {
	value, _ := summary[key].(string)
	return strings.TrimSpace(value) != ""
}

func summaryString(summary map[string]any, key string) string {
	value, _ := summary[key].(string)
	return value
}

func (b *SecEventBridge) computeLifecycleFields(ev *repository.SecurityEvent) lifecycleFields {
	if ev.EventType == "agent_endpoint_risk" {
		return lifecycleFields{effectiveSeverity: normalizeEffectiveSeverity(ev.Severity), dispositionClass: "action_required", classKey: "agent_endpoint_risk"}
	}
	if ev.EventType == "tool_execution_risk" {
		return lifecycleFields{effectiveSeverity: normalizeEffectiveSeverity(ev.Severity), dispositionClass: "action_required", classKey: "tool_execution_risk", stage: "tool"}
	}
	if ev.EventType == "tool_attempt_blocked" {
		return lifecycleFields{effectiveSeverity: normalizeEffectiveSeverity(ev.Severity), dispositionClass: "informational", classKey: "tool_attempt_blocked", stage: "tool"}
	}
	// 工具连续失败是运行状况：新旧形态一律低危留观，存量旧事件落库的高危级别不带进告警组。
	if isToolFailureLoopEvent(ev) {
		return lifecycleFields{effectiveSeverity: "low", dispositionClass: "informational", classKey: agentToolFailureLoopCategory, stage: alertStage(ev)}
	}
	findingsRaw, _ := ev.MatchedSummary["findings"].([]any)
	eff := effectiveSeverityForEvent(ev)
	classKey := dominantCategory(ev)
	disp := "informational"
	if isRedline(ev) ||
		(!isPassivePureSemanticEvent(ev, findingsRaw) &&
			!isPassiveObservationOnlyEvent(ev, findingsRaw) &&
			(eff == "high" || eff == "critical")) {
		disp = "action_required"
	}
	// bank_card_cn 已证 ≥90% 正则误报：无红线、无佐证(id_card/secret/data_leak 共现) → 降为留观。
	if disp == "action_required" && !isRedline(ev) && classKey == "bank_card_cn" && !hasCorroboration(findingsRaw) {
		disp = "informational"
	}
	// 可信开发主体分流：编码 agent 读进来的机器上下文（工具输出/工具定义/系统提示词）命中规则，
	// 或主体在信任清单里 → 降为留观，并把 triage_route 写进组 body 让页面说明为什么不用处置。
	// 该判定独立于上面的 disp：即使事件因为低危已经是 informational，具体原因也比"低危"更有用，
	// 所以在 bank_card 特判之后无条件判定。
	var triageRoute *trustedDevRoute
	if route, routed := trustedDevelopmentRoute(ev, b.trustedDevRouteConfig()); routed && route.Reason != "" {
		disp = "informational"
		triageRoute = &route
	}
	return lifecycleFields{
		effectiveSeverity: eff,
		dispositionClass:  disp,
		classKey:          classKey,
		isCanary:          hasCanary(findingsRaw),
		stage:             eventStage(ev),
		triageRoute:       triageRoute,
	}
}

// triageSaysLikelyFP 报告某 finding 是否被 LLM 异步裁判标为 likely_false_positive。
func triageSaysLikelyFP(fm map[string]any) bool {
	tr, ok := fm["triage"].(map[string]any)
	if !ok {
		return false
	}
	v, _ := tr["verdict"].(string)
	return v == "likely_false_positive" || v == "audit_evidence"
}

// allTriageSuppressible 仅当事件的每个 finding 都满足「被标 likely_false_positive 且非
// 未被标 likely_fp 的 finding 都会让整事件穿透（绝不因个别 FP 藏掉真信号）。
func allTriageSuppressible(findingsRaw []any) bool {
	sawSuppressible := false
	for _, raw := range findingsRaw {
		fm, ok := raw.(map[string]any)
		if !ok {
			return false // 形状异常 → 不压（fail open）
		}
		if !triageSaysLikelyFP(fm) {
			return false // 存在非 FP finding → 整事件提升
		}
		sawSuppressible = true
	}
	return sawSuppressible
}

// 抑制原因常量：RunOnce 依赖字面量做分类计数，收敛到常量避免两处漂移。
const (
	reasonTriageSuppressed    = "LLM triage: likely_false_positive"
	reasonExceptionSuppressed = "exception: all findings exempted"
	reasonReviewPending       = "review pending"
	reasonPassiveSemantic     = "passive semantic evidence only"
	reasonObservationOnly     = "observation-only evidence"
	reasonAgentBehaviorOnly   = "ordinary agent behavior evidence only"
	reasonSemanticBudgetFault = "semantic review timeout/budget is operational telemetry"
	reasonUpgradeSelfTest     = "upgrade installer self-test traffic"
)

// upgradeSelfTestProjectPrefix 是升级安装器自检临时应用的编号前缀（deploy/docker-compose/upgrade-bundle.sh
// verify_security_events_persistence）。控制台/接口建应用一律生成 proj_ 随机编号，这个前缀只有安装器直接写库
// 才能产生，普通用户改应用名、改请求头都伪造不出来；告警页的测评车道（alert_cases.go）按同一前缀判定。
const upgradeSelfTestProjectPrefix = "project_upgrade_verify_"

// isUpgradeSelfTestEvent：自检请求照常检测、阻断并落 security_events（安装器靠它验证检测链路），
// 只是不进客户收件箱、告警组与外发通知。
func isUpgradeSelfTestEvent(ev *repository.SecurityEvent) bool {
	return ev != nil && strings.HasPrefix(ev.ProjectID, upgradeSelfTestProjectPrefix)
}

// isSemanticBudgetFault：语义复核因超时、预算/容量不足没做完——是引擎负载状况，与请求内容无关。
// 它照常落 security_events，按阶段+原因折叠进运行故障告警组（观察、计次），不进收件箱、不外发。
// 引擎不可用、熔断、HTTP 错误等真实故障不在此列，照旧提醒运维。放行/拦截由网关按失败策略定，这里不碰。
func isSemanticBudgetFault(ev *repository.SecurityEvent) bool {
	reason := strings.ToLower(semanticFaultReason(ev))
	if reason == "" || reason == agentToolFailureLoopCategory {
		return false
	}
	for _, marker := range []string{"timeout", "budget", "capacity", "deadline"} {
		if strings.Contains(reason, marker) {
			return true
		}
	}
	return false
}

// allExceptionSuppressible 镜像 allTriageSuppressible：仅当事件的每个 finding 都满足
// exception_id 由 gateway-core 在命中运营配置的例外时透传进 matched_summary.findings[]。
func allExceptionSuppressible(findingsRaw []any) bool {
	sawSuppressible := false
	for _, raw := range findingsRaw {
		fm, ok := raw.(map[string]any)
		if !ok {
			return false // 形状异常 → 不压（fail open）
		}
		if eid, _ := fm["exception_id"].(string); eid == "" {
			return false // 存在未豁免 finding → 整事件提升
		}
		sawSuppressible = true
	}
	return sawSuppressible
}

// storedAlertBody 是写进 alert_groups.body_json、alert_inbox.body_json 的正文：去掉命中原文字段
// （alertevidence.RawFields）。原文只在 security_events 存一份，收件箱要看原文按内容证据权限从事件取；
// 邮件、Webhook 外发正文用未剔除的 body（用户已定外发带原文），见 notificationBody。
func storedAlertBody(body map[string]any) map[string]any {
	stored, _ := alertevidence.StripRaw(body).(map[string]any)
	return stored
}

// leakFingerprint builds a stable per-finding identifier for "the same leak":
// the same secret/match seen again, regardless of which request carried it. It
// prefers the content hash the engine already computed and falls back to coarser
// identifiers so a finding without a content hash still groups by its rule
// rather than looking unique on every occurrence.
func leakFingerprint(fm map[string]any) string {
	cat, _ := fm["category"].(string)
	findingType, _ := fm["type"].(string)
	id := ""
	for _, k := range []string{"matched_text_preview_sha256", "matched_location_sha256"} {
		if s, _ := fm[k].(string); s != "" {
			id = s
			break
		}
	}
	if id == "" && findingType == "data_leak" {
		id = rawEvidenceHashID(fm)
	}
	if id == "" {
		for _, k := range []string{"rule_id", "type"} {
			if s, _ := fm[k].(string); s != "" {
				id = s
				break
			}
		}
	}
	return cat + "|" + id
}

// rawEvidenceHashID 只给 2026-07-25～09-20 那批只存原文、没有原文哈希的旧事件按原文算指纹。
// 2.9.22 起网关同时存原文和 raw_evidence_sha256：这类事件不按原文算，继续落到规则编号，
// 与 2.9.21（只存哈希）归组一致，告警组不因为原文入库而拆开或换组。
func rawEvidenceHashID(fm map[string]any) string {
	if _, hashed := fm["raw_evidence_sha256"]; hashed {
		return ""
	}
	raw, _ := fm[alertevidence.FieldRawEvidence].(string)
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return "raw:" + hex.EncodeToString(sum[:])[:16]
}

// eventGroupKey derives an event's dedup key from the SET of its finding
// fingerprints (order-independent). Two events leaking the same secret(s)
// collapse onto one inbox alert. Events without structured findings fall back to
// their rule identity so repeats of the same rule firing still collapse rather
// than each opening a fresh alert.
func eventGroupKey(ev *repository.SecurityEvent) string {
	return repository.ScopedAlertGroupKey(severityTieredGroupKey(ev, legacyEventGroupKey(ev)), ev.ProjectID, alertStage(ev))
}

// severityTieredGroupKey：删除与破坏事件的指纹只有“类别+类型”，同一应用所有用户的删除命令都并进一个组；
// 组级别取历史最高，偶发一条严重事件之后，大量高危事件会一直给这个【严重】组计数（客户A 11-21：
// critical 10 + high 3947 = 3957）。严重事件保持原组键（继续落原来的严重组），高危及以下按级别另开组。
// 只作用于 tool_destructive_intent；其他类型的组键与误报处置静默不受影响。
func severityTieredGroupKey(ev *repository.SecurityEvent, key string) string {
	if ev == nil || ev.EventType != "tool_destructive_intent" {
		return key
	}
	severity := effectiveSeverityForEvent(ev)
	if severity == "" || severity == "critical" {
		return key
	}
	return key + "|tier:" + severity
}

func legacyEventGroupKey(ev *repository.SecurityEvent) string {
	if ev.EventType == "tool_execution_risk" || ev.EventType == "tool_attempt_blocked" {
		return toolEventGroupKey(ev)
	}
	// Runtime faults fold by stage+reason instead of by evidence fingerprint: the
	// per-occurrence evidence (which host, which request) must not shatter one
	// operational fault into an alert per host.
	if alertTypeForSecurityEvent(ev) == "runtime_fault" {
		return faultGroupKey(ev)
	}
	var parts []string
	if findingsRaw, ok := ev.MatchedSummary["findings"].([]any); ok {
		for _, raw := range findingsRaw {
			if fm, ok := raw.(map[string]any); ok {
				parts = append(parts, leakFingerprint(fm))
			}
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "rule|"+ev.EventType+"|"+ev.RuleName+"|"+ev.RuleType)
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}

// --- P1/P2 误报治理:每 tick 预取与逐事件判定的辅助函数 ---

// distinctTenants 收集本批事件涉及的租户集合（保持首现顺序）。
func distinctTenants(events []*repository.SecurityEvent) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	for _, ev := range events {
		if !seen[ev.TenantID] {
			seen[ev.TenantID] = true
			out = append(out, ev.TenantID)
		}
	}
	return out
}

// loadFPGroupKeys 每 tick 一次性查询本轮涉及租户的「有效期内误报处置组」集合。
// 未启用（0 天或未接入来源）返回 nil；查询失败 fail open（宁可多报也不静默）。
func (b *SecEventBridge) loadFPGroupKeys(ctx context.Context, events []*repository.SecurityEvent) map[string]map[string]bool {
	if b.fpSuppressDays <= 0 || b.fpDispositions == nil || len(events) == 0 {
		return nil
	}
	since := time.Now().UTC().AddDate(0, 0, -b.fpSuppressDays)
	keys, err := b.fpDispositions.ListFalsePositiveGroupKeys(ctx, distinctTenants(events), since)
	if err != nil {
		log.Printf("[secevent] list false-positive group keys failed: %v (fail open)", err)
		return nil
	}
	return keys
}

// isFPSilenced 判定事件是否命中误报处置静默：同租户同 group_key 在有效期内被处置为
func (b *SecEventBridge) isFPSilenced(ev *repository.SecurityEvent, groupKey string, fpKeys map[string]map[string]bool) bool {
	if len(fpKeys) == 0 {
		return false
	}
	if isRedline(ev) {
		return false
	}
	return fpKeys[ev.TenantID][groupKey]
}

// dailyCountKey 是日计数查找键：租户×日×维度。
func dailyCountKey(tenantID, day, dim string) string {
	return tenantID + "\n" + day + "\n" + dim
}

// loadRuleDailyCounts 每 tick 一次性做分组计数查询（DB 锚定，照 anomaly 先例）。
// 日窗按事件 CreatedAt 的 UTC 归日（防跨 tick 错格）：取批内最早/最晚事件所在日的整日区间。
// 未启用返回 nil；查询失败 fail open（照常逐条，不聚合）。
func (b *SecEventBridge) loadRuleDailyCounts(ctx context.Context, events []*repository.SecurityEvent) map[string]int {
	if b.ruleDailyLimit <= 0 || b.dailyCounter == nil || len(events) == 0 {
		return nil
	}
	minDay := events[0].CreatedAt.UTC().Truncate(24 * time.Hour)
	maxDay := minDay
	for _, ev := range events[1:] {
		d := ev.CreatedAt.UTC().Truncate(24 * time.Hour)
		if d.Before(minDay) {
			minDay = d
		}
		if d.After(maxDay) {
			maxDay = d
		}
	}
	counts, err := b.dailyCounter.CountAlertableDaily(ctx, distinctTenants(events), minDay, maxDay.Add(24*time.Hour))
	if err != nil {
		log.Printf("[secevent] count rule daily failed: %v (fail open)", err)
		return nil
	}
	out := make(map[string]int, len(counts))
	for _, c := range counts {
		out[dailyCountKey(c.TenantID, c.Day, c.Dimension)] = c.Count
	}
	return out
}

// ruleDailyDimension uses the same dominant-risk function as database day counts.
func ruleDailyDimension(ev *repository.SecurityEvent) string {
	return repository.SecurityFindingDailyDimension(ev.MatchedSummary)
}

// secEventDailySummaryType 是日聚合卡的收件箱类型枚举（web-console 侧映射为「安全事件日汇总」）。
const secEventDailySummaryType = "security_event_daily_summary"

// dailyAggCard 是一张日聚合卡的收件箱要素。
type dailyAggCard struct {
	groupKey  string
	title     string
	targetURL string
	body      map[string]any
}

// dailyAggregate 判定事件是否应折叠进日聚合卡：当日该维度可告警事件数（DB 锚定）
func (b *SecEventBridge) dailyAggregate(ev *repository.SecurityEvent, counts map[string]int) (dailyAggCard, bool) {
	if b.ruleDailyLimit <= 0 || len(counts) == 0 || alertTypeForSecurityEvent(ev) == "runtime_fault" || alertTypeForSecurityEvent(ev) == "access_governance" {
		return dailyAggCard{}, false
	}
	if isRedline(ev) {
		return dailyAggCard{}, false
	}
	dim := ruleDailyDimension(ev)
	if dim == "" {
		return dailyAggCard{}, false
	}
	// 日期按事件 CreatedAt 的 UTC 归日，与计数 SQL 同格：防止跨 tick/跨日错格。
	day := ev.CreatedAt.UTC().Format("2006-01-02")
	count := counts[dailyCountKey(ev.TenantID, day, dim)]
	if count <= b.ruleDailyLimit {
		return dailyAggCard{}, false
	}
	name := ev.RuleName
	if name == "" {
		name = eventDisplayLabelCN(ev)
	}
	title := fmt.Sprintf("高频安全事件日汇总【%s】%s · 当日累计 %d 条", severityLabelCN(ev.Severity), name, count)
	body := map[string]any{
		"event_type":      ev.EventType,
		"severity":        ev.Severity,
		"rule_name":       ev.RuleName,
		"category":        dominantCategory(ev),
		"rule_id":         dominantFinding(ev)["rule_id"],
		"rule_type":       ev.RuleType,
		"dimension":       dim,
		"date":            day,
		"daily_count":     count,
		"daily_limit":     b.ruleDailyLimit,
		"sample_event_id": ev.ID,
		"created_at":      ev.CreatedAt.Format(time.RFC3339),
	}
	return dailyAggCard{
		groupKey:  "daily_agg|" + dim + "|" + day,
		title:     title,
		targetURL: "/security-events",
		body:      body,
	}, true
}

// secretNoveltyPairs 判定事件是否走 secret 首见路径，并抽出去重后的 (指纹,目的地) 对。
// 仅当：非 enforcement、事件顶层有 target_host（正向代理路径特征）、且全部 finding 都是
// sha256，自然不参与。任一条件不满足返回空（照常逐条路径）。
func secretNoveltyPairs(ev *repository.SecurityEvent) []repository.SecretFlowPair {
	host, _ := ev.MatchedSummary["target_host"].(string)
	if host == "" {
		return nil
	}
	findingsRaw, ok := ev.MatchedSummary["findings"].([]any)
	if !ok || len(findingsRaw) == 0 {
		return nil
	}
	seen := map[string]bool{}
	pairs := make([]repository.SecretFlowPair, 0, len(findingsRaw))
	for _, raw := range findingsRaw {
		fm, ok := raw.(map[string]any)
		if !ok {
			return nil
		}
		if typ, _ := fm["type"].(string); typ != "secret" {
			return nil
		}
		sha, _ := fm["matched_text_preview_sha256"].(string)
		if sha == "" {
			return nil
		}
		if !seen[sha] {
			seen[sha] = true
			pairs = append(pairs, repository.SecretFlowPair{SecretFP: sha, TargetHost: host})
		}
	}
	return pairs
}

// RunOnce processes one batch of unalerted security events. It is idempotent:
// an event is marked alerted only after its inbox row is durably written or
// folded (or it is deliberately suppressed by the gate), so a crash mid-batch
// re-delivers at most the in-flight event on the next cycle. Returns the number
// of events surfaced as NEW inbox alerts (suppressed and deduped events are not
// counted).
// DrainBatches processes a bounded number of oldest-first batches under a
// single in-process lock. alerted_at is the durable per-event checkpoint: after
// every committed batch, the next query resumes from the oldest remaining event.
// A crash leaves only unmarked events eligible for retry, never deletes evidence.
func (b *SecEventBridge) DrainBatches(ctx context.Context, maxBatches int) (int, error) {
	if b == nil {
		return 0, fmt.Errorf("security event bridge is nil")
	}
	if maxBatches < 1 {
		maxBatches = 1
	}
	b.runMu.Lock()
	defer b.runMu.Unlock()
	total := 0
	for i := 0; i < maxBatches; i++ {
		n, err := b.RunOnce(ctx)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (b *SecEventBridge) RunOnce(ctx context.Context) (int, error) {
	events, err := b.src.ListUnalerted(ctx, secEventBatchSize)
	if err != nil {
		return 0, fmt.Errorf("list unalerted security events: %w", err)
	}
	if len(events) == 0 {
		return 0, nil
	}

	// 每 tick 一次性预取：误报处置组集合（P1-2）与规则日计数（P1-1）。
	// 任一查询失败一律 fail open（不静默、不聚合），绝不因辅助数据故障丢告警。
	fpKeys := b.loadFPGroupKeys(ctx, events)
	dailyCounts := b.loadRuleDailyCounts(ctx, events)

	// processed = events to mark alerted (pushed, folded, OR deliberately
	// suppressed), so none is re-evaluated next cycle. pushed counts NEW alerts.
	processed := make([]string, 0, len(events))
	pushed := 0
	deduped := 0
	suppressed := 0
	triageSuppressed := 0
	exceptionSuppressed := 0
	fpSilenced := 0
	dailyFolded := 0
	secretSeenSilenced := 0

	for _, sourceEvent := range events {
		ev := attributedEvent(sourceEvent)
		surface, reason := b.shouldSurface(ev)
		// Passive semantic findings are not actionable inbox alerts, but they are
		// operator-visible evidence and belong in the informational alert bucket.
		groupOnly := !surface && (reason == reasonPassiveSemantic || reason == reasonSemanticBudgetFault)
		if !surface && !groupOnly {
			if reason == reasonReviewPending {
				continue
			}
			// Low-signal noise: stays in security_events as evidence, but does
			// not flood the actionable inbox. Mark it so we don't re-scan it.
			log.Printf("[secevent] suppressed low-signal event %s (%s/%s): %s", ev.ID, ev.EventType, ev.Severity, reason)
			processed = append(processed, ev.ID)
			suppressed++
			switch reason {
			case reasonTriageSuppressed:
				triageSuppressed++
			case reasonExceptionSuppressed:
				exceptionSuppressed++
			}
			continue
		}

		groupKey := eventGroupKey(ev)

		// 误报处置静默（P1-2）：该组在有效期内被人工处置为 false_positive → 同组后续
		// 事件不进收件箱/不通知/不再开新告警组；security_events 照常留证、照常 MarkAlerted。
		if b.isFPSilenced(ev, groupKey, fpKeys) {
			log.Printf("[secevent] fp-disposition silenced event %s (%s/%s) group=%s", ev.ID, ev.EventType, ev.Severity, groupKey)
			processed = append(processed, ev.ID)
			fpSilenced++
			continue
		}

		lc := b.computeLifecycleFields(ev)
		title := alertGroupTitle(ev, lc)
		body := map[string]any{
			"review_state":      effectiveReviewState(ev),
			"review_evidence":   "retained_in_security_event",
			"event_id":          ev.ID,
			"event_type":        ev.EventType,
			"notification_kind": alertTypeForSecurityEvent(ev),
			"severity":          lc.effectiveSeverity,
			"authored_severity": ev.Severity,
			"rule_name":         ev.RuleName,
			"rule_id":           dominantFinding(ev)["rule_id"],
			"category":          dominantCategory(ev),
			"primary_finding":   dominantFinding(ev),
			"rule_type":         ev.RuleType,
			"action":            ev.ActionTaken,
			"request_id":        ev.RequestID,
			"project_id":        ev.ProjectID,
			"user_id":           ev.UserID,
			"domain":            alertDomainForSecurityEvent(ev),
			"matched":           ev.MatchedSummary,
			"created_at":        ev.CreatedAt.Format(time.RFC3339),
		}
		// 分流留观：把原因写进组 body，页面据此说明"为什么这条不用处置"。
		if lc.triageRoute != nil {
			body["triage_route"] = map[string]any{
				"route":  lc.triageRoute.Route,
				"reason": lc.triageRoute.Reason,
			}
		}
		targetURL := fmt.Sprintf("/security-events/%s", ev.ID)

		if b.groups != nil {
			group, _, err := b.groups.UpsertOpen(ctx, repository.AlertGroupUpsertInput{
				TenantID:              ev.TenantID,
				ProjectID:             ev.ProjectID,
				GroupKey:              groupKey,
				Severity:              lc.effectiveSeverity,
				AlertType:             alertTypeForSecurityEvent(ev),
				Title:                 title,
				RepresentativeEventID: ev.ID,
				RequestID:             ev.RequestID,
				OccurredAt:            ev.CreatedAt,
				BodyJSON:              storedAlertBody(body),
				EffectiveSeverity:     lc.effectiveSeverity,
				DispositionClass:      lc.dispositionClass,
				ClassKey:              lc.classKey,
				PrincipalKey:          ev.PrincipalKey,
				IsCanary:              lc.isCanary,
				Stage:                 lc.stage,
				Domain:                alertDomainForSecurityEvent(ev),
			})
			if err != nil {
				log.Printf("[secevent] alert group upsert failed for %s (%s): %v", ev.ID, ev.TenantID, err)
				continue
			}
			if group != nil {
				body["alert_group_id"] = group.ID
				body["occurrence_count"] = group.OccurrenceCount
				body["group_first_seen_at"] = group.FirstSeenAt.Format(time.RFC3339)
				body["group_last_seen_at"] = group.LastSeenAt.Format(time.RFC3339)
				// P1-D：UpsertOpen 成功后回填 security_events.alert_group_id，随后幂等重算
				// 主指标（distinct_occurrences/affected_users）。UpsertOpen 已把 principal_key
				// 沾到组上（上方 input），此处两步失败均只记日志不阻断——事件照常 MarkAlerted，
				// 计数由下一次同组事件或存量回算任务补齐（宁可迟到不可重复计数）。
				if b.groupCounters != nil {
					if aerr := b.groupCounters.AttachEvent(ctx, ev.TenantID, ev.ID, group.ID); aerr != nil {
						log.Printf("[secevent] attach event %s to group %s failed: %v", ev.ID, group.ID, aerr)
					} else if occ, users, rerr := b.groupCounters.RecalcCounters(ctx, ev.TenantID, group.ID); rerr != nil {
						log.Printf("[secevent] recalc counters for group %s failed: %v", group.ID, rerr)
					} else {
						body["distinct_occurrences"] = occ
						body["affected_users"] = users
						// 口径同步（设计 3b）：收件箱与外部通知（钉钉/邮件/Webhook）标题
						// 改用新主指标，与告警页数字同源。运行故障不套这个口径：它是运维
						// 事件，没有"事发次数/涉及人数"可言，保留故障标题反而更准确。
						if alertTypeForSecurityEvent(ev) != "runtime_fault" {
							title = fmt.Sprintf("安全告警【%s】%s · 独立事发 %d 次 · 涉及 %d 人",
								severityLabelCN(lc.effectiveSeverity), alertSubjectCN(ev), occ, users)
						}
					}
				}
			}
		}

		// Informational semantic evidence is visible in alert_groups without
		// entering the actionable inbox or triggering external notification.
		if groupOnly {
			processed = append(processed, ev.ID)
			continue
		}
		// secret 首见（P2-3）：全部 (指纹,目的地) 对都已见过 → 折叠进告警组（上方
		// UpsertOpen 已累计）但不进收件箱/不通知；任一新对（新密钥或旧密钥流向新目的地）
		// → 照常提升。登记失败 fail open（按首见提升）。注意登记在 UpsertOpen 之后：
		// 组写失败时事件原样重试，不会先占用「首见」名额。
		if b.secretNovelty && b.secretSink != nil {
			if pairs := secretNoveltyPairs(ev); len(pairs) > 0 {
				newN, serr := b.secretSink.MarkSeen(ctx, ev.TenantID, pairs)
				if serr != nil {
					log.Printf("[secevent] secret novelty mark failed for %s (%s): %v (fail open)", ev.ID, ev.TenantID, serr)
				} else if newN == 0 && !isRedline(ev) {
					log.Printf("[secevent] non-redline secret-like flow already seen, silenced event %s (%s) group=%s", ev.ID, ev.TenantID, groupKey)
					processed = append(processed, ev.ID)
					secretSeenSilenced++
					continue
				}
			}
		}

		// 高频规则日聚合（P1-1）：当日该维度可告警事件数已超上限 → 不再逐条进收件箱，
		// 改投一张按日折叠的聚合卡；卡首建时照常外发通知（=每规则每日至多一条外部通知）。
		if card, aggregate := b.dailyAggregate(ev, dailyCounts); aggregate {
			created, aerr := b.inbox.UpsertByGroup(ctx, ev.TenantID, lc.effectiveSeverity, secEventDailySummaryType, card.title, card.body, card.targetURL, card.groupKey)
			if aerr != nil {
				log.Printf("[secevent] daily summary upsert failed for %s (%s): %v", ev.ID, ev.TenantID, aerr)
				continue
			}
			processed = append(processed, ev.ID)
			if created {
				pushed++
				if b.notifier != nil {
					if err := b.notifier.Dispatch(ctx, ev.TenantID, lc.effectiveSeverity, card.title, notificationBody(ev, card.body)); err != nil {
						log.Printf("[secevent] notify dispatch failed for daily summary %s (%s): %v", card.groupKey, ev.TenantID, err)
					}
				}
			} else {
				dailyFolded++
			}
			continue
		}

		if b.dedup || alertTypeForSecurityEvent(ev) == "runtime_fault" {
			// Fold repeats of the same leak onto one unread alert. created=false
			// means an existing alert had its occurrence count bumped — real
			// work done, but no new alert and (deliberately) no re-notify.
			created, err := b.inbox.UpsertByGroup(ctx, ev.TenantID, lc.effectiveSeverity, alertTypeForSecurityEvent(ev), title, storedAlertBody(body), targetURL, groupKey)
			if err != nil {
				log.Printf("[secevent] inbox upsert failed for %s (%s): %v", ev.ID, ev.TenantID, err)
				continue
			}
			processed = append(processed, ev.ID)
			if !created {
				deduped++
				continue
			}
			pushed++
		} else {
			// Legacy: one inbox row per event. The inbox is the durable record;
			// if it fails, leave the event unalerted so the next cycle retries.
			if err := b.inbox.Push(ctx, ev.TenantID, lc.effectiveSeverity, alertTypeForSecurityEvent(ev), title, storedAlertBody(body), targetURL); err != nil {
				log.Printf("[secevent] inbox push failed for %s (%s): %v", ev.ID, ev.TenantID, err)
				continue
			}
			processed = append(processed, ev.ID)
			pushed++
		}

		// External notify is best-effort and only fires for NEW alerts: a folded
		// repeat must not re-page. A failed dispatch must not duplicate the inbox
		// row next cycle, so the event is already marked processed above.
		if b.notifier != nil {
			if err := b.notifier.Dispatch(ctx, ev.TenantID, lc.effectiveSeverity, title, notificationBody(ev, body)); err != nil {
				log.Printf("[secevent] notify dispatch failed for %s (%s): %v", ev.ID, ev.TenantID, err)
			}
		}
	}

	if len(processed) > 0 {
		if err := b.src.MarkAlerted(ctx, processed); err != nil {
			return pushed, fmt.Errorf("mark security events alerted: %w", err)
		}
	}
	if suppressed > 0 || deduped > 0 || fpSilenced > 0 || dailyFolded > 0 || secretSeenSilenced > 0 {
		log.Printf("[secevent] batch done: %d new alerts, %d folded, %d suppressed (%d by LLM triage, %d by exception), %d fp-disposition silenced, %d daily-folded, %d secret-seen silenced (min_confidence=%.2f, dedup=%v)",
			pushed, deduped, suppressed, triageSuppressed, exceptionSuppressed, fpSilenced, dailyFolded, secretSeenSilenced, b.minConfidence, b.dedup)
	}
	return pushed, nil
}

// --- 告警标题中文标签 ---
// 收件箱/通知渠道的标题面向客户,枚举值(severity/event_type/action)一律中文化,
// 不外露原始英文 id。与 handler 包的 riskLevelLabel/actionLabel 保持一致(跨包不能直接复用,故本地维护)。

// severityLabelCN 与前端 risk.ts 的 SEVERITY_LABELS 同口径；未知值不输出英文。
func severityLabelCN(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	case "warning":
		return "提醒"
	case "info":
		return "提示"
	default:
		return "未知"
	}
}

// actionLabelsCN 逐键对齐前端 apps/web-console/src/utils/alertReadable.ts 的 ACTION_RESULTS，
// 叫法以前端为准；secevent_bridge_action_labels_test.go 会读前端文件逐键比对。
var actionLabelsCN = map[string]string{
	"block": "已阻断", "blocked": "已阻断", "deny": "已阻断", "security_blocked": "已阻断", "stream_blocked": "已阻断",
	"tool_attempt_blocked": "已阻断", "tool_blocked": "已阻断", "mcp_tool_result_blocked": "已阻断", "mcp_server_request_blocked": "已阻断",
	"quarantine": "已隔离",
	"mask":       "已脱敏", "redact": "已脱敏", "security_masked": "已脱敏",
	"reply": "安全代答", "security_replied": "安全代答",
	"rewrite": "已改写",
	"confirm": "要求人工确认",
	"alert":   "告警放行", "mcp_server_request_alerted": "告警放行", "mcp_tool_result_alerted": "告警放行", "mcp_tools_list_alerted": "告警放行",
	"flag": "告警放行", "flagged": "告警放行",
	"audit": "仅记录", "security_audit": "仅记录", "tool_audited": "仅记录", "tool_audit_only": "仅记录",
	"allow":                 "已放行",
	"security_audit_only":   "观察留痕放行",
	"security_check_failed": "检测异常", "security_output_check_failed": "输出检测异常",
	"mcp_tools_list_filtered":       "已过滤工具列表",
	"agentguard_policy_load_failed": "策略加载失败",
}

func actionLabelCN(a string) string {
	key := strings.ToLower(strings.TrimSpace(a))
	if key == "" || key == "unknown" {
		return "未记录"
	}
	if label, ok := actionLabelsCN[key]; ok {
		return label
	}
	return "其他处置"
}

// eventTypeLabelCN 把安全事件 event_type 翻成中文。
// 正向代理动态生成的 proxy_<stage>_<action> 按构件拼装,其余按已知表映射,未知回退原值。
func alertTypeForSecurityEvent(ev *repository.SecurityEvent) string {
	if isInspectionFaultOnlyEvent(ev) {
		return "runtime_fault"
	}
	switch ev.EventType {
	case "security_check_failed", "security_output_check_failed":
		return "runtime_fault"
	case "access_denied", "model_policy", "quota", "proxy_auth_denied", "proxy_access_denied":
		return "access_governance"
	case "tool_execution_risk":
		return "tool_execution_risk"
	case "agent_endpoint_risk":
		return "agent_endpoint_risk"
	case "tool_attempt_blocked":
		return "tool_attempt_blocked"
	default:
		return "security_event"
	}
}

func toolEventGroupKey(ev *repository.SecurityEvent) string {
	tool, _ := ev.MatchedSummary["tool_name"].(string)
	server, _ := ev.MatchedSummary["server_id"].(string)
	raw, _ := ev.MatchedSummary["raw_decision"].(string)
	sum := sha256.Sum256([]byte("tool|" + ev.EventType + "|" + server + "|" + tool + "|" + raw))
	return hex.EncodeToString(sum[:])[:16]
}

func eventDisplayLabelCN(ev *repository.SecurityEvent) string {
	if ev == nil {
		return "安全事件"
	}
	if alertTypeForSecurityEvent(ev) == "runtime_fault" {
		if semanticFaultReason(ev) == agentToolFailureLoopCategory {
			return agentToolFailureLoopTitleCN
		}
		return "检测运行故障"
	}
	if alertTypeForSecurityEvent(ev) == "access_governance" {
		return "访问治理"
	}
	finding := dominantFinding(ev)
	category, _ := finding["category"].(string)
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "semantic_harassment":
		return "语义骚扰"
	case "semantic_threat":
		return "语义威胁"
	case "semantic_hate":
		return "语义仇恨"
	case "semantic_jailbreak":
		return "语义越狱"
	case "semantic_roleplay":
		return "角色扮演绕过"
	case "semantic_instruction_override":
		return "指令覆盖"
	case "semantic_exfil_induce":
		return "数据外泄诱导"
	}
	typ, _ := finding["type"].(string)
	switch typ {
	case "secret":
		return "凭据泄露"
	case "pii":
		return "个人信息泄露"
	case "data_leak":
		return "数据泄露"
	}
	if genericContentEventTypes[strings.ToLower(ev.EventType)] {
		if label := specificFindingLabelCN(finding); label != "" {
			return label
		}
	}
	return eventTypeLabelCN(ev.EventType)
}

func eventTypeLabelCN(t string) string {
	switch strings.ToLower(t) {
	case "security_check":
		return "安全检测"
	case "data_security":
		return "数据安全"
	case "file_security":
		return "文件安全"
	case "prompt_injection":
		return "提示词注入"
	case "prompt_guard":
		return "提示词防护"
	case "eval_content_safety":
		return "内容安全测评"
	case "tool_audit_only", "tool_risk", "tool_call_risk", "tool_execution_risk":
		return "工具执行风险"
	case "tool_attempt_blocked":
		return "工具尝试已阻断"
	case "tool_destructive_intent":
		return "破坏性操作意图"
	case "skill_invocation_risk":
		return "Skill 调用风险"
	case "skill_admission_changed":
		return "Skill 准入变更"
	case "mcp_policy_hit":
		return "MCP 策略命中"
	case "mcp_redline_hit":
		return "MCP 红线命中"
	case "mcp_confirmation_required":
		return "MCP 待人工确认"
	case "model_policy":
		return "模型策略"
	case "quota":
		return "额度控制"
	case "semantic_attack":
		return "语义攻击"
	case "security_mode_changed":
		return "执行模式变更"
	case "agent_endpoint_risk":
		return "终端智能体风险"
	case "agent_identity_mismatch":
		return "智能体身份与凭据不符"
	}
	if strings.HasPrefix(t, "proxy_") {
		parts := strings.Split(t, "_")
		if len(parts) == 3 {
			stage := map[string]string{"input": "输入", "output": "输出"}[parts[1]]
			act := map[string]string{"audit": "审计", "block": "拦截", "mask": "脱敏"}[parts[2]]
			if stage != "" && act != "" {
				return "代理" + stage + act
			}
		}
	}
	if t == "" {
		return "安全事件"
	}
	return t
}
