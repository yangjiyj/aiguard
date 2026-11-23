package alert

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// consoleAlertInbox is the operator-facing source that names every engine fault
// reason. The Go label table is generated from it, so this test re-reads it and
// fails the moment the two sides drift: an operator reading the inbox and an
// operator reading the DingTalk card must see the same words.
const consoleAlertInbox = "../../../../apps/web-console/src/utils/alertInboxDisplay.ts"

var consoleReasonEntry = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*:\s*'([^']*)'`)

func TestFaultReasonLabelsMatchTheConsole(t *testing.T) {
	raw, err := os.ReadFile(consoleAlertInbox)
	if err != nil {
		t.Fatalf("read console alertInboxDisplay.ts: %v", err)
	}
	source := string(raw)

	const decl = "const reasons: Record<string, string> = {"
	start := strings.Index(source, decl)
	if start < 0 {
		t.Fatal("the console no longer declares its fault reason map where this test looks")
	}
	end := strings.Index(source[start:], "}\n")
	if end < 0 {
		t.Fatal("unterminated fault reason map in the console")
	}
	entries := consoleReasonEntry.FindAllStringSubmatch(source[start:start+end], -1)
	if len(entries) < 8 {
		t.Fatalf("only %d reason labels parsed; the console map changed shape", len(entries))
	}

	seen := map[string]bool{}
	for _, entry := range entries {
		key, label := entry[1], entry[2]
		seen[key] = true
		got, ok := faultReasonLabelCN[key]
		if !ok {
			t.Errorf("console labels %s but the Go table has no entry for it; regenerate with python3 deploy/maintenance/gen_fault_labels.py", key)
			continue
		}
		if got != label {
			t.Errorf("label drift for %s: console=%q go=%q", key, label, got)
		}
	}
	for key := range faultReasonLabelCN {
		if !seen[key] {
			t.Errorf("the Go table carries %s, which the console no longer labels", key)
		}
	}

	// The class label and the unknown-reason fallback must come from the console
	// too, not from a paraphrase invented on the Go side. The console renders the
	// fault title as a template literal that begins with the class label.
	if !strings.Contains(source, "`"+faultDisplayLabelCN) {
		t.Errorf("the console no longer titles runtime faults with %q", faultDisplayLabelCN)
	}
	if !strings.Contains(source, "|| '"+faultUnknownReasonLabelCN+"'") {
		t.Errorf("the console no longer falls back to %q", faultUnknownReasonLabelCN)
	}
	// Fullwidth parens only; an ASCII "(input)" inside a Chinese title is the
	// kind of thing that survives review and looks wrong forever.
	if faultStageParenOpen != "\uFF08" || faultStageParenClose != "\uFF09" {
		t.Errorf("stage parens must be the fullwidth pair, got %q and %q", faultStageParenOpen, faultStageParenClose)
	}
}

// faultFixtureEvent builds a detection-failure event with a given stage and
// engine reason.
func faultFixtureEvent(id, stage, reason string) *repository.SecurityEvent {
	ev := sampleSecEvent(id)
	ev.EventType = "security_check_failed"
	ev.Severity = "low"
	ev.ActionTaken = "allow"
	summary := map[string]any{"semantic_status": "unavailable"}
	if reason != "" {
		summary["semantic_reason"] = reason
	}
	if stage != "" {
		summary["stage"] = stage
	}
	ev.MatchedSummary = summary
	return ev
}

// TestRuntimeFaultFoldsByStageAndReason is the point of the fold: which host
// answered, and which request tripped it, must not shatter one operational fault
// into an alert per occurrence.
func TestRuntimeFaultFoldsByStageAndReason(t *testing.T) {
	base := faultFixtureEvent("req-a", "input", "breaker_open")
	other := faultFixtureEvent("req-b", "input", "breaker_open")
	other.MatchedSummary["target_host"] = "judge-2.internal"
	other.MatchedSummary["rule_version"] = "2026.09.17"

	if eventGroupKey(base) != eventGroupKey(other) {
		t.Fatal("the same fault on a different host and request must fold onto one group")
	}
	if eventGroupKey(base) != eventGroupKey(faultFixtureEvent("req-c", "input", "breaker_open")) {
		t.Fatal("fault grouping must not depend on the request id")
	}
}

func TestRuntimeFaultSeparatesReasonsAndStages(t *testing.T) {
	base := eventGroupKey(faultFixtureEvent("r", "input", "breaker_open"))
	if base == eventGroupKey(faultFixtureEvent("r", "input", "judge_timeout")) {
		t.Error("two different fault reasons must not share a group")
	}
	if base == eventGroupKey(faultFixtureEvent("r", "output", "breaker_open")) {
		t.Error("the same fault on another stage must not share a group")
	}
}

func TestRuntimeFaultWithoutReasonFallsBackToEventType(t *testing.T) {
	unclassified := faultFixtureEvent("r1", "input", "")
	sibling := faultFixtureEvent("r2", "input", "")
	sibling.EventType = "security_output_check_failed"

	if eventGroupKey(unclassified) == eventGroupKey(sibling) {
		t.Error("unclassified failures of different event types must not merge")
	}
	if eventGroupKey(unclassified) == eventGroupKey(faultFixtureEvent("r3", "input", "breaker_open")) {
		t.Error("an unclassified fault must not merge into a classified one")
	}
}

func TestRuntimeFaultTitleNamesReasonAndStage(t *testing.T) {
	title := alertGroupTitle(faultFixtureEvent("r", "input", "breaker_open"), lifecycleFields{})
	if !strings.Contains(title, faultDisplayLabelCN) {
		t.Fatalf("title=%q must name the fault class", title)
	}
	if !strings.Contains(title, faultReasonLabel("breaker_open")) {
		t.Fatalf("title=%q must name the engine reason in Chinese", title)
	}
	if !strings.Contains(title, faultStageParenOpen+"input"+faultStageParenClose) {
		t.Fatalf("title=%q must name the pipeline stage", title)
	}
}

func TestRuntimeFaultTitleOmitsEmptyStage(t *testing.T) {
	title := alertGroupTitle(faultFixtureEvent("r", "", "tier1_timeout"), lifecycleFields{})
	if strings.Contains(title, faultStageParenOpen) || strings.Contains(title, faultStageParenClose) {
		t.Fatalf("a stage-less fault must not render empty parens: %q", title)
	}
	if !strings.Contains(title, faultReasonLabel("tier1_timeout")) {
		t.Fatalf("title=%q must still name the reason", title)
	}
}

func TestRuntimeFaultTitleNeverLeaksTheRawEnum(t *testing.T) {
	const unknown = "brand_new_engine_reason"
	title := alertGroupTitle(faultFixtureEvent("r", "input", unknown), lifecycleFields{})
	if strings.Contains(title, unknown) {
		t.Fatalf("the raw engine enum reached an operator title: %q", title)
	}
	if !strings.Contains(title, faultUnknownReasonLabelCN) {
		t.Fatalf("title=%q must use the neutral fallback", title)
	}
}

// TestFaultGroupingLeavesOrdinaryEventsAlone guards the branch condition: the
// fold keys off the alert type, not off the mere presence of a semantic_reason.
func TestFaultGroupingLeavesOrdinaryEventsAlone(t *testing.T) {
	same := secEventSha("a", "shared-evidence")
	other := secEventSha("b", "shared-evidence")
	if eventGroupKey(same) != eventGroupKey(other) {
		t.Fatal("ordinary evidence grouping must keep folding identical evidence")
	}
	if eventGroupKey(same) == eventGroupKey(secEventSha("c", "different-evidence")) {
		t.Fatal("ordinary grouping must still split different evidence")
	}
	carrier := secEventSha("d", "shared-evidence")
	carrier.MatchedSummary["semantic_reason"] = "breaker_open"
	if eventGroupKey(carrier) != eventGroupKey(same) {
		t.Fatal("a security event that merely carries a semantic_reason must not be folded as a fault")
	}
}

// TestBridgeAssemblesRuntimeFaultGroup pins the wiring end to end: the group
// carries the fault alert type, the folded key and the fault-shaped title.
func TestBridgeAssemblesRuntimeFaultGroup(t *testing.T) {
	ev := faultFixtureEvent("f1", "input", "breaker_open")
	groups := &fakeAlertGrouper{}
	_, err := gateBridge(&fakeSecEventSource{events: []*repository.SecurityEvent{ev}}, &fakePusher{}, &fakeNotifier{}, 0.5).
		WithAlertGroups(groups).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(groups.inputs) != 1 {
		t.Fatalf("expected 1 alert group, got %d", len(groups.inputs))
	}
	in := groups.inputs[0]
	if in.AlertType != "runtime_fault" {
		t.Fatalf("alert_type=%q want runtime_fault", in.AlertType)
	}
	if in.GroupKey != eventGroupKey(ev) {
		t.Fatalf("group key=%q, want the folded fault key %q", in.GroupKey, eventGroupKey(ev))
	}
	if in.Title != faultAlertTitle(ev) {
		t.Fatalf("group title=%q, want the fault-shaped title %q", in.Title, faultAlertTitle(ev))
	}
	// A second occurrence on another request folds into the very same group key.
	if eventGroupKey(faultFixtureEvent("f2", "input", "breaker_open")) != in.GroupKey {
		t.Fatal("the second occurrence must fold into the same group")
	}
}

// toolFailureLoopEvent 按网关 recordToolResultFailures 的真实写入形态构造：
// event_type=security_check（finding.type 不在工具事件之列，落默认分桶）、action_taken=tool_failure_loop、
// 级别 low、stage 由 withSecurityEventStage 写成 tool，finding 不计入安全命中、证据类别 runtime。
func toolFailureLoopEvent(id string) *repository.SecurityEvent {
	ev := sampleSecEvent(id)
	ev.EventType = "security_check"
	ev.Severity = "low"
	ev.ActionTaken = "tool_failure_loop"
	ev.MatchedSummary = map[string]any{
		"action_taken":   "tool_failure_loop",
		"summary":        `tool "Bash" failed 3 times within the failure-loop window`,
		"findings_count": float64(0),
		"source":         "gateway",
		"stage":          "tool",
		"findings": []any{map[string]any{
			"type": "tool_failure_loop", "category": agentToolFailureLoopCategory, "severity": "low",
			"rule_id": "", "rule_name": "Bash", "rule_type": "agentguard", "action": "audit",
			"matched_location": "tool_result", "content_source": "tool_result",
			"evidence_kind": "runtime", "counts_as_security_finding": false,
			"redacted_evidence": "Bash 在窗口内失败 3 次",
			"triage":            map[string]any{"disposition": "observation", "disposition_reason": agentToolFailureLoopCategory},
		}},
	}
	return ev
}

func TestToolFailureLoopIsARuntimeEventNotASecurityAlert(t *testing.T) {
	ev := toolFailureLoopEvent("loop-1")
	if got := alertTypeForSecurityEvent(ev); got != "runtime_fault" {
		t.Fatalf("alert type=%q want runtime_fault", got)
	}
	if got := semanticFaultReason(ev); got != agentToolFailureLoopCategory {
		t.Fatalf("fault reason=%q want %q", got, agentToolFailureLoopCategory)
	}
	if title := alertGroupTitle(ev, lifecycleFields{}); title != agentToolFailureLoopTitleCN {
		t.Fatalf("title=%q want %q", title, agentToolFailureLoopTitleCN)
	}
	if label := eventDisplayLabelCN(ev); label != agentToolFailureLoopTitleCN {
		t.Fatalf("display label=%q want %q", label, agentToolFailureLoopTitleCN)
	}
	if eventGroupKey(ev) != eventGroupKey(toolFailureLoopEvent("loop-2")) {
		t.Fatal("tool failure loops of one project and stage must fold into one runtime group")
	}
	other := toolFailureLoopEvent("loop-3")
	other.ProjectID = "proj_y"
	if eventGroupKey(ev) == eventGroupKey(other) {
		t.Fatal("tool failure loops of different projects must not share a group")
	}
	// 不同工具、不同次数仍是同一组：组按项目与阶段折叠，不按工具拆。
	diff := toolFailureLoopEvent("loop-4")
	diff.MatchedSummary["findings"].([]any)[0].(map[string]any)["rule_name"] = "Read"
	if eventGroupKey(ev) != eventGroupKey(diff) {
		t.Fatal("different tools in one project and stage must fold into one group")
	}
}

// legacyToolFailureLoopEvent 是 2.9.16 及更早写下的存量形态：finding type=tool_failure_loop、
// category=tool_risk、高危、计入告警，action_taken=tool_failure_loop，stage 是 input
// （旧网关没有给这条事件标 tool 阶段，按请求的输入阶段落库）。
func legacyToolFailureLoopEvent(id string) *repository.SecurityEvent {
	ev := sampleSecEvent(id)
	ev.EventType = "security_check"
	ev.Severity = "high"
	ev.ActionTaken = "tool_failure_loop"
	ev.MatchedSummary = map[string]any{
		"action_taken": "tool_failure_loop",
		"stage":        "input",
		"findings": []any{map[string]any{
			"type": "tool_failure_loop", "category": "tool_risk", "severity": "high", "rule_name": "Bash", "action": "audit",
		}},
	}
	return ev
}

func TestLegacyToolFailureLoopIsRecognisedAsRuntimeObservation(t *testing.T) {
	ev := legacyToolFailureLoopEvent("legacy-loop")
	if got := alertTypeForSecurityEvent(ev); got != "runtime_fault" {
		t.Fatalf("alert type=%q want runtime_fault", got)
	}
	if got := semanticFaultReason(ev); got != agentToolFailureLoopCategory {
		t.Fatalf("fault reason=%q want %q", got, agentToolFailureLoopCategory)
	}
	if title := alertGroupTitle(ev, lifecycleFields{}); title != agentToolFailureLoopTitleCN {
		t.Fatalf("title=%q want %q", title, agentToolFailureLoopTitleCN)
	}
	// 只靠 action_taken + tool_risk 类别也算（finding.type 不是 tool_failure_loop）。
	byAction := legacyToolFailureLoopEvent("legacy-loop-action")
	byAction.MatchedSummary["findings"].([]any)[0].(map[string]any)["type"] = "tool_risk"
	if got := alertTypeForSecurityEvent(byAction); got != "runtime_fault" {
		t.Fatalf("action+tool_risk alert type=%q want runtime_fault", got)
	}
}

// 新旧两种形态是同一件事：同项目的工具连续失败必须落进同一个运行告警组，组阶段都是 tool，
// 旧形态不能因为落库的 input 阶段和高危级别另开一个“高危、需处置”的组。
func TestLegacyAndCurrentToolFailureLoopShareOneLowInformationalGroup(t *testing.T) {
	legacy := legacyToolFailureLoopEvent("legacy-fold")
	current := toolFailureLoopEvent("current-fold")
	if eventGroupKey(legacy) != eventGroupKey(current) {
		t.Fatalf("legacy key %q and current key %q must be the same group", eventGroupKey(legacy), eventGroupKey(current))
	}
	bridge := NewSecEventBridge(&fakeSecEventSource{}, &fakePusher{}, nil)
	for name, ev := range map[string]*repository.SecurityEvent{"legacy": legacy, "current": current} {
		fields := bridge.computeLifecycleFields(ev)
		if fields.effectiveSeverity != "low" || fields.dispositionClass != "informational" ||
			fields.stage != "tool" || fields.classKey != agentToolFailureLoopCategory {
			t.Errorf("%s lifecycle=%+v want low/informational/tool/%s", name, fields, agentToolFailureLoopCategory)
		}
	}

	src := &fakeSecEventSource{events: []*repository.SecurityEvent{legacyToolFailureLoopEvent("legacy-run")}}
	groups := &fakeAlertGrouper{}
	inbox := &recordingInbox{}
	if _, err := NewSecEventBridge(src, inbox, &fakeNotifier{}).WithAlertGroups(groups).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(groups.inputs) != 1 {
		t.Fatalf("expected 1 alert group, got %d", len(groups.inputs))
	}
	in := groups.inputs[0]
	if in.GroupKey != eventGroupKey(current) || in.Stage != "tool" || in.Severity != "low" ||
		in.EffectiveSeverity != "low" || in.DispositionClass != "informational" {
		t.Fatalf("legacy group input=%+v want current key, tool stage, low/informational", in)
	}
	if len(inbox.severities) != 1 || inbox.severities[0] != "low" {
		t.Fatalf("legacy inbox severities=%v want [low]", inbox.severities)
	}
}

func TestLegacyToolFailureLoopDoesNotSwallowRealToolRisk(t *testing.T) {
	// 同类别 tool_risk 但动作不是 tool_failure_loop：真实工具风险，仍是安全告警。
	real := legacyToolFailureLoopEvent("real-tool-risk")
	real.ActionTaken = "block"
	real.MatchedSummary["action_taken"] = "block"
	real.MatchedSummary["findings"].([]any)[0].(map[string]any)["type"] = "tool_risk"
	if got := alertTypeForSecurityEvent(real); got == "runtime_fault" {
		t.Fatal("a real tool_risk finding must stay a security alert")
	}
	// 老形态事件里混有真实命中：仍是安全告警。
	mixed := legacyToolFailureLoopEvent("mixed")
	mixed.MatchedSummary["findings"] = append(mixed.MatchedSummary["findings"].([]any),
		map[string]any{"type": "pii", "category": "pii_email", "severity": "high", "action": "block"})
	if got := alertTypeForSecurityEvent(mixed); got == "runtime_fault" {
		t.Fatal("an event with a real sibling hit must stay a security alert")
	}
}

func TestToolFailureLoopStaysLowAndInformational(t *testing.T) {
	bridge := NewSecEventBridge(&fakeSecEventSource{}, &fakePusher{}, nil)
	ev := toolFailureLoopEvent("loop-lc")
	fields := bridge.computeLifecycleFields(ev)
	if fields.effectiveSeverity != "low" || fields.dispositionClass != "informational" {
		t.Fatalf("lifecycle=%+v want low/informational", fields)
	}
	if fields.stage != "tool" {
		t.Fatalf("stage=%q want tool", fields.stage)
	}
	if surface, _ := bridge.shouldSurface(ev); !surface {
		t.Fatal("tool failure loop must still reach the runtime inbox")
	}
}

type recordingInbox struct {
	types, severities, titles []string
}

func (r *recordingInbox) Push(_ context.Context, _, severity, typ, title string, _ map[string]any, _ string) error {
	r.types, r.severities, r.titles = append(r.types, typ), append(r.severities, severity), append(r.titles, title)
	return nil
}

func (r *recordingInbox) UpsertByGroup(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL, _ string) (bool, error) {
	return true, r.Push(ctx, tenantID, severity, typ, title, body, targetURL)
}

func TestToolFailureLoopNotificationIsLowRuntimeFault(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{toolFailureLoopEvent("loop-n")}}
	inbox := &recordingInbox{}
	notifier := &fakeNotifier{}
	if _, err := NewSecEventBridge(src, inbox, notifier).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(inbox.types) != 1 || inbox.types[0] != "runtime_fault" || inbox.severities[0] != "low" || inbox.titles[0] != agentToolFailureLoopTitleCN {
		t.Fatalf("inbox types=%v severities=%v titles=%v", inbox.types, inbox.severities, inbox.titles)
	}
	if notifier.calls != 1 || notifier.lastTitle != agentToolFailureLoopTitleCN {
		t.Fatalf("notifier calls=%d title=%q", notifier.calls, notifier.lastTitle)
	}
}

// 存量旧事件（高危、计入安全命中）在读取侧识别为工具连续失败运行观察；混有真实威胁的事件也不能被归入运行告警。
func TestToolFailureLoopOnlyRoutesWhenEveryFindingIsRuntime(t *testing.T) {
	legacy := toolFailureLoopEvent("loop-legacy")
	legacy.Severity = "high"
	finding := legacy.MatchedSummary["findings"].([]any)[0].(map[string]any)
	delete(finding, "counts_as_security_finding")
	delete(finding, "evidence_kind")
	finding["severity"] = "high"
	if got := alertTypeForSecurityEvent(legacy); got != "runtime_fault" {
		t.Fatalf("legacy high-severity loop is a runtime observation, got %q", got)
	}

	mixed := toolFailureLoopEvent("loop-mixed")
	mixed.MatchedSummary["findings"] = append(mixed.MatchedSummary["findings"].([]any), map[string]any{
		"type": "secret", "category": "secret_leak", "severity": "high", "counts_as_security_finding": true,
	})
	if got := alertTypeForSecurityEvent(mixed); got != "security_event" {
		t.Fatalf("a sibling security finding keeps the event in the security lane, got %q", got)
	}
}
