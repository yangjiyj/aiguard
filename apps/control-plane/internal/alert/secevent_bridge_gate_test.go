package alert

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// secEventWithFindings builds a passive (default audit) security event whose
// matched_summary carries the given findings, mirroring the live jsonb shape.
func secEventWithFindings(id, action string, findings ...map[string]any) *repository.SecurityEvent {
	fs := make([]any, len(findings))
	for i, f := range findings {
		fs[i] = f
	}
	ev := sampleSecEvent(id)
	ev.ActionTaken = action
	ev.MatchedSummary = map[string]interface{}{"findings": fs}
	return ev
}

func finding(confidence float64) map[string]any {
	return map[string]any{"confidence": confidence}
}

func findingCat(confidence float64, category string) map[string]any {
	return map[string]any{"confidence": confidence, "category": category}
}

// catBridge builds a bridge with an explicit confidence floor and baseline
// category set, independent of environment variables.
func catBridge(src secEventSource, inbox secInboxPusher, notifier secNotifier, floor float64, cats ...string) *SecEventBridge {
	b := gateBridge(src, inbox, notifier, floor)
	b.suppressCategories = map[string]bool{}
	for _, c := range cats {
		b.suppressCategories[c] = true
	}
	return b
}

// gateBridge constructs a bridge with an explicit confidence floor so tests do
// not depend on the SECEVENT_INBOX_MIN_CONFIDENCE environment variable.
func gateBridge(src secEventSource, inbox secInboxPusher, notifier secNotifier, floor float64) *SecEventBridge {
	b := NewSecEventBridge(src, inbox, notifier)
	b.minConfidence = floor
	return b
}

func TestSecEventBridge_SuppressesLowConfidence(t *testing.T) {
	// A lone audit event whose only finding scored 0.30 (e.g. a card number that
	// failed its checksum) must NOT reach the inbox, but must still be marked
	// processed so it isn't re-scanned, and must not notify.
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("low1", "audit", finding(0.30)),
	}}
	pusher := &fakePusher{}
	notifier := &fakeNotifier{}

	n, err := gateBridge(src, pusher, notifier, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 alerted for low-confidence event, got %d", n)
	}
	if len(pusher.pushedTypes) != 0 {
		t.Fatalf("expected no inbox push, got %v", pusher.pushedTypes)
	}
	if notifier.calls != 0 {
		t.Fatalf("expected no dispatch, got %d", notifier.calls)
	}
	if len(src.markedIDs) != 1 || src.markedIDs[0][0] != "low1" {
		t.Fatalf("expected low1 marked alerted (so it is not re-scanned), got %v", src.markedIDs)
	}
}

func TestSecEventBridge_SurfacesHighConfidence(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("hi1", "audit", finding(0.90)),
	}}
	pusher := &fakePusher{}
	notifier := &fakeNotifier{}

	n, err := gateBridge(src, pusher, notifier, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("expected high-confidence event surfaced, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_SurfacesChineseProfanityFindingInAuditOnly(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("cn-profanity", "security_audit_only", map[string]any{
			"type":                       "content_safety",
			"category":                   "harassment_profanity_cn",
			"rule_id":                    "content_safety_harassment_profanity_cn",
			"severity":                   "medium",
			"confidence":                 0.98,
			"action":                     "audit",
			"counts_as_security_finding": true,
		}),
	}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("audit-only Chinese profanity finding must surface, n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func semanticFinding(confidence float64, category string) map[string]any {
	return map[string]any{
		"type": "semantic_attack", "category": category,
		"confidence": confidence, "severity": "high",
	}
}

func TestSecEventBridge_PassivePureSemanticStaysEvidenceOnly(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("semantic-audit", "security_audit_only",
			semanticFinding(0.90, "semantic_instruction_override")),
	}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || len(pusher.pushedTypes) != 0 {
		t.Fatalf("passive pure semantic evidence must stay out of inbox, n=%d pushed=%v", n, pusher.pushedTypes)
	}
	if len(src.markedIDs) != 1 || src.markedIDs[0][0] != "semantic-audit" {
		t.Fatalf("semantic evidence must still be marked processed, got %v", src.markedIDs)
	}
}

func TestSecEventBridge_ConfirmedPureSemanticSurfaces(t *testing.T) {
	ev := secEventWithFindings("semantic-confirmed", "security_audit_only",
		map[string]any{
			"type":       "semantic_attack",
			"category":   "semantic_instruction_override",
			"confidence": 0.96,
			"severity":   "high",
			"triage": map[string]any{
				"verdict":      "confirmed_risk",
				"review_state": "confirmed_risk",
				"risk_level":   "high",
			},
		})
	ev.MatchedSummary["content_source"] = "verified_user_input"
	ev.MatchedSummary["review_state"] = "confirmed_risk"
	ev.MatchedSummary["effective_severity"] = "high"
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("confirmed pure semantic risk must surface, n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_OrdinaryAgentBehaviorStaysEvidenceOnly(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("agent-behavior", "security_audit",
			map[string]any{
				"type": "agent", "rule_type": "agent_detect", "category": "agent_openai_codex",
				"confidence": 1.0, "severity": "low", "counts_as_security_finding": true,
			},
			map[string]any{
				"type": "request_context", "rule_type": "agent_detect", "category": "agent_long_session",
				"confidence": 1.0, "severity": "medium", "counts_as_security_finding": true,
			}),
	}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || len(pusher.pushedTypes) != 0 {
		t.Fatalf("ordinary agent behavior must stay out of alerts, n=%d pushed=%v", n, pusher.pushedTypes)
	}
	if len(src.markedIDs) != 1 || src.markedIDs[0][0] != "agent-behavior" {
		t.Fatalf("agent behavior evidence must still be marked processed, got %v", src.markedIDs)
	}
}

func TestSecEventBridge_AgentBehaviorAlongsideSecurityFindingStillSurfaces(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("agent-plus-secret", "security_audit",
			map[string]any{
				"type": "agent", "rule_type": "agent_detect", "category": "agent_openai_codex",
				"confidence": 1.0, "severity": "low", "counts_as_security_finding": true,
			},
			map[string]any{
				"type": "secret", "rule_type": "data_leak", "category": "openai_key",
				"confidence": 0.99, "severity": "critical", "counts_as_security_finding": true,
			}),
	}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("security finding beside agent behavior must surface, n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_PassiveObservationOnlyStaysEvidenceOnly(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("bom-observation", "security_audit_only",
			map[string]any{
				"type": "prompt_stego", "category": "zero_width_char",
				"confidence": 0.2, "severity": "low",
				"counts_as_security_finding": false,
			}),
	}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || len(pusher.pushedTypes) != 0 {
		t.Fatalf("observation-only evidence must stay out of inbox, n=%d pushed=%v", n, pusher.pushedTypes)
	}
	if len(src.markedIDs) != 1 || src.markedIDs[0][0] != "bom-observation" {
		t.Fatalf("observation evidence must still be marked processed, got %v", src.markedIDs)
	}
}

func TestSecEventBridge_ObservationAlongsideRealFindingStillSurfaces(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("bom-plus-secret", "security_audit_only",
			map[string]any{
				"type": "prompt_stego", "category": "zero_width_char",
				"confidence": 0.2, "severity": "low",
				"counts_as_security_finding": false,
			},
			map[string]any{
				"type": "secret", "category": "openai_key",
				"confidence": 0.99, "severity": "critical",
				"counts_as_security_finding": true,
			}),
	}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("real finding beside observation must surface, n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_RedlineWinsOverIncorrectObservationFlag(t *testing.T) {
	ev := secEventWithFindings("redline-observation", "security_audit_only",
		map[string]any{
			"type": "secret", "category": "openai_key",
			"confidence": 0.99, "severity": "critical",
			"counts_as_security_finding": false,
		})
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakePusher{}
	bridge := gateBridge(src, pusher, &fakeNotifier{}, 0)

	n, err := bridge.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("redline must surface despite an incorrect observation flag, n=%d pushed=%v", n, pusher.pushedTypes)
	}
	if fields := bridge.computeLifecycleFields(ev); fields.dispositionClass != "action_required" {
		t.Fatalf("redline disposition=%q want action_required", fields.dispositionClass)
	}
}

func TestSecEventBridge_ObservationOnlyLifecycleIsInformational(t *testing.T) {
	ev := secEventWithFindings("bom-lifecycle", "security_audit_only",
		map[string]any{
			"type": "prompt_stego", "category": "zero_width_char",
			"confidence": 0.2, "severity": "low",
			"counts_as_security_finding": false,
		})
	ev.Severity = "high"

	fields := gateBridge(&fakeSecEventSource{}, &fakePusher{}, nil, 0).computeLifecycleFields(ev)
	if fields.dispositionClass != "informational" {
		t.Fatalf("observation-only disposition=%q want informational", fields.dispositionClass)
	}
}

func TestSecEventBridge_PureSemanticLifecycleIsInformational(t *testing.T) {
	ev := secEventWithFindings("semantic-lifecycle", "security_audit_only",
		semanticFinding(0.90, "semantic_instruction_override"))
	ev.Severity = "high"

	fields := gateBridge(&fakeSecEventSource{}, &fakePusher{}, nil, 0.5).computeLifecycleFields(ev)
	if fields.dispositionClass != "informational" {
		t.Fatalf("pure semantic audit disposition=%q want informational", fields.dispositionClass)
	}
}

func TestSecEventBridge_SemanticWithDeterministicLeakStillSurfaces(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("semantic-plus-secret", "security_audit_only",
			semanticFinding(0.90, "semantic_instruction_override"),
			map[string]any{"type": "secret", "category": "openai_key", "confidence": 0.99, "severity": "critical"}),
	}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("semantic plus deterministic leak must surface, n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_DeterministicTypeCannotHideBehindSemanticCategory(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("semantic-category-secret", "security_audit_only",
			map[string]any{"type": "secret", "category": "semantic_secret_exfiltration", "confidence": 0.99, "severity": "critical"}),
	}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("deterministic finding type must surface regardless of category, n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_EnforcementActionAlwaysSurfaces(t *testing.T) {
	// Low confidence, but the data plane actually blocked → must be auditable.
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("blk1", "block", finding(0.30)),
	}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("expected enforcement event surfaced despite low confidence, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_NoFindingsFailsOpen(t *testing.T) {
	// sampleSecEvent has matched_summary without findings → can't assess → surface.
	ev := sampleSecEvent("nf1")
	ev.ActionTaken = "audit"
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("expected fail-open surface when findings absent, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_DisabledGateSurfacesEverything(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("low2", "audit", finding(0.10)),
	}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("expected disabled gate (floor=0) to surface everything, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_MixedBatchPartialSuppress(t *testing.T) {
	// One noisy, one real, in the same batch: only the real one alerts, but BOTH
	// are marked processed in a single MarkAlerted call.
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("low3", "audit", finding(0.30)),
		secEventWithFindings("hi3", "audit", finding(0.90)),
	}}
	pusher := &fakePusher{}
	notifier := &fakeNotifier{}

	n, err := gateBridge(src, pusher, notifier, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 alerted in mixed batch, got %d", n)
	}
	if len(pusher.pushedTypes) != 1 {
		t.Fatalf("expected exactly 1 inbox push, got %v", pusher.pushedTypes)
	}
	if notifier.calls != 1 {
		t.Fatalf("expected 1 dispatch (only the surfaced event), got %d", notifier.calls)
	}
	if len(src.markedIDs) != 1 || len(src.markedIDs[0]) != 2 {
		t.Fatalf("expected both events marked alerted in one batch, got %v", src.markedIDs)
	}
}

func TestSecEventBridge_HighestFindingWins(t *testing.T) {
	// A real leak (0.90) mixed with noise (0.30) in the SAME event → surface.
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("mix1", "audit", finding(0.30), finding(0.90)),
	}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("expected event with one high-confidence finding surfaced, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_BaselineCategorySuppressedDespiteHighConfidence(t *testing.T) {
	// env_file at 0.85 is a real match but a configured baseline → suppress.
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("base1", "audit", findingCat(0.85, "env_file")),
	}}
	pusher := &fakePusher{}

	n, err := catBridge(src, pusher, &fakeNotifier{}, 0.5, "env_file").RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || len(pusher.pushedTypes) != 0 {
		t.Fatalf("expected baseline category suppressed, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
	if len(src.markedIDs) != 1 || src.markedIDs[0][0] != "base1" {
		t.Fatalf("expected base1 marked alerted, got %v", src.markedIDs)
	}
}

func TestSecEventBridge_RealLeakAlongsideBaselineStillSurfaces(t *testing.T) {
	// env_file (baseline) + a real password-in-code leak (0.90, not baselined).
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("base2", "audit",
			findingCat(0.85, "env_file"),
			findingCat(0.90, "code_leak_password_in_code")),
	}}
	pusher := &fakePusher{}

	n, err := catBridge(src, pusher, &fakeNotifier{}, 0.5, "env_file").RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("expected real leak alongside baseline to surface, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_NonBaselineHighConfidenceSurfaces(t *testing.T) {
	// Category list is set but this finding's category is not in it → surface.
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("nb1", "audit", findingCat(0.90, "aws_access_key")),
	}}
	pusher := &fakePusher{}

	n, err := catBridge(src, pusher, &fakeNotifier{}, 0.5, "env_file").RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("expected non-baseline high-confidence event surfaced, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_CategorySuppressWorksWithFloorDisabled(t *testing.T) {
	// floor=0 (confidence gate off) but category lever on → still suppresses baseline.
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("base3", "audit", findingCat(0.99, "openai_key")),
	}}
	pusher := &fakePusher{}

	n, err := catBridge(src, pusher, &fakeNotifier{}, 0, "openai_key").RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || len(pusher.pushedTypes) != 0 {
		t.Fatalf("expected category suppression with floor disabled, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

// srcBridge builds a bridge whose source-suppression lever
// (SECEVENT_INBOX_SUPPRESS_SOURCES) is set to the given sources, independent of
// the environment. It mirrors catBridge for the source dimension.
func srcBridge(src secEventSource, inbox secInboxPusher, notifier secNotifier, floor float64, sources ...string) *SecEventBridge {
	b := gateBridge(src, inbox, notifier, floor)
	b.suppressSources = map[string]bool{}
	for _, s := range sources {
		b.suppressSources[s] = true
	}
	return b
}

// secEventFromSource builds an audit event whose matched_summary carries a
// top-level "source" tag (e.g. "llm_safety_eval"), mirroring the live jsonb
// shape of offline-eval results that were mis-routed into the runtime inbox.
func secEventFromSource(id, action, source string, findings ...map[string]any) *repository.SecurityEvent {
	ev := secEventWithFindings(id, action, findings...)
	ev.MatchedSummary["source"] = source
	return ev
}

func TestSecEventBridge_SuppressedSourceRoutedOutOfInbox(t *testing.T) {
	// An offline-eval result (matched.source=llm_safety_eval), even at high
	// confidence, is not a runtime detection: it must stay in security_events but
	// NOT flood the actionable inbox. It must still be marked processed so it is
	// not re-scanned, and must not notify.
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventFromSource("eval1", "alert", "llm_safety_eval", finding(0.90)),
	}}
	pusher := &fakePusher{}
	notifier := &fakeNotifier{}

	n, err := srcBridge(src, pusher, notifier, 0.5, "llm_safety_eval").RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 alerted for suppressed-source event, got %d", n)
	}
	if len(pusher.pushedTypes) != 0 {
		t.Fatalf("expected no inbox push, got %v", pusher.pushedTypes)
	}
	if notifier.calls != 0 {
		t.Fatalf("expected no dispatch, got %d", notifier.calls)
	}
	if len(src.markedIDs) != 1 || src.markedIDs[0][0] != "eval1" {
		t.Fatalf("expected eval1 marked alerted (so it is not re-scanned), got %v", src.markedIDs)
	}
}
func TestSecEventBridge_UnlistedSourceSurfaces(t *testing.T) {
	// The lever names a different source; this event's source is not in it → a
	// real high-confidence finding must still surface (only listed sources are
	// baselined out).
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventFromSource("other1", "audit", "llm_safety_eval", finding(0.90)),
	}}
	pusher := &fakePusher{}

	n, err := srcBridge(src, pusher, &fakeNotifier{}, 0.5, "some_other_source").RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("expected unlisted-source event to surface, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_SuppressedSourceWithoutFindingsStillSuppressed(t *testing.T) {
	// 排序洞：eval 事件的 matched_summary 只有顶层 source、没有 findings 数组时，
	// findings fail-open 不得抢在整源抑制之前放行——source 在顶层可读，不依赖
	// 事件仍要标记 processed（不重扫）且不外发通知。
	ev := sampleSecEvent("evalnf1")
	ev.ActionTaken = "alert"
	ev.Severity = "high"
	ev.MatchedSummary = map[string]interface{}{"source": "llm_safety_eval"}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakePusher{}
	notifier := &fakeNotifier{}

	n, err := srcBridge(src, pusher, notifier, 0.5, "llm_safety_eval").RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 alerted for suppressed-source event without findings, got %d", n)
	}
	if len(pusher.pushedTypes) != 0 {
		t.Fatalf("expected no inbox push, got %v", pusher.pushedTypes)
	}
	if notifier.calls != 0 {
		t.Fatalf("expected no dispatch, got %d", notifier.calls)
	}
	if len(src.markedIDs) != 1 || src.markedIDs[0][0] != "evalnf1" {
		t.Fatalf("expected evalnf1 marked alerted (so it is not re-scanned), got %v", src.markedIDs)
	}
}

func TestSecEventBridge_SuppressedSourceEmptyFindingsStillSuppressed(t *testing.T) {
	// findings 键存在但为空数组：与「无 findings 键」同理，整源抑制照常成立。
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventFromSource("evalef1", "alert", "llm_safety_eval"),
	}}
	pusher := &fakePusher{}

	n, err := srcBridge(src, pusher, &fakeNotifier{}, 0.5, "llm_safety_eval").RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || len(pusher.pushedTypes) != 0 {
		t.Fatalf("expected suppression for empty-findings event, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_EnforcementBeatsSourceSuppression(t *testing.T) {
	// 数据面对流量做过动作（block）的事件即使 source 命中抑制名单也必须提升——
	// 真实发生的处置必须可审计，恒放行检查排在整源抑制之前。
	ev := sampleSecEvent("evalblk1")
	ev.ActionTaken = "block"
	ev.MatchedSummary = map[string]interface{}{"source": "llm_safety_eval"}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakePusher{}

	n, err := srcBridge(src, pusher, &fakeNotifier{}, 0.5, "llm_safety_eval").RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("expected enforcement event surfaced despite suppressed source, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestSecEventBridge_SourceSuppressWorksWithFloorDisabled(t *testing.T) {
	// floor=0 (confidence gate off) and no category lever, but the source lever is
	// on → the gate must NOT short-circuit to "surface everything"; the suppressed
	// source is still routed out of the inbox.
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventFromSource("eval3", "alert", "llm_safety_eval", finding(0.99)),
	}}
	pusher := &fakePusher{}

	n, err := srcBridge(src, pusher, &fakeNotifier{}, 0, "llm_safety_eval").RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || len(pusher.pushedTypes) != 0 {
		t.Fatalf("expected source suppression with floor disabled, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

func TestPipelineFailureTelemetryNeverSurfacesInActionableInbox(t *testing.T) {
	bridge := &SecEventBridge{minConfidence: defaultInboxMinConfidence}
	for _, action := range []string{"security_check_failed", "security_output_check_failed"} {
		event := &repository.SecurityEvent{
			ActionTaken: action,
			Severity:    "critical",
			MatchedSummary: map[string]any{
				"summary": "pipeline unavailable",
			},
		}
		surface, reason := bridge.shouldSurface(event)
		if surface || !strings.Contains(reason, "operational telemetry") {
			t.Fatalf("action=%s surface=%v reason=%q", action, surface, reason)
		}
	}
}
