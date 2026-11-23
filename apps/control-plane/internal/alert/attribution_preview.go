package alert

import "github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"

// AttributionPreview is a metadata-only dry-run result. It deliberately omits
// matched findings, evidence, request content and any writable database handle.
type AttributionPreview struct {
	EventID          string `json:"event_id"`
	PreviousRuleName string `json:"previous_rule_name"`
	RuleName         string `json:"rule_name"`
	RuleID           string `json:"rule_id"`
	RuleType         string `json:"rule_type"`
	PreviousSeverity string `json:"previous_severity"`
	Severity         string `json:"severity"`
	Category         string `json:"category"`
	DisplayLabel     string `json:"display_label"`
	NotificationKind string `json:"notification_kind"`
	Changed          bool   `json:"changed"`
}

// PreviewAlertBodyAttribution shares the live bridge's dominant-finding logic.
// Input is one existing alert_groups/alert_inbox body_json object; it is never
// mutated. This is a preview, not authorization to rewrite historical facts.
func PreviewAlertBodyAttribution(body map[string]any) AttributionPreview {
	value := func(key string) string { result, _ := body[key].(string); return result }
	matched, _ := body["matched"].(map[string]any)
	ev := &repository.SecurityEvent{ID: value("event_id"), EventType: value("event_type"), RuleName: value("rule_name"), RuleType: value("rule_type"), Severity: value("severity"), ActionTaken: value("action"), MatchedSummary: matched}
	if authored := value("authored_severity"); authored != "" {
		ev.Severity = authored
	}
	proposed := attributedEvent(ev)
	ruleID, _ := dominantFinding(proposed)["rule_id"].(string)
	result := AttributionPreview{EventID: ev.ID, PreviousRuleName: ev.RuleName, RuleName: proposed.RuleName, RuleID: ruleID, RuleType: proposed.RuleType, PreviousSeverity: value("severity"), Severity: effectiveSeverityForEvent(proposed), Category: dominantCategory(proposed), DisplayLabel: eventDisplayLabelCN(proposed), NotificationKind: alertTypeForSecurityEvent(proposed)}
	result.Changed = result.PreviousRuleName != result.RuleName || ev.RuleType != result.RuleType || result.PreviousSeverity != result.Severity
	if category := value("category"); category != "" && category != result.Category {
		result.Changed = true
	}
	return result
}
