package agentguardmatch

const (
	ActionAllow   = "allow"
	ActionAudit   = "audit"
	ActionConfirm = "confirm"
	ActionBlock   = "block"
)

// Rule is the transport-neutral subset needed to evaluate an AgentGuard rule.
type Rule struct {
	ID      string
	Pattern string
	Action  string
	Enabled bool
}

// Evaluation identifies the strongest matching action and its stable winning rule.
type Evaluation struct {
	Matched bool
	RuleID  string
	Action  string
}

// Evaluate applies canonical action precedence while preserving the first winner on ties.
func Evaluate(rules []Rule, toolName, toolType string) Evaluation {
	bestRank := 0
	result := Evaluation{}
	for _, rule := range rules {
		if !rule.Enabled || !Matches(rule.Pattern, toolName, toolType) {
			continue
		}
		rank := actionRank(rule.Action)
		if rank == 0 || rank <= bestRank {
			continue
		}
		bestRank = rank
		result = Evaluation{
			Matched: true,
			RuleID:  rule.ID,
			Action:  rule.Action,
		}
	}
	return result
}

func actionRank(action string) int {
	switch action {
	case ActionAllow:
		return 1
	case ActionAudit:
		return 2
	case ActionConfirm:
		return 3
	case ActionBlock:
		return 4
	default:
		return 0
	}
}
