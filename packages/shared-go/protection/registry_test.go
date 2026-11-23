package protection

import "testing"

func TestEveryItemHasValidDefaultAndUniqueReasons(t *testing.T) {
	seenKeys := map[string]bool{}
	seenReasons := map[string]string{}
	for _, item := range All() {
		if seenKeys[item.Key] {
			t.Fatalf("duplicate key %s", item.Key)
		}
		seenKeys[item.Key] = true
		if !item.Allows(item.Default) {
			t.Fatalf("%s default %s not in actions %v", item.Key, item.Default, item.Actions)
		}
		for _, reason := range item.Reasons {
			if owner, ok := seenReasons[reason]; ok {
				t.Fatalf("reason %s owned by %s and %s", reason, owner, item.Key)
			}
			seenReasons[reason] = item.Key
		}
	}
}

func TestDefaultsAreAlertAllow(t *testing.T) {
	for _, item := range All() {
		if item.Key == KeyRestrictedFile {
			continue
		}
		if item.Default != ActionAlertAllow {
			t.Fatalf("%s default = %s, want alert_allow (设计 D2)", item.Key, item.Default)
		}
	}
}

func TestItemForReason(t *testing.T) {
	item, ok := ItemForReason("blocked_ssh_private_key_path")
	if !ok || item.Key != "agent.ssh_private_key" {
		t.Fatalf("got %+v %v", item, ok)
	}
	if _, ok := ItemForReason("command_no_risk"); ok {
		t.Fatal("unregistered reason must not resolve")
	}
}

func TestSettingsActionForFallsBackToDefault(t *testing.T) {
	var s Settings
	if got := s.ActionFor("agent.ssh_private_key"); got != ActionAlertAllow {
		t.Fatalf("nil settings: %s", got)
	}
	s = Settings{"agent.ssh_private_key": {Action: ActionBlock}}
	if got := s.ActionFor("agent.ssh_private_key"); got != ActionBlock {
		t.Fatalf("configured: %s", got)
	}
	s = Settings{"agent.ssh_private_key": {Action: "nonsense"}}
	if got := s.ActionFor("agent.ssh_private_key"); got != ActionAlertAllow {
		t.Fatalf("invalid stored action must fall back to default: %s", got)
	}
}

func TestNormalizeRejectsUnknownKeyAndDisallowedAction(t *testing.T) {
	if _, err := Normalize(map[string]Setting{"agent.nope": {Action: ActionBlock}}); err == nil {
		t.Fatal("unknown key accepted")
	}
	if _, err := Normalize(map[string]Setting{"agent.confirm_without_channel": {Action: ActionConfirm}}); err == nil {
		t.Fatal("confirm not allowed for confirm_without_channel")
	}
	if _, err := Normalize(map[string]Setting{"agent.tool_failure_loop": {Action: ActionBlock, Params: map[string]any{"threshold": 0}}}); err == nil {
		t.Fatal("threshold 0 accepted")
	}
}

func TestIntParamDefaultAndOverride(t *testing.T) {
	var s Settings
	if got := s.IntParam("agent.tool_failure_loop", "threshold"); got != 5 {
		t.Fatalf("default threshold %d", got)
	}
	s = Settings{"agent.tool_failure_loop": {Action: ActionAlertAllow, Params: map[string]any{"threshold": float64(8)}}}
	if got := s.IntParam("agent.tool_failure_loop", "threshold"); got != 8 {
		t.Fatalf("override threshold %d", got)
	}
}
