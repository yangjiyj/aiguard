package alert

import "testing"

func TestSecEventFPSuppressDays_DefaultThirty(t *testing.T) {
	t.Setenv("SECEVENT_FP_DISPOSITION_SUPPRESS_DAYS", "")
	if got := secEventFPSuppressDays(); got != 30 {
		t.Fatalf("default fp suppress days must be 30, got %d", got)
	}
}

func TestSecEventFPSuppressDays_ZeroDisables(t *testing.T) {
	t.Setenv("SECEVENT_FP_DISPOSITION_SUPPRESS_DAYS", "0")
	if got := secEventFPSuppressDays(); got != 0 {
		t.Fatalf("0 must disable the gate, got %d", got)
	}
}

func TestSecEventFPSuppressDays_MalformedFallsBack(t *testing.T) {
	t.Setenv("SECEVENT_FP_DISPOSITION_SUPPRESS_DAYS", "abc")
	if got := secEventFPSuppressDays(); got != 30 {
		t.Fatalf("malformed value must fall back to default 30, got %d", got)
	}
	t.Setenv("SECEVENT_FP_DISPOSITION_SUPPRESS_DAYS", "-3")
	if got := secEventFPSuppressDays(); got != 30 {
		t.Fatalf("negative value must fall back to default 30, got %d", got)
	}
}

func TestSecEventRuleDailyLimit_DefaultZeroOff(t *testing.T) {
	t.Setenv("SECEVENT_RULE_DAILY_LIMIT", "")
	if got := secEventRuleDailyLimit(); got != 0 {
		t.Fatalf("default rule daily limit must be 0 (off, no behaviour change), got %d", got)
	}
}

func TestSecEventRuleDailyLimit_ParsesValue(t *testing.T) {
	t.Setenv("SECEVENT_RULE_DAILY_LIMIT", "20")
	if got := secEventRuleDailyLimit(); got != 20 {
		t.Fatalf("expected 20, got %d", got)
	}
}

func TestSecEventRuleDailyLimit_MalformedFallsBackToOff(t *testing.T) {
	t.Setenv("SECEVENT_RULE_DAILY_LIMIT", "lots")
	if got := secEventRuleDailyLimit(); got != 0 {
		t.Fatalf("malformed value must fall back to 0 (off), got %d", got)
	}
}

func TestSecEventSecretNoveltyEnabled_DefaultOff(t *testing.T) {
	t.Setenv("SECEVENT_SECRET_NOVELTY_ENABLED", "")
	if secEventSecretNoveltyEnabled() {
		t.Fatal("secret novelty must default off (no behaviour change)")
	}
}

func TestSecEventSecretNoveltyEnabled_TrueTurnsOn(t *testing.T) {
	t.Setenv("SECEVENT_SECRET_NOVELTY_ENABLED", "true")
	if !secEventSecretNoveltyEnabled() {
		t.Fatal("SECEVENT_SECRET_NOVELTY_ENABLED=true must enable the gate")
	}
}
