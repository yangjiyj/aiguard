package repository

import "testing"

func TestSecEventInboxSeverities_DefaultsToHighCritical(t *testing.T) {
	t.Setenv("SECEVENT_INBOX_MIN_SEVERITY", "")
	got := secEventInboxSeverities()
	if len(got) != 2 || got[0] != "high" || got[1] != "critical" {
		t.Fatalf("default floor must be high/critical (zero regression), got %v", got)
	}
}

func TestSecEventInboxSeverities_MediumFloorIncludesMediumAndUp(t *testing.T) {
	t.Setenv("SECEVENT_INBOX_MIN_SEVERITY", "medium")
	got := secEventInboxSeverities()
	want := map[string]bool{"medium": true, "high": true, "critical": true}
	if len(got) != 3 {
		t.Fatalf("medium floor must surface medium/high/critical, got %v", got)
	}
	for _, s := range got {
		if !want[s] {
			t.Fatalf("unexpected severity %q in %v", s, got)
		}
	}
}

func TestSecEventInboxSeverities_UnknownFallsBackToDefault(t *testing.T) {
	t.Setenv("SECEVENT_INBOX_MIN_SEVERITY", "bogus")
	got := secEventInboxSeverities()
	if len(got) != 2 || got[0] != "high" || got[1] != "critical" {
		t.Fatalf("unknown floor must fall back to high/critical, got %v", got)
	}
}
