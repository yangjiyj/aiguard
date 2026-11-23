package alertconfig

import (
	"testing"
	"time"
)

func TestTimingBounds(t *testing.T) {
	for _, c := range []struct {
		value string
		want  time.Duration
	}{{"", 900 * time.Second}, {"60", 60 * time.Second}, {"86400", 86400 * time.Second}, {"59", 900 * time.Second}, {"oops", 900 * time.Second}, {"86401", 900 * time.Second}} {
		t.Setenv("SECEVENT_REVIEW_PENDING_TIMEOUT_SECONDS", c.value)
		if got := ReviewPendingTimeout(); got != c.want {
			t.Errorf("%q=%v want %v", c.value, got, c.want)
		}
	}
	t.Setenv("SECEVENT_BRIDGE_INTERVAL_SECONDS", "")
	if BridgeInterval() != 10*time.Second {
		t.Fatal("default interval")
	}
	t.Setenv("SECEVENT_BRIDGE_INTERVAL_SECONDS", "1")
	if BridgeInterval() != time.Second {
		t.Fatal("configured interval")
	}
}
