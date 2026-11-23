package logretention

import "testing"

func TestResolveClampsToFloor(t *testing.T) {
	cases := map[string]int{"120": 120, " 30 ": 30, "1": MinDays, "29": MinDays, "0": DefaultDays, "-1": DefaultDays, "abc": DefaultDays, "": DefaultDays, "3651": MaxDays, "3650": 3650}
	for raw, want := range cases {
		if got := Resolve(raw); got != want {
			t.Fatalf("Resolve(%q)=%d want %d", raw, got, want)
		}
	}
}

func TestValidateRejectsBelowFloorWithChineseError(t *testing.T) {
	for _, raw := range []string{"1", "29", "0", "abc", "3651"} {
		if _, err := Validate(raw); err != ErrOutOfRange {
			t.Fatalf("Validate(%q) err=%v", raw, err)
		}
	}
	if days, err := Validate("30"); err != nil || days != 30 {
		t.Fatalf("Validate(30)=%d %v", days, err)
	}
	if ErrOutOfRange.Error() == "" || ErrOutOfRange.Error()[0] < 0x80 {
		t.Fatal("error must be Chinese")
	}
}
