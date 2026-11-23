package budget

import "testing"

func TestKeyBuilder(t *testing.T) {
	if BudgetKey("tenant", "tn1", "2026-05") != "budget:tenant:tn1:2026-05" {
		t.Errorf("BudgetKey: %s", BudgetKey("tenant", "tn1", "2026-05"))
	}
	if BudgetKeyDay("project", "pj1", "2026-05-29") != "budget:project:pj1:2026-05-29" {
		t.Errorf("BudgetKeyDay: %s", BudgetKeyDay("project", "pj1", "2026-05-29"))
	}
	if PauseKey("sk-abc12345") != "pause:sk-abc12345" {
		t.Errorf("PauseKey: %s", PauseKey("sk-abc12345"))
	}
}

// Golden vectors were captured from a real Valkey after gateway-core
// AtomicAdmission served chat requests (evidence ws7-evidence/7.1-7.2-before.txt).
// The control-plane reader must address exactly these keys; the old
// "rpm:<scope>:<id>" / "concurrency:<scope>:<id>" keys are never written.
func TestKeyBuilderMatchesGatewayAtomicAdmissionLayout(t *testing.T) {
	cases := []struct{ got, want string }{
		{RpmKey("tenant-a", "tenant", "tenant-a", 29844900), "orgquota:{80a707af7dc77ee1}:rpm:tenant:dGVuYW50LWE:29844900"},
		{RpmKey("tenant-a", "project", "project-a", 29844900), "orgquota:{80a707af7dc77ee1}:rpm:project:cHJvamVjdC1h:29844900"},
		{ConcurrencyKey("tenant-a", "tenant", "tenant-a"), "orgquota:{80a707af7dc77ee1}:concurrency:tenant:dGVuYW50LWE"},
		{ConcurrencyKey("tenant-a", "project", "project-a"), "orgquota:{80a707af7dc77ee1}:concurrency:project:cHJvamVjdC1h"},
		{QuotaPeriodBucket("America/New_York", "2026-09"), "2026-09@acb2a3287bc6"},
		{QuotaPeriodBucket("America/New_York", "2026-09-29"), "2026-09-29@acb2a3287bc6"},
		{QuotaPeriodBucket("Asia/Shanghai", "2026-09"), "2026-09"},
		{QuotaPeriodBucket("", "2026-09"), "2026-09"},
		{QuotaPeriodBucket("  ", "2026-09-29"), "2026-09-29"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("key layout drifted: got %q want %q", c.got, c.want)
		}
	}
}

func TestFormatMicrosCNYIsExact(t *testing.T) {
	cases := []struct {
		micros int64
		want   string
	}{
		{0, "0"},
		{1, "0.000001"},
		{3_234_567, "3.234567"},
		{50_000_000, "50"},
		{1_500_000, "1.5"},
		{-2_500_000, "-2.5"},
		{9007199254740991, "9007199254.740991"},
		{-9223372036854775808, "-9223372036854.775808"},
	}
	for _, c := range cases {
		if got := FormatMicrosCNY(c.micros); got != c.want {
			t.Errorf("FormatMicrosCNY(%d)=%q want %q", c.micros, got, c.want)
		}
	}
}
