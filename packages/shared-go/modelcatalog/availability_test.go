package modelcatalog

import (
	"strings"
	"testing"
)

// 能不能用只看管理员开关、渠道状态、凭据和上游是否下架；探测结果只影响建议。
func TestAvailabilityBlocksOnlyOnAdministrativeFacts(t *testing.T) {
	cases := []struct {
		model, provider string
		cred, present   bool
		proof           int
		health, want    string
	}{
		{"active", "active", true, true, 1, "unknown", "callable"},
		{"active", "active", true, false, 1, "healthy", "upstream_removed"},
		{"disabled", "active", true, true, 1, "healthy", "disabled"},
		{"pending", "active", true, true, 1, "healthy", "pending_admission"},
		{"active", "disabled", true, true, 1, "healthy", "provider_disabled"},
		{"active", "active", false, true, 1, "healthy", "credential_unavailable"},
		// 探测过期、未验证、健康异常都不拦截
		{"active", "active", true, true, 0, "healthy", "callable"},
		{"active", "active", true, true, 0, "unknown", "callable"},
		{"active", "active", true, true, 1, "unhealthy", "callable"},
	}
	for _, c := range cases {
		if got := State(c.model, c.provider, c.cred, c.present, c.proof, c.health); got != c.want {
			t.Fatalf("%+v got %s", c, got)
		}
	}
}

func TestAdviceExplainsProbeResultsWithoutBlocking(t *testing.T) {
	cases := []struct {
		proof                    int
		health                   string
		sawExpired, sawUnsupport bool
		want                     string
	}{
		{1, "healthy", false, false, ""},
		{1, "unknown", true, false, ""},
		{1, "unhealthy", false, false, "unhealthy"},
		{0, "unknown", true, false, "expired"},
		{0, "unknown", true, true, "expired"},
		{0, "unknown", false, true, "unsupported"},
		{0, "unknown", false, false, "unverified"},
		{0, "unhealthy", true, false, "unhealthy"},
	}
	for _, c := range cases {
		if got := Advice(c.proof, c.health, c.sawExpired, c.sawUnsupport); got != c.want {
			t.Fatalf("%+v got %q", c, got)
		}
	}
}

func TestCallablePredicateIgnoresProbeResults(t *testing.T) {
	for _, forbidden := range []string{"model_endpoint_capability_effective", "model_route_health_snapshots"} {
		if strings.Contains(CallablePredicate, forbidden) {
			t.Fatalf("CallablePredicate must not depend on %s", forbidden)
		}
	}
	for _, required := range []string{"p.status='active'", "m.status='active'", "provider_credentials", "NOT c.present"} {
		if !strings.Contains(CallablePredicate, required) {
			t.Fatalf("CallablePredicate lost administrative condition %s", required)
		}
	}
}
