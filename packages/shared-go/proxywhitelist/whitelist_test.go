package proxywhitelist

import "testing"

func TestMatchTenantDomainAndPort(t *testing.T) {
	rules := []Rule{{HostPattern: "*.openai.com", Port: 443, TenantID: "tenant_default"}, {HostPattern: "foreign.example", Port: 443, TenantID: "foreign"}}
	for _, tc := range []struct {
		host    string
		port    int
		allowed bool
	}{
		{"API.OPENAI.COM.", 443, true}, {"openai.com", 443, true}, {"evilopenai.com", 443, false}, {"api.openai.com", 80, false}, {"foreign.example", 443, false},
	} {
		matched, count := Match(rules, "", tc.host, tc.port)
		if (matched != nil) != tc.allowed || count != 1 {
			t.Errorf("%+v matched=%v count=%d", tc, matched, count)
		}
	}
	if host, port := Target("[2001:db8::1]:8443", 443); host != "2001:db8::1" || port != 8443 {
		t.Fatalf("host=%s port=%d", host, port)
	}
	for _, port := range []int{0, -1, 65536} {
		if Matches(Rule{HostPattern: "api.openai.com", Port: port}, "api.openai.com", 443) {
			t.Fatalf("invalid rule port %d must not authorize traffic", port)
		}
	}
}
