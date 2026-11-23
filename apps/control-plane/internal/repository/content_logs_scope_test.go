package repository

import "testing"

func TestResolveContentLogEnvironmentScope(t *testing.T) {
	tests := []struct {
		name, explicit, deployment, want string
	}{
		{name: "deployment wins", explicit: "home", deployment: "customer", want: "customer"},
		{name: "deployment fallback", deployment: "customer", want: "customer"},
		{name: "invalid explicit is contained", explicit: "from-header", deployment: "customer", want: "customer"},
		{name: "explicit without boundary", explicit: "home", deployment: "legacy-unclassified", want: "home"},
		{name: "blank defaults legacy", want: "legacy-unclassified"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveContentLogEnvironmentScope(tt.explicit, tt.deployment); got != tt.want {
				t.Fatalf("resolveContentLogEnvironmentScope(%q,%q)=%q, want %q", tt.explicit, tt.deployment, got, tt.want)
			}
		})
	}
}
