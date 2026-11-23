package handler

import (
	"os"
	"regexp"
	"testing"
)

func TestNormalizeTeamMemberRoleSupportsLegacyAdmin(t *testing.T) {
	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{input: "", want: "member", ok: true},
		{input: "admin", want: "owner", ok: true},
		{input: "owner", want: "owner", ok: true},
		{input: "member", want: "member", ok: true},
		{input: "viewer", want: "viewer", ok: true},
		{input: "root", ok: false},
	}
	for _, test := range tests {
		got, err := normalizeTeamMemberRole(test.input)
		if test.ok && (err != nil || got != test.want) {
			t.Errorf("normalize role %q = %q, %v; want %q", test.input, got, err, test.want)
		}
		if !test.ok && err == nil {
			t.Errorf("normalize role %q unexpectedly succeeded as %q", test.input, got)
		}
	}
}

func TestProductionHandlersDoNotMutateDepartmentThroughTeamMemberRepository(t *testing.T) {
	forbidden := regexp.MustCompile(`TeamMemberRepo\.(?:Add|BatchAdd|Remove)\s*\(`)
	for _, filename := range []string{
		"org_handler.go",
		"iam_handler.go",
		"portal_integration.go",
	} {
		body, err := os.ReadFile(filename)
		if err != nil {
			t.Fatalf("read %s: %v", filename, err)
		}
		if match := forbidden.Find(body); match != nil {
			t.Errorf("%s bypasses IdentityBindingService through %q", filename, match)
		}
	}
}

func TestPortalIdentityBindingActorIsControlledMachineIdentity(t *testing.T) {
	if portalIdentityBindingActor == "" || portalIdentityBindingActor == "admin" {
		t.Fatalf("portal actor must be a controlled machine identity, got %q", portalIdentityBindingActor)
	}
}
