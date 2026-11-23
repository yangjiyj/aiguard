package modelaccess

import (
	"reflect"
	"testing"
	"time"
)

func TestResolveUserModelAccess(t *testing.T) {
	for _, tc := range []struct {
		name      string
		policy    Policy
		want      []string
		wantError bool
	}{
		{"inherit", Policy{Mode: "inherit"}, []string{"model-a", "model-b"}, false},
		{"per-user intersection", Policy{Mode: "allowlist", ModelNames: []string{"model-a", "model-c"}}, []string{"model-a"}, false},
		{"explicit empty denies all", Policy{Mode: "allowlist", ModelNames: []string{}}, []string{}, false},
		{"normalize duplicates", Policy{Mode: "allowlist", ModelNames: []string{" model-b ", "model-b"}}, []string{"model-b"}, false},
		{"invalid mode fails closed", Policy{Mode: "all"}, nil, true},
		{"inherit cannot hide a whitelist", Policy{Mode: "inherit", ModelNames: []string{"model-a"}}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve([]string{"model-b", "model-a", "model-a"}, tc.policy)
			if (err != nil) != tc.wantError || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%v err=%v want=%v", got, err, tc.want)
			}
		})
	}
}

func TestPersonalGrantNeverSurvivesDepartmentRemoval(t *testing.T) {
	got, err := Resolve(nil, Policy{Mode: "allowlist", ModelNames: []string{"model-a"}})
	if err != nil || len(got) != 0 {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestNormalizeRejectsInvalidModelNames(t *testing.T) {
	for _, name := range []string{"", "   ", "model\nforged", "model\x00forged"} {
		if _, err := Normalize(Policy{Mode: "allowlist", ModelNames: []string{name}}); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}

func TestFinalModelReferencesStayWithinPersonalCeiling(t *testing.T) {
	access := &Access{ChatAllowed: true, EffectiveModels: []string{"allowed"}, ModelReferences: map[string]string{"model-id-a": "allowed", "model-id-b": "forbidden"}}
	for _, tc := range []struct {
		ref  string
		want bool
	}{{"allowed", true}, {"model-id-a", true}, {"forbidden", false}, {"model-id-b", false}, {"unknown-alias", false}} {
		if got := access.AllowsReference(tc.ref); got != tc.want {
			t.Fatalf("%s: got=%v want=%v", tc.ref, got, tc.want)
		}
	}
}

func TestFinalModelReferencePrefersUnallowedNameOverAllowedID(t *testing.T) {
	access := &Access{ChatAllowed: true, EffectiveModels: []string{"allowed-A"}, KnownModelNames: []string{"allowed-A", "ref-a"}, ModelReferences: map[string]string{"ref-a": "allowed-A"}}
	if access.AllowsReference("ref-a") {
		t.Fatal("unallowed exact name must shadow an allowed model ID, matching routing resolution")
	}
}

func TestResolveExtrasSourcesExpiryAndStale(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	expired := now
	future := now.Add(time.Minute)
	revoked := now.Add(-time.Minute)
	grants := []ExtraGrant{
		{ID: "valid", Model: "extra", Reason: "业务需要", ExpiresAt: &future},
		{ID: "expired", Model: "expired", Reason: "到期", ExpiresAt: &expired},
		{ID: "revoked", Model: "revoked", Reason: "已撤销", RevokedAt: &revoked},
		{ID: "unavailable", Model: "disabled", Reason: "已停用"},
	}
	result, sources, stale, err := ResolveWithExtras([]string{"a", "b"}, Policy{Mode: Allowlist, ModelNames: []string{"a", "stale"}}, grants, []string{"a", "b", "extra", "expired", "revoked"}, now)
	if err != nil || !reflect.DeepEqual(result, []string{"a", "disabled", "extra"}) || sources["a"] != "personal_narrowed" || sources["extra"] != "personal_extra" || !reflect.DeepEqual(stale, []string{"stale"}) {
		t.Fatalf("result=%v sources=%v stale=%v err=%v", result, sources, stale, err)
	}
	inherit, source, _, err := ResolveWithExtras([]string{"a"}, Policy{Mode: Inherit}, nil, []string{"a"}, now)
	if err != nil || len(inherit) != 1 || source["a"] != "department" {
		t.Fatalf("inherit=%v source=%v err=%v", inherit, source, err)
	}
	blank, _, _, err := ResolveWithExtras([]string{"a"}, Policy{Mode: Allowlist}, grants, []string{"extra"}, now)
	if err != nil || !reflect.DeepEqual(blank, []string{"disabled", "extra"}) {
		t.Fatalf("blank base with extras=%v err=%v", blank, err)
	}
}

func TestExtraGrantRequiresReasonAndFutureExpiry(t *testing.T) {
	now := time.Now()
	for _, grant := range []ExtraGrant{{Model: "a"}, {Model: "a", Reason: "  "}, {Model: "a", Reason: "ok", ExpiresAt: &now}} {
		if _, err := NormalizeExtraGrant(grant, now); err == nil {
			t.Fatal("invalid grant accepted")
		}
	}
}

func TestReviewUnavailableRouteKeepsAuthorization(t *testing.T) {
	got, sources, _, err := ResolveWithExtras([]string{"base"}, Policy{Mode: Inherit}, []ExtraGrant{{Model: "extra", Reason: "approved"}}, nil, time.Now())
	if err != nil || !reflect.DeepEqual(got, []string{"base", "extra"}) || sources["base"] != SourceDepartment || sources["extra"] != SourcePersonalExtra {
		t.Fatalf("authorization lost: %v %v %v", got, sources, err)
	}
}
