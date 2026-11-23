package repository

import "testing"

func TestNormalizeAndParseSecurityPolicySubjectBinding(t *testing.T) {
	binding, err := NormalizeSecurityPolicySubjectBinding(&SecurityPolicySubjectBinding{
		TenantIDs: []string{"tenant-a", "tenant-a"}, ProjectIDs: []string{"app-b", "app-a"},
		Protocols: []string{" OpenAI "},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(binding.TenantIDs) != 1 || binding.ProjectIDs[0] != "app-a" || binding.Protocols[0] != "openai" {
		t.Fatalf("binding not canonical: %+v", binding)
	}
	parsed, ok := ParseSecurityPolicySubjectBinding([]byte(`{"scene":"data_leak","subject_binding":{"tenant_ids":["tenant-a"],"key_ids":["key-a"]}}`))
	if !ok || parsed == nil || parsed.KeyIDs[0] != "key-a" {
		t.Fatalf("binding not parsed: %+v ok=%v", parsed, ok)
	}
	if _, ok := ParseSecurityPolicySubjectBinding([]byte(`{"subject_binding":{"tenant_ids":["tenant-a"],"unexpected":["x"]}}`)); ok {
		t.Fatal("unknown binding field was accepted")
	}
}

func TestScopeWithSubjectBindingSupportsExplicitClear(t *testing.T) {
	bound, err := scopeWithSubjectBinding([]byte(`{"scene":"data_leak"}`), &SecurityPolicySubjectBinding{KeyIDs: []string{"key-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if parsed, ok := ParseSecurityPolicySubjectBinding(bound); !ok || parsed == nil {
		t.Fatalf("binding not persisted: %s", bound)
	}
	cleared, err := scopeWithSubjectBinding(bound, nil)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, ok := ParseSecurityPolicySubjectBinding(cleared); !ok || parsed != nil {
		t.Fatalf("binding not explicitly cleared: %s", cleared)
	}
}
