package main

import "testing"

func TestLocalIdentityRuntimePartialConfigurationNeverFallsBack(t *testing.T) {
	for _, name := range []string{"JJD_SSO_PUBLIC_URL", "JJD_IDENTITY_RUNTIME_URL", "JJD_IDENTITY_RUNTIME_ALLOWED_URLS", "JJD_IDENTITY_RUNTIME_CLIENT_ID", "JJD_IDENTITY_RUNTIME_CLIENT_SECRET", "JJD_SSO_ALLOW_INSECURE_PUBLIC_URL"} {
		t.Run(name, func(t *testing.T) {
			env := map[string]string{name: "configured"}
			if !localIdentityRuntimeConfigured(func(key string) string { return env[key] }) {
				t.Fatal("partial identity runtime selected standalone mode")
			}
		})
	}
}
func TestLocalIdentityRuntimeEmptyAndDefaultFalseAllowsStandalone(t *testing.T) {
	for _, value := range []string{"", "false", " FALSE ", "  "} {
		env := map[string]string{"JJD_SSO_ALLOW_INSECURE_PUBLIC_URL": value}
		if localIdentityRuntimeConfigured(func(key string) string { return env[key] }) {
			t.Fatalf("empty/default config rejected standalone mode: %q", value)
		}
	}
}
