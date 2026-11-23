package main

import "strings"

// A broken or partially configured identity runtime must never select CP-only
// credentials. An empty configuration supports an offline standalone account.
func localIdentityRuntimeConfigured(getenv func(string) string) bool {
	for _, name := range []string{"JJD_SSO_PUBLIC_URL", "JJD_IDENTITY_RUNTIME_URL", "JJD_IDENTITY_RUNTIME_ALLOWED_URLS", "JJD_IDENTITY_RUNTIME_CLIENT_ID", "JJD_IDENTITY_RUNTIME_CLIENT_SECRET"} {
		if strings.TrimSpace(getenv(name)) != "" {
			return true
		}
	}
	// The default false flag carries no runtime coordinates or credentials.
	return strings.TrimSpace(getenv("JJD_SSO_ALLOW_INSECURE_PUBLIC_URL")) != "" && !strings.EqualFold(strings.TrimSpace(getenv("JJD_SSO_ALLOW_INSECURE_PUBLIC_URL")), "false")
}
