package config

import "testing"

func TestLoadNormalizesDeploymentEnvironmentScope(t *testing.T) {
	t.Setenv("GATEWAY_ENVIRONMENT_SCOPE", " CUSTOMER ")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EnvironmentScope != "customer" {
		t.Fatalf("EnvironmentScope = %q, want customer", cfg.EnvironmentScope)
	}
}

func TestLoadRejectsUntrustedDeploymentEnvironmentScope(t *testing.T) {
	for _, value := range []string{"", "customer-from-header"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("GATEWAY_ENVIRONMENT_SCOPE", value)
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.EnvironmentScope != "legacy-unclassified" {
				t.Fatalf("EnvironmentScope = %q, want legacy-unclassified", cfg.EnvironmentScope)
			}
		})
	}
}

func TestLoadReadsRetentionStorePath(t *testing.T) {
	t.Setenv("RETENTION_STORE_PATH", "/var/lib/jjdguard/retention")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.RetentionStorePath != "/var/lib/jjdguard/retention" {
		t.Fatalf("RetentionStorePath = %q", cfg.RetentionStorePath)
	}
}

func TestLoadInternalAPISecretIgnoresNewAPILegacyVariables(t *testing.T) {
	t.Setenv("JJD_INTERNAL_API_SECRET", "")
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "")
	t.Setenv("NEWAPI_INTERNAL_API_SECRET", "legacy-internal-canary")
	t.Setenv("NEWAPI_PROVIDER_SECRET_KEY", "legacy-provider-canary")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.InternalAPISecret != "" {
		t.Fatalf("InternalAPISecret must ignore NEWAPI_* variables, got %q", cfg.InternalAPISecret)
	}
}

func TestLoadInternalAPISecretUsesJJDInternalFirst(t *testing.T) {
	t.Setenv("JJD_INTERNAL_API_SECRET", "jjd-internal")
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "jjd-provider")
	t.Setenv("NEWAPI_INTERNAL_API_SECRET", "legacy-internal")
	t.Setenv("NEWAPI_PROVIDER_SECRET_KEY", "legacy-provider")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.InternalAPISecret != "jjd-internal" {
		t.Fatalf("InternalAPISecret = %q, want JJD internal value", cfg.InternalAPISecret)
	}
}

func TestLoadInternalAPISecretFallsBackToJJDProvider(t *testing.T) {
	t.Setenv("JJD_INTERNAL_API_SECRET", "")
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "jjd-provider")
	t.Setenv("NEWAPI_INTERNAL_API_SECRET", "legacy-internal")
	t.Setenv("NEWAPI_PROVIDER_SECRET_KEY", "legacy-provider")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.InternalAPISecret != "jjd-provider" {
		t.Fatalf("InternalAPISecret = %q, want JJD provider fallback", cfg.InternalAPISecret)
	}
}

func TestLoadInternalAPISecretDoesNotUseNewAPIProviderWhenJJDInternalIsBlank(t *testing.T) {
	t.Setenv("JJD_INTERNAL_API_SECRET", "")
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "")
	t.Setenv("NEWAPI_PROVIDER_SECRET_KEY", "legacy-provider-canary")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.InternalAPISecret != "" {
		t.Fatalf("InternalAPISecret leaked legacy provider value: %q", cfg.InternalAPISecret)
	}
}
