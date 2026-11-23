package config

import (
	"testing"
	"time"
)

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

func TestLoadAPIRequestBodyLimitDefaultsTo200MiB(t *testing.T) {
	t.Setenv("GATEWAY_API_BODY_LIMIT_MB", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.APIRequestBodyLimitBytes != 200<<20 {
		t.Fatalf("APIRequestBodyLimitBytes=%d, want %d", cfg.APIRequestBodyLimitBytes, 200<<20)
	}
}

func TestLoadAPIRequestBodyLimitHonorsSafeOverride(t *testing.T) {
	t.Setenv("GATEWAY_API_BODY_LIMIT_MB", "128")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.APIRequestBodyLimitBytes != 128<<20 {
		t.Fatalf("APIRequestBodyLimitBytes=%d, want %d", cfg.APIRequestBodyLimitBytes, 128<<20)
	}
}

func TestLoadAPIRequestBodyLimitFallsBackFromUnsafeValues(t *testing.T) {
	for _, value := range []string{"0", "-1", "201", "invalid"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("GATEWAY_API_BODY_LIMIT_MB", value)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load returned error: %v", err)
			}
			if cfg.APIRequestBodyLimitBytes != 200<<20 {
				t.Fatalf("value=%q limit=%d, want %d", value, cfg.APIRequestBodyLimitBytes, 200<<20)
			}
		})
	}
}

func TestResolveBillingMode(t *testing.T) {
	tests := []struct {
		name, value, want string
		legacy            bool
	}{
		{name: "default off", want: BillingModeOff},
		{name: "legacy prepaid", legacy: true, want: BillingModePrepaid},
		{name: "metering", value: " METERING ", want: BillingModeMetering},
		{name: "explicit prepaid", value: BillingModePrepaid, want: BillingModePrepaid},
		{name: "explicit off wins", value: BillingModeOff, legacy: true, want: BillingModeOff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveBillingMode(tt.value, tt.legacy)
			if err != nil || got != tt.want {
				t.Fatalf("resolveBillingMode(%q,%v)=(%q,%v), want %q", tt.value, tt.legacy, got, err, tt.want)
			}
		})
	}
	if _, err := resolveBillingMode("charge-everything", false); err == nil {
		t.Fatal("invalid billing mode was accepted")
	}
}

func TestLoadNormalizesOutputSecurityMode(t *testing.T) {
	t.Setenv("GATEWAY_OUTPUT_SECURITY_MODE", " STRICT_BUFFERED ")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputSecurityMode != "strict_buffered" {
		t.Fatalf("OutputSecurityMode=%q, want strict_buffered", cfg.OutputSecurityMode)
	}
}

func TestLoadRejectsUnknownOutputSecurityMode(t *testing.T) {
	t.Setenv("GATEWAY_OUTPUT_SECURITY_MODE", "best_effort")
	if _, err := Load(); err == nil {
		t.Fatal("unknown output security mode was silently accepted")
	}
}

func TestLoadFailureModePolicies(t *testing.T) {
	t.Setenv("GUARDRAIL_FAILURE_MODE", "")
	t.Setenv("RETENTION_FAILURE_MODE", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GuardrailFailureMode != "auto" || cfg.RetentionFailureMode != "open" {
		t.Fatalf("failure modes guardrail=%q retention=%q", cfg.GuardrailFailureMode, cfg.RetentionFailureMode)
	}
	t.Setenv("RETENTION_FAILURE_MODE", "fail_close")
	cfg, err = Load()
	if err != nil || cfg.RetentionFailureMode != "close" {
		t.Fatalf("retention close cfg=%+v err=%v", cfg, err)
	}
	t.Setenv("GUARDRAIL_FAILURE_MODE", "unsafe")
	if _, err := Load(); err == nil {
		t.Fatal("invalid guardrail failure mode was accepted")
	}
}

func TestLoadInputSecurityRequestTimeout(t *testing.T) {
	t.Setenv("GATEWAY_INPUT_SECURITY_REQUEST_TIMEOUT", "")
	cfg, err := Load()
	if err != nil || cfg.InputSecurityRequestTimeout != 30*time.Second {
		t.Fatalf("default timeout=%v err=%v", cfg.InputSecurityRequestTimeout, err)
	}
	t.Setenv("GATEWAY_INPUT_SECURITY_REQUEST_TIMEOUT", "12s")
	cfg, err = Load()
	if err != nil || cfg.InputSecurityRequestTimeout != 12*time.Second {
		t.Fatalf("configured timeout=%v err=%v", cfg.InputSecurityRequestTimeout, err)
	}
	for _, invalid := range []string{"invalid", "0", "-1s"} {
		t.Setenv("GATEWAY_INPUT_SECURITY_REQUEST_TIMEOUT", invalid)
		cfg, err = Load()
		if err != nil || cfg.InputSecurityRequestTimeout != 30*time.Second {
			t.Fatalf("invalid %q timeout=%v err=%v", invalid, cfg.InputSecurityRequestTimeout, err)
		}
	}
}

func TestLoadOutputBufferBudgets(t *testing.T) {
	for _, key := range []string{"GATEWAY_OUTPUT_STREAM_HOLDBACK_BYTES", "GATEWAY_OUTPUT_STREAM_SCAN_BATCH_BYTES", "GATEWAY_OUTPUT_STREAM_PENDING_BYTES", "GATEWAY_OUTPUT_STRICT_MAX_BYTES"} {
		t.Setenv(key, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputStreamHoldbackBytes != 256 || cfg.OutputStreamScanBatchBytes != 1024 || cfg.OutputStreamPendingBytes != 4<<20 || cfg.OutputStrictMaxBytes != 4<<20 {
		t.Fatalf("unexpected output defaults: %+v", cfg)
	}
	t.Setenv("GATEWAY_OUTPUT_STREAM_HOLDBACK_BYTES", "512")
	t.Setenv("GATEWAY_OUTPUT_STREAM_SCAN_BATCH_BYTES", "4096")
	t.Setenv("GATEWAY_OUTPUT_STREAM_PENDING_BYTES", "8388608")
	t.Setenv("GATEWAY_OUTPUT_STRICT_MAX_BYTES", "1048576")
	cfg, err = Load()
	if err != nil || cfg.OutputStreamHoldbackBytes != 512 || cfg.OutputStreamScanBatchBytes != 4096 || cfg.OutputStreamPendingBytes != 8<<20 || cfg.OutputStrictMaxBytes != 1<<20 {
		t.Fatalf("budgets ignored: cfg=%+v err=%v", cfg, err)
	}
}
func TestLoadRejectsUnsafeOutputBufferBudgets(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"GATEWAY_OUTPUT_STREAM_HOLDBACK_BYTES", "0"},
		{"GATEWAY_OUTPUT_STREAM_HOLDBACK_BYTES", "16385"},
		{"GATEWAY_OUTPUT_STREAM_SCAN_BATCH_BYTES", "3"},
		{"GATEWAY_OUTPUT_STREAM_SCAN_BATCH_BYTES", "49153"},
		{"GATEWAY_OUTPUT_STREAM_PENDING_BYTES", "invalid"},
		{"GATEWAY_OUTPUT_STRICT_MAX_BYTES", "1073741824"},
	} {
		t.Run(tc.key+"_"+tc.value, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			if _, err := Load(); err == nil {
				t.Fatal("unsafe output budget accepted")
			}
		})
	}
}

func TestLoadProductProfileAndBrand(t *testing.T) {
	t.Setenv("PRODUCT_PROFILE", "")
	t.Setenv("PRODUCT_NAME", "")
	t.Setenv("PRODUCT_VERSION", "")
	t.Setenv("JJD_VERSION", "2.6.10")
	t.Setenv("AGENT_ENDPOINT_ENABLED", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProductProfile != "gateway" || cfg.ProductName != "JJDGuard" || cfg.ProductVersion != "2.6.10" || cfg.AgentEndpointEnabled {
		t.Fatalf("unexpected gateway defaults: %+v", cfg)
	}
	t.Setenv("PRODUCT_NAME", "伪造品牌")
	t.Setenv("PRODUCT_VERSION", "999.0.0")
	cfg, err = Load()
	if err != nil || cfg.ProductName != "JJDGuard" || cfg.ProductVersion != "2.6.10" {
		t.Fatalf("gateway must ignore product overrides: cfg=%+v err=%v", cfg, err)
	}
	t.Setenv("PRODUCT_NAME", "")
	t.Setenv("PRODUCT_VERSION", "")
	t.Setenv("PRODUCT_PROFILE", "agent-platform")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProductProfile != "agent-platform" || !cfg.AgentEndpointEnabled {
		t.Fatalf("unexpected platform defaults: %+v", cfg)
	}
	if cfg.ProductName != "JJDGuard Agent Platform" || cfg.ProductVersion != "1.0.0" {
		t.Fatalf("unexpected platform placeholder: %+v", cfg)
	}
	t.Setenv("AGENT_ENDPOINT_ENABLED", "false")
	t.Setenv("PRODUCT_NAME", "客户品牌")
	t.Setenv("PRODUCT_VERSION", "3.1.4")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProductName != "客户品牌" || cfg.ProductVersion != "3.1.4" || cfg.AgentEndpointEnabled {
		t.Fatalf("explicit overrides ignored: %+v", cfg)
	}
	t.Setenv("AGENT_ENDPOINT_ENABLED", "true")
	cfg, err = Load()
	if err != nil || !cfg.AgentEndpointEnabled {
		t.Fatalf("explicit true ignored: cfg=%+v err=%v", cfg, err)
	}
}

func TestLoadRejectsInvalidProductProfile(t *testing.T) {
	for _, value := range []string{"Gateway", " gateway ", "agent_platform", "unknown"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("PRODUCT_PROFILE", value)
			if _, err := Load(); err == nil {
				t.Fatalf("invalid PRODUCT_PROFILE %q accepted", value)
			}
		})
	}
}
