package identity

import "testing"

func withEgressSettings(t *testing.T, values map[string]string) {
	t.Helper()
	SetEgressSettingsSource(func() map[string]string { return values })
	t.Cleanup(func() { SetEgressSettingsSource(nil) })
}

func TestSSRFGuardConsoleSettingsBeatEnvironmentOnlyWhenStored(t *testing.T) {
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "10.0.0.0/8")
	// 库里没有键：环境变量作初值（与 2.9.21 一致）。
	withEgressSettings(t, map[string]string{})
	if !HTTPEndpointsExplicitlyAllowed("http://10.1.2.3/token") {
		t.Fatal("without a stored key the env CIDR applies")
	}
	// 库里存了名单：用库里的。
	withEgressSettings(t, map[string]string{"idp_allowed_cidrs": `["192.168.0.0/16"]`})
	if HTTPEndpointsExplicitlyAllowed("http://10.1.2.3/token") {
		t.Fatal("stored list must replace the env list")
	}
	if !HTTPEndpointsExplicitlyAllowed("http://192.168.1.5/token") {
		t.Fatal("stored CIDR must be honoured")
	}
	// 回环照旧拒绝。
	withEgressSettings(t, map[string]string{"idp_allowed_cidrs": `["127.0.0.0/8"]`})
	if HTTPEndpointsExplicitlyAllowed("http://127.0.0.1/token") {
		t.Fatal("loopback stays blocked")
	}
}

func TestSSRFGuardBlockPrivateReadsConsoleSetting(t *testing.T) {
	t.Setenv("JJD_IDP_BLOCK_PRIVATE", "true")
	withEgressSettings(t, map[string]string{"idp_block_private": "false"})
	if NewSSRFGuard().blockPrivate {
		t.Fatal("stored false must beat env true")
	}
	withEgressSettings(t, map[string]string{})
	if !NewSSRFGuard().blockPrivate {
		t.Fatal("without a stored key the env value applies")
	}
}
