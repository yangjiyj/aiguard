package main

import (
	"strings"
	"testing"
)

func TestLoadIdentityRuntimeMissingConfigIsNonFatal(t *testing.T) {
	runtime, publicConfig, err := loadIdentityRuntime(func(string) string { return "" })
	if err == nil || runtime != nil || publicConfig.CallbackURL != "" {
		t.Fatalf("missing runtime config must disable only SSO publication: runtime=%#v config=%#v err=%v",
			runtime, publicConfig, err)
	}
}

func TestLoadIdentityRuntimeBuildsOnlyPublicCallback(t *testing.T) {
	values := map[string]string{
		"JJD_SSO_PUBLIC_URL":                 "https://sso.example.com",
		"JJD_IDENTITY_RUNTIME_URL":           "http://chat-idp:8180/sso",
		"JJD_IDENTITY_RUNTIME_CLIENT_ID":     "control-plane",
		"JJD_IDENTITY_RUNTIME_CLIENT_SECRET": "runtime-secret",
		"JJD_SSO_ALLOW_INSECURE_PUBLIC_URL":  "false",
	}
	runtime, publicConfig, err := loadIdentityRuntime(func(key string) string { return values[key] })
	if err != nil || runtime == nil {
		t.Fatalf("load runtime: %#v %v", runtime, err)
	}
	if !strings.HasPrefix(publicConfig.CallbackURL, "https://sso.example.com/sso/") ||
		strings.Contains(publicConfig.CallbackURL, "chat-idp") {
		t.Fatalf("unexpected customer callback: %q", publicConfig.CallbackURL)
	}
}
func TestIdentityRuntimeConsumersUseDeploymentAllowlist(t *testing.T) {
	values := map[string]string{
		"JJD_SSO_PUBLIC_URL":                 "https://sso.example.com",
		"JJD_IDENTITY_RUNTIME_URL":           "https://jjdguard-keycloak:8443",
		"JJD_IDENTITY_RUNTIME_ALLOWED_URLS":  "https://jjdguard-keycloak:8443",
		"JJD_IDENTITY_RUNTIME_CLIENT_ID":     "control-plane",
		"JJD_IDENTITY_RUNTIME_CLIENT_SECRET": "runtime-secret",
		"JJD_SSO_ALLOW_INSECURE_PUBLIC_URL":  "false",
	}
	getenv := func(key string) string { return values[key] }
	runtime, _, err := loadIdentityRuntime(getenv)
	if err != nil || runtime == nil {
		t.Fatalf("load runtime: %#v %v", runtime, err)
	}
	client, _, err := loadLocalIdentityClient(getenv)
	if err != nil || client == nil {
		t.Fatalf("load local identity client: %#v %v", client, err)
	}
}

func TestLoadLocalIdentityClientMissingConfigFailsClosed(t *testing.T) {
	client, issuer, err := loadLocalIdentityClient(func(string) string { return "" })
	if err == nil || client != nil || issuer != "" {
		t.Fatalf("missing local identity config: client=%#v issuer=%q err=%v", client, issuer, err)
	}
}

func TestLoadLocalIdentityClientUsesFixedRuntimeAndPublicIssuer(t *testing.T) {
	values := map[string]string{
		"JJD_SSO_PUBLIC_URL":                 "https://sso.example.com",
		"JJD_IDENTITY_RUNTIME_URL":           "http://chat-idp:8180/sso",
		"JJD_IDENTITY_RUNTIME_CLIENT_ID":     "control-plane",
		"JJD_IDENTITY_RUNTIME_CLIENT_SECRET": "runtime-secret",
		"JJD_SSO_ALLOW_INSECURE_PUBLIC_URL":  "false",
	}
	client, issuer, err := loadLocalIdentityClient(func(key string) string { return values[key] })
	if err != nil || client == nil {
		t.Fatalf("load local identity client: client=%#v err=%v", client, err)
	}
	if issuer != "https://sso.example.com/sso/realms/jjdguard" {
		t.Fatalf("issuer=%q", issuer)
	}
	description := client.String()
	if !strings.Contains(description, "http://chat-idp:8180/sso") ||
		strings.Contains(description, "runtime-secret") {
		t.Fatalf("unsafe or uncontrolled client description: %s", description)
	}
}
