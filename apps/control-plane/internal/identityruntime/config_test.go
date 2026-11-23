package identityruntime

import (
	"errors"
	"testing"
)

func TestLoadConfigBuildsFixedPublicEndpoints(t *testing.T) {
	cfg, err := LoadConfig(ConfigInput{
		PublicURL:    "https://sso.example.com/",
		RuntimeURL:   "http://chat-idp:8180/sso",
		ClientID:     "jjdguard-identity-orchestrator",
		ClientSecret: "runtime-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CallbackURL != "https://sso.example.com/sso/realms/jjdguard/broker/enterprise/endpoint" {
		t.Fatalf("callback=%q", cfg.CallbackURL)
	}
	if cfg.IssuerURL != "https://sso.example.com/sso/realms/jjdguard" {
		t.Fatalf("issuer=%q", cfg.IssuerURL)
	}
}
func TestLoadConfigAcceptsOnlyExactAllowlistedHTTPSRuntime(t *testing.T) {
	cfg, err := LoadConfig(ConfigInput{
		PublicURL: "https://sso.example.com", RuntimeURL: "https://jjdguard-keycloak:8443",
		AllowedRuntimeURLs: " , https://jjdguard-keycloak:8443, ",
		ClientID:           "svc", ClientSecret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RuntimeURL != "https://jjdguard-keycloak:8443" {
		t.Fatalf("runtime=%q", cfg.RuntimeURL)
	}
}

func TestLoadConfigRejectsUnsafeOrUnlistedAllowlistedRuntime(t *testing.T) {
	tests := []ConfigInput{
		{RuntimeURL: "https://jjdguard-keycloak:8443"},
		{RuntimeURL: "https://other-keycloak:8443", AllowedRuntimeURLs: "https://jjdguard-keycloak:8443"},
		{RuntimeURL: "https://user@jjdguard-keycloak:8443", AllowedRuntimeURLs: "https://user@jjdguard-keycloak:8443"},
		{RuntimeURL: "https://jjdguard-keycloak:8443?x=1", AllowedRuntimeURLs: "https://jjdguard-keycloak:8443?x=1"},
		{RuntimeURL: "https://jjdguard-keycloak:8443#fragment", AllowedRuntimeURLs: "https://jjdguard-keycloak:8443#fragment"},
		{RuntimeURL: "http://jjdguard-keycloak:8443", AllowedRuntimeURLs: "http://jjdguard-keycloak:8443"},
		{RuntimeURL: "https://127.0.0.1:8443", AllowedRuntimeURLs: "https://127.0.0.1:8443"},
		{RuntimeURL: "https://localhost:8443", AllowedRuntimeURLs: "https://localhost:8443"},
		{RuntimeURL: "https://keycloak.localhost:8443", AllowedRuntimeURLs: "https://keycloak.localhost:8443"},
		{RuntimeURL: "https://jjdguard-keycloak:8443/a/../b", AllowedRuntimeURLs: "https://jjdguard-keycloak:8443/a/../b"},
		{RuntimeURL: "https://jjdguard-keycloak:8443", AllowedRuntimeURLs: "https://jjdguard-keycloak:8443,http://unsafe:8080"},
	}
	for _, input := range tests {
		input.PublicURL, input.ClientID, input.ClientSecret = "https://sso.example.com", "svc", "secret"
		if _, err := LoadConfig(input); !errors.Is(err, ErrInvalidRuntimeTarget) {
			t.Fatalf("input=%+v error=%v", input, err)
		}
	}

}
func TestLoadConfigRejectsUnsafeRuntimeTargets(t *testing.T) {
	tests := []string{
		"https://chat-idp:8180/sso",
		"http://attacker.example.com:8180/sso",
		"http://chat-idp:8181/sso",
		"http://chat-idp:8180/",
		"http://user@chat-idp:8180/sso",
		"http://chat-idp:8180/sso?next=evil",
		"http://chat-idp:8180/sso#fragment",
	}
	for _, runtimeURL := range tests {
		t.Run(runtimeURL, func(t *testing.T) {
			_, err := LoadConfig(ConfigInput{
				PublicURL: "https://sso.example.com", RuntimeURL: runtimeURL,
				ClientID: "svc", ClientSecret: "secret",
			})
			if !errors.Is(err, ErrInvalidRuntimeTarget) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestLoadConfigRejectsUnsafePublicURL(t *testing.T) {
	tests := []string{
		"http://sso.example.com",
		"https://user@sso.example.com",
		"https://sso.example.com/base",
		"https://sso.example.com?next=evil",
		"https://sso.example.com#fragment",
	}
	for _, publicURL := range tests {
		t.Run(publicURL, func(t *testing.T) {
			_, err := LoadConfig(ConfigInput{
				PublicURL: publicURL, RuntimeURL: "http://chat-idp:8180/sso",
				ClientID: "svc", ClientSecret: "secret",
			})
			if !errors.Is(err, ErrInvalidPublicURL) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestLoadConfigAllowsExplicitHTTPTestURL(t *testing.T) {
	cfg, err := LoadConfig(ConfigInput{
		PublicURL: "http://127.0.0.1:18180", RuntimeURL: "http://chat-idp:8180/sso",
		ClientID: "svc", ClientSecret: "secret", AllowInsecurePublicURL: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IssuerURL != "http://127.0.0.1:18180/sso/realms/jjdguard" {
		t.Fatalf("issuer=%q", cfg.IssuerURL)
	}
}

func TestLoadConfigRequiresServiceCredentials(t *testing.T) {
	_, err := LoadConfig(ConfigInput{
		PublicURL: "https://sso.example.com", RuntimeURL: "http://chat-idp:8180/sso",
	})
	if !errors.Is(err, ErrRuntimeCredentialsRequired) {
		t.Fatalf("error=%v", err)
	}
}
