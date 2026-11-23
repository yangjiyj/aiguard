package directoryruntime

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigAcceptsOnlyInternalKeycloakRuntime(t *testing.T) {
	config, err := LoadConfig(ConfigInput{
		RuntimeURL:   "http://chat-idp:8180/sso",
		ClientID:     "jjdguard-directory-orchestrator",
		ClientSecret: "directory-runtime-secret",
	})
	require.NoError(t, err)
	require.Equal(t, "http://chat-idp:8180/sso", config.RuntimeURL)
	require.NotContains(t, config.String(), "directory-runtime-secret")
}

func TestLoadConfigAcceptsDeploymentAllowlistedHTTPSRuntime(t *testing.T) {
	config, err := LoadConfig(ConfigInput{
		RuntimeURL:         "https://jjdguard-keycloak:8443",
		AllowedRuntimeURLs: " , https://jjdguard-keycloak:8443, ",
		ClientID:           "jjdguard-directory-orchestrator",
		ClientSecret:       "directory-runtime-secret",
	})
	require.NoError(t, err)
	require.Equal(t, "https://jjdguard-keycloak:8443", config.RuntimeURL)
}

func TestLoadConfigRejectsUnsafeOrUnlistedDeploymentRuntime(t *testing.T) {
	for _, input := range []ConfigInput{
		{RuntimeURL: "https://jjdguard-keycloak:8443", ClientID: "client", ClientSecret: "secret"},
		{RuntimeURL: "https://other-keycloak:8443", AllowedRuntimeURLs: "https://jjdguard-keycloak:8443", ClientID: "client", ClientSecret: "secret"},
		{RuntimeURL: "https://jjdguard-keycloak:8443", AllowedRuntimeURLs: "https://jjdguard-keycloak:8443,http://unsafe-keycloak:8080", ClientID: "client", ClientSecret: "secret"},
		{RuntimeURL: "https://user@jjdguard-keycloak:8443", AllowedRuntimeURLs: "https://user@jjdguard-keycloak:8443", ClientID: "client", ClientSecret: "secret"},
		{RuntimeURL: "https://jjdguard-keycloak:8443?x=1", AllowedRuntimeURLs: "https://jjdguard-keycloak:8443?x=1", ClientID: "client", ClientSecret: "secret"},
		{RuntimeURL: "https://jjdguard-keycloak:8443#fragment", AllowedRuntimeURLs: "https://jjdguard-keycloak:8443#fragment", ClientID: "client", ClientSecret: "secret"},
		{RuntimeURL: "http://jjdguard-keycloak:8443", AllowedRuntimeURLs: "http://jjdguard-keycloak:8443", ClientID: "client", ClientSecret: "secret"},
		{RuntimeURL: "https://127.0.0.1:8443", AllowedRuntimeURLs: "https://127.0.0.1:8443", ClientID: "client", ClientSecret: "secret"},
		{RuntimeURL: "https://localhost:8443", AllowedRuntimeURLs: "https://localhost:8443", ClientID: "client", ClientSecret: "secret"},
		{RuntimeURL: "https://keycloak.localhost:8443", AllowedRuntimeURLs: "https://keycloak.localhost:8443", ClientID: "client", ClientSecret: "secret"},
		{RuntimeURL: "https://jjdguard-keycloak:8443/a/../b", AllowedRuntimeURLs: "https://jjdguard-keycloak:8443/a/../b", ClientID: "client", ClientSecret: "secret"},
		{RuntimeURL: "https://jjdguard-keycloak:8443/%2e%2e/admin", AllowedRuntimeURLs: "https://jjdguard-keycloak:8443/%2e%2e/admin", ClientID: "client", ClientSecret: "secret"},
	} {
		_, err := LoadConfig(input)
		require.ErrorIs(t, err, ErrRuntimeUnavailable)
	}
}

func TestLoadConfigRejectsPublicOrCredentiallessRuntime(t *testing.T) {
	for _, input := range []ConfigInput{
		{RuntimeURL: "https://keycloak.example.test/sso", ClientID: "client", ClientSecret: "secret"},
		{RuntimeURL: "http://127.0.0.1:8180/sso", ClientID: "client", ClientSecret: "secret"},
		{RuntimeURL: "http://chat-idp:8180/sso", ClientID: "", ClientSecret: "secret"},
		{RuntimeURL: "http://chat-idp:8180/sso", ClientID: "client", ClientSecret: ""},
	} {
		_, err := LoadConfig(input)
		require.ErrorIs(t, err, ErrRuntimeUnavailable)
	}
}
