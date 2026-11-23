package main

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryruntime"
	"github.com/stretchr/testify/require"
)

func TestLoadDirectoryRuntimeUsesInternalServiceCredentials(t *testing.T) {
	values := map[string]string{
		"DIRECTORY_RUNTIME_URL":           "http://chat-idp:8180/sso",
		"DIRECTORY_RUNTIME_ALLOWED_URLS":  "",
		"DIRECTORY_RUNTIME_CLIENT_ID":     "jjdguard-directory-orchestrator",
		"DIRECTORY_RUNTIME_CLIENT_SECRET": "directory-runtime-secret",
	}
	runtime, err := loadDirectoryRuntime(func(key string) string { return values[key] })
	require.NoError(t, err)
	require.NotNil(t, runtime)
}

func TestLoadDirectoryRuntimeUsesDeploymentAllowlist(t *testing.T) {
	values := map[string]string{
		"DIRECTORY_RUNTIME_URL":           "https://jjdguard-keycloak:8443",
		"DIRECTORY_RUNTIME_ALLOWED_URLS":  "https://jjdguard-keycloak:8443",
		"DIRECTORY_RUNTIME_CLIENT_ID":     "jjdguard-directory-orchestrator",
		"DIRECTORY_RUNTIME_CLIENT_SECRET": "directory-runtime-secret",
	}
	runtime, err := loadDirectoryRuntime(func(key string) string { return values[key] })
	require.NoError(t, err)
	require.NotNil(t, runtime)
}

func TestLoadDirectoryRuntimeIsUnavailableWithoutCredentials(t *testing.T) {
	runtime, err := loadDirectoryRuntime(func(string) string { return "" })
	require.ErrorIs(t, err, directoryruntime.ErrRuntimeUnavailable)
	require.Nil(t, runtime)
}
