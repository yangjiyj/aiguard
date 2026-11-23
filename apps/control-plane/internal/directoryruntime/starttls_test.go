package directoryruntime

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// W9 9.4：ldap:// 目录必须让 Keycloak 走 StartTLS；ldaps:// 不带 startTls。
func TestLDAPURLProviderRequiresStartTLS(t *testing.T) {
	config := DirectoryConfig{
		Kind:          KindLDAP,
		ConnectionURL: "ldap://ldap.corp.test:389",
		BindDN:        "cn=svc,dc=corp,dc=test",
		BindPassword:  "super-secret",
		UsersDN:       "ou=users,dc=corp,dc=test",
	}
	provider, err := DesiredProvider(config)
	require.NoError(t, err)
	require.Equal(t, []string{"true"}, provider.Config["startTls"])

	ldaps := config
	ldaps.ConnectionURL = "ldaps://ldap.corp.test:3269"
	provider, err = DesiredProvider(ldaps)
	require.NoError(t, err)
	require.NotContains(t, provider.Config, "startTls")
}

func TestComponentDigestTreatsDisabledStartTLSAsDrift(t *testing.T) {
	config := DirectoryConfig{
		Kind:          KindLDAP,
		ConnectionURL: "ldap://ldap.corp.test:389",
		BindDN:        "cn=svc,dc=corp,dc=test",
		BindPassword:  "super-secret",
		UsersDN:       "ou=users,dc=corp,dc=test",
	}
	provider, err := DesiredProvider(config)
	require.NoError(t, err)
	want, err := ComputeDigest(config)
	require.NoError(t, err)
	got, err := ComputeComponentDigest(provider)
	require.NoError(t, err)
	require.Equal(t, want, got)

	provider.Config["startTls"] = []string{"false"}
	_, err = ComputeComponentDigest(provider)
	require.ErrorIs(t, err, ErrInvalidDirectoryConfig)
	delete(provider.Config, "startTls")
	_, err = ComputeComponentDigest(provider)
	require.ErrorIs(t, err, ErrInvalidDirectoryConfig)
}
