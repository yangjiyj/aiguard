package directoryruntime

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestADProviderUsesReadOnlyImport(t *testing.T) {
	provider, err := DesiredProvider(DirectoryConfig{
		Kind:          KindActiveDirectory,
		ConnectionURL: "ldaps://dc.corp.test:636",
		BindDN:        "CN=svc-jjdguard,OU=Service Accounts,DC=corp,DC=test",
		BindPassword:  "super-secret",
		UsersDN:       "OU=Users,DC=corp,DC=test",
	})
	require.NoError(t, err)
	require.Equal(t, "jjdguard-directory", provider.Name)
	require.Equal(t, "ldap", provider.ProviderID)
	require.Equal(t, "org.keycloak.storage.UserStorageProvider", provider.ProviderType)
	require.Equal(t, []string{"READ_ONLY"}, provider.Config["editMode"])
	require.Equal(t, []string{"true"}, provider.Config["importEnabled"])
	require.Equal(t, []string{"false"}, provider.Config["syncRegistrations"])
	require.Equal(t, []string{"ad"}, provider.Config["vendor"])
	require.Equal(t, []string{"objectGUID"}, provider.Config["uuidLDAPAttribute"])
	require.Equal(t, []string{"sAMAccountName"}, provider.Config["usernameLDAPAttribute"])
	require.Equal(t, []string{"person,organizationalPerson,user"}, provider.Config["userObjectClasses"])
	require.Equal(t, []string{"cn"}, provider.Config["rdnLDAPAttribute"])
	require.Equal(t, []string{"ldaps://dc.corp.test:636"}, provider.Config["connectionUrl"])
	require.Equal(t, []string{"super-secret"}, provider.Config["bindCredential"])
}

func TestLDAPProviderUsesStandardIdentifiers(t *testing.T) {
	provider, err := DesiredProvider(DirectoryConfig{
		Kind:          KindLDAP,
		ConnectionURL: "ldaps://ldap.corp.test:636",
		BindDN:        "cn=svc-jjdguard,ou=service,dc=corp,dc=test",
		BindPassword:  "super-secret",
		UsersDN:       "ou=users,dc=corp,dc=test",
	})
	require.NoError(t, err)
	require.Equal(t, []string{"other"}, provider.Config["vendor"])
	require.Equal(t, []string{"entryUUID"}, provider.Config["uuidLDAPAttribute"])
	require.Equal(t, []string{"uid"}, provider.Config["usernameLDAPAttribute"])
}

func TestADBinaryGUIDMapperDecoratesLDAPConnection(t *testing.T) {
	mapper := DesiredADBinaryMapper("provider-id")
	require.Equal(t, "provider-id", mapper.ParentID)
	require.Equal(t, "user-attribute-ldap-mapper", mapper.ProviderID)
	require.Equal(t, "org.keycloak.storage.ldap.mappers.LDAPStorageMapper", mapper.ProviderType)
	require.Equal(t, []string{"objectGUID"}, mapper.Config["ldap.attribute"])
	require.Equal(t, []string{"true"}, mapper.Config["is.binary.attribute"])
	require.Equal(t, []string{"true"}, mapper.Config["read.only"])
	require.Equal(t, []string{"true"}, mapper.Config["always.read.value.from.ldap"])
}

func TestStandardLDAPMappersSwitchUsernameAndKeepHumanNameAttributes(t *testing.T) {
	ldapMappers := DesiredStandardLDAPMappers("provider-id", KindLDAP)
	adMappers := DesiredStandardLDAPMappers("provider-id", KindActiveDirectory)
	byName := func(mappers []ComponentRepresentation, name string) ComponentRepresentation {
		for _, mapper := range mappers {
			if mapper.Name == name {
				return mapper
			}
		}
		t.Fatalf("mapper %q missing", name)
		return ComponentRepresentation{}
	}
	require.Equal(t, []string{"uid"}, byName(ldapMappers, "username").Config["ldap.attribute"])
	require.Equal(t, []string{"sAMAccountName"}, byName(adMappers, "username").Config["ldap.attribute"])
	require.Equal(t, []string{"givenName"}, byName(ldapMappers, "first name").Config["ldap.attribute"])
	require.Equal(t, []string{"givenName"}, byName(adMappers, "first name").Config["ldap.attribute"])
}

func TestDesiredProviderRejectsIncompleteConfig(t *testing.T) {
	_, err := DesiredProvider(DirectoryConfig{
		Kind:          KindLDAP,
		ConnectionURL: "ldaps://ldap.corp.test:636",
		BindDN:        "cn=svc,dc=corp,dc=test",
		BindPassword:  "super-secret",
	})
	require.ErrorIs(t, err, ErrInvalidDirectoryConfig)
}

func TestDirectoryConfigRedactsBindPassword(t *testing.T) {
	desired := DirectoryConfig{
		Kind:          KindLDAP,
		ConnectionURL: "ldaps://ldap.corp.test:636",
		BindDN:        "cn=svc,dc=corp,dc=test",
		BindPassword:  "super-secret",
		UsersDN:       "ou=users,dc=corp,dc=test",
	}
	require.NotContains(t, desired.String(), desired.BindPassword)
	require.NotContains(t, desired.GoString(), desired.BindPassword)

	provider, err := DesiredProvider(desired)
	require.NoError(t, err)
	require.NotContains(t, provider.String(), "super-secret")
	require.NotContains(t, provider.GoString(), "super-secret")
	require.True(t, strings.Contains(provider.String(), "Config:[redacted]"))
}
