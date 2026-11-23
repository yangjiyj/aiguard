package directoryruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientApplyCreatesLDAPComponentWithRealmParent(t *testing.T) {
	var createdProvider ComponentRepresentation
	providerCreated := false
	createdMappers := make(map[string]ComponentRepresentation)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/realms/jjdguard/protocol/openid-connect/token":
			require.Equal(t, http.MethodPost, request.Method)
			_, _ = writer.Write([]byte(`{"access_token":"test-token","expires_in":300}`))
		case "/admin/realms/jjdguard":
			require.Equal(t, "Bearer test-token", request.Header.Get("Authorization"))
			_, _ = writer.Write([]byte(`{"id":"realm-internal-id"}`))
		case "/admin/realms/jjdguard/components":
			require.Equal(t, "Bearer test-token", request.Header.Get("Authorization"))
			if request.Method == http.MethodGet {
				parent := request.URL.Query().Get("parent")
				require.Contains(t, []string{"realm-internal-id", "provider-id"}, parent)
				require.Empty(t, request.URL.Query().Get("type"))
				if parent == "realm-internal-id" && providerCreated {
					_, _ = writer.Write([]byte(`[{"id":"provider-id","name":"jjdguard-directory","providerId":"ldap","providerType":"org.keycloak.storage.UserStorageProvider","parentId":"realm-internal-id","config":{}}]`))
					return
				}
				_, _ = writer.Write([]byte("[]"))
				return
			}
			require.Equal(t, http.MethodPost, request.Method)
			var created ComponentRepresentation
			require.NoError(t, json.NewDecoder(request.Body).Decode(&created))
			if created.Name == ProviderName {
				createdProvider = created
				providerCreated = true
			} else {
				createdMappers[created.Name] = created
			}
			writer.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.String())
		}
	}))
	defer server.Close()

	client, err := newClient(clientOptions{
		RuntimeURL:   server.URL,
		ClientID:     "service-client",
		ClientSecret: "service-secret",
		HTTPClient:   server.Client(),
	})
	require.NoError(t, err)
	digest, err := ComputeDigest(testDirectoryConfig())
	require.NoError(t, err)

	config := testDirectoryConfig()
	config.Kind = KindLDAP
	require.NoError(t, client.Apply(context.Background(), config, digest))
	require.Equal(t, ProviderName, createdProvider.Name)
	require.Equal(t, "realm-internal-id", createdProvider.ParentID)
	require.NotContains(t, createdProvider.Config, "jjdguardConfigDigest")
	require.Equal(t, []string{"READ_ONLY"}, createdProvider.Config["editMode"])
	require.Len(t, createdMappers, 4)
	require.Equal(t, []string{"givenName"}, createdMappers["first name"].Config["ldap.attribute"])
}

func TestClientApplyCreatesADBinaryGUIDMapper(t *testing.T) {
	var updatedProvider ComponentRepresentation
	createdMappers := make(map[string]ComponentRepresentation)
	updatedMappers := make(map[string]ComponentRepresentation)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/realms/jjdguard/protocol/openid-connect/token":
			_, _ = writer.Write([]byte(`{"access_token":"test-token","expires_in":300}`))
		case "/admin/realms/jjdguard":
			_, _ = writer.Write([]byte(`{"id":"realm-internal-id"}`))
		case "/admin/realms/jjdguard/components":
			parent := request.URL.Query().Get("parent")
			if request.Method == http.MethodGet && parent == "realm-internal-id" {
				_, _ = writer.Write([]byte(`[{"id":"provider-id","name":"jjdguard-directory","providerId":"ldap","providerType":"org.keycloak.storage.UserStorageProvider","parentId":"realm-internal-id","config":{}}]`))
				return
			}
			if request.Method == http.MethodGet && parent == "provider-id" {
				_, _ = writer.Write([]byte(`[
                  {"id":"username-id","name":"username","providerId":"user-attribute-ldap-mapper","providerType":"org.keycloak.storage.ldap.mappers.LDAPStorageMapper","parentId":"provider-id","config":{"ldap.attribute":["uid"]}},
                  {"id":"first-name-id","name":"first name","providerId":"user-attribute-ldap-mapper","providerType":"org.keycloak.storage.ldap.mappers.LDAPStorageMapper","parentId":"provider-id","config":{"ldap.attribute":["cn"]}}
                ]`))
				return
			}
			require.Equal(t, http.MethodPost, request.Method)
			var created ComponentRepresentation
			require.NoError(t, json.NewDecoder(request.Body).Decode(&created))
			createdMappers[created.Name] = created
			writer.WriteHeader(http.StatusCreated)
		case "/admin/realms/jjdguard/components/provider-id":
			require.Equal(t, http.MethodPut, request.Method)
			require.NoError(t, json.NewDecoder(request.Body).Decode(&updatedProvider))
			writer.WriteHeader(http.StatusNoContent)
		case "/admin/realms/jjdguard/components/username-id", "/admin/realms/jjdguard/components/first-name-id":
			require.Equal(t, http.MethodPut, request.Method)
			var updated ComponentRepresentation
			require.NoError(t, json.NewDecoder(request.Body).Decode(&updated))
			updatedMappers[updated.Name] = updated
			writer.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.String())
		}
	}))
	defer server.Close()

	client, err := newClient(clientOptions{
		RuntimeURL:   server.URL,
		ClientID:     "service-client",
		ClientSecret: "service-secret",
		HTTPClient:   server.Client(),
	})
	require.NoError(t, err)
	config := testDirectoryConfig()
	config.Kind = KindActiveDirectory
	require.NoError(t, client.Apply(context.Background(), config, "digest"))
	require.Equal(t, "ad", updatedProvider.Config["vendor"][0])
	require.Equal(t, "provider-id", createdMappers[ADBinaryMapperName].ParentID)
	require.Equal(t, []string{"true"}, createdMappers[ADBinaryMapperName].Config["is.binary.attribute"])
	require.Equal(t, []string{"sAMAccountName"}, updatedMappers["username"].Config["ldap.attribute"])
	require.Equal(t, []string{"givenName"}, updatedMappers["first name"].Config["ldap.attribute"])
	require.Equal(t, "username-id", updatedMappers["username"].ID)
	require.Equal(t, "first-name-id", updatedMappers["first name"].ID)
}

func TestClientRefreshesCachedTokenOnceAfterUnauthorized(t *testing.T) {
	tokenCalls := 0
	realmCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/realms/jjdguard/protocol/openid-connect/token":
			tokenCalls++
			token := "stale-token"
			if tokenCalls > 1 {
				token = "fresh-token"
			}
			_, _ = writer.Write([]byte(`{"access_token":"` + token + `","expires_in":300}`))
		case "/admin/realms/jjdguard":
			realmCalls++
			if request.Header.Get("Authorization") == "Bearer stale-token" {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			require.Equal(t, "Bearer fresh-token", request.Header.Get("Authorization"))
			_, _ = writer.Write([]byte(`{"id":"realm-internal-id"}`))
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.String())
		}
	}))
	defer server.Close()

	client, err := newClient(clientOptions{
		RuntimeURL:   server.URL,
		ClientID:     "service-client",
		ClientSecret: "service-secret",
		HTTPClient:   server.Client(),
	})
	require.NoError(t, err)

	realmID, err := client.realmID(context.Background())
	require.NoError(t, err)
	require.Equal(t, "realm-internal-id", realmID)
	require.Equal(t, 2, tokenCalls)
	require.Equal(t, 2, realmCalls)
}
