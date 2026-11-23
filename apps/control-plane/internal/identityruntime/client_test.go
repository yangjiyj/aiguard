package identityruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tokenResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "runtime-token", "expires_in": 300})
}

func mustTestClient(t *testing.T, server *httptest.Server, logBuffer *bytes.Buffer, mutate func(*clientOptions)) *Client {
	t.Helper()
	options := clientOptions{
		RuntimeURL: server.URL + "/sso", ClientID: "svc", ClientSecret: "service-secret",
		HTTPClient: server.Client(), Logger: log.New(logBuffer, "", 0),
		RequestTimeout: time.Second, MaxResponseBytes: 1 << 20,
	}
	if mutate != nil {
		mutate(&options)
	}
	client, err := newClient(options)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestSnapshotUsesFixedTokenAndAdminPaths(t *testing.T) {
	var tokenCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/sso/realms/jjdguard/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "svc" ||
			r.Form.Get("client_secret") != "service-secret" {
			t.Errorf("unexpected token form: %v", r.Form)
		}
		tokenResponse(w)
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/identity-provider/instances/enterprise", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer runtime-token" {
			t.Errorf("unexpected provider request: %s %s", r.Method, r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(ProviderRepresentation{
			Alias: ProviderAlias, ProviderID: "oidc", Enabled: true,
			Config: map[string]string{digestConfigKey: "sha256:current"},
		})
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/identity-provider/instances/enterprise/mappers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]MapperRepresentation{})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := mustTestClient(t, server, new(bytes.Buffer), nil)
	first, err := client.Snapshot(context.Background(), RealmName, ProviderAlias)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Snapshot(context.Background(), RealmName, ProviderAlias)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Exists || first.Digest != "sha256:current" || second.Digest != first.Digest {
		t.Fatalf("snapshots: %#v %#v", first, second)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token calls=%d", tokenCalls.Load())
	}
}

func TestSnapshotRejectsCoordinateOverrideBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	client := mustTestClient(t, server, new(bytes.Buffer), nil)
	_, err := client.Snapshot(context.Background(), "master", ProviderAlias)
	if !errors.Is(err, ErrInvalidRuntimeTarget) || calls.Load() != 0 {
		t.Fatalf("error=%v calls=%d", err, calls.Load())
	}
}

func TestClientMapsUnauthorizedWithoutLeakingSecret(t *testing.T) {
	logBuffer := new(bytes.Buffer)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			tokenResponse(w)
			return
		}
		http.Error(w, "service-secret upstream-secret", http.StatusUnauthorized)
	}))
	defer server.Close()
	client := mustTestClient(t, server, logBuffer, nil)
	_, err := client.Snapshot(context.Background(), RealmName, ProviderAlias)
	if !errors.Is(err, ErrRuntimeUnauthorized) {
		t.Fatalf("error=%v", err)
	}
	if strings.Contains(logBuffer.String(), "service-secret") || strings.Contains(logBuffer.String(), "upstream-secret") ||
		strings.Contains(err.Error(), "service-secret") || strings.Contains(err.Error(), "upstream-secret") {
		t.Fatalf("secret leaked: log=%q err=%q", logBuffer.String(), err)
	}
}

func TestClientRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			tokenResponse(w)
			return
		}
		_, _ = io.WriteString(w, strings.Repeat("x", 513))
	}))
	defer server.Close()
	client := mustTestClient(t, server, new(bytes.Buffer), func(options *clientOptions) {
		options.MaxResponseBytes = 512
	})
	_, err := client.Snapshot(context.Background(), RealmName, ProviderAlias)
	if !errors.Is(err, ErrRuntimeResponseTooLarge) {
		t.Fatalf("error=%v", err)
	}
}

func TestClientTimeoutIsStableAndSanitized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			tokenResponse(w)
			return
		}
		time.Sleep(100 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(ProviderRepresentation{})
	}))
	defer server.Close()
	client := mustTestClient(t, server, new(bytes.Buffer), func(options *clientOptions) {
		options.RequestTimeout = 20 * time.Millisecond
	})
	_, err := client.Snapshot(context.Background(), RealmName, ProviderAlias)
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("error=%v", err)
	}
}

func TestApplyCreatesOnlyNormalizedProviderAndManagedMappers(t *testing.T) {
	var provider ProviderRepresentation
	var providerPayload map[string]json.RawMessage
	var mappers []MapperRepresentation
	mux := http.NewServeMux()
	mux.HandleFunc("/sso/realms/jjdguard/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		tokenResponse(w)
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/identity-provider/instances/enterprise", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/identity-provider/instances", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if err := json.Unmarshal(body, &provider); err != nil {
			t.Error(err)
		}
		if err := json.Unmarshal(body, &providerPayload); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/identity-provider/instances/enterprise/mappers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode([]MapperRepresentation{})
		case http.MethodPost:
			var mapper MapperRepresentation
			if err := json.NewDecoder(r.Body).Decode(&mapper); err != nil {
				t.Error(err)
			}
			mappers = append(mappers, mapper)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("method=%s", r.Method)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := mustTestClient(t, server, new(bytes.Buffer), nil)
	desired := testDesiredIdentitySource(t)
	if err := client.Apply(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	if provider.Alias != ProviderAlias || provider.ProviderID != "oidc" || !provider.Enabled ||
		provider.Config["clientId"] != desired.ClientID || provider.Config["clientSecret"] != desired.ClientSecret ||
		provider.Config[digestConfigKey] != desired.Digest || provider.Config["authorizationUrl"] != desired.Endpoints.Authorization ||
		provider.Config["tokenUrl"] != desired.Endpoints.Token || provider.Config["jwksUrl"] != desired.Endpoints.JWKS {
		t.Fatalf("provider=%#v", provider)
	}
	if _, exists := providerPayload["hideOnLogin"]; exists {
		t.Fatal("Keycloak 25 rejects hideOnLogin in identity provider writes")
	}
	if len(mappers) != len(desired.ClaimMappings) {
		t.Fatalf("mappers=%#v", mappers)
	}
	for _, mapper := range mappers {
		if mapper.IdentityProviderAlias != ProviderAlias || mapper.IdentityProviderMapper != "oidc-user-attribute-idp-mapper" ||
			!strings.HasPrefix(mapper.Name, managedMapperPrefix) {
			t.Fatalf("mapper=%#v", mapper)
		}
	}
}
func TestSyncManagedMappersPreservesUnmanagedMappers(t *testing.T) {
	var deleted atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/sso/realms/jjdguard/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		tokenResponse(w)
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/identity-provider/instances/enterprise/mappers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method=%s", r.Method)
		}
		_ = json.NewEncoder(w).Encode([]MapperRepresentation{{
			ID:                     "customer-managed-group-mapper",
			Name:                   "customer-managed-group-mapper",
			IdentityProviderAlias:  ProviderAlias,
			IdentityProviderMapper: "oidc-advanced-group-idp-mapper",
		}})
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/identity-provider/instances/enterprise/mappers/customer-managed-group-mapper", func(w http.ResponseWriter, r *http.Request) {
		deleted.Store(true)
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := mustTestClient(t, server, new(bytes.Buffer), nil)
	if err := client.syncManagedMappers(context.Background(), "enterprise", nil); err != nil {
		t.Fatal(err)
	}
	if deleted.Load() {
		t.Fatal("identity publication deleted an unmanaged Keycloak mapper")
	}
}

func TestRestoreEmptySnapshotDeletesOnlyFixedProvider(t *testing.T) {
	var deleted atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			tokenResponse(w)
			return
		}
		if r.Method == http.MethodDelete && r.URL.Path == "/sso/admin/realms/jjdguard/identity-provider/instances/enterprise" {
			deleted.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	client := mustTestClient(t, server, new(bytes.Buffer), nil)
	err := client.Restore(context.Background(), RuntimeSnapshot{Realm: RealmName, Alias: ProviderAlias, Exists: false})
	if err != nil || !deleted.Load() {
		t.Fatalf("error=%v deleted=%v", err, deleted.Load())
	}
}

func TestNewClientDisablesEnvironmentProxy(t *testing.T) {
	cfg, err := LoadConfig(ConfigInput{
		PublicURL: "https://sso.example.com", RuntimeURL: "http://chat-idp:8180/sso",
		ClientID: "svc", ClientSecret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("transport=%T proxy_enabled=%t", client.httpClient.Transport, transport.Proxy != nil)
	}
}

func TestRuntimeURLJoiningCannotEscapeConfiguredBase(t *testing.T) {
	base, _ := url.Parse("http://chat-idp:8180/sso")
	got, err := joinRuntimePath(base, "/admin/realms/jjdguard")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://chat-idp:8180/sso/admin/realms/jjdguard" {
		t.Fatalf("url=%q", got)
	}
}

func TestStatusDetectsMapperDriftWithUnchangedPublicationMarker(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	provider := desiredProvider(desired, desired.Digest)
	mappers := make([]MapperRepresentation, 0, len(desired.ClaimMappings))
	for _, mapping := range desired.ClaimMappings {
		mappers = append(mappers, managedMapper("enterprise", mapping))
	}
	structureDigest, err := computeRuntimeStructureDigest(provider, mappers)
	if err != nil {
		t.Fatal(err)
	}
	provider.Config[structureDigestConfigKey] = structureDigest
	mappers[0].Config["claim"] = "tampered_claim"

	mux := http.NewServeMux()
	mux.HandleFunc("/sso/realms/jjdguard/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		tokenResponse(w)
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/identity-provider/instances/enterprise", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(provider)
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/identity-provider/instances/enterprise/mappers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mappers)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := mustTestClient(t, server, new(bytes.Buffer), nil)
	status, err := client.Status(context.Background(), RealmName, ProviderAlias)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Drifted {
		t.Fatalf("status=%#v", status)
	}
}

func TestClientRefusesRuntimeRedirect(t *testing.T) {
	var redirectedCalls atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedCalls.Add(1)
		http.Error(w, "must not be reached", http.StatusInternalServerError)
	}))
	defer redirected.Close()

	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			tokenResponse(w)
			return
		}
		http.Redirect(w, r, redirected.URL+"/admin", http.StatusFound)
	}))
	defer runtime.Close()

	client := mustTestClient(t, runtime, new(bytes.Buffer), nil)
	_, err := client.Snapshot(context.Background(), RealmName, ProviderAlias)
	if err == nil {
		t.Fatal("redirect must be rejected")
	}
	if redirectedCalls.Load() != 0 {
		t.Fatalf("redirect target calls=%d", redirectedCalls.Load())
	}
}

func TestStatusIgnoresUnmanagedServerDefaults(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	provider := desiredProvider(desired, desired.Digest)
	mappers := make([]MapperRepresentation, 0, len(desired.ClaimMappings))
	for _, mapping := range desired.ClaimMappings {
		mappers = append(mappers, managedMapper("enterprise", mapping))
	}
	provider.Config["serverAddedDefault"] = "false"

	mux := http.NewServeMux()
	mux.HandleFunc("/sso/realms/jjdguard/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		tokenResponse(w)
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/identity-provider/instances/enterprise", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(provider)
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/identity-provider/instances/enterprise/mappers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mappers)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	status, err := mustTestClient(t, server, new(bytes.Buffer), nil).Status(context.Background(), RealmName, ProviderAlias)
	if err != nil {
		t.Fatal(err)
	}
	if status.Drifted {
		t.Fatalf("server default caused false drift: %#v", status)
	}
}
