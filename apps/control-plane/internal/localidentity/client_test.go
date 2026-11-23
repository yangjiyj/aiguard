package localidentity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientCreateUserUsesControlledRealmAndStartsDisabled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sso/realms/jjdguard/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("token method = %s, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse token form: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "client_credentials" {
			t.Fatalf("grant_type = %q", got)
		}
		if got := r.Form.Get("client_id"); got != "control-plane" {
			t.Fatalf("client_id = %q", got)
		}
		if got := r.Form.Get("client_secret"); got != "admin-secret" {
			t.Fatalf("client_secret = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "admin-token",
			"expires_in":   300,
		})
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("create method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer admin-token" {
			t.Fatalf("authorization = %q", got)
		}
		var body struct {
			Username    string `json:"username"`
			Email       string `json:"email"`
			Enabled     bool   `json:"enabled"`
			Credentials []struct {
				Type      string `json:"type"`
				Value     string `json:"value"`
				Temporary bool   `json:"temporary"`
			} `json:"credentials"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode create body: %v", err)
		}
		if body.Username != "alice" || body.Email != "alice@example.com" || body.Enabled {
			t.Fatalf("unexpected create body: %+v", body)
		}
		if len(body.Credentials) != 1 || body.Credentials[0].Type != "password" ||
			body.Credentials[0].Value != "initial-password" || !body.Credentials[0].Temporary {
			t.Fatalf("unexpected credentials: %+v", body.Credentials)
		}
		w.Header().Set("Location", "/sso/admin/realms/jjdguard/users/kc-user-1")
		w.WriteHeader(http.StatusCreated)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := NewClient(Config{
		BaseURL: server.URL + "/sso", Realm: "jjdguard",
		ClientID: "control-plane", ClientSecret: "admin-secret",
		HTTPClient: server.Client(), RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	externalSubject, err := client.CreateUser(context.Background(), CreateUserInput{
		Username: "alice", Email: "alice@example.com",
		Password: "initial-password", Temporary: true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if externalSubject != "kc-user-1" {
		t.Fatalf("external subject = %q", externalSubject)
	}
}
func TestClientLifecycleMethodsEncodeSubjectAndPayloads(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sso/realms/jjdguard/protocol/openid-connect/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "admin-token", "expires_in": 300})
	})
	var requests []string
	mux.HandleFunc("/sso/admin/realms/jjdguard/users/", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer admin-token" {
			t.Fatalf("authorization = %q", got)
		}
		requests = append(requests, r.Method+" "+r.URL.EscapedPath())
		switch len(requests) {
		case 1, 2:
			var payload struct {
				Enabled *bool `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode enabled payload: %v", err)
			}
			want := len(requests) == 1
			if payload.Enabled == nil || *payload.Enabled != want {
				t.Fatalf("enabled = %v, want %v", payload.Enabled, want)
			}
		case 3:
			var payload passwordCredential
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode password payload: %v", err)
			}
			if payload.Type != "password" || payload.Value != "rotated-password" || payload.Temporary {
				t.Fatalf("password payload = %+v", payload)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client, err := NewClient(Config{
		BaseURL: server.URL + "/sso", Realm: "jjdguard",
		ClientID: "control-plane", ClientSecret: "admin-secret",
		HTTPClient: server.Client(), RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := client.SetEnabled(ctx, "subject/with space", true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := client.SetEnabled(ctx, "subject/with space", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := client.ResetPassword(ctx, "subject/with space", "rotated-password", false); err != nil {
		t.Fatalf("reset password: %v", err)
	}
	if err := client.DeleteUser(ctx, "subject/with space"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	want := []string{
		"PUT /sso/admin/realms/jjdguard/users/subject%2Fwith%20space",
		"PUT /sso/admin/realms/jjdguard/users/subject%2Fwith%20space",
		"PUT /sso/admin/realms/jjdguard/users/subject%2Fwith%20space/reset-password",
		"DELETE /sso/admin/realms/jjdguard/users/subject%2Fwith%20space",
	}
	if len(requests) != len(want) {
		t.Fatalf("requests = %v", requests)
	}
	for i := range want {
		if requests[i] != want[i] {
			t.Fatalf("request[%d] = %q, want %q", i, requests[i], want[i])
		}
	}
}

func TestClientMapsConflictWithoutLeakingRuntimeBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sso/realms/jjdguard/protocol/openid-connect/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "admin-token", "expires_in": 300})
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/users", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("initial-password admin-token admin-secret credential-id-1"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client, err := NewClient(Config{
		BaseURL: server.URL + "/sso", Realm: "jjdguard",
		ClientID: "control-plane", ClientSecret: "admin-secret",
		HTTPClient: server.Client(), RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateUser(context.Background(), CreateUserInput{
		Username: "alice", Password: "initial-password",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}
	for _, secret := range []string{"initial-password", "admin-token", "admin-secret", "credential-id-1"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked %q: %v", secret, err)
		}
	}
}

func TestClientBoundsResponsesAndTimeouts(t *testing.T) {
	t.Run("response too large", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", 128)))
		}))
		defer server.Close()
		client, err := NewClient(Config{
			BaseURL: server.URL, Realm: "jjdguard",
			ClientID: "control-plane", ClientSecret: "admin-secret",
			HTTPClient: server.Client(), RequestTimeout: time.Second, MaxResponseBytes: 32,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.CreateUser(context.Background(), CreateUserInput{Username: "alice", Password: "password"})
		if !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("error = %v, want ErrResponseTooLarge", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			<-release
		}))
		client, err := NewClient(Config{
			BaseURL: server.URL, Realm: "jjdguard",
			ClientID: "control-plane", ClientSecret: "admin-secret",
			HTTPClient: server.Client(), RequestTimeout: 20 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.CreateUser(context.Background(), CreateUserInput{Username: "alice", Password: "password"})
		close(release)
		server.Close()
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
	})
}

func TestClientRejectsUncontrolledConfigAndRedactsString(t *testing.T) {
	if _, err := NewClient(Config{
		BaseURL: "https://identity.invalid/sso?target=http://attacker.invalid",
		Realm:   "jjdguard", ClientID: "control-plane", ClientSecret: "admin-secret",
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig", err)
	}
	client, err := NewClient(Config{
		BaseURL: "https://identity.invalid/sso", Realm: "jjdguard",
		ClientID: "control-plane", ClientSecret: "admin-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	printed := client.String()
	if strings.Contains(printed, "admin-secret") {
		t.Fatalf("String leaked credential: %s", printed)
	}
}

// M8：Keycloak 404 必须映射为 ErrNotFound（而非 ErrRejected），
// 让删除编排能把"已不存在的 subject"识别为幂等成功，避免误判补偿失败。
func TestClientMapsNotFoundToErrNotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sso/realms/jjdguard/protocol/openid-connect/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "admin-token", "expires_in": 300})
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/users/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("user not found in keycloak"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client, err := NewClient(Config{
		BaseURL: server.URL + "/sso", Realm: "jjdguard",
		ClientID: "control-plane", ClientSecret: "admin-secret",
		HTTPClient: server.Client(), RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	// SetEnabled / ResetPassword 对不存在 subject 应返 ErrNotFound
	enableErr := client.SetEnabled(context.Background(), "missing-subject", false)
	if !errors.Is(enableErr, ErrNotFound) {
		t.Fatalf("SetEnabled error = %v, want ErrNotFound", enableErr)
	}
	if strings.Contains(enableErr.Error(), "user not found in keycloak") {
		t.Fatalf("SetEnabled leaked upstream body: %v", enableErr)
	}
	resetErr := client.ResetPassword(context.Background(), "missing-subject", "new-password", false)
	if !errors.Is(resetErr, ErrNotFound) {
		t.Fatalf("ResetPassword error = %v, want ErrNotFound", resetErr)
	}
	if strings.Contains(resetErr.Error(), "user not found in keycloak") {
		t.Fatalf("ResetPassword leaked upstream body: %v", resetErr)
	}
}

// M8：删除已不存在的 subject 必须返 nil（幂等），
// 否则重复删除会被误判为补偿失败、污染 reconciliation_required 状态。
func TestClientDeleteUserIsIdempotentForMissingSubject(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sso/realms/jjdguard/protocol/openid-connect/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "admin-token", "expires_in": 300})
	})
	mux.HandleFunc("/sso/admin/realms/jjdguard/users/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client, err := NewClient(Config{
		BaseURL: server.URL + "/sso", Realm: "jjdguard",
		ClientID: "control-plane", ClientSecret: "admin-secret",
		HTTPClient: server.Client(), RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteUser(context.Background(), "missing-subject"); err != nil {
		t.Fatalf("DeleteUser missing subject error = %v, want nil (idempotent)", err)
	}
}
