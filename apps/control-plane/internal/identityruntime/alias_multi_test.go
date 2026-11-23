package identityruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// 9.2：第二个身份源的发布只读写它自己的 broker 实例与 mapper，不碰默认 enterprise。
func TestApplyAndDisableUseDesiredAliasPaths(t *testing.T) {
	const alias = "jjd-second0001"
	var mu sync.Mutex
	var paths []string
	var created ProviderRepresentation
	var mapperAliases []string
	mux := http.NewServeMux()
	mux.HandleFunc("/sso/realms/jjdguard/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) { tokenResponse(w) })
	mux.HandleFunc("/sso/admin/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		base := "/sso/admin/realms/jjdguard/identity-provider/instances"
		switch {
		case r.URL.Path == base+"/"+alias && r.Method == http.MethodGet:
			if created.Alias == "" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(created)
		case r.URL.Path == base && r.Method == http.MethodPost:
			_ = json.NewDecoder(r.Body).Decode(&created)
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == base+"/"+alias && r.Method == http.MethodPut:
			_ = json.NewDecoder(r.Body).Decode(&created)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == base+"/"+alias+"/mappers" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]MapperRepresentation{})
		case r.URL.Path == base+"/"+alias+"/mappers" && r.Method == http.MethodPost:
			var m MapperRepresentation
			_ = json.NewDecoder(r.Body).Decode(&m)
			mapperAliases = append(mapperAliases, m.IdentityProviderAlias)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected runtime request %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := mustTestClient(t, server, new(bytes.Buffer), nil)

	desired := testDesiredIdentitySource(t)
	desired.Alias = alias
	digest, err := ComputeDesiredDigest(desired)
	if err != nil {
		t.Fatal(err)
	}
	desired.Digest = digest
	if err := client.Apply(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	if created.Alias != alias {
		t.Fatalf("created provider alias = %q", created.Alias)
	}
	if len(mapperAliases) != len(desired.ClaimMappings) {
		t.Fatalf("mappers = %v", mapperAliases)
	}
	for _, a := range mapperAliases {
		if a != alias {
			t.Fatalf("mapper bound to %q, want %q", a, alias)
		}
	}
	if _, err := client.Snapshot(context.Background(), RealmName, alias); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if strings.Contains(p, "/instances/"+ProviderAlias) {
			t.Fatalf("default provider touched: %s", p)
		}
	}
}

func TestProviderAliasValidation(t *testing.T) {
	for _, ok := range []string{"enterprise", "jjd-a", "jjd-0123456789ab", "jjd-a_b-c"} {
		if !ValidProviderAlias(ok) {
			t.Fatalf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "master", "jjd-", "JJD-a", "jjd-A", "jjd-a.b", "jjd-a/b", "jjd-a%2f", "jjd-..", "enterprise ", "jjd-" + strings.Repeat("a", 57)} {
		if ValidProviderAlias(bad) {
			t.Fatalf("%q should be rejected", bad)
		}
	}
	if a, err := AliasForSource("0123456789AB", false); err != nil || a != "jjd-0123456789ab" {
		t.Fatalf("AliasForSource = %q %v", a, err)
	}
	if _, err := AliasForSource("../x", false); !errors.Is(err, ErrInvalidRuntimeTarget) {
		t.Fatalf("unsafe source id must be rejected: %v", err)
	}
	if got := CallbackURLForAlias("https://gw.example.com/", "jjd-x1"); got != "https://gw.example.com/sso/realms/jjdguard/broker/jjd-x1/endpoint" {
		t.Fatalf("callback = %q", got)
	}
	desired := testDesiredIdentitySource(t)
	desired.Alias = "jjd-a/../../master"
	if err := ValidateDesired(desired); err == nil {
		t.Fatal("ValidateDesired must reject unsafe alias")
	}
}
