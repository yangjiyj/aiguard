package identityruntime

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"os"
	"testing"
	"time"
)

// W9 9.2 live：真实 Keycloak 上两个身份源（enterprise 与 jjd-*）同时存在、各自独立。
// 需要 IDENTITY_RUNTIME_LIVE_URL（…/sso 形式或 KC 根地址）与服务账号 IDENTITY_RUNTIME_LIVE_CLIENT_ID/SECRET。
func TestLiveMultipleProviderAliasesCoexist(t *testing.T) {
	base := os.Getenv("IDENTITY_RUNTIME_LIVE_URL")
	if base == "" {
		t.Skip("IDENTITY_RUNTIME_LIVE_URL not set")
	}
	client, err := newClient(clientOptions{
		RuntimeURL: base, ClientID: os.Getenv("IDENTITY_RUNTIME_LIVE_CLIENT_ID"),
		ClientSecret: os.Getenv("IDENTITY_RUNTIME_LIVE_CLIENT_SECRET"),
		HTTPClient:   &http.Client{Timeout: 10 * time.Second}, Logger: log.New(new(bytes.Buffer), "", 0),
		RequestTimeout: 10 * time.Second, MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mk := func(alias, issuer string) DesiredIdentitySource {
		d := testDesiredIdentitySource(t)
		d.Alias = alias
		d.DisplayName = alias
		d.Endpoints = DiscoveryEndpoints{
			Issuer: issuer, Authorization: issuer + "/authorize", Token: issuer + "/token",
			JWKS: issuer + "/jwks", UserInfo: issuer + "/userinfo", EndSession: issuer + "/logout",
		}
		d.Digest = ""
		digest, err := ComputeDesiredDigest(d)
		if err != nil {
			t.Fatal(err)
		}
		d.Digest = digest
		return d
	}
	second := "jjd-live" + time.Now().Format("150405")
	defA, defB := mk(ProviderAlias, "https://hq.example.com"), mk(second, "https://branch.example.com")
	t.Cleanup(func() {
		_ = client.Restore(ctx, RuntimeSnapshot{Realm: RealmName, Alias: second})
		_ = client.Restore(ctx, RuntimeSnapshot{Realm: RealmName, Alias: ProviderAlias})
	})
	if err := client.Apply(ctx, defA); err != nil {
		t.Fatalf("apply default: %v", err)
	}
	if err := client.Apply(ctx, defB); err != nil {
		t.Fatalf("apply second: %v", err)
	}
	for _, d := range []DesiredIdentitySource{defA, defB} {
		st, err := client.Status(ctx, RealmName, d.Alias)
		if err != nil || !st.Exists || !st.Enabled || st.Digest != d.Digest || st.Drifted {
			t.Fatalf("status %s = %+v %v", d.Alias, st, err)
		}
		snap, err := client.Snapshot(ctx, RealmName, d.Alias)
		if err != nil || snap.Provider.Config["issuer"] != d.Endpoints.Issuer {
			t.Fatalf("snapshot %s issuer=%q err=%v", d.Alias, snap.Provider.Config["issuer"], err)
		}
		if len(snap.Mappers) != len(d.ClaimMappings) {
			t.Fatalf("mappers %s = %d", d.Alias, len(snap.Mappers))
		}
		for _, m := range snap.Mappers {
			if m.IdentityProviderAlias != d.Alias {
				t.Fatalf("mapper %s bound to %s", m.Name, m.IdentityProviderAlias)
			}
		}
	}
	// 停用第二个身份源，默认身份源不受影响。
	if err := client.Disable(ctx, RealmName, second); err != nil {
		t.Fatalf("disable second: %v", err)
	}
	if st, _ := client.Status(ctx, RealmName, second); st.Enabled {
		t.Fatalf("second still enabled: %+v", st)
	}
	if st, _ := client.Status(ctx, RealmName, ProviderAlias); !st.Enabled || st.Digest != defA.Digest {
		t.Fatalf("default affected by disabling second: %+v", st)
	}
}
