package identityruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// 默认值摘要金额：由改动前的代码（git stash 回到 main）对同一夹具计算得到。
// 任何让它变化的改动都会使存量身份源升级后漂移。
const (
	goldenDefaultDesiredDigest   = "sha256:a8eee3123f3bd02e4fcc3f9114b7ce44692421e7dbeaf5dd9c170b6c4fafa981"
	goldenDefaultStructureDigest = "sha256:16f04b0629f93247a4b617c6f3c6297b3d0955d271b1fda7989a8f9cc765df0c"
)

func goldenDesired() DesiredIdentitySource {
	return DesiredIdentitySource{
		Realm: RealmName, Alias: ProviderAlias, DisplayName: "企业 SSO",
		Endpoints: DiscoveryEndpoints{
			Issuer: "https://idp.example.com", Authorization: "https://idp.example.com/auth",
			Token: "https://idp.example.com/token", JWKS: "https://idp.example.com/jwks",
			UserInfo: "https://idp.example.com/userinfo",
		},
		ClientID: "cid", ClientSecret: "sec", Scopes: []string{"openid", "profile", "email"},
		ClaimMappings: []ClaimMapping{
			{Name: "username", Claim: "preferred_username", UserAttribute: "username"},
			{Name: "email", Claim: "email", UserAttribute: "email"},
		},
	}
}

func TestDefaultOptionsKeepDigestsByteIdentical(t *testing.T) {
	for _, mode := range []string{"", SignatureModeJWKS} {
		d := goldenDesired()
		d.SignatureMode = mode
		got, err := ComputeDesiredDigest(d)
		if err != nil || got != goldenDefaultDesiredDigest {
			t.Fatalf("mode=%q desired digest=%s err=%v", mode, got, err)
		}
		p := desiredProvider(d, got)
		if p.Config[structureDigestConfigKey] != goldenDefaultStructureDigest {
			t.Fatalf("mode=%q structure digest=%s", mode, p.Config[structureDigestConfigKey])
		}
		if p.Config["validateSignature"] != "true" || p.Config["useJwksUrl"] != "true" {
			t.Fatalf("默认必须按 JWKS 验签: %v", p.Config)
		}
		if _, ok := p.Config[skipProfileMarkerKey]; ok {
			t.Fatal("默认不得写入 skip 标记")
		}
	}
}

func TestNonDefaultOptionsChangeDigests(t *testing.T) {
	base := goldenDesired()
	baseDigest, _ := ComputeDesiredDigest(base)
	none := base
	none.SignatureMode = SignatureModeNone
	allowInsecureNoneSignature = true
	t.Cleanup(func() { allowInsecureNoneSignature = false })
	skip := base
	skip.SkipProfileReview = true
	seen := map[string]string{baseDigest: "base"}
	for name, d := range map[string]DesiredIdentitySource{"none": none, "skip": skip} {
		got, err := ComputeDesiredDigest(d)
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[got]; dup {
			t.Fatalf("%s 与 %s 摘要相同", name, prev)
		}
		seen[got] = name
	}
	email := base
	email.ClaimMappings = []ClaimMapping{{Name: "username", Claim: "email", UserAttribute: "username"}, {Name: "email", Claim: "email", UserAttribute: "email"}}
	got, _ := ComputeDesiredDigest(email)
	if got == baseDigest {
		t.Fatal("用户名取值变化必须改变摘要")
	}
}

func TestSignatureModeNoneRequiresHTTPSTokenEndpointAndEnum(t *testing.T) {
	d := goldenDesired()
	d.SignatureMode = SignatureModeNone
	if err := ValidateDesired(d); err != nil {
		t.Fatalf("https token 端点应允许 none: %v", err)
	}
	d.Endpoints.Token = "http://10.0.0.5/token"
	d.AllowPrivateHTTP = true
	err := ValidateDesired(d)
	if !errors.Is(err, ErrInvalidDesiredSource) || !errors.Is(err, ErrInsecureEndpoint) {
		t.Fatalf("私网 http 例外不得放行 none: %v", err)
	}
	d.SignatureMode = "hmac"
	d.Endpoints.Token = "https://idp.example.com/token"
	if err := ValidateDesired(d); !errors.Is(err, ErrInvalidDesiredSource) {
		t.Fatalf("未知验签方式必须拒绝: %v", err)
	}
	// jwks 模式 JWKS 仍必填；none 模式可缺省。
	d = goldenDesired()
	d.Endpoints.JWKS = ""
	if err := ValidateDesired(d); !errors.Is(err, ErrInvalidDesiredSource) {
		t.Fatalf("jwks 缺 JWKS 必须拒绝: %v", err)
	}
	d.SignatureMode = SignatureModeNone
	if err := ValidateDesired(d); err != nil {
		t.Fatalf("none 允许无 JWKS: %v", err)
	}
}

func TestDesiredProviderNoneAndSkip(t *testing.T) {
	d := goldenDesired()
	d.SignatureMode = SignatureModeNone
	d.SkipProfileReview = true
	allowInsecureNoneSignature = true
	t.Cleanup(func() { allowInsecureNoneSignature = false })
	digest, err := ComputeDesiredDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	p := desiredProvider(d, digest)
	if p.Config["validateSignature"] != "false" || p.Config[skipProfileMarkerKey] != "true" {
		t.Fatalf("config=%v", p.Config)
	}
}

// fakeKeycloak 模拟 Keycloak 管理 API 中本功能用到的最小子集，并记录写入。
type fakeKeycloak struct {
	mu          sync.Mutex
	provider    ProviderRepresentation
	hasProvider bool
	mappers     []MapperRepresentation
	reviewCfg   map[string]string // nil = 执行器尚无配置
	reviewID    string
	profile     map[string]any
	writes      []string
	forbidRealm bool // 模拟服务账号没有 manage-realm
	nextID      int
}

func newFakeKeycloak() *fakeKeycloak {
	return &fakeKeycloak{
		reviewID: "exec-review",
		profile: map[string]any{
			"unmanagedAttributePolicy": "ENABLED",
			"attributes": []any{
				map[string]any{"name": "username", "validations": map[string]any{"length": map[string]any{"min": 3.0}}},
				map[string]any{"name": "email", "required": map[string]any{"roles": []any{"user"}}},
				map[string]any{"name": "firstName", "required": map[string]any{"roles": []any{"user"}}, "displayName": "${firstName}"},
				map[string]any{"name": "lastName", "required": map[string]any{"roles": []any{"user"}}},
			},
		},
	}
}

func (f *fakeKeycloak) writeLog(s string) { f.writes = append(f.writes, s) }

func (f *fakeKeycloak) server(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		path := strings.TrimPrefix(r.URL.Path, "/sso")
		body, _ := io.ReadAll(r.Body)
		writeJSON := func(v any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
		isWrite := r.Method != http.MethodGet
		switch {
		case strings.HasSuffix(path, "/protocol/openid-connect/token"):
			tokenResponse(w)
		case path == "/admin/realms/jjdguard/identity-provider/instances/"+ProviderAlias:
			switch r.Method {
			case http.MethodGet:
				if !f.hasProvider {
					http.NotFound(w, r)
					return
				}
				writeJSON(f.provider)
			default:
				f.writeLog(r.Method + " provider")
				_ = json.Unmarshal(body, &f.provider)
				f.hasProvider = true
				w.WriteHeader(http.StatusNoContent)
			}
		case path == "/admin/realms/jjdguard/identity-provider/instances":
			f.writeLog("POST provider")
			_ = json.Unmarshal(body, &f.provider)
			f.hasProvider = true
			w.WriteHeader(http.StatusCreated)
		case path == "/admin/realms/jjdguard/identity-provider/instances/enterprise/mappers":
			if r.Method == http.MethodGet {
				writeJSON(f.mappers)
				return
			}
			var m MapperRepresentation
			_ = json.Unmarshal(body, &m)
			f.nextID++
			m.ID = "m" + string(rune('a'+f.nextID))
			f.mappers = append(f.mappers, m)
			f.writeLog("POST mapper " + m.Name)
			w.WriteHeader(http.StatusCreated)
		case strings.HasPrefix(path, "/admin/realms/jjdguard/identity-provider/instances/enterprise/mappers/"):
			id := strings.TrimPrefix(path, "/admin/realms/jjdguard/identity-provider/instances/enterprise/mappers/")
			for i, m := range f.mappers {
				if m.ID != id {
					continue
				}
				if r.Method == http.MethodDelete {
					f.writeLog("DELETE mapper " + m.Name)
					f.mappers = append(f.mappers[:i], f.mappers[i+1:]...)
				} else {
					f.writeLog("PUT mapper " + m.Name)
					_ = json.Unmarshal(body, &m)
					f.mappers[i] = m
				}
				break
			}
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(path, "/admin/realms/jjdguard/authentication/"), path == "/admin/realms/jjdguard/users/profile":
			if isWrite && f.forbidRealm {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			f.realmHandler(w, r, path, body, writeJSON)
		default:
			t.Errorf("unexpected request %s %s", r.Method, path)
			http.NotFound(w, r)
		}
	}))
}

func (f *fakeKeycloak) realmHandler(w http.ResponseWriter, r *http.Request, path string, body []byte, writeJSON func(any)) {
	switch {
	case path == "/admin/realms/jjdguard/authentication/flows/first broker login/executions":
		exec := map[string]any{"id": f.reviewID, "providerId": "idp-review-profile"}
		if f.reviewCfg != nil {
			exec["authenticationConfig"] = "cfg-review"
		}
		writeJSON([]any{map[string]any{"id": "exec-other", "providerId": "idp-create-user-if-unique"}, exec})
	case path == "/admin/realms/jjdguard/authentication/config/cfg-review":
		if r.Method == http.MethodGet {
			writeJSON(map[string]any{"id": "cfg-review", "alias": "review profile config", "config": f.reviewCfg})
			return
		}
		var in struct{ Config map[string]string }
		_ = json.Unmarshal(body, &in)
		f.reviewCfg = in.Config
		f.writeLog("PUT review-config")
		w.WriteHeader(http.StatusNoContent)
	case path == "/admin/realms/jjdguard/authentication/executions/"+f.reviewID+"/config":
		var in struct{ Config map[string]string }
		_ = json.Unmarshal(body, &in)
		f.reviewCfg = in.Config
		f.writeLog("POST review-config")
		w.WriteHeader(http.StatusCreated)
	case path == "/admin/realms/jjdguard/users/profile":
		if r.Method == http.MethodGet {
			writeJSON(f.profile)
			return
		}
		f.profile = map[string]any{}
		_ = json.Unmarshal(body, &f.profile)
		f.writeLog("PUT user-profile")
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeKeycloak) attr(name string) map[string]any {
	for _, a := range f.profile["attributes"].([]any) {
		if m := a.(map[string]any); m["name"] == name {
			return m
		}
	}
	return nil
}

func skipDesired(t *testing.T) DesiredIdentitySource {
	d := goldenDesired()
	d.SignatureMode = SignatureModeNone
	d.SkipProfileReview = true
	d.ClaimMappings = []ClaimMapping{
		{Name: "username", Claim: "email", UserAttribute: "username"},
		{Name: "email", Claim: "email", UserAttribute: "email"},
	}
	digest, err := ComputeDesiredDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	d.Digest = digest
	return d
}

func TestApplySkipProfileReviewWritesRealmSettingsAndPreservesCustomMappers(t *testing.T) {
	allowInsecureNoneSignature = true
	t.Cleanup(func() { allowInsecureNoneSignature = false })
	f := newFakeKeycloak()
	f.mappers = []MapperRepresentation{{ID: "custom1", Name: "jjdguard-username-from-email", IdentityProviderAlias: ProviderAlias,
		IdentityProviderMapper: "oidc-username-idp-mapper", Config: map[string]string{"template": "${CLAIM.email}"}}}
	f.reviewCfg = map[string]string{"update.profile.on.first.login": "missing", "other": "keep"}
	server := f.server(t)
	defer server.Close()
	client := mustTestClient(t, server, new(bytes.Buffer), nil)
	d := skipDesired(t)
	if err := client.Apply(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if f.reviewCfg["update.profile.on.first.login"] != "off" || f.reviewCfg["other"] != "keep" {
		t.Fatalf("review config=%v", f.reviewCfg)
	}
	for _, n := range []string{"firstName", "lastName"} {
		if _, ok := f.attr(n)["required"]; ok {
			t.Fatalf("%s 仍为必填", n)
		}
	}
	if _, ok := f.attr("email")["required"]; !ok {
		t.Fatal("email 的 required 不得被改动")
	}
	if f.attr("firstName")["displayName"] != "${firstName}" || f.profile["unmanagedAttributePolicy"] != "ENABLED" {
		t.Fatalf("user profile 其余字段必须原样保留: %v", f.profile)
	}
	found := false
	for _, m := range f.mappers {
		if m.Name == "jjdguard-username-from-email" {
			found = true
		}
	}
	if !found {
		t.Fatal("用户自行添加的非受管映射器被删除")
	}
	snap, err := client.Snapshot(context.Background(), RealmName, ProviderAlias)
	if err != nil || snap.StructureDrifted || snap.Digest != d.Digest {
		t.Fatalf("snapshot err=%v drifted=%v digest=%s", err, snap.StructureDrifted, snap.Digest)
	}
	// 重复 Apply（修复/重新发布）：幂等，且仍不变回默认值。
	if err := client.Apply(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if f.provider.Config["validateSignature"] != "false" || f.reviewCfg["update.profile.on.first.login"] != "off" {
		t.Fatalf("重发布把配置改回去了: %v %v", f.provider.Config, f.reviewCfg)
	}
}

func TestApplySkipProfileReviewCreatesMissingReviewConfig(t *testing.T) {
	allowInsecureNoneSignature = true
	t.Cleanup(func() { allowInsecureNoneSignature = false })
	f := newFakeKeycloak()
	server := f.server(t)
	defer server.Close()
	client := mustTestClient(t, server, new(bytes.Buffer), nil)
	if err := client.Apply(context.Background(), skipDesired(t)); err != nil {
		t.Fatal(err)
	}
	if f.reviewCfg["update.profile.on.first.login"] != "off" {
		t.Fatalf("review config=%v", f.reviewCfg)
	}
}

func TestApplyWithoutSkipNeverTouchesRealmSettings(t *testing.T) {
	f := newFakeKeycloak()
	f.reviewCfg = map[string]string{"update.profile.on.first.login": "missing"}
	f.forbidRealm = true
	server := f.server(t)
	defer server.Close()
	client := mustTestClient(t, server, new(bytes.Buffer), nil)
	d := goldenDesired()
	d.Digest, _ = ComputeDesiredDigest(d)
	if err := client.Apply(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	// 关闭 skip（默认）不回滚 realm 共享设置，也不会访问它们。
	f.reviewCfg["update.profile.on.first.login"] = "off"
	if err := client.Apply(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	for _, w := range f.writes {
		if strings.Contains(w, "review-config") || strings.Contains(w, "user-profile") {
			t.Fatalf("默认选项不得写 realm 级设置: %v", f.writes)
		}
	}
	if f.reviewCfg["update.profile.on.first.login"] != "off" {
		t.Fatal("关闭选项不得把 realm 设置改回去")
	}
	snap, err := client.Snapshot(context.Background(), RealmName, ProviderAlias)
	if err != nil || snap.StructureDrifted || snap.Digest != d.Digest {
		t.Fatalf("默认路径 snapshot err=%v drifted=%v", err, snap.StructureDrifted)
	}
}

func TestApplySkipProfileReviewFailsClearlyWithoutManageRealm(t *testing.T) {
	allowInsecureNoneSignature = true
	t.Cleanup(func() { allowInsecureNoneSignature = false })
	f := newFakeKeycloak()
	f.forbidRealm = true
	server := f.server(t)
	defer server.Close()
	client := mustTestClient(t, server, new(bytes.Buffer), nil)
	err := client.Apply(context.Background(), skipDesired(t))
	if !errors.Is(err, ErrManageRealmRequired) || errors.Is(err, ErrRuntimeUnauthorized) {
		t.Fatalf("缺 manage-realm 应返回专用错误: %v", err)
	}
}

func TestSnapshotDetectsSkipProfileDrift(t *testing.T) {
	allowInsecureNoneSignature = true
	t.Cleanup(func() { allowInsecureNoneSignature = false })
	f := newFakeKeycloak()
	server := f.server(t)
	defer server.Close()
	client := mustTestClient(t, server, new(bytes.Buffer), nil)
	d := skipDesired(t)
	if err := client.Apply(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	f.reviewCfg["update.profile.on.first.login"] = "on"
	snap, _ := client.Snapshot(context.Background(), RealmName, ProviderAlias)
	if !snap.StructureDrifted {
		t.Fatal("review profile 被改回 on 必须判漂移")
	}
	if err := client.Apply(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	f.attr("lastName")["required"] = map[string]any{"roles": []any{"user"}}
	snap, _ = client.Snapshot(context.Background(), RealmName, ProviderAlias)
	if !snap.StructureDrifted {
		t.Fatal("lastName 恢复必填必须判漂移")
	}
}

func TestObserveInfersSettingsReadOnly(t *testing.T) {
	f := newFakeKeycloak()
	f.hasProvider = true
	f.provider = ProviderRepresentation{Alias: ProviderAlias, ProviderID: "oidc", Enabled: true,
		Config: map[string]string{"validateSignature": "false", skipProfileMarkerKey: ""}}
	f.mappers = []MapperRepresentation{
		{ID: "x1", Name: "jjdguard-claim-email", IdentityProviderMapper: "oidc-user-attribute-idp-mapper",
			Config: map[string]string{"claim": "email", "user.attribute": "email"}},
		{ID: "x2", Name: "jjdguard-username-from-email", IdentityProviderMapper: "oidc-username-idp-mapper",
			Config: map[string]string{"template": "${CLAIM.email}"}},
	}
	f.reviewCfg = map[string]string{"update.profile.on.first.login": "off"}
	server := f.server(t)
	defer server.Close()
	client := mustTestClient(t, server, new(bytes.Buffer), nil)
	obs, err := client.Observe(context.Background(), RealmName, ProviderAlias)
	if err != nil {
		t.Fatal(err)
	}
	if !obs.Exists || obs.SignatureMode != SignatureModeNone || obs.UsernameClaim != "email" || !obs.SkipProfileReview {
		t.Fatalf("obs=%+v", obs)
	}
	if len(f.writes) != 0 {
		t.Fatalf("采纳反推必须只读 Keycloak: %v", f.writes)
	}
	// 验签开启 + 受管 username 映射器：按受管映射器取值。
	f.provider.Config = map[string]string{"validateSignature": "true"}
	f.mappers = []MapperRepresentation{{ID: "x3", Name: "jjdguard-claim-username", IdentityProviderMapper: "oidc-user-attribute-idp-mapper",
		Config: map[string]string{"claim": "sub", "user.attribute": "username"}}}
	f.reviewCfg = map[string]string{"update.profile.on.first.login": "missing"}
	obs, _ = client.Observe(context.Background(), RealmName, ProviderAlias)
	if obs.SignatureMode != SignatureModeJWKS || obs.UsernameClaim != "sub" || obs.SkipProfileReview {
		t.Fatalf("obs=%+v", obs)
	}
	// 没有任何 username 来源：不臆测。
	f.mappers = nil
	obs, _ = client.Observe(context.Background(), RealmName, ProviderAlias)
	if obs.UsernameClaim != "" {
		t.Fatalf("不应臆测用户名取值: %+v", obs)
	}
	if len(f.writes) != 0 {
		t.Fatalf("writes=%v", f.writes)
	}
}
