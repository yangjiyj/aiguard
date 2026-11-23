package identityruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// 真 Keycloak 验收（IDENTITY_PROFILE_LIVE_URL 开关）：HS256 无 kid、不返回 preferred_username 的 mock IdP
// 经 signature_mode=none + username_claim=email + skip_profile_review=true 发布后真实登录。
//
// 环境变量：
//   IDENTITY_PROFILE_LIVE_URL           Keycloak 根地址，如 http://127.0.0.1:18080
//   IDENTITY_PROFILE_LIVE_CLIENT_ID/SECRET  jjdguard realm 的服务账号（需含 manage-realm 才能做 skip）
//   IDENTITY_PROFILE_LIVE_ADMIN_USER/PASS   master 管理员，仅用于核对用户
//   IDENTITY_PROFILE_LIVE_IDP_BASE      mock IdP，如 http://127.0.0.1:18099
//   IDENTITY_PROFILE_LIVE_EXPECT_FORBIDDEN=1  服务账号无 manage-realm：断言带 skip 的发布被拒绝（401/403 映射）
//
// mock IdP 是 http：测试里通过同包开关 allowInsecureNoneSignature 放行「none 必须 https」，生产路径恒严格。

type liveEnv struct {
	kc, idpBase, adminUser, adminPass string
	client                            *Client
}

func newLiveEnv(t *testing.T) *liveEnv {
	t.Helper()
	kc := os.Getenv("IDENTITY_PROFILE_LIVE_URL")
	if kc == "" {
		t.Skip("IDENTITY_PROFILE_LIVE_URL not set")
	}
	client, err := newClient(clientOptions{
		RuntimeURL: kc, ClientID: os.Getenv("IDENTITY_PROFILE_LIVE_CLIENT_ID"),
		ClientSecret: os.Getenv("IDENTITY_PROFILE_LIVE_CLIENT_SECRET"),
		HTTPClient:   &http.Client{Timeout: 10 * time.Second}, Logger: log.New(new(bytes.Buffer), "", 0),
		RequestTimeout: 10 * time.Second, MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	allowInsecureNoneSignature = true
	t.Cleanup(func() { allowInsecureNoneSignature = false })
	return &liveEnv{kc: kc, idpBase: os.Getenv("IDENTITY_PROFILE_LIVE_IDP_BASE"),
		adminUser: os.Getenv("IDENTITY_PROFILE_LIVE_ADMIN_USER"), adminPass: os.Getenv("IDENTITY_PROFILE_LIVE_ADMIN_PASS"), client: client}
}

func (e *liveEnv) desired(t *testing.T, alias, signature, usernameClaim string, skip bool) DesiredIdentitySource {
	t.Helper()
	b := e.idpBase + "/oidc"
	d := DesiredIdentitySource{
		Realm: RealmName, Alias: alias, DisplayName: "live " + alias,
		Endpoints: DiscoveryEndpoints{Issuer: b, Authorization: b + "/auth", Token: b + "/token", JWKS: b + "/jwks"}, // 不配 userinfo：保证 IdP 完全不提供姓名，才能真实检验「首登不弹资料页」
		ClientID:  "kc", ClientSecret: "client-secret-for-hs256-experiment-0123456789",
		Scopes: []string{"openid", "email", "profile"}, AllowPrivateHTTP: true,
		SignatureMode: signature, SkipProfileReview: skip,
		ClaimMappings: []ClaimMapping{
			{Name: "subject", Claim: "sub", UserAttribute: "external_subject"},
			{Name: "username", Claim: usernameClaim, UserAttribute: "username"},
			{Name: "name", Claim: "name", UserAttribute: "name"},
			{Name: "email", Claim: "email", UserAttribute: "email"},
		},
	}
	digest, err := ComputeDesiredDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	d.Digest = digest
	return d
}

func (e *liveEnv) adminToken(t *testing.T) string {
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {e.adminUser}, "password": {e.adminPass}}
	resp, err := http.PostForm(e.kc+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.AccessToken == "" {
		t.Fatal("master admin token empty")
	}
	return out.AccessToken
}

func (e *liveEnv) adminGet(t *testing.T, path string, out any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.kc+"/admin/realms/"+RealmName+path, nil)
	req.Header.Set("Authorization", "Bearer "+e.adminToken(t))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || json.Unmarshal(raw, out) != nil {
		t.Fatalf("admin GET %s: %d %s", path, resp.StatusCode, raw)
	}
}

func (e *liveEnv) deleteUsers(t *testing.T) {
	var users []struct{ ID string }
	e.adminGet(t, "/users", &users)
	for _, u := range users {
		req, _ := http.NewRequest(http.MethodDelete, e.kc+"/admin/realms/"+RealmName+"/users/"+u.ID, nil)
		req.Header.Set("Authorization", "Bearer "+e.adminToken(t))
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}
}

// login 走真实的授权码流程：kc_idp_hint 直达 IdP → mock IdP 自动回调 → broker 端点 → 回到应用回调。
// 返回最终落到应用回调的 URL；中途落到任何页面（资料页/报错页）都视为失败并返回页面标题。
func (e *liveEnv) login(alias string) (string, error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	next := e.kc + "/realms/" + RealmName + "/protocol/openid-connect/auth?" + url.Values{
		"client_id": {"app"}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:9/cb"},
		"scope": {"openid"}, "kc_idp_hint": {alias}}.Encode()
	for i := 0; i < 15; i++ {
		resp, err := client.Get(next)
		if err != nil {
			return "", err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
			if strings.HasPrefix(loc, "http://127.0.0.1:9/") {
				if strings.Contains(loc, "error=") {
					return loc, fmt.Errorf("应用回调带错误: %s", loc)
				}
				return loc, nil
			}
			base, _ := url.Parse(next)
			target, _ := base.Parse(loc)
			next = target.String()
			continue
		}
		title := ""
		if s := strings.Index(string(body), "<title>"); s >= 0 {
			if e2 := strings.Index(string(body[s:]), "</title>"); e2 > 0 {
				title = strings.TrimSpace(string(body[s+7 : s+e2]))
			}
		}
		return "", fmt.Errorf("停在页面 status=%d title=%q", resp.StatusCode, title)
	}
	return "", errors.New("重定向过多")
}

type liveUser struct {
	Username  string `json:"username"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
}

func (e *liveEnv) users(t *testing.T) []liveUser {
	var users []liveUser
	e.adminGet(t, "/users", &users)
	return users
}

func TestLiveSkipProfileRequiresManageRealm(t *testing.T) {
	if os.Getenv("IDENTITY_PROFILE_LIVE_EXPECT_FORBIDDEN") != "1" {
		t.Skip("仅在服务账号无 manage-realm 时运行")
	}
	e := newLiveEnv(t)
	ctx := context.Background()
	alias := "jjd-live-forbidden"
	t.Cleanup(func() { _ = e.client.Restore(ctx, RuntimeSnapshot{Realm: RealmName, Alias: alias}) })
	err := e.client.Apply(ctx, e.desired(t, alias, SignatureModeNone, "email", true))
	if !errors.Is(err, ErrManageRealmRequired) {
		t.Fatalf("无 manage-realm 时带 skip 的发布应返回 ErrManageRealmRequired，实际: %v", err)
	}
	// 默认选项（不带 skip）在最小权限下仍可发布，证明未破坏既有最小权限部署。
	std := e.desired(t, alias, "", "preferred_username", false)
	if err := e.client.Apply(ctx, std); err != nil {
		t.Fatalf("最小权限下默认发布失败: %v", err)
	}
	snap, err := e.client.Snapshot(ctx, RealmName, alias)
	if err != nil || snap.StructureDrifted {
		t.Fatalf("snapshot err=%v drifted=%v", err, snap.StructureDrifted)
	}
}

func TestLiveHS256NoKidEmailUsernameSkipProfile(t *testing.T) {
	if os.Getenv("IDENTITY_PROFILE_LIVE_EXPECT_FORBIDDEN") == "1" {
		t.Skip("服务账号无 manage-realm 场景")
	}
	e := newLiveEnv(t)
	ctx := context.Background()
	alias := "jjd-live-hs"
	t.Cleanup(func() {
		_ = e.client.Restore(ctx, RuntimeSnapshot{Realm: RealmName, Alias: alias})
		e.deleteUsers(t)
	})
	// mock IdP 不返回 name，用来证明「首次登录不弹资料页」确实生效。
	if err := os.WriteFile("/tmp/idp-noname", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove("/tmp/idp-noname") })
	e.deleteUsers(t)

	// 对照组（必须在全新 realm 上先跑）：none + email 但不跳过资料页，IdP 不给姓名 → 应停在资料页。
	ctrl := "jjd-live-ctrl"
	t.Cleanup(func() { _ = e.client.Restore(ctx, RuntimeSnapshot{Realm: RealmName, Alias: ctrl}) })
	if err := e.client.Apply(ctx, e.desired(t, ctrl, SignatureModeNone, "email", false)); err != nil {
		t.Fatalf("对照组 Apply: %v", err)
	}
	if _, err := e.login(ctrl); err == nil || !strings.Contains(err.Error(), "停在页面") {
		t.Fatalf("对照组应停在资料页（证明不跳过时确会弹页），实际: %v", err)
	} else {
		t.Logf("对照组（skip=false）符合预期: %v", err)
	}
	_ = e.client.Restore(ctx, RuntimeSnapshot{Realm: RealmName, Alias: ctrl})
	e.deleteUsers(t)

	d := e.desired(t, alias, SignatureModeNone, "email", true)
	if err := e.client.Apply(ctx, d); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// 用户自行添加的非受管映射器（模板取邮箱），必须在后续发布中保留。
	custom := MapperRepresentation{Name: "customer-own-mapper", IdentityProviderAlias: alias,
		IdentityProviderMapper: "hardcoded-attribute-idp-mapper",
		Config:                 map[string]string{"attribute": "tag", "attribute.value": "mine", "syncMode": "INHERIT"}}
	if err := e.client.doJSON(ctx, http.MethodPost, mapperCollectionPath(alias), custom, nil, http.StatusCreated, http.StatusNoContent); err != nil {
		t.Fatal(err)
	}

	snap, err := e.client.Snapshot(ctx, RealmName, alias)
	if err != nil || !snap.Exists || snap.StructureDrifted || snap.Digest != d.Digest {
		t.Fatalf("发布后 snapshot: err=%v exists=%v drifted=%v digest=%s", err, snap.Exists, snap.StructureDrifted, snap.Digest)
	}
	if snap.Provider.Config["validateSignature"] != "false" || snap.Provider.Config[skipProfileMarkerKey] != "true" {
		t.Fatalf("provider config: %v", snap.Provider.Config)
	}
	status, err := e.client.Status(ctx, RealmName, alias)
	if err != nil || status.Drifted || !status.Enabled {
		t.Fatalf("status=%+v err=%v", status, err)
	}

	if loc, err := e.login(alias); err != nil {
		t.Fatalf("真实登录失败: %v", err)
	} else {
		t.Logf("登录成功 -> %s", loc[:min(len(loc), 60)])
	}
	users := e.users(t)
	if len(users) != 1 || users[0].Username != "zhang.san@example.cn" {
		t.Fatalf("用户名应为完整邮箱: %+v", users)
	}
	t.Logf("用户: %+v", users[0])

	// 「修复/重新发布」：再次 Apply，配置不得被改回默认；删用户后再次首登仍直接进入。
	if err := e.client.Apply(ctx, d); err != nil {
		t.Fatalf("re-Apply: %v", err)
	}
	snap, _ = e.client.Snapshot(ctx, RealmName, alias)
	if snap.StructureDrifted || snap.Digest != d.Digest || snap.Provider.Config["validateSignature"] != "false" {
		t.Fatalf("重新发布后配置被改动: drifted=%v digest=%s cfg=%v", snap.StructureDrifted, snap.Digest, snap.Provider.Config)
	}
	hasCustom, hasManagedUsername := false, false
	for _, m := range snap.Mappers {
		hasCustom = hasCustom || m.Name == "customer-own-mapper"
		if m.Name == managedMapperPrefix+"username" && m.Config["claim"] == "email" {
			hasManagedUsername = true
		}
	}
	if !hasCustom || !hasManagedUsername {
		t.Fatalf("映射器: custom=%v managedUsername=%v", hasCustom, hasManagedUsername)
	}
	e.deleteUsers(t)
	if _, err := e.login(alias); err != nil {
		t.Fatalf("重新发布后真实登录失败: %v", err)
	}
	if users := e.users(t); len(users) != 1 || users[0].Username != "zhang.san@example.cn" {
		t.Fatalf("重新发布后用户名: %+v", users)
	}

	// 采纳反推（只读）：对已发布的运行态反推应与发布选项一致。
	obs, err := e.client.Observe(ctx, RealmName, alias)
	if err != nil || obs.SignatureMode != SignatureModeNone || obs.UsernameClaim != "email" || !obs.SkipProfileReview {
		t.Fatalf("observe=%+v err=%v", obs, err)
	}

	// 关闭 skip（默认选项）的另一个身份源发布：realm 级设置不得被回滚。
	other := "jjd-live-std"
	t.Cleanup(func() { _ = e.client.Restore(ctx, RuntimeSnapshot{Realm: RealmName, Alias: other}) })
	std := e.desired(t, other, "", "preferred_username", false)
	if err := e.client.Apply(ctx, std); err != nil {
		t.Fatalf("标准路径 Apply: %v", err)
	}
	stdSnap, err := e.client.Snapshot(ctx, RealmName, other)
	if err != nil || stdSnap.StructureDrifted || stdSnap.Digest != std.Digest {
		t.Fatalf("标准路径 snapshot err=%v drifted=%v", err, stdSnap.StructureDrifted)
	}
	if stdSnap.Provider.Config["validateSignature"] != "true" || stdSnap.Provider.Config["useJwksUrl"] != "true" ||
		stdSnap.Provider.Config["jwksUrl"] == "" {
		t.Fatalf("标准路径必须按 JWKS 验签: %v", stdSnap.Provider.Config)
	}
	if _, has := stdSnap.Provider.Config[skipProfileMarkerKey]; has {
		t.Fatal("标准路径不应写 skip 标记")
	}
	again, _ := e.client.Snapshot(ctx, RealmName, alias)
	if again.StructureDrifted {
		t.Fatal("别的身份源发布后，首个身份源不应漂移（realm 设置未被回滚）")
	}
}

// 模拟客户现场：按默认选项发布后，现场手工把 Keycloak 改成「关验签、删 jjdguard-claim-username、
// 另加 oidc-username-idp-mapper(${CLAIM.email})」。采纳反推必须读出 none/email，且全程不写运行态。
func TestLiveObserveManuallyEditedSite(t *testing.T) {
	if os.Getenv("IDENTITY_PROFILE_LIVE_EXPECT_FORBIDDEN") == "1" {
		t.Skip("服务账号无 manage-realm 场景")
	}
	e := newLiveEnv(t)
	ctx := context.Background()
	alias := "jjd-live-site"
	t.Cleanup(func() { _ = e.client.Restore(ctx, RuntimeSnapshot{Realm: RealmName, Alias: alias}) })
	d := e.desired(t, alias, "", "preferred_username", false)
	if err := e.client.Apply(ctx, d); err != nil {
		t.Fatal(err)
	}
	snap, _ := e.client.Snapshot(ctx, RealmName, alias)
	provider := snap.Provider
	provider.Config["validateSignature"] = "false"
	if err := e.client.doJSON(ctx, http.MethodPut, providerPath(alias), provider, nil, http.StatusOK, http.StatusNoContent); err != nil {
		t.Fatal(err)
	}
	for _, m := range snap.Mappers {
		if m.Name == managedMapperPrefix+"username" {
			if err := e.client.doJSON(ctx, http.MethodDelete, mapperCollectionPath(alias)+"/"+m.ID, nil, nil, http.StatusNoContent, http.StatusOK); err != nil {
				t.Fatal(err)
			}
		}
	}
	manual := MapperRepresentation{Name: "jjdguard-username-from-email", IdentityProviderAlias: alias,
		IdentityProviderMapper: "oidc-username-idp-mapper", Config: map[string]string{"template": "${CLAIM.email}", "syncMode": "INHERIT"}}
	if err := e.client.doJSON(ctx, http.MethodPost, mapperCollectionPath(alias), manual, nil, http.StatusCreated, http.StatusNoContent); err != nil {
		t.Fatal(err)
	}
	before, _ := e.client.Snapshot(ctx, RealmName, alias)
	if !before.StructureDrifted {
		t.Fatal("手工改动后应判漂移（复现现场 drifted）")
	}
	obs, err := e.client.Observe(ctx, RealmName, alias)
	if err != nil || obs.SignatureMode != SignatureModeNone || obs.UsernameClaim != "email" || !obs.SkipProfileReview {
		t.Fatalf("observe=%+v err=%v", obs, err)
	}
	after, _ := e.client.Snapshot(ctx, RealmName, alias)
	a, _ := json.Marshal(before.Provider.Config)
	b, _ := json.Marshal(after.Provider.Config)
	if string(a) != string(b) || len(before.Mappers) != len(after.Mappers) {
		t.Fatal("Observe 不得改动运行态")
	}
}
