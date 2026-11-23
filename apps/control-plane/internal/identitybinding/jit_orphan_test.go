package identitybinding

// High-1 第 4 项：被禁用/已删除用户的 Keycloak 账号能否通过 Chat 门户 JIT 重新建号。
//
// BindAndResolve 的行为（核实结论，用测试钉死）：
//  1. 它只认「已验证的外部身份」，完全不查 Keycloak 里账号是否仍启用——不存在这种缓存，也没有绕过路径可以让它「忽略禁用」，
//     因为禁用的拦截点本来就不在这里，而在 IdP：Keycloak 对 enabled=false 的用户不会发 token，门户拿不到 profile，根本走不到这里。
//  2. 所以 JIT 的安全性依赖一个前提：用户被删除时 Keycloak 账号已先被禁用。这正是 High-1 把「先禁用、失败即中止」放在删库之前的原因。
//  3. 一旦 users 行被删而 Keycloak 账号仍可登录，这里会把它当作「没见过的外部身份」，建出一个新的 chat_user——下面第一个用例证明这点，
//     说明为什么顺序不能反。
//  4. 已存在但被禁用的本地用户（status != active）：link 还在，走 resolveLinkedUser，PortalAllowed 为 false，不会被重新启用或重建。

import (
	"context"
	"testing"
)

func localIdentity(subject string) ExternalIdentity {
	return ExternalIdentity{TenantID: "tenant-a", Issuer: "https://sso.example/realms/x", SourceType: "local",
		ExternalSubject: subject, Username: "alice", Email: "alice@example.test"}
}

// 用户行被删除、link 随之级联消失，而 Keycloak 账号仍可登录：BindAndResolve 会建出一个全新的 chat_user。
// 这就是「必须先禁用 Keycloak、再删库」的原因：禁用之后 Keycloak 不再发 token，请求到不了这里。
func TestBindAndResolveRecreatesAnAccountForAnOrphanThatCanStillAuthenticate(t *testing.T) {
	store := newFakeStore()
	svc := NewService(store)
	first, err := svc.BindAndResolve(context.Background(), localIdentity("kc-orphan"))
	if err != nil {
		t.Fatal(err)
	}
	// 模拟删除用户：users 行与 link 一并消失（user_identity_links 对 users 是 ON DELETE CASCADE）。
	delete(store.users, "tenant-a|"+first.UserID)
	delete(store.links, stableKey(localIdentity("kc-orphan")))

	second, err := svc.BindAndResolve(context.Background(), localIdentity("kc-orphan"))
	if err != nil {
		t.Fatal(err)
	}
	if second.UserID == first.UserID {
		t.Fatal("预期是建出一个新用户（证明为什么必须先在 Keycloak 禁用）")
	}
	if u := store.users["tenant-a|"+second.UserID]; u.Role != "chat_user" || u.Status != "active" {
		t.Fatalf("JIT 建出的应是 active chat_user：%+v", u)
	}
}

// 已存在但被禁用的本地用户：link 还在，BindAndResolve 不会重新启用它，也不会建新用户，门户入口保持关闭。
func TestBindAndResolveNeverReEnablesADisabledUserAndDoesNotCreateAnother(t *testing.T) {
	store := newFakeStore()
	svc := NewService(store)
	first, err := svc.BindAndResolve(context.Background(), localIdentity("kc-disabled"))
	if err != nil {
		t.Fatal(err)
	}
	key := "tenant-a|" + first.UserID
	u := store.users[key]
	u.Status = "disabled"
	store.users[key] = u
	before := len(store.users)

	res, err := svc.BindAndResolve(context.Background(), localIdentity("kc-disabled"))
	if err != nil {
		t.Fatal(err)
	}
	if res.UserID != first.UserID || len(store.users) != before {
		t.Fatalf("不应建新用户：%s vs %s，用户数 %d -> %d", res.UserID, first.UserID, before, len(store.users))
	}
	if res.PortalAllowed {
		t.Fatal("被禁用的用户不得获得门户入口")
	}
	if store.users[key].Status != "disabled" {
		t.Fatalf("BindAndResolve 不得改动用户状态：%q", store.users[key].Status)
	}
}
