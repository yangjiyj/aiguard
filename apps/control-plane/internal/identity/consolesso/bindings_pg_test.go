package consolesso

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 真库（需迁移 931）：cas/wecom 绑定可写入；按协议类型隔离解析；OIDC 绑定不能被 CAS 登录借用；
// 同一外部主体不能绑到两个账号；删除只影响 cas/wecom 绑定。
func TestPGProviderBindings(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("JJD_REQUIRE_IDENTITY_DB_TESTS") == "1" {
			t.Fatal("CONTENT_LOGS_TEST_DATABASE_URL is required when JJD_REQUIRE_IDENTITY_DB_TESTS=1")
		}
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tenant, user, other := "tpb_"+sfx, "upb_"+sfx, "upb2_"+sfx
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO tenants (id,name,edition,status,is_test) VALUES ($1,$1,'enterprise','active',TRUE)`, tenant)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM user_identity_links WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant)
	})
	for _, id := range []string{user, other} {
		exec(`INSERT INTO users (id,tenant_id,username,email,password_hash,role,status) VALUES ($1,$2,$3,$4,'x','tenant_admin','active')`, id, tenant, id, id+"@x.test")
	}
	casIssuer := "https://cas-" + sfx + ".example.gov.cn/cas"
	wecomIssuer := "wecom:ww" + sfx[len(sfx)-10:]
	store := NewBindingStore(pool)
	resolver := NewPGSubjectResolver(pool).(*pgSubjectResolver)

	b, created, err := store.Create(ctx, Binding{TenantID: tenant, UserID: user, Provider: ProviderCAS, Issuer: casIssuer + "/", Subject: "zhangsan"})
	if err != nil || !created || b.Issuer != casIssuer {
		t.Fatalf("create cas binding: %+v %v %v", b, created, err)
	}
	if again, created, err := store.Create(ctx, Binding{TenantID: tenant, UserID: user, Provider: ProviderCAS, Issuer: casIssuer, Subject: "zhangsan"}); err != nil || created || again.ID != b.ID {
		t.Fatalf("idempotent create: %+v %v %v", again, created, err)
	}
	if _, _, err := store.Create(ctx, Binding{TenantID: tenant, UserID: other, Provider: ProviderCAS, Issuer: casIssuer, Subject: "zhangsan"}); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("same CAS user bound to a second account: %v", err)
	}
	if _, _, err := store.Create(ctx, Binding{TenantID: tenant, UserID: user, Provider: ProviderWeCom, Issuer: wecomIssuer, Subject: "zhangsan"}); err != nil {
		t.Fatalf("create wecom binding: %v", err)
	}

	if gotT, gotU, err := resolver.ResolveProviderSubject(ctx, ProviderCAS, casIssuer, "zhangsan"); err != nil || gotT != tenant || gotU != user {
		t.Fatalf("resolve cas: %q %q %v", gotT, gotU, err)
	}
	if _, gotU, err := resolver.ResolveProviderSubject(ctx, ProviderWeCom, wecomIssuer, "zhangsan"); err != nil || gotU != user {
		t.Fatalf("resolve wecom: %q %v", gotU, err)
	}
	// CAS 绑定不能被 OIDC 登录借用，反之亦然。
	if _, _, err := resolver.ResolveConsoleSubject(ctx, casIssuer, "zhangsan"); !errors.Is(err, errAccountNotLinked) {
		t.Fatalf("cas binding leaked into oidc resolver: %v", err)
	}
	exec(`INSERT INTO user_identity_links (id,tenant_id,user_id,issuer,source_type,source_id,external_subject) VALUES ($1,$2,$3,$4,'oidc','',$5)`, "lo_"+sfx, tenant, other, casIssuer, "lisi")
	if _, _, err := resolver.ResolveProviderSubject(ctx, ProviderCAS, casIssuer, "lisi"); !errors.Is(err, errAccountNotLinked) {
		t.Fatalf("oidc binding leaked into cas resolver: %v", err)
	}
	if _, _, err := resolver.ResolveProviderSubject(ctx, "oidc", casIssuer, "lisi"); !errors.Is(err, errAccountNotLinked) {
		t.Fatalf("provider resolver must only serve cas/wecom: %v", err)
	}

	// 迁移 931 的约束：未知 source_type、非法 wecom issuer 被库拒绝。
	if _, err := pool.Exec(ctx, `INSERT INTO user_identity_links (id,tenant_id,user_id,issuer,source_type,source_id,external_subject) VALUES ($1,$2,$3,'x','saml','','s')`, "lx_"+sfx, tenant, user); err == nil {
		t.Fatal("unknown source_type accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO user_identity_links (id,tenant_id,user_id,issuer,source_type,source_id,external_subject) VALUES ($1,$2,$3,'https://x','wecom','','s')`, "ly_"+sfx, tenant, user); err == nil {
		t.Fatal("wecom binding with non-corp issuer accepted")
	}

	list, err := store.List(ctx, tenant, user)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v %v", list, err)
	}
	// 删除只作用于 cas/wecom：拿 OIDC 绑定的 id 删不掉。
	if _, err := store.Delete(ctx, tenant, "lo_"+sfx); !errors.Is(err, ErrBindingNotFound) {
		t.Fatalf("oidc binding deletable via cas/wecom api: %v", err)
	}
	if _, err := store.Delete(ctx, "other-tenant", b.ID); !errors.Is(err, ErrBindingNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	if _, err := store.Delete(ctx, tenant, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolver.ResolveProviderSubject(ctx, ProviderCAS, casIssuer, "zhangsan"); !errors.Is(err, errAccountNotLinked) {
		t.Fatalf("deleted binding still resolves: %v", err)
	}
}
