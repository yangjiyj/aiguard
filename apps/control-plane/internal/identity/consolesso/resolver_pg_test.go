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

// 真库：只按 user_identity_links 的 (issuer, local/oidc, subject) 绑定找账号；
// 同名/同邮箱但未绑定的账号不会被匹配。
func TestPGSubjectResolver(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	// 先登记 Close：Cleanup 按 LIFO 执行，保证数据清理在连接池关闭之前完成。
	t.Cleanup(pool.Close)
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	subject := "sub-a-" + sfx
	tenant, user, other := "tcs_"+sfx, "ucs_"+sfx, "ucs2_"+sfx
	issuer := "https://sso.example/sso/realms/jjdguard"
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
	exec(`INSERT INTO user_identity_links (id,tenant_id,user_id,issuer,source_type,source_id,external_subject) VALUES ($1,$2,$3,$4,'oidc','',$5)`, "l1_"+sfx, tenant, user, issuer, subject)
	exec(`INSERT INTO user_identity_links (id,tenant_id,user_id,issuer,source_type,source_id,external_subject) VALUES ($1,$2,$3,$4,'local','',$5)`, "l2_"+sfx, tenant, user, issuer, subject)

	r := NewPGSubjectResolver(pool)
	gotTenant, gotUser, err := r.ResolveConsoleSubject(ctx, issuer+"/", subject)
	if err != nil || gotTenant != tenant || gotUser != user {
		t.Fatalf("resolve = %q %q %v", gotTenant, gotUser, err)
	}
	if _, _, err := r.ResolveConsoleSubject(ctx, issuer, other); !errors.Is(err, errAccountNotLinked) {
		t.Fatalf("username must not be used as subject: %v", err)
	}
	if _, _, err := r.ResolveConsoleSubject(ctx, "https://other/realms/jjdguard", subject); !errors.Is(err, errAccountNotLinked) {
		t.Fatalf("foreign issuer matched: %v", err)
	}
	// 同一 issuer+subject 绑到另一个租户的账号：拒绝，不猜。
	tenant2, user2 := "tcs2_"+sfx, "ucs3_"+sfx
	exec(`INSERT INTO tenants (id,name,edition,status,is_test) VALUES ($1,$1,'enterprise','active',TRUE)`, tenant2)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM user_identity_links WHERE tenant_id=$1`, tenant2)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id=$1`, tenant2)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant2)
	})
	exec(`INSERT INTO users (id,tenant_id,username,email,password_hash,role,status) VALUES ($1,$2,$3,$4,'x','tenant_admin','active')`, user2, tenant2, user2, user2+"@x.test")
	exec(`INSERT INTO user_identity_links (id,tenant_id,user_id,issuer,source_type,source_id,external_subject) VALUES ($1,$2,$3,$4,'oidc','',$5)`, "l3_"+sfx, tenant2, user2, issuer, subject)
	if _, _, err := r.ResolveConsoleSubject(ctx, issuer, subject); !errors.Is(err, errAccountAmbiguous) {
		t.Fatalf("ambiguous subject resolved: %v", err)
	}
}
