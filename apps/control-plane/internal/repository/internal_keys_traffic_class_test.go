package repository

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 真实 PostgreSQL：traffic_class 的写入必须带租户条件，跨租户、已删除密钥、非法取值都不能写入。
func TestInternalKeySetTrafficClassIsTenantScoped(t *testing.T) {
	dsn := os.Getenv("KEY_TRAFFIC_CLASS_TEST_DSN")
	if dsn == "" {
		t.Skip("KEY_TRAFFIC_CLASS_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(ctx, `CREATE TEMP TABLE internal_keys(id text PRIMARY KEY, tenant_id text, traffic_class text NOT NULL DEFAULT '' CHECK (traffic_class IN ('','evaluation','coding')), deleted_at timestamptz);
INSERT INTO internal_keys(id,tenant_id) VALUES('k-a','tenant-a'),('k-b','tenant-b');
INSERT INTO internal_keys(id,tenant_id,deleted_at) VALUES('k-gone','tenant-a',now());`); err != nil {
		t.Fatal(err)
	}
	conn, err := db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	repo := &InternalKeyRepository{db: nil}
	get := func(id string) string {
		var v string
		if err := conn.QueryRow(ctx, "SELECT traffic_class FROM internal_keys WHERE id=$1", id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if err = repo.setTrafficClass(ctx, conn, "tenant-a", "k-a", "evaluation"); err != nil || get("k-a") != "evaluation" {
		t.Fatalf("own tenant write failed: %v %q", err, get("k-a"))
	}
	if err = repo.setTrafficClass(ctx, conn, "tenant-a", "k-b", "evaluation"); !errors.Is(err, ErrKeyNotFound) || get("k-b") != "" {
		t.Fatalf("cross-tenant write must be rejected without touching the row: %v %q", err, get("k-b"))
	}
	if err = repo.setTrafficClass(ctx, conn, "tenant-a", "k-gone", "coding"); !errors.Is(err, ErrKeyNotFound) || get("k-gone") != "" {
		t.Fatalf("deleted key must not be writable: %v %q", err, get("k-gone"))
	}
	if err = repo.setTrafficClass(ctx, conn, "tenant-a", "k-a", "bogus"); err == nil || get("k-a") != "evaluation" {
		t.Fatalf("invalid class must be rejected and leave value intact: %v %q", err, get("k-a"))
	}
	if err = repo.setTrafficClass(ctx, conn, "tenant-a", "k-a", ""); err != nil || get("k-a") != "" {
		t.Fatalf("clearing the mark failed: %v %q", err, get("k-a"))
	}
}

// 密钥列表必须把 traffic_class 带给控制台，否则管理员看不到也改不了。
func TestInternalKeyListReturnsTrafficClass(t *testing.T) {
	dsn := os.Getenv("KEY_TRAFFIC_CLASS_TEST_DSN")
	if dsn == "" {
		t.Skip("KEY_TRAFFIC_CLASS_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, `CREATE TEMP TABLE internal_keys(id text PRIMARY KEY, tenant_id text, project_id text, user_id text, key_hash text, key_prefix text,
 scopes_json jsonb DEFAULT '[]', name text, expires_at timestamptz, last_used_at timestamptz, status text DEFAULT 'active', created_at timestamptz DEFAULT now(),
 key_ciphertext text, model_allowlist text[] DEFAULT '{}', traffic_class text NOT NULL DEFAULT '', deleted_at timestamptz);
INSERT INTO internal_keys(id,tenant_id,project_id,key_hash,key_prefix,traffic_class) VALUES
 ('k-eval','t1','p1','h1','pre1','evaluation'),('k-plain','t1','p1','h2','pre2',''),('k-other','t2','p1','h3','pre3','coding');`); err != nil {
		t.Fatal(err)
	}
	keys, err := listKeysWith(ctx, conn, "t1", "p1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, k := range keys {
		got[k.ID] = k.TrafficClass
	}
	if len(got) != 2 || got["k-eval"] != "evaluation" || got["k-plain"] != "" {
		t.Fatalf("list must return own-tenant keys with their traffic class: %v", got)
	}
}
