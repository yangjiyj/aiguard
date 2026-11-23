package rewrap

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

const dbEnv = "SECRETS_REWRAP_TEST_DATABASE_URL"

func connect(t *testing.T) *pgx.Conn {
	t.Helper()
	url := os.Getenv(dbEnv)
	if url == "" {
		t.Skip(dbEnv + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func setKeys(t *testing.T) {
	t.Helper()
	for _, k := range []string{"JJD_MASTER_KEY", secrets.CipherEnv, secrets.SM4KeyringEnv, secrets.SM4ActiveKeyEnv} {
		t.Setenv(k, "")
	}
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "rewrap-provider-secret")
	t.Setenv("JJD_INTERNAL_API_SECRET", "rewrap-internal-secret")
}

func fixture(t *testing.T, conn *pgx.Conn) []Column {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	cred, ca := "ws10_rw_cred_"+suffix, "ws10_rw_ca_"+suffix
	for _, stmt := range []string{
		`CREATE TABLE ` + cred + ` (id text PRIMARY KEY, secret text)`,
		`CREATE TABLE ` + ca + ` (id text PRIMARY KEY, pk text)`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), `DROP TABLE IF EXISTS `+cred+`, `+ca)
	})
	return []Column{
		{Table: cred, KeyColumn: "id", ValueColumn: "secret", Family: ProviderSecret},
		{Table: ca, KeyColumn: "id", ValueColumn: "pk", Family: CAPrivateKey},
		{Table: "ws10_rw_missing_" + suffix, KeyColumn: "id", ValueColumn: "v", Family: ProviderSecret},
	}
}

func values(t *testing.T, conn *pgx.Conn, c Column) map[string]string {
	t.Helper()
	rows, err := conn.Query(context.Background(), fmt.Sprintf(`SELECT %s, %s FROM %s`, c.KeyColumn, c.ValueColumn, c.Table))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatal(err)
		}
		out[k] = v
	}
	return out
}

func mustEnc(t *testing.T, s string) string {
	t.Helper()
	v, _, err := secrets.EncryptProviderSecret(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// AES -> SM4 -> rotate -> AES, with plaintext rows and a missing table.
func TestRewrapMigrationRotationAndRollback(t *testing.T) {
	conn := connect(t)
	setKeys(t)
	cols := fixture(t, conn)
	ctx := context.Background()

	caPK, err := secrets.EncryptCAPrivateKey("ca-private-pem")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO ` + cols[0].Table + ` VALUES ($1,$2),($3,$4),($5,$6)`, []any{"a", mustEnc(t, "sk-a"), "b", mustEnc(t, "sk-b"), "plain", "legacy-plaintext"}},
		{`INSERT INTO ` + cols[1].Table + ` VALUES ($1,$2)`, []any{"ca1", caPK}},
	} {
		if _, err := conn.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}

	check := func(stage, wantFormat string) {
		t.Helper()
		cred := values(t, conn, cols[0])
		for id, want := range map[string]string{"a": "sk-a", "b": "sk-b"} {
			if got := secrets.DescribeCiphertext(cred[id]); got != wantFormat {
				t.Fatalf("%s: %s format=%s want %s", stage, id, got, wantFormat)
			}
			if plain, err := secrets.DecryptProviderSecret(cred[id]); err != nil || plain != want {
				t.Fatalf("%s: %s decrypt=%q %v", stage, id, plain, err)
			}
		}
		if cred["plain"] != "legacy-plaintext" {
			t.Fatalf("%s: plaintext row touched: %q", stage, cred["plain"])
		}
		pk := values(t, conn, cols[1])["ca1"]
		if got := secrets.DescribeCiphertext(pk); got != wantFormat {
			t.Fatalf("%s: CA format=%s want %s", stage, got, wantFormat)
		}
		if plain, err := secrets.DecryptCAPrivateKey(pk); err != nil || plain != "ca-private-pem" {
			t.Fatalf("%s: CA decrypt=%q %v", stage, plain, err)
		}
	}

	// Dry run under SM4 must not change anything.
	t.Setenv(secrets.CipherEnv, secrets.CipherSM4GCM)
	reps, err := Run(ctx, conn, cols, false)
	if err != nil || len(reps) != 2 || reps[0].Formats[secrets.CipherAESGCM] != 2 {
		t.Fatalf("dry run: %+v %v", reps, err)
	}
	check("after dry run", secrets.CipherAESGCM)

	// 1) Migrate to SM4 under the implicit root key.
	reps, err = Run(ctx, conn, cols, true)
	if err != nil || Summarize(reps) != nil || reps[0].Rewrapped != 2 || reps[1].Rewrapped != 1 {
		t.Fatalf("migrate: %+v %v", reps, err)
	}
	check("sm4 root", "sm4-gcm:root")
	// Idempotent second pass.
	if reps, _ = Run(ctx, conn, cols, true); reps[0].Rewrapped != 0 {
		t.Fatalf("second pass rewrapped again: %+v", reps)
	}

	// 2) Rotate to a keyring key.
	t.Setenv(secrets.SM4KeyringEnv, "k2026=rotation-secret-2026-abc")
	if reps, err = Run(ctx, conn, cols, true); err != nil || reps[0].Rewrapped != 2 {
		t.Fatalf("rotate: %+v %v", reps, err)
	}
	check("rotated", "sm4-gcm:k2026")

	// 3) Roll back to AES-GCM (keyring still present so old values decrypt).
	t.Setenv(secrets.CipherEnv, "")
	if reps, err = Run(ctx, conn, cols, true); err != nil || reps[0].Rewrapped != 2 || reps[1].Rewrapped != 1 {
		t.Fatalf("rollback: %+v %v", reps, err)
	}
	check("rolled back", secrets.CipherAESGCM)
}

func TestRewrapCompareAndSwapAndFailures(t *testing.T) {
	conn := connect(t)
	setKeys(t)
	cols := fixture(t, conn)[:1]
	ctx := context.Background()
	good := mustEnc(t, "sk-good")
	if _, err := conn.Exec(ctx, `INSERT INTO `+cols[0].Table+` VALUES ('good',$1),('bad','enc:v1:sm4:gone:AAAA')`, good); err != nil {
		t.Fatal(err)
	}
	t.Setenv(secrets.CipherEnv, secrets.CipherSM4GCM)
	reps, err := Run(ctx, conn, cols, true)
	if err != nil {
		t.Fatal(err)
	}
	if reps[0].Rewrapped != 1 || reps[0].Failed != 1 || Summarize(reps) == nil {
		t.Fatalf("want 1 rewrapped + 1 failed, got %+v", reps[0])
	}
	if !strings.Contains(strings.Join(reps[0].Errors, ";"), "id=bad") {
		t.Fatalf("failure not attributed: %v", reps[0].Errors)
	}
	// The failing row is left exactly as it was.
	if values(t, conn, cols[0])["bad"] != "enc:v1:sm4:gone:AAAA" {
		t.Fatal("failed row was modified")
	}

	// CAS: an update whose old value no longer matches affects no rows.
	tag, err := conn.Exec(ctx, cols[0].updateSQL(), "enc:v1:x", "good", good)
	if err != nil || tag.RowsAffected() != 0 {
		t.Fatalf("stale CAS affected %d rows (%v)", tag.RowsAffected(), err)
	}

	// Bad configuration aborts before touching any table.
	t.Setenv(secrets.CipherEnv, "sm4-typo")
	if _, err := Run(ctx, conn, cols, true); err == nil {
		t.Fatal("invalid cipher config did not abort")
	}
}

// Read-only check that the production column list matches the real schema.
// Only meaningful on a database migrated with deploy/migrations.
func TestProductionColumnsMatchSchema(t *testing.T) {
	conn := connect(t)
	setKeys(t)
	ok, err := tableExists(context.Background(), conn, "provider_credentials")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Skip("database is not migrated")
	}
	reps, err := Run(context.Background(), conn, Columns, false)
	if err != nil {
		t.Fatalf("production column list does not match schema: %v", err)
	}
	if len(reps) != len(Columns) {
		t.Fatalf("expected every production table to exist, got %d/%d", len(reps), len(Columns))
	}
}
