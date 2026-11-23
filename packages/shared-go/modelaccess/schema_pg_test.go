package modelaccess

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"testing"
)

func TestReviewModelAccessReadinessRequiresTableAndColumns(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("isolated PostgreSQL required for this migration contract")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	schema := "review_schema_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := db.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	for _, table := range []string{"users", "teams", "providers", "models", "user_model_policies", "employee_api_keys"} {
		if _, err := db.Exec(ctx, "CREATE TABLE "+schema+"."+table+" (LIKE public."+table+" INCLUDING ALL)"); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	scoped, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer scoped.Close()
	if ready, err := SchemaReady(ctx, scoped); err != nil || ready {
		t.Errorf("missing grants table reported ready=%v err=%v", ready, err)
	}
	if _, err := db.Exec(ctx, "CREATE TABLE "+schema+".user_model_extra_grants (LIKE public.user_model_extra_grants INCLUDING ALL)"); err != nil {
		t.Fatal(err)
	}
	if ready, err := SchemaReady(ctx, scoped); err != nil || !ready {
		t.Errorf("complete contract reported ready=%v err=%v", ready, err)
	}
 if _,err:=db.Exec(ctx,"ALTER TABLE "+schema+".employee_api_keys DROP COLUMN issued_role");err!=nil {t.Fatal(err)}
 if ready,err:=SchemaReady(ctx,scoped);err!=nil||ready {t.Errorf("missing issued role reported ready=%v err=%v",ready,err)}
 if _,err:=db.Exec(ctx,"ALTER TABLE "+schema+".employee_api_keys ADD COLUMN issued_role varchar(64) NOT NULL DEFAULT ''");err!=nil {t.Fatal(err)}
	if _, err := db.Exec(ctx, "ALTER TABLE "+schema+".user_model_extra_grants DROP COLUMN expires_at CASCADE"); err != nil {
		t.Fatal(err)
	}
	if ready, err := SchemaReady(ctx, scoped); err != nil || ready {
		t.Errorf("missing grants column reported ready=%v err=%v", ready, err)
	}
}
