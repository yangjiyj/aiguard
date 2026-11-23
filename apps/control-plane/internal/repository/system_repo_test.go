package repository

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCreateHeaderContractConflictOnceIdempotencyAndCollision(t *testing.T) {
	url := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	db, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := NewSystemRepository(db)
	id := "header-contract-conflict:" + uuid.NewString()
	payload := map[string]any{"service": "control-plane.internal", "header_kind": "internal_token", "request_id": "req", "source_ip": ""}
	if err := r.CreateHeaderContractConflictOnce(context.Background(), id, payload); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- r.CreateHeaderContractConflictOnce(context.Background(), id, payload) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent same occurrence: %v", err)
		}
	}
	var count int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM audit_operations WHERE id=$1`, id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("same occurrence rows=%d err=%v", count, err)
	}
	secondID := "header-contract-conflict:" + uuid.NewString()
	if err := r.CreateHeaderContractConflictOnce(context.Background(), secondID, payload); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateHeaderContractConflictOnce(context.Background(), id, payload); err != nil {
		t.Fatal(err)
	}
	changed := map[string]any{"service": "control-plane.internal", "header_kind": "internal_token", "request_id": "different", "source_ip": ""}
	if err := r.CreateHeaderContractConflictOnce(context.Background(), id, changed); !errors.Is(err, ErrHeaderContractCollision) {
		t.Fatalf("collision=%v", err)
	}
	identityID := "header-contract-conflict:" + uuid.NewString()
	if _, err := db.Exec(context.Background(), `INSERT INTO audit_operations
		(id,user_id,action_type,action_detail,target_type,target_id,ip_address)
		VALUES ($1,NULL,'header_contract_conflict',$2::jsonb,'forged_target','forged_id','203.0.113.7')`, identityID, payload); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateHeaderContractConflictOnce(context.Background(), identityID, payload); !errors.Is(err, ErrHeaderContractCollision) {
		t.Fatalf("fixed identity collision=%v", err)
	}
}

func TestSystemSettingsModeBatchIsAtomic(t *testing.T) {
	url := os.Getenv("SECURITY_MODE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SECURITY_MODE_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	schema := "mode_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(ctx, `CREATE TABLE system_settings (key text PRIMARY KEY, value text NOT NULL CHECK(value <> 'reject'), updated_at timestamptz NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	repo := NewSystemRepository(db)
	initial := map[string]string{"security_execution_mode": "record", "security_audit_only": "true"}
	if err := repo.SetMultiple(ctx, initial); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetMultiple(ctx, map[string]string{"security_execution_mode": "protect", "security_audit_only": "false", "modified_by": "reject"}); err == nil {
		t.Fatal("expected constraint failure")
	}
	for key, want := range initial {
		got, err := repo.Get(ctx, key)
		if err != nil || got.Value != want {
			t.Fatalf("partial batch write: %s %#v %v", key, got, err)
		}
	}
	if err := repo.SetMultiple(ctx, map[string]string{"security_execution_mode": "protect", "security_audit_only": "false"}); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(ctx, "security_execution_mode")
	if err != nil || got.Value != "protect" {
		t.Fatalf("successful batch: %#v %v", got, err)
	}
}
