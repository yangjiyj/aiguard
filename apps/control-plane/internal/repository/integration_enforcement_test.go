package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
	"time"
)

func enforcementTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("INTEGRATION_ENFORCEMENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("未配置隔离的凭据测试数据库")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("j1_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(); admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); admin.Close() })
	_, err = db.Exec(ctx, `CREATE TABLE projects(id text,tenant_id text);
 CREATE TABLE providers(id text,tenant_id text);
 CREATE TABLE models(provider_id text,model_name text);
 CREATE TABLE internal_keys(id text PRIMARY KEY,tenant_id text,project_id text,name text,key_hash text,key_prefix text,scopes_json jsonb,status text,created_at timestamptz DEFAULT now(),expires_at timestamptz,key_ciphertext text,agent_instance_id text,model_allowlist text[] NOT NULL DEFAULT '{}');
 INSERT INTO projects VALUES('proj','tenant-a'); INSERT INTO providers VALUES('p-a','tenant-a'),('p-b','tenant-b'); INSERT INTO models VALUES('p-a','模型甲'),('p-a','模型乙'),('p-b','异租户模型');
 INSERT INTO internal_keys(id,tenant_id,project_id,status) VALUES('legacy','tenant-a','proj','active');`)
	if err != nil {
		t.Fatal(err)
	}
	sql, err := os.ReadFile("../../../../deploy/migrations/980_integration_key_enforcement.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, string(sql)); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestIntegrationEnforcementPersistence(t *testing.T) {
	t.Setenv("INTEGRATION_KEY_ENFORCEMENT", "record_only")
	db := enforcementTestDB(t)
	ctx := context.Background()
	repo := NewIntegrationRepository(db)
	var legacyModel, legacyDLP string
	if err := db.QueryRow(ctx, `SELECT model_enforcement,dlp_enforcement FROM internal_keys WHERE id='legacy'`).Scan(&legacyModel, &legacyDLP); err != nil {
		t.Fatal(err)
	}
	if legacyModel != "block" || legacyDLP != "record" {
		t.Fatal("存量凭据默认档位变化")
	}
	var input ai.Credential
	json.Unmarshal([]byte(`{"agent_instance_id":"agent1","project_id":"proj","scopes":["chat"],"model_restriction":"allowlist","model_allowlist":["模型甲"],"enforcement":"block","dlp_enforcement":"block"}`), &input)
	key, err := repo.IssueCredential(ctx, "tenant-a", input, "fixture-credential-not-for-production", "")
	if err != nil {
		t.Fatal(err)
	}
	assertCredentialContract(t, key, "block", "record")
	rotated, err := repo.IssueCredential(ctx, "tenant-a", ai.Credential{AgentInstanceID: "rotation"}, "fixture-rotation-not-for-production", key.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	assertCredentialContract(t, rotated, "block", "record")
	if _, err = repo.RevokeCredential(ctx, "tenant-b", rotated.KeyID); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("跨租户吊销：%v", err)
	}
	revoked, err := repo.RevokeCredential(ctx, "tenant-a", rotated.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	assertCredentialContract(t, revoked, "block", "record")
	keys, err := repo.ListCredentials(ctx, "tenant-a", "agent1")
	if err != nil || len(keys) != 2 {
		t.Fatalf("列表不完整 %v", err)
	}
	t.Setenv("INTEGRATION_KEY_ENFORCEMENT", "allow_block")
	keys, err = repo.ListCredentials(ctx, "tenant-a", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	assertCredentialContract(t, &keys[0], "block", "block")
}

func assertCredentialContract(t *testing.T, key *ai.Credential, configured, effective string) {
	t.Helper()
	raw, _ := json.Marshal(key)
	var got map[string]any
	json.Unmarshal(raw, &got)
	for k, want := range map[string]string{"model_restriction": "allowlist", "enforcement": configured, "effective_enforcement": effective, "dlp_enforcement": configured, "effective_dlp_enforcement": effective} {
		if got[k] != want {
			t.Errorf("%s=%v，期望 %s", k, got[k], want)
		}
	}
	list, ok := got["model_allowlist"].([]any)
	if !ok || len(list) != 1 || list[0] != "模型甲" {
		t.Errorf("模型名单丢失")
	}
}

func TestCredentialControlsValidationAndTenantScope(t *testing.T) {
	t.Setenv("INTEGRATION_KEY_ENFORCEMENT", "record_only")
	db := enforcementTestDB(t)
	repo := NewIntegrationRepository(db)
	ctx := context.Background()
	for _, body := range []string{
		`{"model_restriction":"allowlist","model_allowlist":[]}`,
		`{"model_restriction":"allowlist","model_allowlist":["*"]}`,
		`{"model_restriction":"allowlist","model_allowlist":["模型*"]}`,
		`{"model_restriction":"allowlist","model_allowlist":["异租户模型"]}`,
		`{"model_restriction":"allowlist","model_allowlist":["不存在"]}`,
		`{"enforcement":"invalid"}`, `{"dlp_enforcement":"invalid"}`,
	} {
		input := ai.Credential{AgentInstanceID: "agent1", ProjectID: "proj", Scopes: []string{"chat"}}
		json.Unmarshal([]byte(body), &input)
		if _, err := repo.IssueCredential(ctx, "tenant-a", input, "fixture-invalid-request", ""); !errors.Is(err, ai.ErrInvalid) {
			t.Errorf("应拒绝 %s: %v", body, err)
		}
	}
	key, err := repo.IssueCredential(ctx, "tenant-a", ai.Credential{AgentInstanceID: "agent1", ProjectID: "proj", Scopes: []string{"chat"}}, "fixture-default-request", "")
	if err != nil {
		t.Fatal(err)
	}
	if key.Enforcement != "record" || key.DLPEnforcement != "record" {
		t.Fatal("集成签发默认档位不是记录")
	}
	if _, err = repo.GetCredential(ctx, "tenant-b", key.KeyID); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("跨租户详情 %v", err)
	}
	models := []string{"模型甲"}
	block := "block"
	if _, err = repo.UpdateCredential(ctx, "tenant-b", key.KeyID, ai.CredentialUpdate{Enforcement: &block}); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("跨租户更新 %v", err)
	}
	got, err := repo.UpdateCredential(ctx, "tenant-a", key.KeyID, ai.CredentialUpdate{ModelAllowlist: &models, Enforcement: &block, DLPEnforcement: &block})
	if err != nil {
		t.Fatal(err)
	}
	assertCredentialContract(t, got, "block", "record")
	empty := []string{}
	if _, err = repo.UpdateCredential(ctx, "tenant-a", key.KeyID, ai.CredentialUpdate{ModelAllowlist: &empty}); !errors.Is(err, ai.ErrInvalid) {
		t.Fatalf("清空名单应拒绝：%v", err)
	}
	got, err = repo.GetCredential(ctx, "tenant-a", key.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	assertCredentialContract(t, got, "block", "record")
}

func TestIntegrationEnforcementMigrationsRollbackPreservesExistingData(t *testing.T) {
	db := enforcementTestDB(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `CREATE TABLE request_logs(request_id text,existing text); INSERT INTO request_logs VALUES('req1','保留数据')`); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../../../../deploy/migrations/981_key_model_policy_note.sql", "../../../../deploy/migrations/rollback/981_key_model_policy_note.sql", "../../../../deploy/migrations/rollback/980_integration_key_enforcement.sql"} {
		sql, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(ctx, string(sql)); err != nil {
			t.Fatal(err)
		}
	}
	var id, value string
	if err := db.QueryRow(ctx, `SELECT id FROM internal_keys WHERE id='legacy'`).Scan(&id); err != nil || id != "legacy" {
		t.Fatal("回滚破坏存量凭据", err)
	}
	if err := db.QueryRow(ctx, `SELECT existing FROM request_logs WHERE request_id='req1'`).Scan(&value); err != nil || value != "保留数据" {
		t.Fatal("回滚破坏存量请求日志", err)
	}
	var columns int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND column_name IN ('policy_note','model_enforcement','dlp_enforcement','model_restriction')`).Scan(&columns); err != nil || columns != 0 {
		t.Fatal("回滚残留新增列", columns, err)
	}
}
