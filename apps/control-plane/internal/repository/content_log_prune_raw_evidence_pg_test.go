package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 原文留证清理失败（例如表被锁、权限或触发器报错）不能连带跳过 content_logs 的保留期清理。
// 触发器只对本测试租户生效，不影响共享库里其他用例；结束时连租户与自动建的未分配部门一起删掉。
func TestContentLogDeleteOlderThanContinuesWhenRawEvidencePruneFails(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOG_PRUNE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOG_PRUNE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	exec := func(sql string) {
		t.Helper()
		if _, err := db.Exec(ctx, sql); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}
	exec(`
INSERT INTO tenants(id,name,is_test) VALUES ('prune_rawev_t','prune rawev',true) ON CONFLICT DO NOTHING;
INSERT INTO request_logs(id,request_id,tenant_id,created_at,proxy_mode) VALUES
 ('prune_rawev_old','prune_rawev_old_r','prune_rawev_t',NOW()-INTERVAL '40 days','chat_completion');
INSERT INTO content_logs(id,request_id,tenant_id,role,content,created_at) VALUES
 ('prune_rawev_c_old','prune_rawev_old','prune_rawev_t','user','过期正文（原文留证清理失败也要删）',NOW()-INTERVAL '40 days');
INSERT INTO content_raw_evidence(tenant_id,request_id,session_id,direction,role,message_index,disposition,content_ciphertext,content_hmac,content_chars,original_chars,created_at)
 VALUES ('prune_rawev_t','prune_rawev_old_r','prune_rawev_old_r','input','user',0,'masked','enc:v3:x',decode(repeat('ab',32),'hex'),1,1,NOW()-INTERVAL '40 days');
CREATE OR REPLACE FUNCTION test_prune_rawev_block_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'raw evidence delete blocked for test'; END $$;
CREATE TRIGGER test_prune_rawev_block_delete BEFORE DELETE ON content_raw_evidence
 FOR EACH ROW WHEN (OLD.tenant_id = 'prune_rawev_t') EXECUTE FUNCTION test_prune_rawev_block_delete();`)
	t.Cleanup(func() {
		c := context.Background()
		for _, sql := range []string{
			`DROP TRIGGER IF EXISTS test_prune_rawev_block_delete ON content_raw_evidence`,
			`DROP FUNCTION IF EXISTS test_prune_rawev_block_delete()`,
			`DELETE FROM content_raw_evidence WHERE tenant_id='prune_rawev_t'`,
			`DELETE FROM content_logs WHERE tenant_id='prune_rawev_t'`,
			`DELETE FROM request_logs WHERE tenant_id='prune_rawev_t'`,
			// 建租户时自动生成的"未分配部门"，以及租户本身。
			`DELETE FROM teams WHERE tenant_id='prune_rawev_t'`,
			`DELETE FROM tenants WHERE id='prune_rawev_t'`,
		} {
			if _, err := db.Exec(c, sql); err != nil {
				t.Errorf("cleanup %q: %v", sql, err)
			}
		}
	})
	if _, err := db.Exec(ctx, `UPDATE content_log_bodies SET created_at=NOW()-INTERVAL '40 days' WHERE tenant_id='prune_rawev_t'`); err != nil {
		t.Logf("content_log_bodies not present (pre-987 layout): %v", err)
	}

	if _, err := NewContentLogRepository(db).DeleteOlderThan(ctx, 30); err != nil {
		t.Fatalf("content log retention must not fail because raw evidence pruning failed: %v", err)
	}
	var left int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM content_logs WHERE tenant_id='prune_rawev_t'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("expired content logs were skipped: %d left", left)
	}
	var rawLeft int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM content_raw_evidence WHERE tenant_id='prune_rawev_t'`).Scan(&rawLeft); err != nil {
		t.Fatal(err)
	}
	if rawLeft != 1 {
		t.Fatalf("test trigger should have blocked the raw evidence delete: %d", rawLeft)
	}
}
