package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 保留期清理要在迁移 987 前（普通表）和 987 后（视图 + 两张底表 + 正文回收）都能运行：补丁可能先于 987 上线。
// CONTENT_LOG_PRUNE_TEST_DATABASE_URL 指向一个一次性库；测试按库里是否已有 content_log_entries 走对应分支。
func TestContentLogDeleteOlderThanWorksBeforeAndAfterDedup(t *testing.T) {
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
	defer db.Close()
	_, err = db.Exec(ctx, `
INSERT INTO tenants(id,name,is_test) VALUES ('prune_t','prune',true) ON CONFLICT DO NOTHING;
INSERT INTO request_logs(id,request_id,tenant_id,created_at,proxy_mode) VALUES
 ('prune_old','prune_old_r','prune_t',NOW()-INTERVAL '40 days','chat_completion'),
 ('prune_new','prune_new_r','prune_t',NOW(),'chat_completion');
INSERT INTO content_logs(id,request_id,tenant_id,role,content,created_at) VALUES
 ('prune_c_old','prune_old','prune_t','user','只在过期请求里出现的正文',NOW()-INTERVAL '40 days'),
 ('prune_c_shared_old','prune_old','prune_t','system','两个请求共用的系统提示词',NOW()-INTERVAL '40 days'),
 ('prune_c_shared_new','prune_new','prune_t','system','两个请求共用的系统提示词',NOW());`)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Exec(context.Background(), `DELETE FROM content_logs WHERE tenant_id='prune_t'; DELETE FROM request_logs WHERE tenant_id='prune_t'`)

	var dedup bool
	if err = db.QueryRow(ctx, `SELECT to_regclass('content_log_entries') IS NOT NULL`).Scan(&dedup); err != nil {
		t.Fatal(err)
	}
	if dedup {
		// 线上正文的 created_at 就是它首次出现的时间；这里把回填的历史消息对应的正文也回填到 40 天前。
		if _, err = db.Exec(ctx, `UPDATE content_log_bodies SET created_at=NOW()-INTERVAL '40 days' WHERE tenant_id='prune_t'`); err != nil {
			t.Fatal(err)
		}
	}

	repo := NewContentLogRepository(db)
	deleted, err := repo.DeleteOlderThan(ctx, 30)
	if err != nil {
		t.Fatal(err)
	}
	if deleted < 2 {
		t.Fatalf("deleted=%d, want at least the 2 expired rows", deleted)
	}
	var left string
	if err = db.QueryRow(ctx, `SELECT string_agg(id||'='||content, ',' ORDER BY id) FROM content_logs WHERE tenant_id='prune_t'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != "prune_c_shared_new=两个请求共用的系统提示词" {
		t.Fatalf("unexpected remaining rows: %s", left)
	}
	if dedup {
		var bodies []string
		rows, err := db.Query(ctx, `SELECT content FROM content_log_bodies WHERE tenant_id='prune_t' ORDER BY content`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var body string
			if err := rows.Scan(&body); err != nil {
				t.Fatal(err)
			}
			bodies = append(bodies, body)
		}
		rows.Close()
		// 过期请求独有的正文被回收，仍被新请求引用的共用正文保留。
		if len(bodies) != 1 || bodies[0] != "两个请求共用的系统提示词" {
			t.Fatalf("orphan bodies must be pruned and shared bodies kept: %v", bodies)
		}
	}
}
