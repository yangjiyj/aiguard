package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestResolveUploadedFileBytesResolvesReferenceWithinTenant 覆盖正向代理网页版上传的
// 三段式流程：上传行(access_content_logs)同时持有「字节元素」(source=multipart,
// 带 data_base64/file_name)与「引用回执元素」(source=json_file_object, 带 reference_id)，
// 而对话行只持有 source=json_file_reference 的引用(无字节)。后台留存详情按 reference_id
// 在「同一租户内」解引用，把真实图片/文件字节取回展示。
//
// 这是安全敏感路径(正向代理 + 多租户隔离)，因此本测试同时断言：
//  1. 同租户内 reference_id 能解析出本租户上传的字节/文件名；
//  2. 另一租户用「相同的 reference_id」上传的字节绝不能被本租户解析出来(隔离不变量)。
func TestResolveUploadedFileBytesResolvesReferenceWithinTenant(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}

	suffix := time.Now().UnixNano()
	tenantA := fmt.Sprintf("tenant_resolve_a_%d", suffix)
	tenantB := fmt.Sprintf("tenant_resolve_b_%d", suffix)
	uploadReqA := fmt.Sprintf("req_resolve_upload_a_%d", suffix)
	uploadReqB := fmt.Sprintf("req_resolve_upload_b_%d", suffix)
	// 两个租户故意复用「相同」的 reference_id，用来证明隔离。
	sharedRef := fmt.Sprintf("file-shared-%d", suffix)

	const (
		fileNameA = "tenantA_chest_ct.png"
		fileNameB = "tenantB_chest_ct.png"
		dataB64A  = "QV9URU5BTlRfSU1BR0VfQllURVM=" // base64("A_TENANT_IMAGE_BYTES")
		dataB64B  = "Ql9URU5BTlRfSU1BR0VfQllURVM=" // base64("B_TENANT_IMAGE_BYTES")
		sha256A   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		sha256B   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	// db.Close() 放 t.Cleanup 末尾：defer 会先于 t.Cleanup 执行，先关池会让 DELETE 静默失败。
	t.Cleanup(func() {
		for _, tid := range []string{tenantA, tenantB} {
			for _, stmt := range []string{
				"DELETE FROM access_content_logs WHERE tenant_id = $1",
				"DELETE FROM request_logs WHERE tenant_id = $1",
				"DELETE FROM tenants WHERE id = $1",
			} {
				if _, err := db.Exec(ctx, stmt, tid); err != nil {
					t.Logf("cleanup %s (%q): %v", tid, stmt, err)
				}
			}
		}
		db.Close()
	})

	insertTenant := func(tid string) {
		t.Helper()
		if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`, tid, tid); err != nil {
			t.Fatalf("insert tenant %s: %v", tid, err)
		}
	}

	// 模拟一条「上传行」：同一 file_metadata_json 数组里既有字节元素，又有引用回执元素。
	insertUploadRow := func(tid, requestID, refID, fileName, contentType, sha256, dataB64 string) {
		t.Helper()
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs (
				id, request_id, tenant_id, endpoint_type, request_status,
				proxy_mode, proxy_target_host, proxy_target_path, proxy_method, created_at
			)
			VALUES ($1, $2, $3, 'proxy', 'success', 'forward', 'chat.deepseek.com', '/api/v0/file/upload_file', 'POST', $4)
		`, requestID, requestID, tid, time.Now().UTC()); err != nil {
			t.Fatalf("insert upload request log %s: %v", requestID, err)
		}
		metadata := fmt.Sprintf(`[
			{"source":"multipart","stage":"request","field_name":"file","file_name":%q,"content_type":%q,"sha256":%q,"size":18,"has_bytes":true,"data_base64":%q},
			{"source":"json_file_object","stage":"response","reference_id":%q,"file_name":%q,"content_type":%q}
		]`, fileName, contentType, sha256, dataB64, refID, fileName, contentType)
		if _, err := db.Exec(ctx, `
			INSERT INTO access_content_logs (id, request_id, tenant_id, provider, product, model, file_metadata_json, created_at)
			VALUES ($1, $2, $3, 'deepseek', 'deepseek_web', 'deepseek-chat', $4::jsonb, $5)
		`, requestID, requestID, tid, metadata, time.Now().UTC()); err != nil {
			t.Fatalf("insert upload access content log %s: %v", requestID, err)
		}
	}

	insertTenant(tenantA)
	insertTenant(tenantB)
	insertUploadRow(tenantA, uploadReqA, sharedRef, fileNameA, "image/png", sha256A, dataB64A)
	insertUploadRow(tenantB, uploadReqB, sharedRef, fileNameB, "image/png", sha256B, dataB64B)

	repo := NewRequestLogRepository(db)

	// (1) 同租户解析：tenantA 必须拿到自己的字节，且文件名/sha256 是 A 的。
	resolvedA, err := repo.ResolveUploadedFileBytes(ctx, tenantA, []string{sharedRef})
	if err != nil {
		t.Fatalf("resolve for tenant A: %v", err)
	}
	gotA, ok := resolvedA[sharedRef]
	if !ok {
		t.Fatalf("tenant A should resolve reference %s, got %#v", sharedRef, resolvedA)
	}
	if gotA.DataBase64 != dataB64A {
		t.Fatalf("tenant A data_base64 = %q, want %q", gotA.DataBase64, dataB64A)
	}
	if gotA.FileName != fileNameA {
		t.Fatalf("tenant A file_name = %q, want %q", gotA.FileName, fileNameA)
	}
	if gotA.ContentType != "image/png" {
		t.Fatalf("tenant A content_type = %q, want image/png", gotA.ContentType)
	}
	if gotA.SHA256 != sha256A {
		t.Fatalf("tenant A sha256 = %q, want %q", gotA.SHA256, sha256A)
	}

	// (1') 隔离反证：tenantA 解析结果绝不能携带 tenantB 的字节/文件名。
	if gotA.DataBase64 == dataB64B || gotA.FileName == fileNameB {
		t.Fatalf("tenant isolation breached: tenant A resolved tenant B's bytes: %#v", gotA)
	}

	// (2) 另一租户解析自己的同名 reference：必须是 B 的字节。
	resolvedB, err := repo.ResolveUploadedFileBytes(ctx, tenantB, []string{sharedRef})
	if err != nil {
		t.Fatalf("resolve for tenant B: %v", err)
	}
	gotB, ok := resolvedB[sharedRef]
	if !ok {
		t.Fatalf("tenant B should resolve reference %s, got %#v", sharedRef, resolvedB)
	}
	if gotB.DataBase64 != dataB64B || gotB.FileName != fileNameB {
		t.Fatalf("tenant B resolved wrong bytes: %#v", gotB)
	}

	// (3) 不存在的 reference_id：返回空映射，不报错。
	resolvedMissing, err := repo.ResolveUploadedFileBytes(ctx, tenantA, []string{"file-does-not-exist"})
	if err != nil {
		t.Fatalf("resolve missing reference: %v", err)
	}
	if len(resolvedMissing) != 0 {
		t.Fatalf("missing reference should resolve to empty map, got %#v", resolvedMissing)
	}

	// (4) 空入参：直接返回空映射，不触发查询。
	resolvedEmpty, err := repo.ResolveUploadedFileBytes(ctx, tenantA, nil)
	if err != nil {
		t.Fatalf("resolve empty input: %v", err)
	}
	if len(resolvedEmpty) != 0 {
		t.Fatalf("empty input should resolve to empty map, got %#v", resolvedEmpty)
	}
}
