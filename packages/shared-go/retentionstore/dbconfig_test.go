package retentionstore

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestIsUndefinedTableErr 验证「表不存在(42P01)」识别:全新装时服务可能早于 migration 启动
// (deploy 先 up -d 再迁移),retention_storage_config 尚未建,此错误须被视同无配置→回退默认/env。
func TestIsUndefinedTableErr(t *testing.T) {
	if !isUndefinedTableErr(&pgconn.PgError{Code: "42P01"}) {
		t.Error("42P01 (undefined_table) 应被识别")
	}
	if !isUndefinedTableErr(fmt.Errorf("load retention storage config: %w", &pgconn.PgError{Code: "42P01"})) {
		t.Error("被包裹的 42P01 应能透过 errors.As 识别")
	}
	if isUndefinedTableErr(&pgconn.PgError{Code: "23505"}) {
		t.Error("其它 PG 错误(唯一约束冲突)不应误判为表不存在")
	}
	if isUndefinedTableErr(pgx.ErrNoRows) {
		t.Error("ErrNoRows 由单独分支处理,不应走表不存在分支")
	}
	if isUndefinedTableErr(nil) {
		t.Error("nil 不应识别为表不存在")
	}
	if isUndefinedTableErr(errors.New("plain")) {
		t.Error("普通 error 不应识别为表不存在")
	}
}
