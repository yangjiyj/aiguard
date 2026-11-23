package repository

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestRawEvidenceRequestIDsAreDistinctAndNonEmpty(t *testing.T) {
	items := []AlertOccurrence{{RequestID: "r1"}, {RequestID: ""}, {RequestID: "r2"}, {RequestID: "r1"}}
	if got := rawEvidenceRequestIDs(items); !reflect.DeepEqual(got, []string{"r1", "r2"}) {
		t.Fatalf("得到 %v", got)
	}
}

func TestApplyRawEvidenceCounts(t *testing.T) {
	items := []AlertOccurrence{{RequestID: "r1"}, {RequestID: "r2"}, {RequestID: ""}}
	applyRawEvidenceCounts(items, map[string]int{"r1": 2})
	if items[0].RawEvidenceCount != 2 || items[1].RawEvidenceCount != 0 || items[2].RawEvidenceCount != 0 {
		t.Fatalf("得到 %+v", items)
	}
	applyRawEvidenceCounts(items, nil) // 查询失败时传 nil，不能 panic，也不改已有值
	if items[0].RawEvidenceCount != 2 {
		t.Fatalf("nil 不应清掉已有计数：%+v", items[0])
	}
}

func TestIsUndefinedTable(t *testing.T) {
	if !isUndefinedTable(fmt.Errorf("count raw evidence by request: %w", &pgconn.PgError{Code: "42P01"})) {
		t.Fatal("42P01 应判为表不存在")
	}
	if isUndefinedTable(&pgconn.PgError{Code: "42703"}) {
		t.Fatal("其他错误码不应静默")
	}
	if isUndefinedTable(errors.New("boom")) || isUndefinedTable(nil) {
		t.Fatal("普通错误和 nil 不应静默")
	}
}
