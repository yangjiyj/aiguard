package repository

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 案件“有无新证据”按证据身份判断。2.9.22 起命中带原文，数据面另写 evidence_identity_sha256（按 2.9.21
// 落库内容算好的身份，迁移 1010 让生成列直接取它）。没有生成列时的兜底口径必须一致：先取这个值；值为空
// 表示 2.9.21 下没有证据身份，按事件与命中序号；不带这个键的存量命中仍按原口径（原文、前后文、预览）。
func TestAlertEvidenceIdentityPrefersDataPlaneHash(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hash := func(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }
	precomputed := hash("2.9.21 落库内容")
	for _, tc := range []struct {
		name, finding, want string
	}{
		{"data plane hash wins over stored original", `{"type":"secret","raw_evidence":"sk-原文","evidence_context":"前后文","evidence_identity_sha256":"` + precomputed + `"}`, precomputed},
		{"empty data plane hash means no 2.9.21 identity", `{"type":"secret","raw_evidence":"sk-原文","evidence_identity_sha256":""}`, hash("ev1:3")},
		{"invalid data plane hash is not trusted", `{"type":"secret","raw_evidence":"sk-原文","evidence_identity_sha256":"not-a-hash"}`, hash("ev1:3")},
		{"legacy literal finding keeps raw first", `{"type":"secret","raw_evidence":"sk-旧","evidence_context":"前后文"}`, hash("sk-旧")},
		{"legacy semantic finding keeps context first", `{"type":"semantic_attack","raw_evidence":"整段","evidence_context":"语义上下文"}`, hash("语义上下文")},
		{"legacy finding without evidence", `{"type":"pii"}`, hash("ev1:3")},
	} {
		var got string
		query := "SELECT " + alertEvidenceIdentitySQL(false) + " FROM (SELECT $1::jsonb AS finding,'ev1'::text AS event_id,3 AS finding_index) x"
		if err := db.QueryRow(ctx, query, tc.finding).Scan(&got); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: identity %s, want %s", tc.name, got, tc.want)
		}
	}
	// 有生成列时先取 _jjd_evidence_identity（迁移 850/1010 算好的值）。
	var got string
	if err := db.QueryRow(ctx, "SELECT "+alertEvidenceIdentitySQL(true)+" FROM (SELECT $1::jsonb AS finding,'ev1'::text AS event_id,3 AS finding_index) x",
		`{"_jjd_evidence_identity":"`+precomputed+`"}`).Scan(&got); err != nil || got != precomputed {
		t.Fatalf("metadata identity: %s %v", got, err)
	}
}
