package repository

import (
	"strings"
	"testing"
)

// 关键字先做 ILIKE、命中后才跑客户正文判定那一串正则：同样的结果，但不再对窗口内每一行先跑二十多个正则；
// 正文表上的 trigram 索引也只有 ILIKE 在前时才能直接筛行。
func TestRetentionKeywordMatchRunsLikeBeforeCustomerTextRegex(t *testing.T) {
	sql := forwardProxyKeywordMatchSourceSQL([]string{"keyword_match.tenant_id = $1"}, []string{"keyword_content.tenant_id = $1"}, 2)
	for _, column := range []string{"keyword_match.request_content_redacted", "keyword_match.response_content_redacted", "keyword_content.content"} {
		want := column + " ILIKE $2 ESCAPE E'\\\\' AND jjdguard_customer_content_text(" + column + ")"
		if !strings.Contains(sql, want) {
			t.Fatalf("keyword source must test %s with ILIKE first, want %q in:\n%s", column, want, sql)
		}
	}
	where, _ := buildForwardProxyWhere("t1", ForwardProxyAccessFilter{Keyword: "Contract"})
	joined := strings.Join(where, " AND ")
	if !strings.Contains(joined, "keyword_content.content ILIKE $2 ESCAPE E'\\\\' AND jjdguard_customer_content_text(keyword_content.content)") {
		t.Fatalf("list keyword filter must test ILIKE first: %s", joined)
	}
	// 没有大小写的关键字改用 LIKE，顺序不变。
	where, _ = buildForwardProxyWhere("t1", ForwardProxyAccessFilter{Keyword: "合同编号"})
	joined = strings.Join(where, " AND ")
	if !strings.Contains(joined, "keyword_content.content LIKE $2 ESCAPE E'\\\\' AND jjdguard_customer_content_text(keyword_content.content)") {
		t.Fatalf("list keyword filter must test LIKE first: %s", joined)
	}
}

// 不足 3 个字符时 trigram 抽不出词元，走索引要扫全索引，比顺序扫描还慢：这类关键字保持原来的计划。
func TestShortRetentionKeywordDoesNotUseTrigramIndex(t *testing.T) {
	sql := forwardProxyKeywordMatchSourceSQL([]string{"keyword_match.tenant_id = $1"}, []string{"keyword_content.tenant_id = $1"}, 2)
	for _, keyword := range []string{"密钥", "ab", "a"} {
		short := retentionKeywordIndexPolicy(sql, keyword, 2)
		for _, column := range []string{"keyword_content.content", "keyword_body.content"} {
			if !strings.Contains(short, "("+column+" || '') ") || strings.Contains(short, "\t"+column+" ILIKE $2") || strings.Contains(short, "\t"+column+" LIKE $2") ||
				strings.Contains(short, " "+column+" ILIKE $2") || strings.Contains(short, " "+column+" LIKE $2") {
				t.Fatalf("keyword %q must not be index-driven on %s:\n%s", keyword, column, short)
			}
		}
	}
	for _, keyword := range []string{"密钥库", "abc", "合同编号"} {
		if strings.Contains(retentionKeywordIndexPolicy(sql, keyword, 2), "|| '')") {
			t.Fatalf("keyword %q of three or more characters must keep the indexable predicate", keyword)
		}
	}
}

// 改 LIKE、改顺序扫描都只动关键字那个参数的匹配，别的参数（例如以后加的筛选条件）的 ILIKE 不受影响。
func TestRetentionKeywordRewriteOnlyTouchesTheKeywordParameter(t *testing.T) {
	sql := "keyword_content.content ILIKE $2 ESCAPE E'\\\\' AND other.y ILIKE $3 ESCAPE E'\\\\' AND keyword_body.content ILIKE $20 ESCAPE E'\\\\'"
	got := retentionKeywordIndexPolicy(sql, "合同", 2)
	for _, want := range []string{"(keyword_content.content || '') LIKE $2 ESCAPE", "other.y ILIKE $3 ESCAPE", "keyword_body.content ILIKE $20 ESCAPE"} {
		if !strings.Contains(got, want) {
			t.Fatalf("want %q in %s", want, got)
		}
	}
}
