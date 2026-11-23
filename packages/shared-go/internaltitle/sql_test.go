package internaltitle

import (
	"strings"
	"testing"
)

func TestPredicateUsesCachedThreeStates(t *testing.T) {
	q := Predicate()
	for _, s := range []string{"CASE WHEN rl.internal_title_request IS NULL THEN", "ELSE NOT rl.internal_title_request END", RawPredicate()} {
		if !strings.Contains(q, s) {
			t.Errorf("缺少三态判定：%s", s)
		}
	}
}

func TestContentRowsFencesBodyMatching(t *testing.T) {
	q := ContentRows("'system'")
	for _, s := range []string{"content_log_entries", "content_logs_legacy", "content_log_bodies", "role = 'system'", "CROSS JOIN LATERAL", "request_id = rl.id", "environment_scope = rl.environment_scope"} {
		if !strings.Contains(q, s) {
			t.Errorf("缺少按请求取正文约束：%s", s)
		}
	}
	if strings.Count(q, "OFFSET 0") < 3 {
		t.Fatal("必须分别隔离消息引用、正文主键查询和历史行")
	}
	if strings.Contains(RawPredicate(), "FROM content_logs ") {
		t.Fatal("不能经兼容视图匹配正文")
	}
}

func TestMetadataRowsDoesNotReadBodies(t *testing.T) {
	q := MetadataRows()
	if strings.Contains(q, "content_log_bodies") || strings.Contains(q, "FROM content_logs ") {
		t.Fatal("会话候选只允许读消息底表元数据")
	}
	for _, s := range []string{"content_log_entries", "content_logs_legacy", "request_id = rl.id", "environment_scope = rl.environment_scope"} {
		if !strings.Contains(q, s) {
			t.Errorf("缺少会话关联约束：%s", s)
		}
	}
}
