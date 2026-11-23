package handler

import (
	"testing"
	"time"
)

func TestContentAuditKeywordSearchAlwaysSkipsTotal(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)

	filter := contentAuditKeywordSearchFilter("tenant-a", "登录失败", start, end, 20, 40)

	if !filter.SkipTotal {
		t.Fatal("keyword search must skip the unbounded total count regardless of client parameters")
	}
	if filter.TenantID != "tenant-a" || filter.Keyword != "登录失败" ||
		!filter.StartTime.Equal(start) || !filter.EndTime.Equal(end) ||
		filter.Limit != 20 || filter.Offset != 40 {
		t.Fatalf("unexpected keyword search filter: %+v", filter)
	}
}
