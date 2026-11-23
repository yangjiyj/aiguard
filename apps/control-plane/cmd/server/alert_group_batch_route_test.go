package main

import (
	"os"
	"strings"
	"testing"
)

func TestServerRegistersAlertGroupBatchStatusRoute(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	s := string(source)
	route := `r.Post("/admin/v1/alert-groups/batch-status", handler.BatchUpdateAlertGroupStatus(deps))`
	idx := strings.Index(s, route)
	if idx < 0 {
		t.Fatalf("main.go missing %q", route)
	}
	// 必须先于 {id} 通配路由登记在同一组内，且不得有不经勾选的"按条件全关"入口。
	if strings.Contains(s, "alert-groups/close-all") || strings.Contains(s, "alert-groups/batch-by-filter") {
		t.Fatal("condition-based bulk close endpoints are not allowed")
	}
}
