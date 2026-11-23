package repository

import (
	"strings"
	"testing"
)

func TestBuildSessionContentPageQuerySeparatesManagerNoise(t *testing.T) {
	manager := buildSessionContentPageQuery(false)
	all := buildSessionContentPageQuery(true)
	if !strings.Contains(manager, "cl.role IN ('user', 'assistant')") {
		t.Fatalf("manager query must exclude tool/system messages: %s", manager)
	}
	if strings.Contains(all, "cl.role IN ('user', 'assistant')") {
		t.Fatalf("all query must include every role: %s", all)
	}
	for _, fragment := range []string{"ORDER BY cl.created_at ASC, cl.id ASC", "LIMIT $3 OFFSET $4", "COUNT(*) OVER()"} {
		if !strings.Contains(manager, fragment) {
			t.Fatalf("session page query missing %q: %s", fragment, manager)
		}
	}
}
