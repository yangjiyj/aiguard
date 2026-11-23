package repository

import (
	"strings"
	"testing"
)

func TestBuildContentSessionEventsQueryUsesWindowAndBoundedPage(t *testing.T) {
	query := buildContentSessionEventsQuery(true, 6, 7)
	for _, required := range []string{
		"cl.created_at >= $4 AND cl.created_at < $5",
		"se.created_at >= $4 AND se.created_at < $5",
		"LIMIT $6 OFFSET $7",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("events page query missing %q: %s", required, query)
		}
	}
}
