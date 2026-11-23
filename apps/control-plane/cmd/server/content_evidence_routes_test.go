package main

import (
	"os"
	"strings"
	"testing"
)

func TestContentEvidenceRoutesUseFullTenantReaderGuard(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, route := range []string{
		`r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/requests",`,
		`r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/requests/{request_id}",`,
		`r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/dispositions",`,
		`r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/content/{session_id}",`,
		`r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/access-retention",`,
	} {
		if !strings.Contains(text, route) {
			t.Errorf("content evidence route missing full-reader guard: %s", route)
		}
	}
}
