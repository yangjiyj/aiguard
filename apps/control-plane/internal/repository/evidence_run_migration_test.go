package repository

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceRunMigrationAddsAttributionAndCorrelationColumns(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "migrations", "145_evidence_runs.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, required := range []string{
		"add column if not exists agent_runtime",
		"add column if not exists agent_detection_source",
		"add column if not exists agent_detection_confidence",
		"add column if not exists evidence_run_id",
		"add column if not exists evidence_run_source",
		"idx_request_logs_tenant_evidence_run_created",
		"where evidence_run_id is not null",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration 145 missing %q", required)
		}
	}
}
