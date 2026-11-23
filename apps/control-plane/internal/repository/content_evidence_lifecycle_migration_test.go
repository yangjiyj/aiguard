package repository

import (
	"strings"
	"testing"
)

const contentEvidenceLifecycleMigration = "131_content_evidence_lifecycle.sql"

func TestContentEvidenceLifecycleMigrationPersistsExpiryWithoutContent(t *testing.T) {
	body := readRepoFile(t, "../../../../deploy/migrations/"+contentEvidenceLifecycleMigration)
	lower := strings.ToLower(body)

	for _, required := range []string{
		"begin;",
		"add column if not exists content_evidence_retention_until",
		"update request_logs",
		"after insert or update of retention_until",
		"new.tenant_id",
		"new.request_id",
		"commit;",
	} {
		if !strings.Contains(lower, required) {
			t.Fatalf("migration %s missing required fragment %q", contentEvidenceLifecycleMigration, required)
		}
	}

	for _, forbidden := range []string{
		"request_content_redacted",
		"response_content_redacted",
		"file_metadata_json",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("migration %s must not copy retained content field %q", contentEvidenceLifecycleMigration, forbidden)
		}
	}

	// Historical rows are backfilled by the resumable request_log_compatibility_v1
	// task; 131 only owns the column and the write-through trigger.
	if strings.Contains(lower, "from access_content_logs") {
		t.Fatal("migration 131 must not backfill historical rows inline")
	}
}
