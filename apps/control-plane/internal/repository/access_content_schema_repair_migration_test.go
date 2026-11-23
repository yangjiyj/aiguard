package repository

import (
	"strings"
	"testing"
)

func TestAccessContentSchemaRepairMigrationIsIdempotentAndComplete(t *testing.T) {
	body := strings.ToLower(readRepoFile(t, "../../../../deploy/migrations/148_access_content_logs_schema_repair.sql"))
	for _, want := range []string{
		"begin;", "commit;", "alter table request_logs", "alter table access_content_logs", "alter table content_logs", "alter table retained_artifacts", "alter table access_content_artifact_links",
		"add column if not exists environment_scope", "add column if not exists section_id", "add column if not exists conversation_id",
		"alter column environment_scope set default", "not valid",
		"request_logs_environment_scope_check", "access_content_logs_environment_scope_check", "content_logs_environment_scope_check", "retained_artifacts_environment_scope_check", "access_content_artifact_links_environment_scope_check",
		"if not exists",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("migration 148 missing %q", want)
		}
	}
	// 148 stays expand-only: historical values, NOT NULL validation and support
	// indexes live in the resumable backfill task registered by 836 and in the
	// concurrent index migration 837.
	for _, forbidden := range []string{
		"set environment_scope = coalesce",
		"set not null",
		"create index",
		"update ",
		"delete from",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("migration 148 must stay expand-only, found %q", forbidden)
		}
	}

	backfill := strings.ToLower(readRepoFile(t, "../../../../deploy/migrations/836_customer_environment_scope_backfill.sql"))
	if !strings.Contains(backfill, "customer_environment_scope_v1") {
		t.Error("migration 836 must register the customer_environment_scope_v1 backfill task")
	}
	indexes := strings.ToLower(readRepoFile(t, "../../../../deploy/migrations/837_customer_environment_scope_indexes.sql"))
	for _, want := range []string{
		"create index concurrently",
		"idx_request_logs_tenant_scope_created",
		"idx_access_content_logs_tenant_scope_created",
		"idx_content_logs_tenant_scope_created",
		"idx_retained_artifacts_tenant_scope_created",
		"idx_access_content_artifact_links_tenant_scope_created",
		"idx_access_content_logs_turn",
	} {
		if !strings.Contains(indexes, want) {
			t.Errorf("migration 837 missing %q", want)
		}
	}
}
