package repository

import (
	"strings"
	"testing"
)

func TestContentLogMessageIndexMigrationIsNullableNonnegativeAndIdempotent(t *testing.T) {
	body := strings.ToLower(readRepoFile(t, "../../../../deploy/migrations/810_content_logs_message_index.sql"))
	for _, want := range []string{
		"begin;", "commit;", "alter table content_logs", "add column if not exists message_index integer",
		"content_logs_message_index_nonnegative_check", "message_index is null or message_index >= 0",
		"if not exists", "to_regclass('public.content_logs')",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("migration 810 missing %q", want)
		}
	}
	if strings.Contains(body, "message_index integer not null") {
		t.Fatal("historical content logs must retain nullable message_index")
	}
	scopeMigration := strings.ToLower(readRepoFile(t, "../../../../deploy/migrations/147_environment_scope_retention_indexes.sql"))
	if !strings.Contains(scopeMigration, "idx_content_logs_tenant_scope_created") {
		t.Fatal("environment-scope content_logs index must remain intact")
	}
}
