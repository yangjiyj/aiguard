package repository

import (
	"strings"
	"testing"
)

func TestEnvironmentScopeIndexesAreNonTransactional(t *testing.T) {
	columns := strings.ToLower(readRepoFile(t, "../../../../deploy/migrations/146_environment_scope_retention.sql"))
	indexes := strings.ToLower(readRepoFile(t, "../../../../deploy/migrations/147_environment_scope_retention_indexes.sql"))
	if !strings.Contains(columns, "begin;") || !strings.Contains(columns, "commit;") {
		t.Fatal("scope columns migration must be transactional")
	}
	if strings.Contains(columns, "create index concurrently") {
		t.Fatal("concurrent index creation must not run in the transactional migration")
	}
	if strings.Contains(indexes, "begin;") || strings.Contains(indexes, "commit;") {
		t.Fatal("concurrent index migration must remain outside an explicit transaction")
	}
	if !strings.Contains(indexes, "create index concurrently") {
		t.Fatal("scope query indexes must use CREATE INDEX CONCURRENTLY")
	}
}
