package repository

import (
	"strings"
	"testing"
)

func TestWorkBuddyEvidenceRunMigrationBackfillsStableWorkspaceIdentity(t *testing.T) {
	// 813 is the expand-only skeleton: stable workspace identity is repaired by the
	// resumable workbuddy_identity_v1 task, not by an inline migration update.
	body := strings.ToLower(readRepoFile(t, "../../../../deploy/migrations/813_workbuddy_workspace_evidence_runs.sql"))
	for _, want := range []string{"begin;", "commit;", "workbuddy_identity_v1"} {
		if !strings.Contains(body, want) {
			t.Fatalf("migration 813 missing %q", want)
		}
	}
	for _, forbidden := range []string{"update ", "delete from", "truncate", "insert into"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("migration 813 must not mutate rows inline, found %q", forbidden)
		}
	}
	task := strings.ToLower(readRepoFile(t, "../../../../deploy/migrations/843_workbuddy_identity_backfill.sql"))
	if !strings.Contains(task, "workbuddy_identity_v1") {
		t.Fatal("migration 843 must register the workbuddy_identity_v1 backfill task")
	}
}
