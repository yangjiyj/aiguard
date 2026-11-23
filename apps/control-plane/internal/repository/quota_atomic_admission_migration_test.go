package repository

import (
	"strings"
	"testing"
)

func TestQuotaAtomicAdmissionMigrationAddsTPMLimitSafely(t *testing.T) {
	body := strings.ToLower(readRepoFile(t, "../../../../deploy/migrations/824_quota_atomic_admission.sql"))
	for _, fragment := range []string{
		"begin;",
		"alter table quota_policies",
		"add column if not exists tpm_limit bigint",
		"add column if not exists tpm_blocked boolean not null default false",
		"quota_policies_tpm_limit_nonnegative_check",
		"tpm_limit is null or tpm_limit >= 0",
		"quota_policies_tpm_block_exclusive_check",
		"not tpm_blocked or tpm_limit is null",
		"comment on column quota_policies.tpm_limit",
		"comment on column quota_policies.tpm_blocked",
		"commit;",
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("TPM migration missing %q:\n%s", fragment, body)
		}
	}
}
