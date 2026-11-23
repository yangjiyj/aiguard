package repository

import (
	"os"
	"strings"
	"testing"
)

const orgTestTenantVisibilityMigration = "075_org_test_tenant_visibility_fix.sql"

func TestOrgTestTenantVisibilityMigrationIsSafeAndComplete(t *testing.T) {
	body := readRepoFile(t, "../../../../deploy/migrations/"+orgTestTenantVisibilityMigration)
	lower := strings.ToLower(body)

	for _, required := range []string{
		"begin;",
		"commit;",
		"update tenants",
		"set is_test = true",
		"tenant\\_audit\\_stats\\_%",
		"tenant\\_weak\\_signal\\_%",
		"tenant\\_resolve\\_a\\_%",
		"tenant\\_resolve\\_b\\_%",
		"tenant\\_auditdetail\\_%",
		"tenant\\_content\\_%",
		"tenant\\_rp\\_test\\_%",
		"tfx\\_%",
		"escape '\\'",
	} {
		if !strings.Contains(lower, required) {
			t.Fatalf("migration %s missing required fragment %q", orgTestTenantVisibilityMigration, required)
		}
	}

	if strings.Contains(lower, "delete") {
		t.Fatalf("migration %s must hide test tenants without deleting data", orgTestTenantVisibilityMigration)
	}
	if strings.Contains(lower, "tenant_system") {
		t.Fatalf("migration %s must not hide tenant_system without PM confirmation", orgTestTenantVisibilityMigration)
	}
}

func TestOrgTestTenantVisibilityMigrationIsInPrivateDeployScripts(t *testing.T) {
	// 自 GW-20260622-02 起，migrate-private.sh 改为自动发现 deploy/migrations/NNN_*.sql，
	// 不再硬编码逐条 run_migration。校验：迁移文件存在(将被自动发现) + 入口委托 migration-runner。
	readRepoFile(t, "../../../../deploy/migrations/"+orgTestTenantVisibilityMigration) // fatals if missing

	for _, path := range []string{
		"../../../../deploy/migrate-private.sh",
		"../../../../deploy/docker-compose/migrate-private.sh",
	} {
		body := readRepoFile(t, path)
		if !strings.Contains(body, "migration-runner.sh") {
			t.Fatalf("%s must delegate to migration-runner.sh for auto-discovery", path)
		}
	}
}

func readRepoFile(t *testing.T, path string) string {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}
