package repository

import (
	"strings"
	"testing"
)

const rbacSeedMigration = "045_rbac_seed.sql"

func TestRBACSeedMigrationCreatesBaseTablesBeforeSeeding(t *testing.T) {
	body := readRepoFile(t, "../../../../deploy/migrations/"+rbacSeedMigration)
	lower := strings.ToLower(body)

	for _, required := range []string{
		"create table if not exists system_roles",
		"create unique index if not exists system_roles_name_key",
		"create unique index if not exists system_roles_code_key",
		"create table if not exists system_permissions",
		"create unique index if not exists system_permissions_code_key",
		"alter table system_roles add column if not exists is_builtin",
		"alter table system_permissions add column if not exists role_name",
		"on conflict (name)",
		"create unique index if not exists uq_perm_role_res_act",
	} {
		if !strings.Contains(lower, required) {
			t.Fatalf("migration %s missing required fragment %q", rbacSeedMigration, required)
		}
	}

	rolesCreate := strings.Index(lower, "create table if not exists system_roles")
	rolesAlter := strings.Index(lower, "alter table system_roles")
	if rolesCreate < 0 || rolesAlter < 0 || rolesCreate > rolesAlter {
		t.Fatalf("migration %s must create system_roles before altering/seeding it", rbacSeedMigration)
	}

	permsCreate := strings.Index(lower, "create table if not exists system_permissions")
	permsAlter := strings.Index(lower, "alter table system_permissions")
	if permsCreate < 0 || permsAlter < 0 || permsCreate > permsAlter {
		t.Fatalf("migration %s must create system_permissions before altering/seeding it", rbacSeedMigration)
	}
}

func TestPrivateBootstrapUsesCustomerSafeDefaultUnit(t *testing.T) {
	body := readRepoFile(t, "../../../../deploy/docker-compose/initdb/001_init_enterprise.sql")

	if !strings.Contains(body, "VALUES ('tenant_default', '默认单位', 'enterprise', 'active', '{}')") {
		t.Fatalf("private bootstrap should create tenant_default as 默认单位")
	}
	if strings.Contains(body, "默认租户") {
		t.Fatalf("private bootstrap should not expose 默认租户 wording to customers")
	}
}

func TestPrivateOrgDataFixDoesNotBrandCustomerDefaultTenant(t *testing.T) {
	body := readRepoFile(t, "../../../../deploy/migrations/050_org_data_fix.sql")

	if strings.Contains(body, "示例科技") {
		t.Fatalf("private org data fix must not brand customer default tenant with internal company name")
	}
	if !strings.Contains(body, "UPDATE tenants SET name = '默认单位'") {
		t.Fatalf("private org data fix should normalize tenant_default to 默认单位")
	}
}

func TestIndustryMigrationIsInPrivateDeployScripts(t *testing.T) {
	currentMigration := "068_industry_data_security_packs.sql"
	// 自 GW-20260622-02 起，migrate-private.sh 改为自动发现 deploy/migrations/NNN_*.sql，
	// 不再硬编码逐条 run_migration。校验：迁移文件存在(将被自动发现) + 入口委托 migration-runner。
	readRepoFile(t, "../../../../deploy/migrations/"+currentMigration) // fatals if missing

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
