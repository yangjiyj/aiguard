package repository

import (
	"regexp"
	"strings"
	"testing"
)

const enterpriseIdentityDepartmentMigration = "137_enterprise_identity_department.sql"

func enterpriseIdentityMigrationBody(t *testing.T) string {
	t.Helper()
	return strings.ToLower(readRepoFile(t, "../../../../deploy/migrations/"+enterpriseIdentityDepartmentMigration))
}

type namedEmailConstraint struct {
	table string
	name  string
}

func createTableDefinition(body, table string) string {
	startPattern := regexp.MustCompile(
		`(?is)create\s+table(?:\s+if\s+not\s+exists)?\s+` + regexp.QuoteMeta(table) + `\s*\(`,
	)
	location := startPattern.FindStringIndex(body)
	if location == nil {
		return ""
	}
	openOffset := strings.LastIndex(body[location[0]:location[1]], "(")
	if openOffset < 0 {
		return ""
	}
	openIndex := location[0] + openOffset
	depth := 0
	for index := openIndex; index < len(body); index++ {
		switch body[index] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return body[location[0] : index+1]
			}
		}
	}
	return ""
}

func identityInsertStatements(body, table string) []string {
	pattern := regexp.MustCompile(
		`(?is)insert\s+into\s+` + regexp.QuoteMeta(table) + `\b.*?;`,
	)
	return pattern.FindAllString(body, -1)
}

func targetEmailUniqueConstraints(body string) ([]string, []namedEmailConstraint) {
	body = strings.ToLower(body)
	targetTables := []string{"users", "user_identity_links"}
	emailUnique := regexp.MustCompile(
		`(?is)(?:constraint\s+(\S+)\s+)?unique\s*\(\s*(?:tenant_id\s*,\s*email|email\s*,\s*tenant_id)\s*\)`,
	)
	var violations []string
	var namedConstraints []namedEmailConstraint

	for _, table := range targetTables {
		definition := createTableDefinition(body, table)
		for _, match := range emailUnique.FindAllStringSubmatch(definition, -1) {
			violations = append(violations, match[0])
			if match[1] != "" {
				namedConstraints = append(namedConstraints, namedEmailConstraint{table: table, name: match[1]})
			}
		}

		alterUnique := regexp.MustCompile(
			`(?is)alter\s+table\s+` + regexp.QuoteMeta(table) +
				`\s+add\s+(?:constraint\s+(\S+)\s+)?unique\s*\(\s*(?:tenant_id\s*,\s*email|email\s*,\s*tenant_id)\s*\)`,
		)
		for _, match := range alterUnique.FindAllStringSubmatch(body, -1) {
			violations = append(violations, match[0])
			if match[1] != "" {
				namedConstraints = append(namedConstraints, namedEmailConstraint{table: table, name: match[1]})
			}
		}
	}
	return violations, namedConstraints
}

func forbiddenEmailIdentityUpsert(body string) string {
	body = strings.ToLower(body)
	targetTables := []string{"users", "user_identity_links"}
	_, namedConstraints := targetEmailUniqueConstraints(body)

	emailConflict := regexp.MustCompile(
		`(?is)on\s+conflict\s*\(\s*(?:tenant_id\s*,\s*email|email\s*,\s*tenant_id)\s*\)`,
	)
	for _, table := range targetTables {
		for _, statement := range identityInsertStatements(body, table) {
			if match := emailConflict.FindString(statement); match != "" {
				return match
			}
		}
	}

	for _, constraint := range namedConstraints {
		namedConflict := regexp.MustCompile(
			`(?is)on\s+conflict\s+on\s+constraint\s+` + regexp.QuoteMeta(constraint.name) + `\b`,
		)
		for _, statement := range identityInsertStatements(body, constraint.table) {
			if match := namedConflict.FindString(statement); match != "" {
				return match
			}
		}
	}

	emailMerge := regexp.MustCompile(
		`(?is)merge\s+into\s+(?:users|user_identity_links)\b.*?\bon\b[^;]*?\bemail\b[^;]*?;`,
	)
	if match := emailMerge.FindString(body); match != "" {
		return match
	}
	return ""
}

func forbiddenEmailIdentityMerge(body string) string {
	body = strings.ToLower(body)
	if violations, _ := targetEmailUniqueConstraints(body); len(violations) > 0 {
		return violations[0]
	}

	uniqueIndex := regexp.MustCompile(
		`(?is)create\s+unique\s+index(?:\s+if\s+not\s+exists)?\s+\S+\s+on\s+(?:users|user_identity_links)\s*\(([^;]+)\)`,
	)
	for _, match := range uniqueIndex.FindAllStringSubmatch(body, -1) {
		columns := match[1]
		if regexp.MustCompile(`\btenant_id\b`).MatchString(columns) &&
			regexp.MustCompile(`\bemail\b`).MatchString(columns) {
			return match[0]
		}
	}
	return forbiddenEmailIdentityUpsert(body)
}

func TestEnterpriseIdentityDepartmentMigrationHasStableIdentityKey(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	if !strings.Contains(body, "create table if not exists user_identity_links") {
		t.Fatal("migration must create user_identity_links")
	}
	stableKey := regexp.MustCompile(`unique\s*\(\s*tenant_id\s*,\s*issuer\s*,\s*source_type\s*,\s*external_subject\s*\)`)
	if !stableKey.MatchString(body) {
		t.Fatal("user_identity_links must use the stable tenant/issuer/source/subject unique key")
	}
	if match := forbiddenEmailIdentityMerge(body); match != "" {
		t.Fatalf("migration must not merge or identify users by email: found %q", match)
	}
}

func TestForbiddenEmailIdentityMergeIsTargeted(t *testing.T) {
	riskySQL := []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS uq_user_email ON users ( tenant_id, email )",
		"CREATE UNIQUE INDEX uq_identity_email ON user_identity_links\n(tenant_id, email)",
		`CREATE TABLE user_identity_links (
			tenant_id text,
			email text,
			CONSTRAINT uq_identity_email UNIQUE (tenant_id, email)
		);`,
		"ALTER TABLE users ADD CONSTRAINT uq_user_email UNIQUE ( tenant_id, email );",
		"ALTER TABLE user_identity_links ADD CONSTRAINT uq_identity_email UNIQUE ( email, tenant_id );",
		"CREATE UNIQUE INDEX uq_user_email_expr ON users (tenant_id, lower(email));",
		"CREATE UNIQUE INDEX uq_identity_email_expr ON user_identity_links ((lower(email)), tenant_id);",
		"INSERT INTO users (tenant_id, email) VALUES ('t', 'e') ON CONFLICT (tenant_id, email) DO NOTHING;",
		"MERGE INTO user_identity_links target USING incoming source ON target.tenant_id=source.tenant_id AND target.email=source.email WHEN MATCHED THEN UPDATE SET external_subject=source.external_subject;",
	}
	for _, sql := range riskySQL {
		if match := forbiddenEmailIdentityMerge(sql); match == "" {
			t.Errorf("email identity guard did not detect %q", sql)
		}
	}

	namedEmailUpsert := `CREATE TABLE user_identity_links (
		tenant_id text,
		email text,
		CONSTRAINT uq_identity_email UNIQUE (tenant_id, email)
	);
	INSERT INTO user_identity_links (tenant_id, email) VALUES ('t', 'e')
	ON CONFLICT ON CONSTRAINT uq_identity_email DO NOTHING;`
	if match := forbiddenEmailIdentityUpsert(namedEmailUpsert); match == "" {
		t.Fatal("named email constraint upsert guard did not detect the matching identity insert")
	}

	safeSQL := `CREATE TABLE user_identity_links (
		tenant_id text,
		issuer text,
		source_type text,
		external_subject text,
		CONSTRAINT uq_identity_stable UNIQUE (tenant_id, issuer, source_type, external_subject)
	);
	INSERT INTO user_identity_links (tenant_id, issuer, source_type, external_subject)
	VALUES ('t', 'issuer', 'oidc', 'subject')
	ON CONFLICT ON CONSTRAINT uq_identity_stable DO NOTHING;`
	if match := forbiddenEmailIdentityMerge(safeSQL); match != "" {
		t.Fatalf("email identity guard rejected safe named stable constraint: %q", match)
	}
	if match := forbiddenEmailIdentityUpsert(safeSQL); match != "" {
		t.Fatalf("email upsert guard rejected safe named stable constraint: %q", match)
	}
}

func TestEnterpriseIdentityDepartmentMigrationDefinesSingleDepartmentAuthority(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	for _, required := range []string{
		"add column if not exists department_id",
		"department_assignment_mode",
		"department_assignment_source",
		"department_assignment_rule_id",
		"department_resolved_at",
		"references teams",
		"department_id is not null or department_assignment_mode = 'emergency'",
		"'automatic'",
		"'manual'",
		"'unassigned'",
		"'emergency'",
		"'local'",
		"'oidc'",
		"'ldap'",
		"'ad'",
		"'admin'",
		"'migration'",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("migration missing single-department contract %q", required)
		}
	}
}

func TestEnterpriseIdentityDepartmentMigrationDefinesMonotonicDepartmentVersion(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	patterns := map[string]string{
		"global sequence":           `create\s+sequence(?:\s+if\s+not\s+exists)?\s+users_department_version_seq`,
		"bigint version column":     `add\s+column\s+if\s+not\s+exists\s+department_version\s+bigint`,
		"existing row backfill":     `update\s+users\s+set\s+department_version\s*=\s*nextval\s*\(\s*'users_department_version_seq'`,
		"sequence-backed default":   `alter\s+column\s+department_version\s+set\s+default\s+nextval\s*\(\s*'users_department_version_seq'`,
		"non-null version":          `alter\s+column\s+department_version\s+set\s+not\s+null`,
		"insert and update trigger": `before\s+insert\s+or\s+update\s+of\s+department_id\s*,\s*department_assignment_mode\s*,\s*department_assignment_source\s*,\s*department_assignment_rule_id\s*,\s*department_resolved_at`,
		"sequence advancement":      `new\.department_version\s*:=\s*nextval\s*\(\s*'users_department_version_seq'`,
	}
	for contract, pattern := range patterns {
		requireEnterpriseIdentityMigrationPattern(t, body, contract, pattern)
	}
}

func TestEnterpriseIdentityDepartmentMigrationCreatesUnassignedDepartmentAndProjection(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	for _, required := range []string{
		"system_key",
		"where system_key = 'unassigned'",
		"未分配部门",
		"from team_members",
		"create unique index if not exists uq_team_members_user",
		"on team_members(user_id)",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("migration missing unassigned/projection contract %q", required)
		}
	}
}

func TestEnterpriseIdentityDepartmentMigrationSupportsPreviewAndUnifiedMappings(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	for _, required := range []string{
		"create table if not exists directory_sync_previews",
		"create table if not exists directory_sync_preview_entries",
		"create table if not exists identity_department_mappings",
		"identity_dept_mappings",
		"group_mapping_rules",
		"directory_group_mappings",
		"insert into identity_department_mappings",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("migration missing preview/unified mapping contract %q", required)
		}
	}
	for _, forbidden := range []string{
		"drop table identity_dept_mappings",
		"drop table group_mapping_rules",
		"drop table directory_group_mappings",
		"drop table if exists identity_dept_mappings",
		"drop table if exists group_mapping_rules",
		"drop table if exists directory_group_mappings",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("migration must preserve legacy mapping tables: found %q", forbidden)
		}
	}
}

func TestEnterpriseIdentityDepartmentMigrationDefinesDedicatedCacheInvalidationOutbox(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	for _, required := range []string{
		"create table if not exists identity_cache_invalidation_outbox",
		"attempt_count",
		"next_attempt_at",
		"locked_at",
		"locked_by",
		"last_error",
		"processed_at",
		"'pending'",
		"'processing'",
		"'failed'",
		"'processed'",
		"'dead_letter'",
		"idx_identity_cache_invalidation_due",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("migration missing dedicated identity cache outbox contract %q", required)
		}
	}
	if strings.Contains(createTableDefinition(body, "identity_cache_invalidation_outbox"), "outbox_events") {
		t.Fatal("identity cache invalidation must not reuse the global audit outbox")
	}
}

func requireEnterpriseIdentityMigrationPattern(t *testing.T, body, contract, pattern string) {
	t.Helper()
	if !regexp.MustCompile(`(?s)` + pattern).MatchString(body) {
		t.Fatalf("migration missing %s contract; pattern %q", contract, pattern)
	}
}

func TestEnterpriseIdentityDepartmentMigrationEnforcesTenantScopedForeignKeys(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	patterns := map[string]string{
		"users department tenant": `foreign\s+key\s*\(\s*tenant_id\s*,\s*department_id\s*\)\s*references\s+teams\s*\(\s*tenant_id\s*,\s*id\s*\)`,
		"mapping target tenant":   `foreign\s+key\s*\(\s*tenant_id\s*,\s*target_department_id\s*\)\s*references\s+teams\s*\(\s*tenant_id\s*,\s*id\s*\)`,
		"preview source tenant":   `foreign\s+key\s*\(\s*tenant_id\s*,\s*directory_source_id\s*\)\s*references\s+directory_sources\s*\(\s*tenant_id\s*,\s*id\s*\)`,
		"preview entry tenant":    `foreign\s+key\s*\(\s*tenant_id\s*,\s*preview_id\s*\)\s*references\s+directory_sync_previews\s*\(\s*tenant_id\s*,\s*id\s*\)`,
	}
	for contract, pattern := range patterns {
		requireEnterpriseIdentityMigrationPattern(t, body, contract, pattern)
	}
}

func TestEnterpriseIdentityDepartmentMigrationFreezesMappingUniqueKey(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	requireEnterpriseIdentityMigrationPattern(
		t,
		body,
		"mapping tenant/source/type/value uniqueness",
		`unique\s*\(\s*tenant_id\s*,\s*source_kind\s*,\s*source_id\s*,\s*match_type\s*,\s*match_value\s*\)`,
	)
}

func TestEnterpriseIdentityDepartmentMigrationUsesCanonicalTypedMatchNames(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	for contract, pattern := range map[string]string{
		"canonical mapping types":    `match_type\s+varchar\(32\)\s+not\s+null\s+check\s*\(\s*match_type\s+in\s*\(\s*'department'\s*,\s*'ou'\s*,\s*'member_of'\s*,\s*'groups'\s*\)\s*\)`,
		"legacy group normalization": `case\s+when\s+lower\(legacy\.match_type\)\s+in\s*\(\s*'group'\s*,\s*'groups'\s*\)\s+then\s+'groups'\s+else\s+'department'\s+end`,
	} {
		requireEnterpriseIdentityMigrationPattern(t, body, contract, pattern)
	}
}

func TestEnterpriseIdentityDepartmentMigrationProtectsEmergencyUsersDuringRerun(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	for contract, pattern := range map[string]string{
		"membership aggregation":                 `count\s*\(\s*t\.id\s*\)\s*::\s*integer\s+as\s+valid_department_count.*?min\s*\(\s*t\.id\s*\)\s+as\s+only_department_id`,
		"membership tenant join":                 `join\s+teams\s+t\s+on\s+t\.id\s*=\s*tm\.team_id\s+and\s+t\.tenant_id\s*=\s*u\.tenant_id`,
		"department assignment case":             `set\s+department_id\s*=\s*case\s+when\s+summary\.valid_department_count\s*=\s*1\s+then\s+summary\.only_department_id\s+else\s+unassigned\.id\s+end`,
		"assignment mode case":                   `department_assignment_mode\s*=\s*case\s+when\s+summary\.valid_department_count\s*=\s*1\s+then\s+'automatic'\s+else\s+'unassigned'\s+end`,
		"membership summary emergency exclusion": `with\s+membership_summary\s+as\s*\(.*?from\s+users\s+u.*?(?:from|join)\s+team_members.*?where\s+u\.department_assignment_mode\s*<>\s*'emergency'.*?group\s+by\s+u\.id\s*\)`,
		"zero membership branch":                 `when\s+summary\.valid_department_count\s*=\s*0\s+then\s+'migration:no_team_membership'`,
		"single membership branch":               `when\s+summary\.valid_department_count\s*=\s*1\s+then\s+'migration:single_membership'`,
		"multiple membership branch":             `else\s+'migration:multiple_memberships'`,
		"user backfill emergency exclusion":      `update\s+users\s+u.*?u\.department_id\s+is\s+null.*?u\.department_assignment_mode\s*<>\s*'emergency'\s*;`,
		"projection delete emergency exclusion":  `delete\s+from\s+team_members\s+tm.*?using\s+users\s+u.*?u\.department_assignment_mode\s*<>\s*'emergency'\s*;`,
		"projection insert emergency exclusion":  `insert\s+into\s+team_members.*?from\s+users\s+u.*?u\.department_id\s+is\s+not\s+null.*?u\.department_assignment_mode\s*<>\s*'emergency'.*?on\s+conflict`,
	} {
		requireEnterpriseIdentityMigrationPattern(t, body, contract, pattern)
	}
}

func enterpriseIdentityLegacyMappingBlock(t *testing.T, body, legacyTable string) string {
	t.Helper()
	fromMarker := "from " + legacyTable + " legacy"
	fromIndex := strings.Index(body, fromMarker)
	if fromIndex < 0 {
		t.Fatalf("migration missing legacy mapping source %s", legacyTable)
	}
	startIndex := strings.LastIndex(body[:fromIndex], "insert into identity_department_mappings")
	if startIndex < 0 {
		t.Fatalf("migration missing unified mapping insert for %s", legacyTable)
	}
	endOffset := strings.Index(body[fromIndex:], "on conflict do nothing;")
	if endOffset < 0 {
		t.Fatalf("migration mapping copy for %s must use ON CONFLICT DO NOTHING", legacyTable)
	}
	return body[startIndex : fromIndex+endOffset+len("on conflict do nothing;")]
}

func TestEnterpriseIdentityDepartmentMigrationCopiesEachLegacyMappingSafely(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	cases := []struct {
		name        string
		legacyTable string
		pattern     string
	}{
		{
			name:        "OIDC department mapping copy",
			legacyTable: "identity_dept_mappings",
			pattern:     `insert\s+into\s+identity_department_mappings.*?legacy\.identity_source_id.*?legacy\.match_value.*?legacy\.mapped_team_id.*?from\s+identity_dept_mappings\s+legacy.*?join\s+teams\s+target\s+on\s+target\.id\s*=\s*legacy\.mapped_team_id\s+and\s+target\.tenant_id\s*=\s*legacy\.tenant_id.*?where\s+legacy\.mapped_team_id\s+is\s+not\s+null.*?on\s+conflict\s+do\s+nothing`,
		},
		{
			name:        "legacy group mapping copy",
			legacyTable: "group_mapping_rules",
			pattern:     `insert\s+into\s+identity_department_mappings.*?legacy\.match_type.*?legacy\.match_value.*?legacy\.gateway_team_id.*?from\s+group_mapping_rules\s+legacy.*?join\s+teams\s+target\s+on\s+target\.id\s*=\s*legacy\.gateway_team_id\s+and\s+target\.tenant_id\s*=\s*legacy\.tenant_id.*?where\s+legacy\.gateway_team_id\s+is\s+not\s+null.*?on\s+conflict\s+do\s+nothing`,
		},
		{
			name:        "directory group mapping copy",
			legacyTable: "directory_group_mappings",
			pattern:     `insert\s+into\s+identity_department_mappings.*?legacy\.directory_source_id.*?legacy\.external_object_id.*?legacy\.mapped_team_id.*?from\s+directory_group_mappings\s+legacy.*?join\s+directory_sources\s+source\s+on\s+source\.id\s*=\s*legacy\.directory_source_id\s+and\s+source\.tenant_id\s*=\s*legacy\.tenant_id.*?join\s+teams\s+target\s+on\s+target\.id\s*=\s*legacy\.mapped_team_id\s+and\s+target\.tenant_id\s*=\s*legacy\.tenant_id.*?where\s+legacy\.mapped_team_id\s+is\s+not\s+null.*?on\s+conflict\s+do\s+nothing`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block := enterpriseIdentityLegacyMappingBlock(t, body, tc.legacyTable)
			requireEnterpriseIdentityMigrationPattern(t, block, tc.name, tc.pattern)
		})
	}
}

func TestEnterpriseIdentityDepartmentMigrationRejectsUnassignedNameHijack(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	hijack := regexp.MustCompile(`(?s)update\s+teams.*?name\s*=\s*'未分配部门'.*?system_key\s*=\s*'unassigned'`)
	if match := hijack.FindString(body); match != "" {
		t.Fatalf("migration must not convert a business department into the system department: %q", match)
	}
	for contract, pattern := range map[string]string{
		"same-name business department conflict": `if\s+exists\s*\(.*?from\s+teams.*?name\s*=\s*'未分配部门'.*?system_key\s+is\s+distinct\s+from\s+'unassigned'.*?\)\s+then\s+raise\s+exception`,
		"dedicated system department insert":     `insert\s+into\s+teams\s*\(\s*id\s*,\s*tenant_id\s*,\s*name\s*,\s*path\s*,\s*is_system\s*,\s*system_key\s*\).*?'未分配部门'.*?'unassigned'`,
	} {
		requireEnterpriseIdentityMigrationPattern(t, body, contract, pattern)
	}
}

func TestEnterpriseIdentityDepartmentMigrationMaintainsTeamMemberProjection(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	for contract, pattern := range map[string]string{
		"user projection trigger":         `create\s+trigger\s+trg_users_project_department.*?after\s+insert\s+or\s+update\s+of\s+department_id\s*,\s*department_assignment_mode\s+on\s+users`,
		"department projection upsert":    `insert\s+into\s+team_members\s*\(\s*team_id\s*,\s*user_id\s*,\s*role\s*\).*?on\s+conflict\s*\(\s*user_id\s*\)\s+do\s+update\s+set\s+team_id\s*=\s*excluded\.team_id`,
		"department change resets role":   `create\s+or\s+replace\s+function\s+project_user_department_to_team_members\(\).*?on\s+conflict\s*\(\s*user_id\s*\)\s+do\s+update\s+set\s+team_id\s*=\s*excluded\.team_id\s*,\s*role\s*=\s*case\s+when\s+team_members\.team_id\s+is\s+distinct\s+from\s+excluded\.team_id\s+then\s+'member'\s+else\s+team_members\.role\s+end`,
		"emergency projection removal":    `if\s+new\.department_assignment_mode\s*=\s*'emergency'.*?delete\s+from\s+team_members.*?user_id\s*=\s*new\.id`,
		"direct write validation trigger": `create\s+trigger\s+trg_team_members_validate_projection.*?before\s+insert\s+or\s+update\s+on\s+team_members`,
		"direct write department check":   `new\.team_id\s+is\s+distinct\s+from\s+expected_department_id.*?raise\s+exception`,
		"delete restoration trigger":      `create\s+trigger\s+trg_team_members_restore_projection.*?after\s+delete\s+on\s+team_members`,
		"delete restoration guard":        `select\s+department_id\s*,\s*department_assignment_mode.*?from\s+users.*?where\s+id\s*=\s*old\.user_id.*?if\s+found.*?<>\s*'emergency'.*?insert\s+into\s+team_members`,
	} {
		requireEnterpriseIdentityMigrationPattern(t, body, contract, pattern)
	}
}

func TestGenericUserUpdateDoesNotWriteDepartmentAuthority(t *testing.T) {
	body := readRepoFile(t, "users.go")
	start := strings.Index(body, "func (r *UserRepository) Update(")
	if start < 0 {
		t.Fatal("could not find UserRepository.Update")
	}
	end := strings.Index(body[start:], "// UpdatePassword")
	if end < 0 {
		t.Fatal("could not isolate UserRepository.Update")
	}
	updateMethod := body[start : start+end]
	if strings.Contains(updateMethod, "department_") {
		t.Fatalf("generic user update must not write department authority: %s", updateMethod)
	}
}

func TestEnterpriseIdentityDepartmentMigrationDefinesStableIssuerSemantics(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	for contract, pattern := range map[string]string{
		"non-empty issuer":        `check\s*\(\s*btrim\s*\(\s*issuer\s*\)\s*<>\s*''\s*\)`,
		"directory issuer source": `check\s*\(\s*source_type\s+not\s+in\s*\(\s*'ldap'\s*,\s*'ad'\s*\).*?source_id\s*=\s*issuer\s*\)`,
	} {
		requireEnterpriseIdentityMigrationPattern(t, body, contract, pattern)
	}
}

func TestEnterpriseIdentityDepartmentMigrationScopesActivatedRunToTenant(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	for contract, pattern := range map[string]string{
		"sync run tenant key":              `alter\s+table\s+directory_sync_runs.*?add\s+constraint\s+uq_directory_sync_runs_tenant_id\s+unique\s*\(\s*tenant_id\s*,\s*id\s*\)`,
		"activated run tenant foreign key": `foreign\s+key\s*\(\s*tenant_id\s*,\s*activated_run_id\s*\)\s*references\s+directory_sync_runs\s*\(\s*tenant_id\s*,\s*id\s*\)`,
	} {
		requireEnterpriseIdentityMigrationPattern(t, body, contract, pattern)
	}
}

func TestEnterpriseIdentityDepartmentMigrationDocumentsLegacyFallbackAndMaintenanceWindow(t *testing.T) {
	body := enterpriseIdentityMigrationBody(t)
	for _, required := range []string{
		"maintenance window",
		"pause iam writes",
		"backup",
		"verify users and team_members counts",
		"empty source_id is a tenant-level legacy fallback",
		"prefer exact source_id before empty fallback",
		"without model, application, or budget bindings",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("migration missing operational/fallback contract %q", required)
		}
	}
}
