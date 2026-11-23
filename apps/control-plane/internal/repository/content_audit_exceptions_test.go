package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setupContentAuditExceptionTestDB(t *testing.T) (*pgxpool.Pool, string, string) {
	t.Helper()
	dbURL := os.Getenv("RULES_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	}
	if dbURL == "" {
		t.Skip("RULES_TEST_DATABASE_URL or CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	schema := fmt.Sprintf("content_audit_exceptions_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatalf("create isolated schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		admin.Close()
		t.Fatalf("parse database config: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatalf("connect isolated schema: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
		admin.Close()
	})
	for _, statement := range []string{
		`CREATE TABLE tenants (
			id VARCHAR(64) PRIMARY KEY,
			name TEXT NOT NULL,
			edition TEXT NOT NULL,
			status TEXT NOT NULL,
			is_test BOOLEAN NOT NULL DEFAULT TRUE
		)`,
		`CREATE TABLE rule_sets (
			id VARCHAR(64) PRIMARY KEY,
			tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			version TEXT NOT NULL,
			source_type TEXT NOT NULL,
			published BOOLEAN NOT NULL DEFAULT FALSE,
			created_by VARCHAR(64)
		)`,
		`CREATE TABLE rules (
			id VARCHAR(64) PRIMARY KEY,
			rule_set_id VARCHAR(64) NOT NULL REFERENCES rule_sets(id) ON DELETE CASCADE,
			rule_type TEXT NOT NULL,
			name TEXT NOT NULL,
			priority INTEGER NOT NULL DEFAULT 0,
			severity TEXT NOT NULL,
			match_config_json JSONB NOT NULL DEFAULT '{}',
			action TEXT NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			description TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE content_audit_exceptions (
		id VARCHAR(64) PRIMARY KEY,
		tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		scope_type VARCHAR(32) NOT NULL,
			scope_ref VARCHAR(255) NOT NULL,
			include_children BOOLEAN NOT NULL DEFAULT FALSE,
		rule_id VARCHAR(64) REFERENCES rules(id) ON DELETE CASCADE,
		rule_ref TEXT,
		decision VARCHAR(16) NOT NULL,
		reason TEXT NOT NULL,
		expires_at TIMESTAMP WITH TIME ZONE,
		enabled BOOLEAN NOT NULL,
		created_by VARCHAR(64),
		created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
	)`,
	} {
		if _, err := db.Exec(ctx, statement); err != nil {
			t.Fatalf("create isolated fixture table: %v", err)
		}
	}
	tenantID := fmt.Sprintf("tenant_content_exc_%d", time.Now().UnixNano())
	ruleSetID := fmt.Sprintf("ruleset_content_exc_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, $3, $4, TRUE)`, tenantID, tenantID, "enterprise", "active"); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO rule_sets (id, tenant_id, name, version, source_type, published, created_by) VALUES ($1, $2, $3, $4, $5, true, $6)`, ruleSetID, tenantID, "内容安全测试规则集", "1.0.0", "test", "test"); err != nil {
		t.Fatalf("insert rule set: %v", err)
	}
	return db, tenantID, ruleSetID
}

func callCreateContentAuditExceptionWithoutDatabase(e *ContentAuditException) (err error, panicValue any) {
	defer func() {
		panicValue = recover()
	}()
	err = NewRuleRepository(nil).CreateContentAuditException(context.Background(), e)
	return err, nil
}

func TestCreateContentAuditExceptionRejectsInvalidStrictPackScopeBeforeDatabase(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)
	tests := []struct {
		name      string
		scopeType string
		scopeRef  string
		ruleID    string
		ruleRef   string
	}{
		{name: "empty scope", scopeType: ""},
		{name: "unknown scope", scopeType: "workspace"},
		{name: "project without scope ref", scopeType: "project"},
		{name: "user with blank scope ref", scopeType: "user", scopeRef: "  \t "},
		{name: "rule without rule reference", scopeType: "rule"},
		{name: "key v1 without stable key id", scopeType: "key_v1"},
		{name: "actor department v1 without team id", scopeType: "actor_department_v1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exception := &ContentAuditException{
				TenantID: "tenant-boundary", ScopeType: tc.scopeType, ScopeRef: tc.scopeRef,
				RuleID: tc.ruleID, RuleRef: tc.ruleRef, Decision: "audit", Reason: "required reason",
				ExpiresAt: &expiresAt, Enabled: true,
			}
			err, panicValue := callCreateContentAuditExceptionWithoutDatabase(exception)
			if panicValue != nil {
				t.Fatalf("invalid exception reached database instead of validation: %v", panicValue)
			}
			if err == nil {
				t.Fatal("invalid exception must be rejected before database access")
			}
		})
	}
}

func TestCreateContentAuditExceptionRejectsIncludeChildrenOutsideActorDepartmentBeforeDatabase(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)
	exception := &ContentAuditException{
		TenantID: "tenant-boundary", ScopeType: "key_v1", ScopeRef: "key-stable",
		Decision: "audit", Reason: "required reason", ExpiresAt: &expiresAt,
		IncludeChildren: true, Enabled: true,
	}

	err, panicValue := callCreateContentAuditExceptionWithoutDatabase(exception)

	if panicValue != nil {
		t.Fatalf("invalid include_children reached database instead of validation: %v", panicValue)
	}
	if err == nil || !errors.Is(err, ErrInvalidContentAuditException) {
		t.Fatalf("include_children outside department scope must be rejected, err=%v", err)
	}
}

func TestCreateContentAuditExceptionRejectsOversizedFieldsBeforeDatabase(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)
	tests := []struct {
		name      string
		scopeType string
		scopeRef  string
		ruleID    string
		ruleRef   string
		reason    string
	}{
		{name: "scope type", scopeType: strings.Repeat("t", 33), reason: "reason"},
		{name: "scope ref", scopeType: "project", scopeRef: strings.Repeat("p", 256), reason: "reason"},
		{name: "rule id", scopeType: "rule", ruleID: strings.Repeat("r", 65), reason: "reason"},
		{name: "rule ref", scopeType: "rule", ruleRef: strings.Repeat("r", 256), reason: "reason"},
		{name: "reason", scopeType: "tenant", reason: strings.Repeat("x", 2049)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exception := &ContentAuditException{
				TenantID: "tenant-boundary", ScopeType: tc.scopeType, ScopeRef: tc.scopeRef,
				RuleID: tc.ruleID, RuleRef: tc.ruleRef, Decision: "audit", Reason: tc.reason,
				ExpiresAt: &expiresAt, Enabled: true,
			}
			err, panicValue := callCreateContentAuditExceptionWithoutDatabase(exception)
			if panicValue != nil {
				t.Fatalf("oversized exception reached database instead of validation: %v", panicValue)
			}
			if err == nil {
				t.Fatal("oversized exception field must be rejected before database access")
			}
		})
	}
}

func insertContentAuditExceptionRule(t *testing.T, db *pgxpool.Pool, ruleSetID, category string) string {
	t.Helper()
	ruleID := fmt.Sprintf("rule_content_exc_%d", time.Now().UnixNano())
	_, err := db.Exec(context.Background(), `
		INSERT INTO rules (id, rule_set_id, rule_type, name, priority, severity, match_config_json, action, enabled, description)
		VALUES ($1, $2, $3, $4, 100, $5, $6::jsonb, $7, true, $8)
	`, ruleID, ruleSetID, "regex", "客户规则", "high", fmt.Sprintf(`{"category":"%s","regex":"TEST-[0-9]+"}`, category), "block", "测试规则")
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	return ruleID
}
func TestCreateContentAuditExceptionAllowsCustomerRuleAndListsIt(t *testing.T) {
	db, tenantID, ruleSetID := setupContentAuditExceptionTestDB(t)
	ruleID := insertContentAuditExceptionRule(t, db, ruleSetID, "customer_sensitive_data")
	repo := NewRuleRepository(db)

	exp := time.Now().Add(24 * time.Hour)
	err := repo.CreateContentAuditException(context.Background(), &ContentAuditException{
		TenantID:  tenantID,
		ScopeType: "tenant",
		RuleID:    ruleID,
		Decision:  "audit",
		Reason:    "客户确认该编号为测试数据",
		ExpiresAt: &exp,
		Enabled:   true,
		CreatedBy: "user_admin",
	})
	if err != nil {
		t.Fatalf("CreateContentAuditException: %v", err)
	}

	got, err := repo.ListContentAuditExceptionsByTenant(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("ListContentAuditExceptionsByTenant: %v", err)
	}
	if len(got) != 1 || got[0].RuleID != ruleID || got[0].Decision != "audit" {
		t.Fatalf("unexpected exceptions: %+v", got)
	}
}

func TestCreateContentAuditExceptionNormalizesStrictPackFieldsBeforeInsert(t *testing.T) {
	db, tenantID, _ := setupContentAuditExceptionTestDB(t)
	repo := NewRuleRepository(db)

	exp := time.Now().Add(24 * time.Hour)
	exception := &ContentAuditException{
		TenantID:  tenantID,
		ScopeType: "  Project  ",
		ScopeRef:  "  project-42  ",
		Decision:  "  AUDIT  ",
		Reason:    "  approved false positive  ",
		ExpiresAt: &exp,
		Enabled:   true,
		CreatedBy: "user_admin",
	}
	if err := repo.CreateContentAuditException(context.Background(), exception); err != nil {
		t.Fatalf("CreateContentAuditException: %v", err)
	}

	got, err := repo.ListContentAuditExceptionsByTenant(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("ListContentAuditExceptionsByTenant: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("exceptions=%d want=1", len(got))
	}
	if got[0].ScopeType != "project" || got[0].ScopeRef != "project-42" || got[0].Decision != "audit" || got[0].Reason != "approved false positive" {
		t.Fatalf("stored fields were not normalized for strict pack contract: %+v", got[0])
	}
}

func TestCreateContentAuditExceptionPersistsDepartmentChildScope(t *testing.T) {
	db, tenantID, _ := setupContentAuditExceptionTestDB(t)
	repo := NewRuleRepository(db)
	exception := &ContentAuditException{
		ID:              fmt.Sprintf("cex_dept_%d", time.Now().UnixNano()),
		TenantID:        tenantID,
		ScopeType:       "actor_department_v1",
		ScopeRef:        "dept-parent",
		IncludeChildren: true,
		Decision:        "audit",
		Reason:          "approved department false positive",
		Enabled:         true,
	}

	if err := repo.CreateContentAuditException(context.Background(), exception); err != nil {
		t.Fatalf("CreateContentAuditException: %v", err)
	}
	got, err := repo.ListContentAuditExceptionsByTenant(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("ListContentAuditExceptionsByTenant: %v", err)
	}
	if len(got) != 1 || got[0].ScopeType != "actor_department_v1" ||
		got[0].ScopeRef != "dept-parent" || !got[0].IncludeChildren {
		t.Fatalf("department child scope was not preserved: %+v", got)
	}
}

func TestListActiveContentAuditExceptionsRejectsTenantOverflow(t *testing.T) {
	db, tenantID, _ := setupContentAuditExceptionTestDB(t)
	if _, err := db.Exec(context.Background(), `
		INSERT INTO content_audit_exceptions
			(id, tenant_id, scope_type, scope_ref, decision, reason, expires_at, enabled, created_by)
		SELECT 'cex_limit_' || value::text, $1, 'tenant', '', 'audit', 'limit probe', NOW() + INTERVAL '1 day', TRUE, 'test'
		FROM generate_series(1, 10001) AS value
	`, tenantID); err != nil {
		t.Fatalf("insert exception overflow fixture: %v", err)
	}

	exceptions, err := NewRuleRepository(db).ListActiveContentAuditExceptionsByTenant(context.Background(), tenantID)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "limit") {
		t.Fatalf("overflow must return a stable limit error, exceptions=%d err=%v", len(exceptions), err)
	}
	if exceptions != nil {
		t.Fatalf("overflow must not return a partial pack candidate set: %d", len(exceptions))
	}
}

func TestDisableContentAuditExceptionHidesItFromActiveList(t *testing.T) {
	db, tenantID, ruleSetID := setupContentAuditExceptionTestDB(t)
	ruleID := insertContentAuditExceptionRule(t, db, ruleSetID, "customer_sensitive_data")
	repo := NewRuleRepository(db)
	exp := time.Now().Add(24 * time.Hour)
	exception := &ContentAuditException{
		ID:        "cex_disable_" + fmt.Sprint(time.Now().UnixNano()),
		TenantID:  tenantID,
		ScopeType: "tenant",
		RuleID:    ruleID,
		Decision:  "audit",
		Reason:    "误报临时例外",
		ExpiresAt: &exp,
		Enabled:   true,
		CreatedBy: "user_admin",
	}
	if err := repo.CreateContentAuditException(context.Background(), exception); err != nil {
		t.Fatalf("CreateContentAuditException: %v", err)
	}
	deleted, err := repo.DisableContentAuditException(context.Background(), tenantID, exception.ID)
	if err != nil {
		t.Fatalf("DisableContentAuditException: %v", err)
	}
	if !deleted {
		t.Fatalf("expected exception to be disabled")
	}
	active, err := repo.ListActiveContentAuditExceptionsByTenant(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("ListActiveContentAuditExceptionsByTenant: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("disabled exception must not stay active: %+v", active)
	}
}

func TestContentAuditExceptionJSONUsesFrontendContract(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	exception := ContentAuditException{
		ID:              "cex_contract",
		TenantID:        "tenant-a",
		ScopeType:       "tenant",
		ScopeRef:        "",
		IncludeChildren: false,
		RuleID:          "rule_1",
		RuleRef:         "rule_1",
		Decision:        "audit",
		Reason:          "误报",
		ExpiresAt:       &exp,
		Enabled:         true,
		CreatedBy:       "user_admin",
		CreatedAt:       time.Now(),
	}

	encoded, err := json.Marshal(exception)
	if err != nil {
		t.Fatalf("marshal exception: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal exception: %v", err)
	}
	for _, key := range []string{"id", "tenant_id", "scope_type", "scope_ref", "include_children", "rule_id", "rule_ref", "decision", "reason", "expires_at", "enabled", "created_by", "created_at"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing frontend JSON key %q in %s", key, string(encoded))
		}
	}
	if _, ok := got["ID"]; ok {
		t.Fatalf("must not expose Go field name ID in %s", string(encoded))
	}
}

// The console and the API never send an exception id. An empty id used to be stored as-is: the row had
// no addressable key, a second exception hit the primary key, and the engine rejected every rule pack
// that contained it ("malformed exception in pack (exception_id=)").
func TestCreateContentAuditExceptionAssignsDistinctIDsWhenNoneGiven(t *testing.T) {
	db, tenantID, _ := setupContentAuditExceptionTestDB(t)
	repo := NewRuleRepository(db)
	ctx := context.Background()
	for _, scope := range []string{"project-a", "project-b"} {
		if err := repo.CreateContentAuditException(ctx, &ContentAuditException{
			TenantID: tenantID, ScopeType: "project", ScopeRef: scope, Decision: "audit", Reason: "误报豁免", Enabled: true,
		}); err != nil {
			t.Fatalf("create exception for %s without an id: %v", scope, err)
		}
	}
	active, err := repo.ListActiveContentAuditExceptionsByTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("list active exceptions: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("active exceptions=%d want 2", len(active))
	}
	if active[0].ID == "" || active[1].ID == "" || active[0].ID == active[1].ID {
		t.Fatalf("every exception needs its own non-empty id: %q %q", active[0].ID, active[1].ID)
	}
	if !strings.HasPrefix(active[0].ID, "cex_") {
		t.Fatalf("generated id %q should use the cex_ prefix", active[0].ID)
	}
	if ok, err := repo.DisableContentAuditException(ctx, tenantID, active[0].ID); err != nil || !ok {
		t.Fatalf("the generated id must be addressable by the disable API ok=%v err=%v", ok, err)
	}
}
