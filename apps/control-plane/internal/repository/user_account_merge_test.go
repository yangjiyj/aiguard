package repository

import (
	"context"
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAccountMergePreviewChoicesAndAtomicAttribution(t *testing.T) {
	db, tenant, target, dept, _, _ := employeeKeyFixture(t)
	ctx := context.Background()
	mergeActor := tenant + "_review_admin"
	if _, err := db.Exec(ctx, "INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,'reviewadmin'||$1::varchar,'platform_admin','active')", mergeActor, tenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec(ctx, `DELETE FROM user_account_merges WHERE tenant_id=$1`, tenant) })
	source := tenant + "_source"
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE users SET role='chat_user' WHERE id=$1`, target)
	exec(`INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode) VALUES($1,$2,$1,'chat_user','active',$3,'manual')`, source, tenant, dept)
	exec(`INSERT INTO user_identity_links(id,tenant_id,user_id,issuer,source_type,external_subject) VALUES($1,$2,$3,'https://idp.fixture','oidc','source-subject')`, tenant+"_link", tenant, source)
	exec(`INSERT INTO user_model_policies(tenant_id,user_id,mode,model_names,updated_by) VALUES($1,$2,'allowlist','[]',$3)`, tenant, source, target)
	repo := NewUserAccountMergeRepository(db)
	preview, err := repo.Preview(ctx, tenant, source, target, mergeActor)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.RequiredChoices) == 0 {
		t.Fatal("policy conflict must require an explicit choice")
	}
	var owner string
	if err = db.QueryRow(ctx, `SELECT user_id FROM user_identity_links WHERE id=$1`, tenant+"_link").Scan(&owner); err != nil || owner != source {
		t.Fatal("preview changed identity ownership")
	}
	if _, err = repo.Merge(ctx, tenant, source, target, mergeActor, AccountMergeInput{PreviewVersion: preview.Version}); !errors.Is(err, ErrAccountMergeChoices) {
		t.Fatalf("missing choices err=%v", err)
	}
	result, err := repo.Merge(ctx, tenant, source, target, mergeActor, AccountMergeInput{PreviewVersion: preview.Version, Choices: map[string]string{"personal_policy": "target"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.TargetUserID != target {
		t.Fatal("wrong target")
	}
	var status string
	if err = db.QueryRow(ctx, `SELECT status FROM users WHERE id=$1`, source).Scan(&status); err != nil || status != "disabled" {
		t.Fatal("source remains active")
	}
	if err = db.QueryRow(ctx, `SELECT user_id FROM user_identity_links WHERE id=$1`, tenant+"_link").Scan(&owner); err != nil || owner != target {
		t.Fatal("link was not moved")
	}
	var audit int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND action_type='user.account.merged'`, tenant).Scan(&audit); err != nil || audit != 1 {
		t.Fatalf("audits=%d err=%v", audit, err)
	}
	if _, err = repo.Preview(ctx, "other-tenant", source, target, mergeActor); err == nil {
		t.Fatal("cross-tenant preview accepted")
	}
}

func TestAccountMergeRollbackAndInactiveTarget(t *testing.T) {
	db, tenant, target, dept, project, _ := employeeKeyFixture(t)
	ctx := context.Background()
	mergeActor := tenant + "_review_admin"
	if _, err := db.Exec(ctx, "INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,'reviewadmin'||$1::varchar,'platform_admin','active')", mergeActor, tenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec(ctx, `DELETE FROM user_account_merges WHERE tenant_id=$1`, tenant) })
	source := tenant + "_source"
	_, err := db.Exec(ctx, `UPDATE users SET role='chat_user' WHERE id=$1`, target)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode) VALUES($1,$2,$1,'chat_user','active',$3,'manual')`, source, tenant, dept)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, "INSERT INTO user_identity_links(id,tenant_id,user_id,issuer,source_type,external_subject) VALUES($1,$2,$3,'https://rollback.test','oidc','rollback-subject')", tenant+"_rollback_link", tenant, source); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, "INSERT INTO internal_keys(id,tenant_id,user_id,project_id,key_hash,key_prefix,status) VALUES($1,$2,$3,$4,$1,'fixture','active')", tenant+"_rollback_key", tenant, source, project); err != nil {
		t.Fatal(err)
	}
	actor := tenant + "_actor"
	if _, err = db.Exec(ctx, "INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,$1,'tenant_admin','active')", actor, tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewUserAccountMergeRepository(db)
	p, err := repo.Preview(ctx, tenant, source, target, mergeActor)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `CREATE OR REPLACE FUNCTION reject_account_merge_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action_type='user.account.merged' THEN RAISE EXCEPTION 'isolated rollback'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_account_merge_test BEFORE INSERT ON audit_operations FOR EACH ROW EXECUTE FUNCTION reject_account_merge_test()`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.Merge(ctx, tenant, source, target, mergeActor, AccountMergeInput{PreviewVersion: p.Version, Choices: map[string]string{"api_keys": "revoke_source"}})
	if err == nil {
		t.Fatal("audit failure did not roll back")
	}
	_, dropErr := db.Exec(ctx, `DROP TRIGGER reject_account_merge_test ON audit_operations; DROP FUNCTION reject_account_merge_test()`)
	if dropErr != nil {
		t.Fatal(dropErr)
	}
	var owner, keyStatus string
	if err = db.QueryRow(ctx, "SELECT user_id FROM user_identity_links WHERE id=$1", tenant+"_rollback_link").Scan(&owner); err != nil || owner != source {
		t.Fatal("identity transfer escaped rollback")
	}
	if err = db.QueryRow(ctx, "SELECT status FROM internal_keys WHERE id=$1", tenant+"_rollback_key").Scan(&keyStatus); err != nil || keyStatus != "active" {
		t.Fatal("Key revocation escaped rollback")
	}
	var status string
	if err = db.QueryRow(ctx, `SELECT status FROM users WHERE id=$1`, source).Scan(&status); err != nil || status != "active" {
		t.Fatal("source state escaped rollback")
	}
	_, err = db.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.Preview(ctx, tenant, source, target, actor); err == nil {
		t.Fatal("inactive target accepted")
	}
}

func TestIdentityUsernameCollisionIsExplicitAndDoesNotCreateSuffixAccount(t *testing.T) {
	db, tenant, user, dept, _, _ := employeeKeyFixture(t)
	ctx := context.Background()
	repo := NewUserIdentityLinkRepository(db)
	err := repo.InTransaction(ctx, func(tx identitybinding.Transaction) error {
		return tx.CreateUser(ctx, identitybinding.User{ID: tenant + "_duplicate", TenantID: tenant, Username: user, Role: "chat_user", Status: "active", DepartmentID: dept, AssignmentMode: "manual", AssignmentSource: "admin"})
	})
	if !errors.Is(err, identitybinding.ErrConflict) {
		t.Fatalf("collision err=%v", err)
	}
	var count int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM users WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate account count=%d err=%v", count, err)
	}
}

func TestAccountMergeEmployeeAndPersonalKeysUseChosenDepartment(t *testing.T) {
	db, tenant, target, targetDept, targetProject, targetVersion := employeeKeyFixture(t)
	ctx := context.Background()
	mergeActor := tenant + "_review_admin"
	if _, err := db.Exec(ctx, "INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,'reviewadmin'||$1::varchar,'platform_admin','active')", mergeActor, tenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec(ctx, "DELETE FROM user_account_merges WHERE tenant_id=$1", tenant) })
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	source, sourceDept, sourceProject := tenant+"_source", tenant+"_dept", tenant+"_project"
	actor := tenant + "_admin"
	exec("INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,$1,'tenant_admin','active')", actor, tenant)
	exec("INSERT INTO teams(id,tenant_id,name,path) VALUES($1,$2,$1,$1)", sourceDept, tenant)
	exec("INSERT INTO projects(id,tenant_id,name,team_id,status,code,environment) VALUES($1,$2,$1,$3,'active','source','production')", sourceProject, tenant, sourceDept)
	exec("INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode,department_assignment_source,must_change_password) VALUES($1,$2,$1,'chat_user','active',$3,'manual','local',false)", source, tenant, sourceDept)
	if err := NewProjectUserRepository(db).BindUser(ctx, sourceProject, source); err != nil {
		t.Fatal(err)
	}
	var sv int64
	if err := db.QueryRow(ctx, "SELECT department_version FROM users WHERE id=$1", source).Scan(&sv); err != nil {
		t.Fatal(err)
	}
	keys := NewEmployeeAPIKeyRepository(db)
	oldTarget, _, err := keys.Ensure(ctx, tenant, target, targetProject, targetDept, targetVersion)
	if err != nil {
		t.Fatal(err)
	}
	oldSource, _, err := keys.Ensure(ctx, tenant, source, sourceProject, sourceDept, sv)
	if err != nil {
		t.Fatal(err)
	}
	exec("INSERT INTO internal_keys(id,tenant_id,user_id,project_id,key_hash,key_prefix,status) VALUES($1,$2,$3,$4,$1,'fixture','active')", tenant+"_personal", tenant, source, sourceProject)
	repo := NewUserAccountMergeRepository(db)
	p, err := repo.Preview(ctx, tenant, source, target, actor)
	if err != nil {
		t.Fatal(err)
	}
	choices := map[string]string{"department": "target", "api_keys": "move_source", "employee_key": "source"}
	if _, err = repo.Merge(ctx, tenant, source, target, actor, AccountMergeInput{PreviewVersion: p.Version, Choices: choices}); err != nil {
		t.Fatal(err)
	}
	current, err := keys.Current(ctx, tenant, target)
	if err != nil || current == nil || current.ID != oldSource.ID || current.ProjectID != targetProject {
		t.Fatalf("employee key not usable in chosen department: err=%v", err)
	}
	var owner, project, status string
	if err = db.QueryRow(ctx, "SELECT user_id,project_id,status FROM internal_keys WHERE id=$1", tenant+"_personal").Scan(&owner, &project, &status); err != nil || owner != target || project != targetProject || status != "active" {
		t.Fatalf("personal key attribution invalid owner=%s project=%s status=%s err=%v", owner, project, status, err)
	}
	if err = db.QueryRow(ctx, "SELECT status FROM internal_keys WHERE id=$1", oldTarget.ID).Scan(&status); err != nil || status != "revoked" {
		t.Fatal("conflicting target employee key retained")
	}
}

func TestAccountMergeExpiredDuplicateGrantAndHistory(t *testing.T) {
	db, tenant, target, dept, _, _ := employeeKeyFixture(t)
	ctx := context.Background()
	mergeActor := tenant + "_review_admin"
	if _, err := db.Exec(ctx, "INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,'reviewadmin'||$1::varchar,'platform_admin','active')", mergeActor, tenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec(ctx, "DELETE FROM user_account_merges WHERE tenant_id=$1", tenant) })
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	source := tenant + "_source"
	exec("UPDATE users SET role='chat_user' WHERE id=$1", target)
	exec("INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode,email) VALUES($1,$2,$1,'chat_user','active',$3,'manual','Same@corp.test ')", source, tenant, dept)
	exec("UPDATE users SET email='same@corp.test' WHERE id=$1", target)
	exec("INSERT INTO user_model_extra_grants(id,tenant_id,user_id,model,reason,created_by,created_at,expires_at) VALUES($1,$2,$3,'outside-model','source reason',$4,now()-interval '2 days',now()+interval '1 day')", tenant+"_grant1", tenant, source, target)
	exec("INSERT INTO user_model_extra_grants(id,tenant_id,user_id,model,reason,created_by,created_at,expires_at) VALUES($1,$2,$3,'outside-model','expired target',$3,now()-interval '2 days',now()-interval '1 day')", tenant+"_grant2", tenant, target)
	uploads := NewPortalUploadEventRepository(db)
	if err := uploads.Insert(ctx, PortalUploadEvent{ID: tenant + "_event", TenantID: tenant, UserID: source, Filename: "same.txt", SHA256: "isolated-sha", Size: 10}); err != nil {
		t.Fatal(err)
	}
	repo := NewUserAccountMergeRepository(db)
	peers, err := repo.PossibleDuplicates(ctx, tenant)
	if err != nil || len(peers[target]) != 1 || peers[target][0] != source {
		t.Fatal("normalized email duplicate missing")
	}
	p, err := repo.Preview(ctx, tenant, source, target, mergeActor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.Merge(ctx, tenant, source, target, mergeActor, AccountMergeInput{PreviewVersion: p.Version, Choices: map[string]string{"extra_grants": "union"}}); err != nil {
		t.Fatal(err)
	}
	events, total, err := uploads.ListByUser(ctx, tenant, target, 50, 0)
	if err != nil || total != 1 || len(events) != 1 || events[0].UserID != source {
		t.Fatalf("historical files not visible total=%d err=%v", total, err)
	}
	var audits int
	if err = db.QueryRow(ctx, "SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND action_type IN('user.model_extra.transferred','user.model_extra.expired')", tenant).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("grant audit count=%d err=%v", audits, err)
	}
}

func TestAccountMergeBillingHistoryAmountsAndIdentityRebind(t *testing.T) {
	db, tenant, target, dept, project, _ := employeeKeyFixture(t)
	ctx := context.Background()
	mergeActor := tenant + "_review_admin"
	if _, err := db.Exec(ctx, "INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,'reviewadmin'||$1::varchar,'platform_admin','active')", mergeActor, tenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec(ctx, "DELETE FROM user_account_merges WHERE tenant_id=$1", tenant) })
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	source := tenant + "_source"
	exec("UPDATE users SET role='chat_user' WHERE id=$1", target)
	exec("INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode) VALUES($1,$2,$1,'chat_user','active',$3,'manual')", source, tenant, dept)
	exec("INSERT INTO user_identity_links(id,tenant_id,user_id,issuer,source_type,external_subject) VALUES($1,$2,$3,'https://idp.test','oidc','merged-subject')", tenant+"_link", tenant, source)
	exec("INSERT INTO billing_usage_facts(id,tenant_id,request_id,user_id,model_name,billable_amount_micros,prompt_tokens,output_tokens,occurred_at,admitted_at) VALUES($1,$2,$1,$3,'merged-model',12345,20,5,now(),now())", tenant+"_fact", tenant, source)
	exec("INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens) VALUES($1,$1,$2,$3,$4,'responses','success',20,5)", tenant+"_fact", tenant, project, source)
	repo := NewUserAccountMergeRepository(db)
	// A link rebind only moves the chosen identity and invalidates pending proof.
	rp1, err := repo.Preview(ctx, tenant, source, target, mergeActor)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.RebindIdentity(ctx, tenant, source, target, mergeActor, tenant+"_link", rp1.Version); err != nil {
		t.Fatal(err)
	}
	var owner string
	if err := db.QueryRow(ctx, "SELECT user_id FROM user_identity_links WHERE id=$1", tenant+"_link").Scan(&owner); err != nil || owner != target {
		t.Fatal("identity rebind missing")
	}
	rp2, err := repo.Preview(ctx, tenant, target, source, mergeActor)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.RebindIdentity(ctx, tenant, target, source, mergeActor, tenant+"_link", rp2.Version); err != nil {
		t.Fatal(err)
	}
	p, err := repo.Preview(ctx, tenant, source, target, mergeActor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.Merge(ctx, tenant, source, target, mergeActor, AccountMergeInput{PreviewVersion: p.Version}); err != nil {
		t.Fatal(err)
	}
	summary, err := billing.NewStore(db).CustomerSummary(ctx, tenant, target, time.Now().Add(-time.Hour), 50)
	if err != nil || summary == nil || summary.Usage.AmountMicros != 12345 || summary.Usage.Requests != 1 {
		t.Fatalf("merged billing attribution missing err=%v", err)
	}
	calls, total, err := NewRequestLogRepository(db).ListPortalCallRecords(ctx, PortalCallRecordFilter{TenantID: tenant, UserID: target, StartTime: time.Now().Add(-time.Hour), Limit: 50})
	if err != nil || total != 1 || len(calls) != 1 {
		t.Fatalf("merged calls missing total=%d err=%v", total, err)
	}
	var amount int64
	if err = db.QueryRow(ctx, "SELECT user_id,billable_amount_micros FROM billing_usage_facts WHERE id=$1", tenant+"_fact").Scan(&owner, &amount); err != nil || owner != source || amount != 12345 {
		t.Fatal("settled fact changed")
	}
	raw, readErr := os.ReadFile("../../../../deploy/migrations/974_user_account_merges.sql")
	if readErr != nil {
		t.Fatal(readErr)
	}
	up := strings.Split(string(raw), "-- +goose Down")[0]
	for i := 0; i < 2; i++ {
		if _, err = db.Exec(ctx, up); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.QueryRow(ctx, "SELECT user_id,billable_amount_micros FROM billing_usage_facts WHERE id=$1", tenant+"_fact").Scan(&owner, &amount); err != nil || owner != source || amount != 12345 {
		t.Fatal("migration reentry changed settled history")
	}
	if _, err = db.Exec(ctx, "UPDATE users SET status='active' WHERE id=$1", source); err == nil {
		t.Fatal("merged source was reactivated")
	}
}
