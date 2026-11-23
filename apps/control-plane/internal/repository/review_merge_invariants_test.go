package repository

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type reviewMergeFixture struct {
	db                                           *pgxpool.Pool
	tenant, source, target, actor, dept, project string
	repo                                         *UserAccountMergeRepository
}

func reviewMergeSetup(t *testing.T) reviewMergeFixture {
	db, tenant, target, dept, project, _ := employeeKeyFixture(t)
	ctx := context.Background()
	source, actor := tenant+"_source", tenant+"_actor"
	for _, v := range []struct{ id, role string }{{source, "chat_user"}, {actor, "platform_admin"}} {
		if _, err := db.Exec(ctx, "INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode) VALUES($1,$2,$1,$3,'active',$4,'manual')", v.id, tenant, v.role, dept); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		db.Exec(ctx, "DELETE FROM user_account_merges WHERE tenant_id=$1", tenant)
		db.Exec(ctx, "DELETE FROM billing_wallets WHERE tenant_id=$1", tenant)
	})
	return reviewMergeFixture{db, tenant, source, target, actor, dept, project, NewUserAccountMergeRepository(db)}
}
func (f reviewMergeFixture) preview(t *testing.T) *AccountMergePreview {
	p, err := f.repo.Preview(context.Background(), f.tenant, f.source, f.target, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestReviewMergeKeepsTargetDepartmentCredentialAndKeys(t *testing.T) {
	f := reviewMergeSetup(t)
	ctx := context.Background()
	second := f.tenant + "_second_project"
	key := f.tenant + "_target_key"
	sourceKey := f.tenant + "_source_key"
	if _, err := f.db.Exec(ctx, "INSERT INTO projects(id,tenant_id,name,team_id,status) VALUES($1,$2,$1,$3,'active')", second, f.tenant, f.dept); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(ctx, "UPDATE users SET department_assignment_mode='automatic' WHERE id=$1", f.target); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(ctx, "UPDATE users SET external_subject='recoverable-legacy-subject' WHERE id=$1", f.source); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct{ k, u, p string }{{key, f.target, second}, {sourceKey, f.source, f.project}} {
		if _, err := f.db.Exec(ctx, "INSERT INTO internal_keys(id,tenant_id,user_id,project_id,key_hash,key_prefix,status) VALUES($1,$2,$3,$4,$1,'fixture','active')", v.k, f.tenant, v.u, v.p); err != nil {
			t.Fatal(err)
		}
	}
	var before int64
	f.db.QueryRow(ctx, "SELECT local_credential_version FROM users WHERE id=$1", f.target).Scan(&before)
	p := f.preview(t)
	if _, err := f.repo.Merge(ctx, f.tenant, f.source, f.target, f.actor, AccountMergeInput{PreviewVersion: p.Version, Choices: map[string]string{"api_keys": "move_source"}}); err != nil {
		t.Fatal(err)
	}
	var mode string
	var version int64
	if err := f.db.QueryRow(ctx, "SELECT department_assignment_mode,local_credential_version FROM users WHERE id=$1", f.target).Scan(&mode, &version); err != nil || mode != "automatic" || version != before {
		t.Errorf("unselected target identity changed: mode=%s version=%d before=%d err=%v", mode, version, before, err)
	}
	var project string
	if err := f.db.QueryRow(ctx, "SELECT project_id FROM internal_keys WHERE id=$1", key).Scan(&project); err != nil || project != second {
		t.Errorf("target Key project changed=%s err=%v", project, err)
	}
	var saved string
	if err := f.db.QueryRow(ctx, "SELECT COALESCE(choices->>'source_external_subject','') FROM user_account_merges WHERE tenant_id=$1 AND source_user_id=$2", f.tenant, f.source).Scan(&saved); err != nil || saved != "recoverable-legacy-subject" {
		t.Errorf("old source identity not saved=%q err=%v", saved, err)
	}
}
func TestReviewMergeRejectsNonzeroWalletBalance(t *testing.T) {
	f := reviewMergeSetup(t)
	ctx := context.Background()
	if _, err := f.db.Exec(ctx, "INSERT INTO billing_wallets(id,tenant_id,user_id,currency,balance_micros) VALUES($1,$2,$3,'CNY',100)", f.tenant+"_wallet", f.tenant, f.source); err != nil {
		t.Fatal(err)
	}
	p := f.preview(t)
	_, err := f.repo.Merge(ctx, f.tenant, f.source, f.target, f.actor, AccountMergeInput{PreviewVersion: p.Version, Choices: map[string]string{"wallet_balance": "retain_read_only"}})
	if err == nil || !strings.Contains(err.Error(), "余额") {
		t.Errorf("nonzero wallet merge error=%v", err)
	}
	var balance int64
	f.db.QueryRow(ctx, "SELECT balance_micros FROM billing_wallets WHERE user_id=$1", f.source).Scan(&balance)
	if balance != 100 {
		t.Fatal("wallet amount changed")
	}
}
func TestReviewMergePreviewIgnoresBillingBalanceChanges(t *testing.T) {
	f := reviewMergeSetup(t)
	ctx := context.Background()
	if _, err := f.db.Exec(ctx, "INSERT INTO billing_wallets(id,tenant_id,user_id,currency,balance_micros) VALUES($1,$2,$3,'CNY',0)", f.tenant+"_wallet", f.tenant, f.target); err != nil {
		t.Fatal(err)
	}
	first := f.preview(t)
	if _, err := f.db.Exec(ctx, "UPDATE billing_wallets SET balance_micros=balance_micros+100 WHERE user_id=$1", f.target); err != nil {
		t.Fatal(err)
	}
	second := f.preview(t)
	if first.Version != second.Version {
		t.Fatalf("billing changed authorization preview: %s != %s", first.Version, second.Version)
	}
}
func TestReviewDuplicateDetectionUsesFullActiveIdentity(t *testing.T) {
	f := reviewMergeSetup(t)
	ctx := context.Background()
	if _, err := f.db.Exec(ctx, "UPDATE users SET username=CASE WHEN id=$1 THEN 'zhang-san' ELSE 'zhang-wei' END,email=NULL WHERE id IN($1,$2)", f.source, f.target); err != nil {
		t.Fatal(err)
	}
	peers, err := f.repo.PossibleDuplicates(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers[f.source]) != 0 || len(peers[f.target]) != 0 {
		t.Errorf("distinct names considered duplicates: %v", peers)
	}
	if _, err := f.db.Exec(ctx, "UPDATE users SET email='same@corp.invalid',status=CASE WHEN id=$1 THEN 'disabled' ELSE status END WHERE id IN($1,$2)", f.source, f.target); err != nil {
		t.Fatal(err)
	}
	peers, err = f.repo.PossibleDuplicates(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers[f.target]) != 0 {
		t.Errorf("disabled peer exposed=%v", peers[f.target])
	}
}

func TestReviewMergeSerializationRetriesAreBounded(t *testing.T) {
	calls := 0
	value, err := retryAccountOperation(context.Background(), func() (string, error) {
		calls++
		if calls < 3 {
			return "", &pgconn.PgError{Code: "40001"}
		}
		return "committed", nil
	})
	if err != nil || value != "committed" || calls != 3 {
		t.Fatalf("serialization retry value=%s calls=%d err=%v", value, calls, err)
	}
	calls = 0
	_, err = retryAccountOperation(context.Background(), func() (bool, error) { calls++; return false, &pgconn.PgError{Code: "40001"} })
	if err == nil || calls != 3 {
		t.Fatalf("unbounded retry calls=%d err=%v", calls, err)
	}
	calls = 0
	_, err = retryAccountOperation(context.Background(), func() (bool, error) { calls++; return false, &pgconn.PgError{Code: "23505"} })
	if err == nil || calls != 1 {
		t.Fatalf("non-serialization error retried calls=%d", calls)
	}
}

func TestReviewConcurrentMergeCommitsOnlyOneAnnotation(t *testing.T) {
	f := reviewMergeSetup(t)
	ctx := context.Background()
	p := f.preview(t)
	var successes atomic.Int32
	var workers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			if _, err := f.repo.Merge(ctx, f.tenant, f.source, f.target, f.actor, AccountMergeInput{PreviewVersion: p.Version}); err == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	workers.Wait()
	var count int
	if err := f.db.QueryRow(ctx, "SELECT count(*) FROM user_account_merges WHERE tenant_id=$1", f.tenant).Scan(&count); err != nil || successes.Load() != 1 || count != 1 {
		t.Fatalf("success=%d annotations=%d err=%v", successes.Load(), count, err)
	}
}
func TestReviewMergeSourceChoicesAndRevokeBoth(t *testing.T) {
	f := reviewMergeSetup(t)
	ctx := context.Background()
	sourceDept, sourceProject := f.tenant+"_source_dept", f.tenant+"_source_project"
	execute := func(sql string, args ...any) {
		t.Helper()
		if _, err := f.db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	execute("INSERT INTO teams(id,tenant_id,name,path) VALUES($1,$2,$1,$1)", sourceDept, f.tenant)
	execute("INSERT INTO projects(id,tenant_id,name,team_id,status,code,environment) VALUES($1,$2,$1,$3,'active','fixture','test')", sourceProject, f.tenant, sourceDept)
	execute("UPDATE users SET department_id=$2 WHERE id=$1", f.source, sourceDept)
	execute(`INSERT INTO user_model_policies(tenant_id,user_id,mode,model_names,updated_by) VALUES($1,$2,'allowlist','["source-model"]',$3)`, f.tenant, f.source, f.actor)
	var sourceVersion, targetVersion int64
	f.db.QueryRow(ctx, "SELECT department_version FROM users WHERE id=$1", f.source).Scan(&sourceVersion)
	f.db.QueryRow(ctx, "SELECT department_version FROM users WHERE id=$1", f.target).Scan(&targetVersion)
	if err := NewProjectUserRepository(f.db).BindUser(ctx, sourceProject, f.source); err != nil {
		t.Fatal(err)
	}
	keys := NewEmployeeAPIKeyRepository(f.db)
	sourceKey, _, err := keys.Ensure(ctx, f.tenant, f.source, sourceProject, sourceDept, sourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	targetKey, _, err := keys.Ensure(ctx, f.tenant, f.target, f.project, f.dept, targetVersion)
	if err != nil {
		t.Fatal(err)
	}
	p := f.preview(t)
	_, err = f.repo.Merge(ctx, f.tenant, f.source, f.target, f.actor, AccountMergeInput{PreviewVersion: p.Version, Choices: map[string]string{"department": "source", "personal_policy": "source", "employee_key": "revoke_both", "api_keys": "revoke_source"}})
	if err != nil {
		t.Fatal(err)
	}
	var dept string
	if err := f.db.QueryRow(ctx, "SELECT department_id FROM users WHERE id=$1", f.target).Scan(&dept); err != nil || dept != sourceDept {
		t.Fatalf("chosen source department=%s err=%v", dept, err)
	}
	var names []byte
	if err := f.db.QueryRow(ctx, "SELECT model_names FROM user_model_policies WHERE tenant_id=$1 AND user_id=$2", f.tenant, f.target).Scan(&names); err != nil {
		t.Fatal(err)
	}
	var policy []string
	if json.Unmarshal(names, &policy) != nil || len(policy) != 1 || policy[0] != "source-model" {
		t.Fatalf("source policy not retained: %s", names)
	}
	for _, key := range []string{sourceKey.ID, targetKey.ID} {
		var status string
		if err := f.db.QueryRow(ctx, "SELECT status FROM internal_keys WHERE id=$1", key).Scan(&status); err != nil || status != "revoked" {
			t.Fatalf("revoke_both status=%s err=%v", status, err)
		}
	}
}
func TestReviewMergeDoesNotChangeChargeWalletOrLedgerAmounts(t *testing.T) {
	f := reviewMergeSetup(t)
	ctx := context.Background()
	execute := func(sql string, args ...any) {
		t.Helper()
		if _, err := f.db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	wallet := f.tenant + "_immutable_wallet"
	if err := billing.NewStore(f.db).EnsureDefaultCustomerGroup(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	execute("INSERT INTO billing_wallets(id,tenant_id,user_id,currency,balance_micros) VALUES($1,$2,$3,'CNY',0)", wallet, f.tenant, f.source)
	execute(`INSERT INTO billing_ledger_entries(id,tenant_id,wallet_id,event_type,balance_delta_micros,reserved_delta_micros,balance_after_micros,reserved_after_micros,idempotency_key) VALUES($1,$2,$3,'credit',100,0,100,0,$1),($1||'-adjust',$2,$3,'adjustment',-100,0,0,0,$1||'-adjust')`, f.tenant+"_credit", f.tenant, wallet)
	execute(`INSERT INTO billing_charge_records(id,tenant_id,wallet_id,request_id,model_name,prompt_tokens,output_tokens,amount_micros,pricing_mode,currency,status) VALUES($1,$2,$3,$1,'fixture-model',10,5,50,'direct','CNY','settled')`, f.tenant+"_charge", f.tenant, wallet)
	snapshot := func() string {
		var value string
		if err := f.db.QueryRow(ctx, `SELECT jsonb_build_object('wallet',(SELECT jsonb_agg(to_jsonb(w) ORDER BY w.id) FROM billing_wallets w WHERE tenant_id=$1),'ledger',(SELECT jsonb_agg(to_jsonb(l) ORDER BY l.id) FROM billing_ledger_entries l WHERE tenant_id=$1),'charges',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.id) FROM billing_charge_records c WHERE tenant_id=$1))::text`, f.tenant).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	p := f.preview(t)
	if _, err := f.repo.Merge(ctx, f.tenant, f.source, f.target, f.actor, AccountMergeInput{PreviewVersion: p.Version}); err != nil {
		t.Fatal(err)
	}
	if after := snapshot(); before != after {
		t.Fatal("immutable charge/wallet/ledger facts changed")
	}
	// These append-only test facts intentionally live until this owned disposable
	// DB is removed; no WORM trigger is disabled to erase them.
}
