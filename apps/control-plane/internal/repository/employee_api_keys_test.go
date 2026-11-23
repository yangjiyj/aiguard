package repository

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/yangjiyj/aiguard/packages/shared-go/authhelpers"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func employeeKeyFixture(t *testing.T) (*pgxpool.Pool, string, string, string, string, int64) {
	t.Helper()
	dsn := os.Getenv("CONSOLE_LOGIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONSOLE_LOGIN_TEST_DATABASE_URL requires isolated migrated PG")
	}
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "employee-key-isolated-test-secret")
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	nonce := uuid.New().String()[:8]
	tenant, user, dept, project := "empkey_t_"+nonce, "empkey_u_"+nonce, "empkey_d_"+nonce, "empkey_p_"+nonce
	ctx := context.Background()
	if _, err = db.Exec(ctx, `INSERT INTO tenants(id,name,is_test) VALUES($1,'employee-key-test',true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO teams(id,tenant_id,name,path,model_access_mode) VALUES($1,$2,'employee-key-department',$1,'all_active')`, dept, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO projects(id,tenant_id,name,team_id,status,code,environment) VALUES($1,$2,'employee-key-project',$3,'active','employee','production')`, project, tenant, dept); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode,department_assignment_source,department_version,must_change_password) VALUES($1,$2,$1,'chat_user','active',$3,'manual','local',1,false)`, user, tenant, dept); err != nil {
		t.Fatal(err)
	}
	if err = NewProjectUserRepository(db).BindUser(ctx, project, user); err != nil {
		t.Fatal(err)
	}
	var actualDepartment, actualRole, actualStatus, tenantStatus string
	var actualVersion int64
	if err = db.QueryRow(ctx, `SELECT u.department_id,u.department_version,u.role,u.status,t.status FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.id=$1`, user).Scan(&actualDepartment, &actualVersion, &actualRole, &actualStatus, &tenantStatus); err != nil {
		t.Fatal(err)
	}
	if actualDepartment != dept || actualRole != "chat_user" || actualStatus != "active" || tenantStatus != "active" {
		t.Fatal("invalid employee key fixture identity")
	}
	t.Cleanup(func() {
		db.Exec(ctx, `DELETE FROM employee_api_keys WHERE tenant_id=$1`, tenant)
		db.Exec(ctx, `DELETE FROM internal_keys WHERE tenant_id=$1`, tenant)
		db.Exec(ctx, `DELETE FROM project_users WHERE user_id=$1`, user)
		db.Exec(ctx, `DELETE FROM audit_operations WHERE tenant_id=$1`, tenant)
		db.Exec(ctx, `DELETE FROM users WHERE tenant_id=$1`, tenant)
		db.Exec(ctx, `DELETE FROM projects WHERE tenant_id=$1`, tenant)
		db.Exec(ctx, `DELETE FROM teams WHERE tenant_id=$1`, tenant)
		db.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant)
		db.Close()
	})
	return db, tenant, user, dept, project, actualVersion
}

func TestEmployeeAPIKeyConcurrentEnsureAndClaim(t *testing.T) {
	db, tenant, user, dept, project, version := employeeKeyFixture(t)
	repo := NewEmployeeAPIKeyRepository(db)
	ctx := context.Background()
	var created atomic.Int32
	var group sync.WaitGroup
	ids := make(chan string, 16)
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			key, newKey, err := repo.Ensure(ctx, tenant, user, project, dept, version)
			if err != nil {
				errs <- err
				return
			}
			if newKey {
				created.Add(1)
			}
			ids <- key.ID
		}()
	}
	group.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Errorf("ensure failed: %v", err)
	}
	current, err := repo.Current(ctx, tenant, user)
	if err != nil || current == nil {
		t.Fatalf("current: %v", err)
	}
	for id := range ids {
		if id != current.ID {
			t.Fatal("concurrent login created another key")
		}
	}
	if created.Load() != 1 {
		t.Fatalf("created=%d", created.Load())
	}
	var auditCount int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND target_id=$2 AND action_type='employee_key_create'`, tenant, current.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("atomic creation audits=%d err=%v", auditCount, err)
	}

	serverKey, serverRaw, err := repo.Credential(ctx, tenant, user)
	if err != nil || serverKey.FirstClaimAt != nil || serverRaw == "" {
		t.Fatal("Chat credential consumed the employee first claim")
	}
	var claims atomic.Int32
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			key, raw, err := repo.Claim(ctx, tenant, user, current.ID, current.Generation)
			if err == nil {
				if raw == "" || key.FirstClaimAt == nil {
					t.Error("claim lacked one-time credential")
				}
				claims.Add(1)
			} else if !errors.Is(err, ErrEmployeeKeyAlreadyClaimed) {
				t.Errorf("claim error: %v", err)
			}
		}()
	}
	group.Wait()
	if claims.Load() != 1 {
		t.Fatalf("claims=%d", claims.Load())
	}
	credential, raw, err := repo.Credential(ctx, tenant, user)
	if err != nil || raw == "" || credential.ID != current.ID {
		t.Fatalf("server credential: %v", err)
	}
	internal, err := NewInternalKeyRepository(db).GetByHash(ctx, authhelpers.HashKey(raw))
	if err != nil || internal.UserID != user || internal.ProjectID != project {
		t.Fatal("credential is not a real owned gateway key")
	}
	encoded, _ := json.Marshal(credential)
	if strings.Contains(string(encoded), raw) || strings.Contains(string(encoded), internal.KeyHash) || strings.Contains(string(encoded), internal.KeyCiphertext) {
		t.Fatal("metadata disclosed credential material")
	}
}

func TestEmployeeAPIKeyResetCASAndManualKeyIsolation(t *testing.T) {
	db, tenant, user, dept, project, version := employeeKeyFixture(t)
	ctx := context.Background()
	repo := NewEmployeeAPIKeyRepository(db)
	manual := &InternalKey{TenantID: tenant, UserID: user, ProjectID: project, Status: "active", Scopes: []string{"chat"}}
	if err := NewInternalKeyRepository(db).Create(ctx, manual, "jjd-manual-isolated-"+user); err != nil {
		t.Fatal(err)
	}
	original, _, err := repo.Ensure(ctx, tenant, user, project, dept, version)
	if err != nil {
		t.Fatal(err)
	}
	replacement, raw, err := repo.Reset(ctx, tenant, user, original.ID, original.Generation, project, dept, version)
	if err != nil || raw == "" || replacement.ID == original.ID || replacement.Generation != original.Generation+1 || replacement.FirstClaimAt == nil {
		t.Fatalf("reset failed: %v", err)
	}
	if _, _, err = repo.Reset(ctx, tenant, user, original.ID, original.Generation, project, dept, version); !errors.Is(err, ErrEmployeeKeyConflict) {
		t.Fatalf("stale reset was not rejected: %v", err)
	}
	if _, _, err = repo.Claim(ctx, tenant, user, original.ID, original.Generation); !errors.Is(err, ErrEmployeeKeyConflict) {
		t.Fatalf("stale claim was not rejected: %v", err)
	}
	if _, _, err = repo.Claim(ctx, tenant, user, replacement.ID, replacement.Generation); !errors.Is(err, ErrEmployeeKeyAlreadyClaimed) {
		t.Fatalf("reset credential can be claimed again: %v", err)
	}
	old, _ := NewInternalKeyRepository(db).GetByID(ctx, tenant, original.ID)
	kept, _ := NewInternalKeyRepository(db).GetByID(ctx, tenant, manual.ID)
	if old.Status != "revoked" || kept.Status != "active" {
		t.Fatal("reset affected unrelated key or retained old credential")
	}
	var auditCount int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND target_id=$2 AND action_type='employee_key_rotate'`, tenant, replacement.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("atomic rotation audits=%d err=%v", auditCount, err)
	}

}

func TestEmployeeAPIKeyCurrentIdentityAndTenantIsolation(t *testing.T) {
	db, tenant, user, dept, project, version := employeeKeyFixture(t)
	ctx := context.Background()
	repo := NewEmployeeAPIKeyRepository(db)
	original, _, err := repo.Ensure(ctx, tenant, user, project, dept, version)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = repo.Claim(ctx, "other-tenant", user, original.ID, 1); !errors.Is(err, ErrEmployeeKeyDenied) {
		t.Fatal("cross-tenant claim accepted")
	}
	var updatedVersion int64
	if err = db.QueryRow(ctx, `UPDATE users SET department_version=department_version+1 WHERE id=$1 RETURNING department_version`, user).Scan(&updatedVersion); err != nil {
		t.Fatal(err)
	}
	if _, _, err = repo.Credential(ctx, tenant, user); !errors.Is(err, ErrEmployeeKeyDenied) {
		t.Fatal("stale department credential accepted")
	}
	if _, _, err = repo.Ensure(ctx, tenant, user, project, dept, version); !errors.Is(err, ErrEmployeeKeyDenied) {
		t.Fatal("stale identity ensure accepted")
	}
	replacement, created, err := repo.Ensure(ctx, tenant, user, project, dept, updatedVersion)
	if err != nil || !created || replacement.ID == original.ID {
		t.Fatalf("department rebind: %v", err)
	}
	if _, err = db.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, user); err != nil {
		t.Fatal(err)
	}
	if _, _, err = repo.Credential(ctx, tenant, user); !errors.Is(err, ErrEmployeeKeyDenied) {
		t.Fatal("disabled user credential accepted")
	}
}

func TestEmployeeAPIKeyClaimEncryptionFaultRollsBack(t *testing.T) {
	db, tenant, user, dept, project, version := employeeKeyFixture(t)
	ctx := context.Background()
	repo := NewEmployeeAPIKeyRepository(db)
	key, _, err := repo.Ensure(ctx, tenant, user, project, dept, version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `UPDATE internal_keys SET key_ciphertext='enc:v1:invalid' WHERE id=$1`, key.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = repo.Claim(ctx, tenant, user, key.ID, key.Generation); err == nil {
		t.Fatal("invalid encrypted credential accepted")
	}
	current, err := repo.Current(ctx, tenant, user)
	if err != nil || current.FirstClaimAt != nil {
		t.Fatal("failed decryption consumed the only claim")
	}
	if _, err = db.Exec(ctx, `UPDATE internal_keys SET expires_at=$2 WHERE id=$1`, key.ID, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = repo.Credential(ctx, tenant, user); !errors.Is(err, ErrEmployeeKeyDenied) {
		t.Fatal("expired credential accepted")
	}
}

func TestEmployeeAPIKeyConcurrentResetHasSingleWinner(t *testing.T) {
	db, tenant, user, dept, project, version := employeeKeyFixture(t)
	ctx := context.Background()
	repo := NewEmployeeAPIKeyRepository(db)
	key, _, err := repo.Ensure(ctx, tenant, user, project, dept, version)
	if err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			replacement, raw, err := repo.Reset(ctx, tenant, user, key.ID, key.Generation, project, dept, version)
			if err == nil {
				if replacement.ID == key.ID || raw == "" {
					t.Error("invalid reset result")
				}
				winners.Add(1)
			} else if !errors.Is(err, ErrEmployeeKeyConflict) {
				t.Errorf("reset error: %v", err)
			}
		}()
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatalf("reset winners=%d", winners.Load())
	}
	var active int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM internal_keys WHERE tenant_id=$1 AND user_id=$2 AND status='active'`, tenant, user).Scan(&active); err != nil || active != 1 {
		t.Fatalf("active managed keys=%d err=%v", active, err)
	}
}

func TestEmployeeAPIKeyPreservesAuthorizedHumanRoleAndRejectsForeignProject(t *testing.T) {
	db, tenant, user, dept, project, version := employeeKeyFixture(t)
	ctx := context.Background()
	repo := NewEmployeeAPIKeyRepository(db)
	if _, _, err := repo.Ensure(ctx, tenant, user, "foreign-project", dept, version); !errors.Is(err, ErrEmployeeKeyDenied) {
		t.Fatal("foreign project accepted")
	}
	if _, err := db.Exec(ctx, `UPDATE users SET role='tenant_admin' WHERE id=$1`, user); err != nil {
		t.Fatal(err)
	}
	if key, _, err := repo.Ensure(ctx, tenant, user, project, dept, version); err != nil || key == nil {
		t.Fatalf("authorized human ensure err=%v", err)
	}
	var role string
	if err := db.QueryRow(ctx, "SELECT role FROM users WHERE id=$1", user).Scan(&role); err != nil || role != "tenant_admin" {
		t.Fatal("credential issuance changed account role")
	}
	if _, err := db.Exec(ctx, "UPDATE users SET role='platform_connector' WHERE id=$1", user); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.Ensure(ctx, tenant, user, project, dept, version); !errors.Is(err, ErrEmployeeKeyDenied) {
		t.Fatal("machine role obtained employee credential")
	}
}

// Authentication can race a password change before the repository gets its lock.
// The credential version must be rechecked inside the same user lock as the claim.
func TestEmployeeAPIKeyVersionIsRecheckedAfterUserLockWait(t *testing.T) {
	db, tenant, user, dept, project, departmentVersion := employeeKeyFixture(t)
	ctx := context.Background()
	repo := NewEmployeeAPIKeyRepository(db)
	key, _, err := repo.Ensure(ctx, tenant, user, project, dept, departmentVersion, 1)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `UPDATE users SET local_credential_version=local_credential_version+1 WHERE id=$1`, user); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		_, _, err := repo.Claim(ctx, tenant, user, key.ID, key.Generation, 1)
		result <- err
	}()
	<-started
	select {
	case err := <-result:
		t.Fatalf("claim bypassed the held identity lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrEmployeeKeyDenied) {
			t.Fatalf("stale version claim accepted after lock wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("claim did not finish after password commit")
	}
	current, err := repo.Current(ctx, tenant, user, 2)
	if err != nil || current.FirstClaimAt != nil {
		t.Fatal("stale request consumed first claim")
	}
	if _, _, err = repo.Credential(ctx, tenant, user, 1); !errors.Is(err, ErrEmployeeKeyDenied) {
		t.Fatal("stale service credential accepted")
	}
	if _, _, err = repo.Reset(ctx, tenant, user, key.ID, key.Generation, project, dept, departmentVersion, 1); !errors.Is(err, ErrEmployeeKeyDenied) {
		t.Fatal("stale reset accepted")
	}
	if _, _, err = repo.Ensure(ctx, tenant, user, project, dept, departmentVersion, 1); !errors.Is(err, ErrEmployeeKeyDenied) {
		t.Fatal("stale ensure accepted")
	}
	if _, _, err = repo.Claim(ctx, tenant, user, key.ID, key.Generation, 2); err != nil {
		t.Fatalf("current version cannot claim: %v", err)
	}
}

func TestEmployeeKeySelfRevokeAllowsImmediateSingleFreshClaim(t *testing.T) {
	db, tenant, user, dept, project, version := employeeKeyFixture(t)
	ctx := context.Background()
	repo := NewEmployeeAPIKeyRepository(db)
	old, _, err := repo.Ensure(ctx, tenant, user, project, dept, version)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = repo.Claim(ctx, tenant, user, old.ID, old.Generation); err != nil {
		t.Fatal(err)
	}
	found, err := NewInternalKeyRepository(db).RevokeOwned(ctx, tenant, old.ID, user)
	if err != nil || !found {
		t.Fatal("self revoke failed")
	}
	fresh, created, err := repo.Ensure(ctx, tenant, user, project, dept, version)
	if err != nil || !created || fresh.ID == old.ID || fresh.Generation <= old.Generation {
		t.Fatal("fresh generation was not issued")
	}
	claimed, raw, err := repo.Claim(ctx, tenant, user, fresh.ID, fresh.Generation)
	if err != nil || raw == "" || claimed.ID != fresh.ID {
		t.Fatal("fresh Key was not claimable")
	}
	var active int
	if err = db.QueryRow(ctx, "SELECT count(*) FROM internal_keys k JOIN employee_api_keys e ON e.tenant_id=k.tenant_id AND e.key_id=k.id WHERE e.tenant_id=$1 AND e.user_id=$2 AND k.status='active'", tenant, user).Scan(&active); err != nil || active != 1 {
		t.Fatalf("active employee Keys=%d err=%v", active, err)
	}
	all, err := NewInternalKeyRepository(db).ListByUser(ctx, tenant, user)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range all {
		if k.ID == fresh.ID && !k.IsEmployee {
			t.Fatal("employee Key is counted as a personal extra Key")
		}
	}
}
