package repository

import (
	"context"
	"errors"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelcatalog"
	"os"
	"strings"
	"testing"
)

func TestPersonalExtraGrantLifecycleAndAudit(t *testing.T) {
	db, tenant, user, dept, _, _ := employeeKeyFixture(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE users SET role='tenant_admin' WHERE id=$1`, user)
	exec(`UPDATE teams SET model_access_mode='allowlist' WHERE id=$1`, dept)
	provider := tenant + "_provider"
	exec(`INSERT INTO providers(id,tenant_id,name,provider_type,base_url,auth_mode,status) VALUES($1,$2,'fixture','custom','https://fixture.invalid','api_key','active')`, provider, tenant)
	exec(`INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status) VALUES($1,$2,'fixture','fixture','fixture','active')`, tenant+"_credential", provider)
	for _, name := range []string{"department", "extra", "unverified"} {
		id := tenant + "_" + name
		exec(`INSERT INTO models(id,provider_id,model_name,status) VALUES($1,$2,$3,'active')`, id, provider, name)
		if name != "unverified" {
			exec(`INSERT INTO model_endpoint_capability_overrides(id,tenant_id,model_id,endpoint_type,state,reason,actor_user_id,config_version) VALUES($1,$2,$3,'chat','supported','fixture',$4,1)`, "ov_"+id, tenant, id, user)
		}
	}
	exec(`INSERT INTO team_models(team_id,model_id,allowed) VALUES($1,$2,true)`, dept, tenant+"_department")
	t.Cleanup(func() {
		db.Exec(ctx, `DELETE FROM model_endpoint_capability_overrides WHERE tenant_id=$1`, tenant)
		db.Exec(ctx, `DELETE FROM team_models WHERE team_id=$1`, dept)
		db.Exec(ctx, `DELETE FROM model_catalog_entries WHERE provider_id=$1`, provider)
		db.Exec(ctx, `DELETE FROM models WHERE provider_id=$1`, provider)
		db.Exec(ctx, `DELETE FROM provider_credentials WHERE provider_id=$1`, provider)
		db.Exec(ctx, `DELETE FROM providers WHERE id=$1`, provider)
	})
	actor:=tenant+"_grant_admin"
 exec("INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,$1,'platform_admin','active')",actor,tenant)
 repo := NewUserModelRepository(db)
	access, err := repo.GetAccess(ctx, tenant, user)
	if err != nil || !access.Allows("department") || access.Allows("extra") {
		t.Fatalf("initial err=%v", err)
	}
	catalog, err := modelcatalog.Load(ctx, db, tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range catalog {
		found := false
		for _, name := range access.CallableModels {
			if name == item.Name {
				found = true
			}
		}
		if found != item.Callable {
			t.Fatalf("inventory projections disagree: %s", item.Name)
		}
	}
	if _, err = repo.AddExtraGrant(ctx, tenant, user, actor, modelaccess.ExtraGrant{Model: "extra"}); !errors.Is(err, modelaccess.ErrInvalidPolicy) {
		t.Fatalf("empty reason err=%v", err)
	}
	// 未验证只是建议，照样可以授权；没有凭据才算不可用。
	if _, err = repo.AddExtraGrant(ctx, tenant, user, actor, modelaccess.ExtraGrant{Model: "unverified", Reason: "业务"}); err != nil {
		t.Fatalf("unverified grant err=%v", err)
	}
	exec(`INSERT INTO providers(id,tenant_id,name,provider_type,base_url,auth_mode,status) VALUES($1,$2,'nocred','custom','https://fixture.invalid','api_key','active')`, provider+"_nocred", tenant)
	exec(`INSERT INTO models(id,provider_id,model_name,status) VALUES($1,$2,'nocred','active')`, tenant+"_nocred", provider+"_nocred")
	t.Cleanup(func() {
		db.Exec(ctx, `DELETE FROM models WHERE provider_id=$1`, provider+"_nocred")
		db.Exec(ctx, `DELETE FROM providers WHERE id=$1`, provider+"_nocred")
	})
	if _, err = repo.AddExtraGrant(ctx, tenant, user, actor, modelaccess.ExtraGrant{Model: "nocred", Reason: "业务"}); !errors.Is(err, ErrUserModelUnavailable) {
		t.Fatalf("uncallable err=%v", err)
	}
	grant, err := repo.AddExtraGrant(ctx, tenant, user, actor, modelaccess.ExtraGrant{Model: "extra", Reason: "业务需要"})
	if err != nil {
		t.Fatal(err)
	}
	access, err = repo.GetAccess(ctx, tenant, user)
	if err != nil || !access.Allows("extra") || access.ModelSources["extra"] != "personal_extra" || !access.AllowsReference(tenant+"_extra") {
		t.Fatalf("extra source err=%v", err)
	}
	if err = repo.RevokeExtraGrant(ctx, tenant, user, actor, grant.ID); err != nil {
		t.Fatal(err)
	}
	access, err = repo.GetAccess(ctx, tenant, user)
	if err != nil || access.Allows("extra") {
		t.Fatalf("revoked grant survived err=%v", err)
	}
	grant, err = repo.AddExtraGrant(ctx, tenant, user, actor, modelaccess.ExtraGrant{Model: "extra", Reason: "临时"})
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE user_model_extra_grants SET created_at=now()-interval '2 minutes',expires_at=now()-interval '1 minute' WHERE id=$1`, grant.ID)
	access, err = repo.GetAccess(ctx, tenant, user)
	if err != nil || access.Allows("extra") {
		t.Fatalf("expired grant survived err=%v", err)
	}
	if err = repo.ExpireExtraGrants(ctx); err != nil {
		t.Fatal(err)
	}
	if err = repo.ExpireExtraGrants(ctx); err != nil {
		t.Fatal(err)
	}
	var audits int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND action_type LIKE 'user.model_extra.%'`, tenant).Scan(&audits); err != nil || audits != 5 {
		t.Fatalf("audit count=%d err=%v", audits, err)
	}
	if _, err = repo.AddExtraGrant(ctx, "other-tenant", user, user, modelaccess.ExtraGrant{Model: "extra", Reason: "跨租户"}); err == nil {
		t.Fatal("cross tenant accepted")
	}
	exec(`UPDATE users SET department_id=NULL WHERE id=$1`, user)
	access, err = repo.GetAccess(ctx, tenant, user)
	if err != nil || access.ChatAllowed || len(access.EffectiveModels) > 0 {
		t.Fatalf("departmentless model access err=%v", err)
	}
}

func TestUnconfiguredDepartmentDefaultsAllAndExplicitEmptyStaysDenied(t *testing.T) {
	db, tenant, user, _, _, _ := employeeKeyFixture(t)
	ctx := context.Background()
	dept := tenant + "_default"
	_, err := db.Exec(ctx, `INSERT INTO teams(id,tenant_id,name,path) VALUES($1,$2,'default models',$1)`, dept, tenant)
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	if err = db.QueryRow(ctx, `SELECT model_access_mode FROM teams WHERE id=$1`, dept).Scan(&mode); err != nil || mode != "all_active" {
		t.Fatalf("default mode=%s err=%v", mode, err)
	}
	teamModels := NewTeamModelRepository(db)
	if err = teamModels.ReplaceAllowlist(ctx, dept, nil); err != nil {
		t.Fatal(err)
	}
	var configured bool
	if err = db.QueryRow(ctx, `SELECT model_access_mode,model_access_configured FROM teams WHERE id=$1`, dept).Scan(&mode, &configured); err != nil || mode != "allowlist" || !configured {
		t.Fatalf("explicit empty mode=%s configured=%v err=%v", mode, configured, err)
	}
	_ = user
}

func TestDepartmentDefaultMigrationPreservesExplicitEmptyAndReentrant(t *testing.T) {
	db, tenant, user, _, _, _ := employeeKeyFixture(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	unseen, explicit, denied := tenant+"_unseen", tenant+"_explicit", tenant+"_denied"
	exec(`INSERT INTO teams(id,tenant_id,name,path,model_access_mode) VALUES($1,$4,'never configured',$1,'allowlist'),($2,$4,'explicit empty',$2,'allowlist'),($3,$4,'explicit deny',$3,'deny_all')`, unseen, explicit, denied, tenant)
	exec(`INSERT INTO audit_operations(id,tenant_id,user_id,action_type,target_type,target_id,action_detail,ip_address) VALUES($1,$2,$3,'team.models.update','team',$4,'{"count":0}','')`, tenant+"_audit", tenant, user, explicit)
	raw, err := os.ReadFile("../../../../deploy/migrations/973_department_default_model_access.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := strings.Split(string(raw), "-- +goose Down")[0]
	for i := 0; i < 2; i++ {
		exec(up)
	}
	for _, tc := range []struct {
		id, mode   string
		configured bool
	}{{unseen, "allowlist", true}, {explicit, "allowlist", true}, {denied, "deny_all", true}} {
		var mode string
		var configured bool
		if err = db.QueryRow(ctx, `SELECT model_access_mode,model_access_configured FROM teams WHERE id=$1`, tc.id).Scan(&mode, &configured); err != nil || mode != tc.mode || configured != tc.configured {
			t.Fatalf("mode=%s configured=%v err=%v", mode, configured, err)
		}
	}
	// Later explicit empty saves survive replay without depending on audit retention.
	if err = NewTeamModelRepository(db).ReplaceAllowlist(ctx, unseen, nil); err != nil {
		t.Fatal(err)
	}
	exec(up)
	var mode string
	if err = db.QueryRow(ctx, `SELECT model_access_mode FROM teams WHERE id=$1`, unseen).Scan(&mode); err != nil || mode != "allowlist" {
		t.Fatalf("later explicit policy lost: %s err=%v", mode, err)
	}
	var unassigned string
	if err = db.QueryRow(ctx, `SELECT model_access_mode FROM teams WHERE tenant_id=$1 AND system_key='unassigned'`, tenant).Scan(&unassigned); err != nil || unassigned != "allowlist" {
		t.Fatalf("system department expanded: %s err=%v", unassigned, err)
	}
}
