package auth

import (
	"context"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIntegrationModelEnforcementMatrix(t *testing.T) {
	for _, agent := range []string{"", "agent1"} {
		for _, configured := range []string{"record", "block"} {
			for _, gate := range []string{"record_only", "allow_block"} {
				t.Run(agent+configured+gate, func(t *testing.T) {
					t.Setenv("INTEGRATION_KEY_ENFORCEMENT", gate)
					ctx := context.WithValue(context.Background(), KeyModelAllowlistKey, []string{"模型甲"})
					ctx = context.WithValue(ctx, AgentInstanceIDKey, agent)
					ctx = context.WithValue(ctx, contextKey("key_model_enforcement"), configured)
					want := agent != "" && (configured == "record" || gate != "allow_block")
					if got := UserModelAllowed(ctx, "模型乙"); got != want {
						t.Fatalf("名单外允许=%v，期望 %v", got, want)
					}
					if !UserModelAllowed(ctx, "模型甲") {
						t.Fatal("名单内被拒绝")
					}
					if UserFinalModelAllowed(ctx, "模型乙") != want {
						t.Fatal("最终模型档位不一致")
					}
					if KeyModelAllowed(ctx, "模型乙") {
						t.Fatal("原始名单匹配不应受档位影响")
					}
					ctx = context.WithValue(ctx, modelAccessContextKey{}, &modelaccess.Access{ChatAllowed: true, KnownModelNames: []string{"模型甲", "模型乙"}, ModelReferences: map[string]string{}})
					if UserModelAllowed(ctx, "模型乙") {
						t.Fatal("记录档绕过了使用人授权")
					}
					wantCode := "key_model_not_allowed"
					if want {
						wantCode = "forbidden_model"
					}
					if got := ModelDenialCode(ctx, "模型乙"); got != wantCode {
						t.Fatalf("拒绝原因=%s，期望 %s", got, wantCode)
					}
				})
			}
		}
	}
}

func TestIntegrationDLPBlockKeySnapshotUsesOnlyActiveTenantCredentials(t *testing.T) {
	dsn := os.Getenv("INTEGRATION_ENFORCEMENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("未配置隔离的凭据测试数据库")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tenant := fmt.Sprintf("j1_dlp_%d", time.Now().UnixNano())
	for _, sql := range []string{
		`INSERT INTO tenants(id,name,is_test) VALUES($1,$1,true),($1||'_foreign',$1,true)`,
		`INSERT INTO projects(id,tenant_id,name) VALUES($1||'_p',$1,'fixture'),($1||'_fp',$1||'_foreign','fixture')`,
	} {
		if _, err = db.Exec(ctx, sql, tenant); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, sql := range []string{`DELETE FROM internal_keys WHERE tenant_id IN ($1,$2)`, `DELETE FROM projects WHERE tenant_id IN ($1,$2)`, `DELETE FROM tenants WHERE id IN ($1,$2)`} {
			if _, err := db.Exec(ctx, sql, tenant, tenant+"_foreign"); err != nil {
				t.Error(err)
			}
		}
	}()
	for _, k := range []struct {
		id, owner, project, agent, mode, status string
		expired                                 bool
	}{
		{"self", tenant, tenant + "_p", "agent1", "block", "active", false},
		{"peer", tenant, tenant + "_p", "agent2", "block", "active", false},
		{"record", tenant, tenant + "_p", "agent3", "record", "active", false},
		{"expired", tenant, tenant + "_p", "agent4", "block", "active", true},
		{"revoked", tenant, tenant + "_p", "agent5", "block", "revoked", false},
		{"legacy", tenant, tenant + "_p", "", "block", "active", false},
		{"foreign", tenant + "_foreign", tenant + "_fp", "agent6", "block", "active", false},
	} {
		_, err = db.Exec(ctx, `INSERT INTO internal_keys(id,tenant_id,project_id,key_hash,key_prefix,scopes_json,status,agent_instance_id,dlp_enforcement,expires_at) VALUES($1,$2,$3,$1,'fixture-','["chat"]',$4,NULLIF($5,''),$6,CASE WHEN $7 THEN now()-interval '1 hour' ELSE NULL END)`, tenant+"_"+k.id, k.owner, k.project, k.status, k.agent, k.mode, k.expired)
		if err != nil {
			t.Fatal(err)
		}
	}
	a := &AuthMiddleware{db: db}
	for _, gate := range []string{"record_only", "allow_block"} {
		t.Setenv("INTEGRATION_KEY_ENFORCEMENT", gate)
		key, err := a.validateKey(ctx, tenant+"_self")
		if err != nil || key == nil {
			t.Fatal(err)
		}
		want := ""
		if gate == "allow_block" {
			want = tenant + "_peer," + tenant + "_self"
		}
		if got := strings.Join(key.IntegrationDLPBlockKeyIDs, ","); got != want {
			t.Fatalf("可信凭据集合=%s，期望 %s", got, want)
		}
		legacy, err := a.validateKey(ctx, tenant+"_legacy")
		if err != nil || legacy == nil || legacy.ModelEnforcement != "block" || len(legacy.IntegrationDLPBlockKeyIDs) != 0 {
			t.Fatalf("存量凭据行为变化：%+v %v", legacy, err)
		}
	}
}
