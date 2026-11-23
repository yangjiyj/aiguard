package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/agentendpoint"
)

// “是否全局观察留痕”只在 globalExecutionRecordOnly 一处判断：两个键一次读出，交给 executionmode.FromValues，
// 与控制台、签名投影、网关同口径。2.9.22（D7）：部署变量 SECURITY_AUDIT_ONLY=true 只在库里没有显式
// 执行模式时作初值，不再锁定观察留痕。
func TestEndpointGlobalRecordOnly2922Resolution(t *testing.T) {
	for _, tc := range []struct {
		env    string
		values map[string]string
		want   bool
	}{
		{"", map[string]string{"security_execution_mode": "protect", "security_audit_only": "true"}, false},
		{"", map[string]string{"security_execution_mode": "record"}, true},
		{"", map[string]string{"security_audit_only": "false"}, false},
		{"", map[string]string{"security_audit_only": "true"}, true},
		{"", map[string]string{"security_audit_only": "sometimes"}, true},
		{"", map[string]string{}, true},
		{"true", map[string]string{"security_execution_mode": "protect"}, false},
		{"true", map[string]string{"security_execution_mode": "record"}, true},
		{"true", map[string]string{"security_audit_only": "false"}, true},
		{"true", map[string]string{}, true},
	} {
		t.Setenv("SECURITY_AUDIT_ONLY", tc.env)
		if got := globalRecordOnlyFromSettings(tc.values); got != tc.want {
			t.Errorf("env=%q values=%v got %v want %v", tc.env, tc.values, got, tc.want)
		}
	}
}

type endpointBundleSnapshot struct {
	version   int64
	checksum  string
	mode      string
	decisions map[string]string
}

func endpointModeTestRepo(t *testing.T, seed string) (*AgentEndpointRepository, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("AGENT_OPERATION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENT_OPERATION_TEST_DATABASE_URL is not set")
	}
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("endpoint_mode_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	if _, err := db.Exec(ctx, `
		CREATE TABLE system_settings (key text PRIMARY KEY, value text NOT NULL);
		CREATE TABLE protection_settings (tenant_id text, item_key text, action text, params_json jsonb NOT NULL DEFAULT '{}');
		CREATE TABLE agentguard_policies (id text, tenant_id text, rules_json jsonb, enabled bool, scope_type text, priority int, created_at timestamptz DEFAULT now());
		CREATE TABLE agentguard_policy_versions (policy_id text, tenant_id text, policy_version text, active bool);
		CREATE TABLE tool_risk_config (tenant_id text, tool_name text, tool_type text, risk_level text, action text);
		CREATE TABLE agent_policy_bundles (id text, tenant_id text, version bigint, checksum text, bundle jsonb, derived_from jsonb, created_by text);
	`+seed); err != nil {
		t.Fatal(err)
	}
	return NewAgentEndpointRepository(db), db
}

func regenerateEndpointBundle(t *testing.T, repo *AgentEndpointRepository, db *pgxpool.Pool) endpointBundleSnapshot {
	t.Helper()
	ctx := context.Background()
	if _, err := repo.RegenerateIfChanged(ctx, "tenant-a", "test"); err != nil {
		t.Fatal(err)
	}
	var snap endpointBundleSnapshot
	var raw []byte
	if err := db.QueryRow(ctx, `SELECT version, checksum, bundle FROM agent_policy_bundles WHERE tenant_id='tenant-a' ORDER BY version DESC LIMIT 1`).Scan(&snap.version, &snap.checksum, &raw); err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		ModeDefault string               `json:"mode_default"`
		Rules       []agentendpoint.Rule `json:"rules"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	snap.mode, snap.decisions = bundle.ModeDefault, map[string]string{}
	for _, rule := range bundle.Rules {
		snap.decisions[rule.ID] = rule.Decision
	}
	return snap
}

// 复审 D6：hookd 用注册、心跳下发的端点模式，策略包 mode_default 只在端点模式为空时才用，降模式
// 对端侧不生效。全局观察留痕时策略包里规则的 block、confirm 一律降为 audit（照记上报，本地不拦）；
// 端点模式不动（阻断模式的端点仍同步调 decide，T13 照常生效）；切回防护模式恢复原动作，模式变化
// 让策略包内容变化、生成新版本（校验和变化，hookd 下次拉取即生效）。
func TestEndpointBundle2922GlobalRecordModeDowngradesRulesDB(t *testing.T) {
	repo, db := endpointModeTestRepo(t, `
		INSERT INTO system_settings VALUES ('agent_endpoint_default_mode','block'), ('security_execution_mode','record');
		INSERT INTO protection_settings(tenant_id,item_key,action) VALUES ('tenant-a','endpoint.rule.builtin_env_files','block');
		INSERT INTO agentguard_policies(id,tenant_id,rules_json,enabled,scope_type,priority) VALUES
			('pol-a','tenant-a','{"rules":[{"id":"deny-bash","tool_pattern":"bash","action":"block"},{"id":"ask-fetch","tool_pattern":"webfetch","action":"confirm"}]}',true,'tenant',10);
		INSERT INTO tool_risk_config VALUES ('tenant-a','wipe_disk','system','high','block');
	`)
	envRule := "builtin_env_files"
	denyBash := agentendpoint.RuleID("policy:pol-a:deny-bash:0")
	askFetch := agentendpoint.RuleID("policy:pol-a:ask-fetch:0")
	wipeTool := agentendpoint.RuleID("tool:wipe_disk")

	record := regenerateEndpointBundle(t, repo, db)
	if record.mode != "block" {
		t.Fatalf("the endpoint mode is not changed by the global mode (D10: block-mode endpoints still call decide): %s", record.mode)
	}
	for _, id := range []string{envRule, denyBash, askFetch, wipeTool} {
		if record.decisions[id] != "audit" {
			t.Errorf("global record mode: rule %s must be audit, got %q", id, record.decisions[id])
		}
	}
	for id, decision := range record.decisions {
		if decision == "block" || decision == "confirm" {
			t.Errorf("global record mode: no rule may block or confirm locally: %s=%s", id, decision)
		}
	}

	if _, err := db.Exec(context.Background(), `UPDATE system_settings SET value='protect' WHERE key='security_execution_mode'`); err != nil {
		t.Fatal(err)
	}
	protect := regenerateEndpointBundle(t, repo, db)
	if protect.version == record.version || protect.checksum == record.checksum {
		t.Fatalf("a global mode change must produce a new bundle: %d/%s -> %d/%s", record.version, record.checksum, protect.version, protect.checksum)
	}
	for id, want := range map[string]string{envRule: "block", denyBash: "block", askFetch: "confirm", wipeTool: "block"} {
		if protect.decisions[id] != want {
			t.Errorf("protect mode restores rule %s=%s, got %q", id, want, protect.decisions[id])
		}
	}
	if protect.mode != "block" {
		t.Fatalf("protect mode keeps the endpoint mode: %s", protect.mode)
	}
}

// 默认配置（库里没有执行模式、没有防护项与策略）反复生成，版本与校验和不变。
func TestEndpointBundle2922DefaultChecksumStableDB(t *testing.T) {
	repo, db := endpointModeTestRepo(t, "")
	first := regenerateEndpointBundle(t, repo, db)
	second := regenerateEndpointBundle(t, repo, db)
	if first.version != second.version || first.checksum != second.checksum {
		t.Fatalf("default configuration must not churn bundles: %d/%s -> %d/%s", first.version, first.checksum, second.version, second.checksum)
	}
	for id, decision := range first.decisions {
		if decision == "block" || decision == "confirm" {
			t.Errorf("default configuration resolves to global record mode: rule %s=%s", id, decision)
		}
	}
}

// D7 真库：部署变量 SECURITY_AUDIT_ONLY=true、库里显式防护时，端侧策略包按防护模式生成（规则不降级）；
// 去掉显式模式后部署变量作初值，规则降为 audit。
func TestEndpointBundle2922DeploymentVariableIsOnlyInitialValueDB(t *testing.T) {
	repo, db := endpointModeTestRepo(t, `
		INSERT INTO system_settings VALUES ('agent_endpoint_default_mode','block'), ('security_execution_mode','protect');
		INSERT INTO protection_settings(tenant_id,item_key,action) VALUES ('tenant-a','endpoint.rule.builtin_env_files','block');
	`)
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	protect := regenerateEndpointBundle(t, repo, db)
	if protect.decisions["builtin_env_files"] != "block" {
		t.Fatalf("explicit protect wins over the deployment variable: builtin_env_files=%q", protect.decisions["builtin_env_files"])
	}
	if _, err := db.Exec(context.Background(), `DELETE FROM system_settings WHERE key='security_execution_mode'`); err != nil {
		t.Fatal(err)
	}
	initial := regenerateEndpointBundle(t, repo, db)
	if initial.decisions["builtin_env_files"] != "audit" {
		t.Fatalf("without an explicit mode the deployment variable is the initial value (record): builtin_env_files=%q", initial.decisions["builtin_env_files"])
	}
}
