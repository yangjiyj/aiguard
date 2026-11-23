package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/agentendpoint"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/executionmode"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AgentEndpointContext struct {
	TenantID      string `json:"tenant_id"`
	EndpointID    string `json:"endpoint_id"`
	AgentProduct  string `json:"agent_product"`
	Mode          string `json:"mode"`
	CaptureLevel  string `json:"capture_level"`
	PolicyVersion int64  `json:"policy_version"`
	ConfigVersion int64  `json:"config_version"`
	Revoked       bool   `json:"revoked"`
}

type AgentEndpointRepository struct{ db *pgxpool.Pool }

type AgentEndpointRegisterRequest struct {
	MachineID       string   `json:"machine_id"`
	Hostname        string   `json:"hostname"`
	OS              string   `json:"os"`
	OSVersion       string   `json:"os_version,omitempty"`
	Arch            string   `json:"arch"`
	OSUser          string   `json:"os_user,omitempty"`
	AgentProduct    string   `json:"agent_product"`
	AgentVersion    string   `json:"agent_version,omitempty"`
	InstallPathHash string   `json:"install_path_hash,omitempty"`
	AdapterName     string   `json:"adapter_name,omitempty"`
	AdapterVersion  string   `json:"adapter_version,omitempty"`
	HookdVersion    string   `json:"hookd_version,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
}

func (q AgentEndpointRegisterRequest) Validate() error {
	required := map[string]string{
		"machine_id": q.MachineID, "hostname": q.Hostname, "os": q.OS,
		"arch": q.Arch, "agent_product": q.AgentProduct,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" || len(value) > 256 {
			return fmt.Errorf("invalid %s", name)
		}
	}
	for name, value := range map[string]string{
		"os_version": q.OSVersion, "os_user": q.OSUser, "agent_version": q.AgentVersion,
		"install_path_hash": q.InstallPathHash, "adapter_name": q.AdapterName,
		"adapter_version": q.AdapterVersion, "hookd_version": q.HookdVersion,
	} {
		if len(value) > 256 {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if len(q.Capabilities) > 64 {
		return fmt.Errorf("too many capabilities")
	}
	seen := make(map[string]struct{}, len(q.Capabilities))
	for _, capability := range q.Capabilities {
		if strings.TrimSpace(capability) == "" || len(capability) > 128 {
			return fmt.Errorf("invalid capability")
		}
		if _, exists := seen[capability]; exists {
			return fmt.Errorf("duplicate capability")
		}
		seen[capability] = struct{}{}
	}
	return nil
}

func NewAgentEndpointRepository(db *pgxpool.Pool) *AgentEndpointRepository {
	return &AgentEndpointRepository{db: db}
}
func HashAgentToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
func NewAgentToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	t := hex.EncodeToString(b)
	return t, HashAgentToken(t), nil
}
func (r *AgentEndpointRepository) Resolve(ctx context.Context, hash string) (*AgentEndpointContext, error) {
	var x AgentEndpointContext
	var status string
	err := r.db.QueryRow(ctx, `SELECT tenant_id,id,agent_product,COALESCE(mode_override,'monitor'),capture_level,last_policy_version,last_config_version,status FROM agent_endpoints WHERE token_hash=$1`, hash).Scan(&x.TenantID, &x.EndpointID, &x.AgentProduct, &x.Mode, &x.CaptureLevel, &x.PolicyVersion, &x.ConfigVersion, &status)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	x.Revoked = status == "revoked" || status == "disabled"
	return &x, nil
}
func productAllowed(allowed []string, product string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if candidate == product {
			return true
		}
	}
	return false
}

func (r *AgentEndpointRepository) Register(ctx context.Context, enrollmentHash string, req AgentEndpointRegisterRequest) (map[string]any, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var tenant, mode, enrollmentID string
	var allowedJSON []byte
	var maxEndpoints int
	err = tx.QueryRow(ctx, `SELECT tenant_id,default_mode,allowed_products,max_endpoints,id
		FROM agent_enrollment_tokens
		WHERE token_hash=$1 AND enabled AND (expires_at IS NULL OR expires_at>now()) AND revoked_at IS NULL
		FOR UPDATE`, enrollmentHash).Scan(&tenant, &mode, &allowedJSON, &maxEndpoints, &enrollmentID)
	if err != nil {
		return nil, fmt.Errorf("enrollment token rejected")
	}
	var allowedProducts []string
	if string(allowedJSON) != "null" {
		if err = json.Unmarshal(allowedJSON, &allowedProducts); err != nil {
			return nil, fmt.Errorf("invalid allowed products: %w", err)
		}
	}
	if !productAllowed(allowedProducts, req.AgentProduct) {
		return nil, fmt.Errorf("product not allowed")
	}

	var endpointID, existingEnrollmentID, existingStatus string
	err = tx.QueryRow(ctx, `SELECT id,COALESCE(enrollment_token_id,''),status FROM agent_endpoints
		WHERE tenant_id=$1 AND machine_id=$2 AND agent_product=$3
		ORDER BY created_at LIMIT 1 FOR UPDATE`, tenant, req.MachineID, req.AgentProduct).Scan(&endpointID, &existingEnrollmentID, &existingStatus)
	existing := err == nil
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if existing && existingEnrollmentID != enrollmentID {
		return nil, fmt.Errorf("endpoint belongs to another enrollment token")
	}
	if (!existing || existingStatus == "revoked") && maxEndpoints > 0 {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM agent_endpoints WHERE enrollment_token_id=$1 AND status<>'revoked'`, enrollmentID).Scan(&count); err != nil {
			return nil, err
		}
		if count >= maxEndpoints {
			return nil, fmt.Errorf("max endpoints reached")
		}
	}

	token, tokenHash, err := NewAgentToken()
	if err != nil {
		return nil, err
	}
	capabilities, err := json.Marshal(req.Capabilities)
	if err != nil {
		return nil, err
	}
	if existing {
		_, err = tx.Exec(ctx, `UPDATE agent_endpoints SET
			hostname=$1,os=$2,os_version=$3,arch=$4,os_user=$5,agent_product=$6,agent_version=$7,
			install_path_hash=$8,adapter_name=$9,adapter_version=$10,hookd_version=$11,capabilities=$12,
			token_hash=$13,token_prefix=$14,token_rotated_at=now(),mode_override=$15,status='active',
			enrollment_token_id=$16,updated_at=now()
			WHERE id=$17 AND tenant_id=$18`, req.Hostname, req.OS, req.OSVersion, req.Arch, req.OSUser,
			req.AgentProduct, req.AgentVersion, req.InstallPathHash, req.AdapterName, req.AdapterVersion,
			req.HookdVersion, capabilities, tokenHash, token[:8], mode, enrollmentID, endpointID, tenant)
	} else {
		endpointID = "ep_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
		_, err = tx.Exec(ctx, `INSERT INTO agent_endpoints(
			id,tenant_id,machine_id,hostname,os,os_version,arch,os_user,agent_product,agent_version,
			install_path_hash,adapter_name,adapter_version,hookd_version,capabilities,token_hash,token_prefix,
			token_rotated_at,mode_override,enrollment_token_id)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,now(),$18,$19)`,
			endpointID, tenant, req.MachineID, req.Hostname, req.OS, req.OSVersion, req.Arch, req.OSUser,
			req.AgentProduct, req.AgentVersion, req.InstallPathHash, req.AdapterName, req.AdapterVersion,
			req.HookdVersion, capabilities, tokenHash, token[:8], mode, enrollmentID)
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_enrollment_tokens SET last_used_at=now() WHERE id=$1`, enrollmentID); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	// The endpoint token is committed above. A failed policy refresh must not hide
	// that token from the client: retrying registration would rotate it again.
	policy, policyErr := r.Policy(ctx, tenant)
	policyMetadata := map[string]any{"version": int64(0), "checksum": "sha256:" + strings.Repeat("0", 64)}
	if policyErr == nil {
		policyMetadata["version"] = policy["version"]
		policyMetadata["checksum"] = policy["checksum"]
	} else {
		policyMetadata["sync_pending"] = true
	}
	return map[string]any{"endpoint_id": endpointID, "endpoint_token": token, "mode": mode, "capture_level": "metadata", "policy": policyMetadata, "config": map[string]any{"version": 1, "heartbeat_interval_sec": 300, "report_interval_sec": 10, "report_batch_max": 200, "decide_timeout_ms": 300, "decide_fail_mode": "open", "queue_max_bytes": 104857600}}, nil
}
func (r *AgentEndpointRepository) Heartbeat(ctx context.Context, tenant, endpoint string, health any, policy, config int64) error {
	b, _ := json.Marshal(health)
	_, err := r.db.Exec(ctx, `UPDATE agent_endpoints SET last_heartbeat_at=now(),health=$1,hookd_version=hookd_version,last_policy_version=$2,last_config_version=$3,updated_at=now(),status='active' WHERE tenant_id=$4 AND id=$5 AND status<>'revoked'`, b, policy, config, tenant, endpoint)
	return err
}
func (r *AgentEndpointRepository) AcceptEvent(ctx context.Context, tenant, endpoint string, event map[string]any) (bool, error) {
	id, _ := event["event_id"].(string)
	if id == "" {
		id = uuid.NewString()
	}
	typ, _ := event["event_type"].(string)
	session, _ := event["session_id"].(string)
	_, err := r.db.Exec(ctx, `INSERT INTO agent_events(id,tenant_id,endpoint_id,session_id,event_type,occurred_at,payload) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, id, tenant, endpoint, session, typ, time.Now().UTC(), event)
	if err != nil {
		return false, err
	}
	var exists bool
	_ = r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_events WHERE tenant_id=$1 AND id=$2)`, tenant, id).Scan(&exists)
	return exists, nil
}
func (r *AgentEndpointRepository) Policy(ctx context.Context, tenant string) (map[string]any, error) {
	if _, err := r.RegenerateIfChanged(ctx, tenant, "agent_endpoint"); err != nil {
		return nil, err
	}
	var ver int64
	var checksum string
	var bundle []byte
	err := r.db.QueryRow(ctx, `SELECT version,checksum,bundle FROM agent_policy_bundles WHERE tenant_id=$1 ORDER BY version DESC LIMIT 1`, tenant).Scan(&ver, &checksum, &bundle)
	if err == pgx.ErrNoRows {
		return map[string]any{"version": 0, "checksum": "sha256:" + strings.Repeat("0", 64), "rules": []any{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := json.Unmarshal(bundle, &v); err != nil {
		return nil, fmt.Errorf("decode stored policy bundle: %w", err)
	}
	v["version"] = ver
	v["checksum"] = checksum
	return v, nil
}

// endpointRulesUnderGlobalMode 落实全局观察留痕对端侧的约束（D6）：全局观察留痕时，策略包里规则的
// block、confirm 一律降为 audit（照记上报，本地不拦）。端点模式不动：hookd 用注册、心跳下发的端点
// 模式，阻断模式的端点仍同步调 decide，T13 授权拒绝照常生效（D10）。
func endpointRulesUnderGlobalMode(rules []agentendpoint.Rule, globalRecordOnly bool) []agentendpoint.Rule {
	if !globalRecordOnly {
		return rules
	}
	for i := range rules {
		switch rules[i].Decision {
		case "block", "confirm":
			rules[i].Decision = "audit"
		}
	}
	return rules
}

// globalExecutionRecordOnly 是端侧“是否全局观察留痕”的唯一判断点：两个键一次读出，按
// executionmode.FromValues 判定，与控制台、签名投影、网关同口径（部署变量 SECURITY_AUDIT_ONLY=true
// 只在库里没有显式执行模式时作初值，D7）。在事务里调用，读库失败返回错误、本次不生成新策略包
// （事务已中止，hookd 继续用上一版）。
func globalExecutionRecordOnly(ctx context.Context, q executionModeQuerier) (bool, error) {
	values, err := loadExecutionModeValues(ctx, q)
	if err != nil {
		return false, fmt.Errorf("load global execution mode: %w", err)
	}
	return globalRecordOnlyFromSettings(values), nil
}

// globalRecordOnlyFromSettings 把读到的两个键交给 executionmode.FromValues（含部署变量初值）。
func globalRecordOnlyFromSettings(values map[string]string) bool {
	auditOnly, _ := executionmode.FromValues(values, executionmode.DeploymentRecordInitialValue())
	return auditOnly
}

// endpointProtectionSettings 读租户为端侧内置规则保存的防护项（endpoint.rule.*）；缺行取注册表默认值。
func endpointProtectionSettings(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, tenant string) (protection.Settings, error) {
	rows, err := q.Query(ctx, `SELECT item_key, action, params_json FROM protection_settings
		WHERE tenant_id=$1 AND item_key LIKE 'endpoint.rule.%' ORDER BY item_key`, tenant)
	if err != nil {
		return nil, fmt.Errorf("load endpoint protection settings: %w", err)
	}
	defer rows.Close()
	settings := protection.Settings{}
	for rows.Next() {
		var key, action string
		var raw []byte
		if err := rows.Scan(&key, &action, &raw); err != nil {
			return nil, err
		}
		setting := protection.Setting{Action: protection.Action(action)}
		if err := json.Unmarshal(raw, &setting.Params); err != nil {
			log.Printf("WARN agent endpoint bundle: unreadable params_json tenant=%s item=%s, params fall back to registry defaults: %v", tenant, key, err)
			setting.Params = nil
		}
		settings[key] = setting
	}
	return settings, rows.Err()
}

// RegenerateIfChanged serializes bundle versions per tenant with a transaction-scoped
// advisory lock. Readers also regenerate, recovering from failed post-write attempts.
func (r *AgentEndpointRepository) RegenerateIfChanged(ctx context.Context, tenant, actor string) (int64, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	// Shared with other regenerators, not source writers; every regeneration reads
	// sources only after this lock and a successful commit is immutable.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 853))`, tenant); err != nil {
		return 0, err
	}
	// 端侧内置规则的动作取防护项 endpoint.rule.*（读完再开下一个查询，同一事务不能并行读两个结果集）。
	settings, err := endpointProtectionSettings(ctx, tx, tenant)
	if err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `SELECT id, rules_json FROM agentguard_policies WHERE tenant_id=$1 AND enabled AND scope_type='tenant' ORDER BY priority DESC,created_at DESC,id LIMIT 1`, tenant)
	if err != nil {
		return 0, err
	}
	rules := agentendpoint.BuiltinRulesFor(settings)
	policyCount := 0
	selectedPolicyID := ""
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return 0, err
		}
		policyCount++
		selectedPolicyID = id
		var value struct {
			Rules []struct {
				ID          string `json:"id"`
				ToolPattern string `json:"tool_pattern"`
				Action      string `json:"action"`
				Enabled     *bool  `json:"enabled"`
			} `json:"rules"`
		}
		if err = json.Unmarshal(raw, &value); err != nil {
			rows.Close()
			return 0, err
		}
		for _, v := range value.Rules {
			matches, e := agentendpoint.ToolPatternMatches(v.ToolPattern)
			if e != nil {
				rows.Close()
				return 0, fmt.Errorf("policy %s rule %s: %w", id, v.ID, e)
			}
			if !agentendpoint.ValidDecision(v.Action) {
				rows.Close()
				return 0, fmt.Errorf("policy %s rule %s: invalid decision", id, v.ID)
			}
			enabled := v.Enabled == nil || *v.Enabled
			for i, match := range matches {
				rules = append(rules, agentendpoint.Rule{ID: agentendpoint.RuleID(fmt.Sprintf("policy:%s:%s:%d", id, v.ID, i)), Match: match, Decision: v.Action, Risk: "medium", Enabled: enabled})
			}
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT tool_name, tool_type, risk_level, action FROM tool_risk_config WHERE tenant_id=$1 ORDER BY tool_name`, tenant)
	if err != nil {
		return 0, err
	}
	toolCount := 0
	toolHash := sha256.New()
	for rows.Next() {
		var name, typ, risk, action string
		if err = rows.Scan(&name, &typ, &risk, &action); err != nil {
			rows.Close()
			return 0, err
		}
		toolCount++
		fmt.Fprintf(toolHash, "%q|%q|%q|%q\n", name, typ, risk, action)
		if !agentendpoint.ValidToolType(typ) || !agentendpoint.ValidRisk(risk) || !agentendpoint.ValidDecision(action) {
			rows.Close()
			return 0, fmt.Errorf("tool risk config %q has unsupported type/risk/action", name)
		}
		rules = append(rules, agentendpoint.Rule{ID: agentendpoint.RuleID("tool:" + name), Match: agentendpoint.Match{ToolType: typ, ToolNameRegex: "^(?i:" + regexp.QuoteMeta(name) + ")$"}, Decision: action, Risk: risk, Enabled: true})
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	var policyVersions string
	err = tx.QueryRow(ctx, `SELECT COALESCE(string_agg(v.policy_id || ':' || v.policy_version, ',' ORDER BY v.policy_id),'') FROM agentguard_policy_versions v JOIN agentguard_policies p ON p.id=v.policy_id AND p.tenant_id=v.tenant_id WHERE v.tenant_id=$1 AND v.active AND p.id=$2`, tenant, selectedPolicyID).Scan(&policyVersions)
	if err != nil {
		return 0, err
	}
	sources := agentendpoint.Sources{AgentGuardPolicyVersion: fmt.Sprintf("%d:%s", policyCount, policyVersions), ToolRiskConfigVersion: fmt.Sprintf("count:%d;sha256:%x", toolCount, toolHash.Sum(nil))}
	var version int64
	err = tx.QueryRow(ctx, `SELECT version FROM agent_policy_bundles WHERE tenant_id=$1 ORDER BY version DESC LIMIT 1`, tenant).Scan(&version)
	if err != nil && err != pgx.ErrNoRows {
		return 0, err
	}
	mode := "monitor"
	err = tx.QueryRow(ctx, `SELECT value FROM system_settings WHERE key='agent_endpoint_default_mode'`).Scan(&mode)
	if err != nil && err != pgx.ErrNoRows {
		return 0, err
	}
	// 全局观察留痕管住端侧本地判定（D6）：规则降为 audit，模式变化让策略包内容变化、生成新版本，
	// 心跳与拉取都走这里，hookd 下次拉取即生效。
	recordOnly, err := globalExecutionRecordOnly(ctx, tx)
	if err != nil {
		return 0, err
	}
	rules = endpointRulesUnderGlobalMode(rules, recordOnly)
	// There is no tenant-scoped command/domain/MCP/path allowlist in these
	// persistence models; do not infer one from unrelated proxy or model ACLs.
	allowlists := agentendpoint.Allowlist{}
	bundle, checksum, err := agentendpoint.BuildBundle(version+1, mode, rules, allowlists, sources, time.Now())
	if err != nil {
		return 0, err
	}
	if err == nil {
		var latest agentendpoint.Bundle
		var candidate agentendpoint.Bundle
		var stored []byte
		if scanErr := tx.QueryRow(ctx, `SELECT bundle FROM agent_policy_bundles WHERE tenant_id=$1 ORDER BY version DESC LIMIT 1`, tenant).Scan(&stored); scanErr == nil {
			if json.Unmarshal(stored, &latest) == nil && json.Unmarshal(bundle, &candidate) == nil {
				latest.Version, latest.Checksum, latest.GeneratedAt = 0, "", ""
				candidate.Version, candidate.Checksum, candidate.GeneratedAt = 0, "", ""
				if reflect.DeepEqual(latest, candidate) {
					return version, nil
				}
			}
		} else if scanErr != pgx.ErrNoRows {
			return 0, scanErr
		}
	}
	// Migration 857 permits a previously used checksum under a new version.
	version++
	_, err = tx.Exec(ctx, `INSERT INTO agent_policy_bundles(id,tenant_id,version,checksum,bundle,derived_from,created_by) VALUES($1,$2,$3,$4,$5,$6,$7)`, "apb_"+uuid.NewString(), tenant, version, checksum, bundle, map[string]any{"agentguard_policies": policyCount, "agentguard_policy_versions": policyVersions, "tool_risk_config": toolCount}, actor)
	if err != nil {
		return 0, err
	}
	return version, tx.Commit(ctx)
}
