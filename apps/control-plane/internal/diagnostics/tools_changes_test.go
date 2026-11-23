package diagnostics

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestT4ChangeTimeline(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()
	other := "t4other_" + f.sfx

	t4Exec(t, ctx, f.conn, `INSERT INTO upgrade_history (id, version_from, version_to, status, created_at, completed_at)
VALUES ($1,'1.0.0','1.1.0','completed', now() - interval '40 minutes', now() - interval '38 minutes')`, "t4up_"+f.sfx+"_a")
	t4Exec(t, ctx, f.conn, `INSERT INTO upgrade_history (id, version_from, version_to, status, created_at)
VALUES ($1,'0.9.0','1.0.0','completed', now() - interval '30 days')`, "t4up_"+f.sfx+"_old") // 窗口外
	ins := `INSERT INTO audit_operations (id, user_id, tenant_id, action_type, action_detail, target_type, target_id, created_at)
VALUES ($1,$2,$3,$4,'{}',$5,$6, now() - make_interval(mins => $7))`
	t4Exec(t, ctx, f.conn, ins, "t4a1_"+f.sfx, f.userA, f.tenant, "update_provider", "provider", f.prov1, 25)
	t4Exec(t, ctx, f.conn, ins, "t4a2_"+f.sfx, f.userA, f.tenant, "routing_policy.update", "routing_policy", "rp1", 10)
	t4Exec(t, ctx, f.conn, ins, "t4a3_"+f.sfx, f.userA, f.tenant, "service.login", "user", f.userA, 15)          // 非配置变更
	t4Exec(t, ctx, f.conn, ins, "t4a4_"+f.sfx, nil, other, "update_provider", "provider", "px", 12)              // 其他租户
	t4Exec(t, ctx, f.conn, ins, "t4a5_"+f.sfx, f.userA, f.tenant, "quota_policy.update", "quota", "q1", 60*24*3) // 窗口外
	// 没写 tenant_id 的历史写入方式（CreateAuditOperation）：靠 user 归属租户
	t4Exec(t, ctx, f.conn, `INSERT INTO audit_operations (id, user_id, action_type, action_detail, target_type, target_id, created_at)
VALUES ($1,$2,'license.import','{}','license','l1', now() - interval '5 minutes')`, "t4a6_"+f.sfx, f.userA)
	t4Exec(t, ctx, f.conn, `INSERT INTO model_ops_config_audit (id, tenant_id, previous_version, version, actor, config_json, cost_confirmed, created_at)
VALUES ($1,$2,3,4,$3,'{"secret_token":"TOPSECRET"}',TRUE, now() - interval '20 minutes')`, "t4mo_"+f.sfx, f.tenant, f.nameA)
	t4Exec(t, ctx, f.conn, `UPDATE providers SET status='disabled', created_at = now() - interval '1 day', updated_at = now() - interval '2 minutes' WHERE id=$1`, f.prov1)

	m, raw := t4Call(t, f, f.admin(), "change_timeline", `{"window_hours":2}`)
	evs := m["events"].([]any)
	var kinds, sums []string
	var ats []time.Time
	for _, e := range evs {
		em := e.(map[string]any)
		kinds = append(kinds, em["kind"].(string))
		sums = append(sums, em["summary"].(string))
		at, err := time.Parse(time.RFC3339, em["at"].(string))
		if err != nil {
			t.Fatalf("at 不是 RFC3339: %v", em["at"])
		}
		ats = append(ats, at)
	}
	for i := 1; i < len(ats); i++ {
		if ats[i].Before(ats[i-1]) {
			t.Fatalf("事件应按时间升序: %v", ats)
		}
	}
	joined := strings.Join(sums, "\n")
	mustHave := []string{"系统升级 1.0.0 → 1.1.0", "update_provider", "routing_policy.update", "license.import", "模型运维配置 v3 → v4", "disabled"}
	for _, s := range mustHave {
		if !strings.Contains(joined, s) {
			t.Errorf("时间线缺少 %q:\n%s", s, joined)
		}
	}
	for _, s := range []string{"service.login", "px", "quota_policy.update", "0.9.0"} {
		if strings.Contains(joined, s) {
			t.Errorf("时间线不应包含 %q:\n%s", s, joined)
		}
	}
	if strings.Contains(raw, "TOPSECRET") {
		t.Error("不应输出 model_ops_config_audit 的配置内容")
	}
	// 顺序：升级(40) < 运维配置(20) < 渠道修改(25 → 在 20 之前)
	idx := func(sub string) int {
		for i, s := range sums {
			if strings.Contains(s, sub) {
				return i
			}
		}
		return -1
	}
	if !(idx("系统升级") < idx("update_provider") && idx("update_provider") < idx("模型运维配置") && idx("模型运维配置") < idx("routing_policy.update") && idx("routing_policy.update") < idx("license.import")) {
		t.Errorf("顺序不对:\n%s", joined)
	}
	if m["truncated"] != false {
		t.Errorf("不应截断: %v", m["truncated"])
	}
	_ = kinds
	// 每条事件字段齐全
	for _, e := range evs {
		em := e.(map[string]any)
		if em["kind"] == "" || em["summary"] == "" || em["at"] == "" {
			t.Errorf("事件字段不全: %v", em)
		}
	}
}

func TestT4ChangeTimelineAround(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()
	ins := `INSERT INTO audit_operations (id, user_id, tenant_id, action_type, action_detail, target_type, target_id, created_at)
VALUES ($1,$2,$3,'update_provider','{}','provider',$4, $5::timestamptz)`
	center := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	t4Exec(t, ctx, f.conn, ins, "t4n1_"+f.sfx, f.userA, f.tenant, "near-"+f.sfx, center.Add(30*time.Minute))
	t4Exec(t, ctx, f.conn, ins, "t4n2_"+f.sfx, f.userA, f.tenant, "far-"+f.sfx, center.Add(-5*time.Hour))
	m, _ := t4Call(t, f, f.admin(), "change_timeline", fmt.Sprintf(`{"window_hours":1,"around":%q}`, center.Format(time.RFC3339)))
	var sums []string
	for _, e := range m["events"].([]any) {
		sums = append(sums, e.(map[string]any)["summary"].(string))
	}
	j := strings.Join(sums, "\n")
	if !strings.Contains(j, "near-"+f.sfx) || strings.Contains(j, "far-"+f.sfx) {
		t.Errorf("around 前后 1 小时应只含 near:\n%s", j)
	}
	// 参数校验：非法时间、窗口上限
	reg := NewRegistry(ChangeTools()...)
	step := reg.Call(ctx, f.x, f.admin(), "change_timeline", []byte(`{"around":"yesterday"}`))
	if step.Err == "" {
		t.Error("非法 around 应报错")
	}
	m, _ = t4Call(t, f, f.admin(), "change_timeline", `{"window_hours":9999}`)
	if m["window_hours"].(float64) != 168 {
		t.Errorf("窗口应被限制为 168: %v", m["window_hours"])
	}
}

func TestT4ActionPrefixesCoverWriters(t *testing.T) {
	// 来自 handler 里 logAudit 的真实配置类 action_type（测试库 audit_operations 无数据，按代码核对）。
	for _, a := range []string{"create_provider", "update_provider", "delete_provider", "rotate_provider_credential",
		"update_model_status", "update_model_routing", "model_routing_override_saved", "model.capabilities.update",
		"routing_policy.update", "routing_policy.delete", "quota_policy.update", "license.import",
		"team.models.update", "update_builtin_policy_action", "system_settings.security_audit_only"} {
		if !t4IsConfigAction(a) {
			t.Errorf("%s 应属于配置变更", a)
		}
	}
	for _, a := range []string{"service.login", "usage.user.read", "evidence.read", "permission.denied", "alert.read"} {
		if t4IsConfigAction(a) {
			t.Errorf("%s 不应属于配置变更", a)
		}
	}
}
