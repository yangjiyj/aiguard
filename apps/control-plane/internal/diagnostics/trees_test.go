package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- t7 夹具（复用 t4 夹具的租户 / 用户 / 渠道 / 模型） ----------

func t7RID(f *t4Fix, n int) string {
	return fmt.Sprintf("req_%s-0000-4000-8000-%012d", f.sfx, n)
}

func t7Registry(t *testing.T) *Registry {
	t.Helper()
	missing := &AgentClient{Dir: filepath.Join(t.TempDir(), "none"), Key: []byte("k")}
	tools := append(append(append(RequestTools(), ConfigTools()...), ChangeTools()...), HostTools(missing)...)
	return NewRegistry(tools...)
}

func t7Add(t *testing.T, f *t4Fix, rid, user, status string, code int, agoMin int, audit string) {
	t.Helper()
	var a, c any
	if audit != "" {
		a = audit
	}
	if code > 0 {
		c = code
	}
	t4Exec(t, context.Background(), f.conn, `
INSERT INTO request_logs (id, request_id, tenant_id, user_id, client_id, provider_id, model_id, endpoint_type, request_status,
  upstream_status_code, latency_ms, created_at, output_audit_result)
VALUES ($1,$2,$3,$4,$5,$6,$7,'chat',$8,$9,123, now() - make_interval(mins => $10), $11::jsonb)`,
		"id_"+rid, rid, f.tenant, user, f.keyA, f.prov1, f.m1, status, c, agoMin, a)
}

func t7Hint(hint, code string) string {
	b, _ := json.Marshal(map[string]any{"response_metadata": map[string]any{"upstream_error_hint": hint, "upstream_error_code": code, "error_message": hint}})
	return string(b)
}

func t7Tree(t *testing.T, f *t4Fix, s Scope, in Input) *Report {
	t.Helper()
	rep, err := RunTree(context.Background(), f.x, t7Registry(t), s, in, &HostView{Err: ErrAgentMissing})
	if err != nil {
		t.Fatalf("RunTree 返回错误（FactCheck 必须通过）: %v", err)
	}
	if rep.Tier != TierL2 {
		t.Fatalf("档位应为 L2: %v", rep.Tier)
	}
	if err := FactCheck(rep); err != nil {
		t.Fatalf("FactCheck: %v", err)
	}
	return rep
}

func t7Find1(rep *Report, id string) *Finding {
	for i := range rep.Findings {
		if rep.Findings[i].CheckID == id {
			return &rep.Findings[i]
		}
	}
	return nil
}

func t7Dump(rep *Report) string {
	b, _ := json.MarshalIndent(rep.Findings, "", " ")
	return string(b)
}

func t7StepTools(rep *Report) []string {
	var out []string
	for _, s := range rep.Steps {
		out = append(out, s.Tool)
	}
	return out
}

func t7HasTool(rep *Report, name string) bool {
	for _, n := range t7StepTools(rep) {
		if n == name {
			return true
		}
	}
	return false
}

const t7AzureHint = "Unsupported parameter: 'max_tokens' is not supported with this model. Use 'max_completion_tokens' instead."

// ---------- 场景 1：Azure max_tokens 400 + 升级记录 ----------

func TestT7RequestAzureParamAndUpgrade(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()
	t4Exec(t, ctx, f.conn, `INSERT INTO upgrade_history (id, version_from, version_to, status, created_at, completed_at)
VALUES ($1,'2.9.6','2.9.7','completed', now() - interval '100 minutes', now() - interval '98 minutes')`, "t4up_"+f.sfx+"_t7")
	audit := t7Hint(t7AzureHint, "unsupported_parameter")
	for i, ago := range []int{95, 92, 90, 85, 80} {
		t7Add(t, f, t7RID(f, i+1), f.userA, "provider_error", 400, ago, audit)
	}
	t7Add(t, f, t7RID(f, 90), f.userA, "success", 200, 200, "") // 窗口内成功请求，不影响

	rep := t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 5)})
	main := t7Find1(rep, "up_param")
	if main == nil || main.Level != LevelConfirmed {
		t.Fatalf("应有确定的上游参数拒绝结论:\n%s", t7Dump(rep))
	}
	if !strings.Contains(main.Title, "上游拒绝") || !strings.Contains(main.Title, "max_tokens") {
		t.Errorf("结论应提到参数被拒绝: %s", main.Title)
	}
	if len(main.Evidence) == 0 || !strings.Contains(main.Evidence[0].Raw, "max_completion_tokens") {
		t.Errorf("证据里应保留上游原文: %+v", main.Evidence)
	}
	excl := strings.Join(main.Excluded, "\n")
	if !strings.Contains(excl, "已排除网关限流") || !strings.Contains(excl, "已排除客户端偶发") {
		t.Errorf("已排除项不足: %v", main.Excluded)
	}
	cor := t7Find1(rep, "tree_change_correlation")
	if cor == nil || cor.Level != LevelSuspected {
		t.Fatalf("应有疑似的升级吻合结论:\n%s", t7Dump(rep))
	}
	if !strings.Contains(cor.Title, "2.9.6 → 2.9.7") || !strings.Contains(cor.Title, "升级") || !strings.Contains(cor.Title, "该问题始于") {
		t.Errorf("疑似结论应指向升级: %s", cor.Title)
	}
	if len(cor.Advice) == 0 || !strings.Contains(cor.Advice[0].Text, "诊断包") {
		t.Errorf("建议应是导出诊断包: %+v", cor.Advice)
	}
	for _, tool := range []string{"get_request", "search_requests", "compare_windows", "change_timeline"} {
		if !t7HasTool(rep, tool) {
			t.Errorf("缺少步骤 %s: %v", tool, t7StepTools(rep))
		}
	}
	for _, s := range rep.Steps {
		if s.Summary == "" {
			t.Errorf("步骤缺少中文进度: %+v", s)
		}
	}

	// 员工看不到 change_timeline，也不会拿到升级结论，建议里没有后台链接
	rep = t7Tree(t, f, f.staff(f.userA), Input{Kind: "request", Ref: t7RID(f, 5)})
	if t7HasTool(rep, "change_timeline") || t7Find1(rep, "tree_change_correlation") != nil {
		t.Errorf("员工不应查变更时间线: %v", t7StepTools(rep))
	}
	for _, fd := range rep.Findings {
		for _, a := range fd.Advice {
			if a.Link != "" && !strings.HasPrefix(a.Link, "/cost/records") {
				t.Errorf("员工建议不应带后台链接: %+v", a)
			}
		}
	}
}

func TestT7RequestParamNotCorrelatedWhenOldOrChangeFar(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()
	t4Exec(t, ctx, f.conn, `INSERT INTO upgrade_history (id, version_from, version_to, status, created_at)
VALUES ($1,'2.9.6','2.9.7','completed', now() - interval '6 hours')`, "t4up_"+f.sfx+"_t7far")
	audit := t7Hint(t7AzureHint, "unsupported_parameter")
	for i, ago := range []int{95, 92, 90} {
		t7Add(t, f, t7RID(f, i+1), f.userA, "provider_error", 400, ago, audit)
	}
	rep := t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 1)})
	if t7Find1(rep, "tree_change_correlation") != nil {
		t.Errorf("升级在 6 小时前，不应判为吻合:\n%s", t7Dump(rep))
	}
	main := t7Find1(rep, "up_param")
	if main == nil || !strings.Contains(strings.Join(main.Excluded, "\n"), "已排除版本升级与配置变更") {
		t.Errorf("应写明已排除升级: %s", t7Dump(rep))
	}

	// 24 小时前就有同类错误：不是新出现的，也不给吻合结论
	t7Add(t, f, t7RID(f, 50), f.userA, "provider_error", 400, 25*60+30, audit)
	t7Add(t, f, t7RID(f, 51), f.userA, "provider_error", 400, 25*60+20, audit)
	rep = t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 1)})
	if t7Find1(rep, "tree_change_correlation") != nil {
		t.Errorf("24 小时前已有同类错误，不应判为新出现")
	}
	if main = t7Find1(rep, "up_param"); main == nil || !strings.Contains(strings.Join(main.Excluded, "\n"), "已排除新近引入") {
		t.Errorf("应写明已排除新近引入: %s", t7Dump(rep))
	}
}

// ---------- 场景 2：网关日配额 429 与上游 429 并存 ----------

func TestT7GatewayQuotaAndUpstream429(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()
	t4Exec(t, ctx, f.conn, `INSERT INTO quota_policies (id, tenant_id, scope_type, user_id, daily_token_limit_canonical, overage_action, enforcement_mode)
VALUES ($1,$2,'user',$3,500,'block','hard')`, "t4q7_"+f.sfx, f.tenant, f.userA)
	for i, tok := range []int{300, 300} {
		t4Exec(t, ctx, f.conn, `INSERT INTO request_logs (id, request_id, tenant_id, user_id, client_id, provider_id, model_id, endpoint_type, request_status, upstream_status_code, input_tokens, output_tokens, created_at)
VALUES ($1,$1,$2,$3,$4,$5,$6,'chat','success',200,$7,0, now() - make_interval(secs => $8))`, fmt.Sprintf("req_t7tok_%s_%d", f.sfx, i), f.tenant, f.userA, f.keyA, f.prov1, f.m1, tok, i+1)
	}
	gw, up := t7RID(f, 1), t7RID(f, 2)
	t7Add(t, f, gw, f.userA, "quota_exceeded", 0, 5, "")
	t7Add(t, f, up, f.userA, "provider_error", 429, 6, "")
	t7Add(t, f, t7RID(f, 3), f.userA, "provider_error", 429, 7, "")
	t7Add(t, f, t7RID(f, 4), f.userA, "success", 200, 8, "")

	rep := t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: gw})
	q := t7Find1(rep, "gw_quota")
	if q == nil || q.Level != LevelConfirmed {
		t.Fatalf("网关额度拦截应被识别:\n%s", t7Dump(rep))
	}
	if !strings.Contains(q.Title, "网关") || !strings.Contains(q.Title, "限额 500") || !strings.Contains(q.Title, "已用 600") {
		t.Errorf("应指出策略、限额与已用: %s", q.Title)
	}
	if t7Find1(rep, "up_429") != nil {
		t.Errorf("网关拦截不应判为上游 429")
	}
	if !t7HasTool(rep, "get_quota_policies") {
		t.Errorf("网关拦截应查配额策略: %v", t7StepTools(rep))
	}

	rep = t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: up})
	u := t7Find1(rep, "up_429")
	if u == nil || !strings.Contains(u.Title, "上游限流") {
		t.Fatalf("上游 429 应被识别:\n%s", t7Dump(rep))
	}
	if t7Find1(rep, "gw_quota") != nil || !strings.Contains(strings.Join(u.Excluded, "\n"), "已排除网关限流与额度拦截") {
		t.Errorf("上游 429 应排除网关拦截: %s", t7Dump(rep))
	}
	if t7Find1(rep, "up_billing") != nil {
		t.Errorf("没有额度不足特征，不应判欠费")
	}
	if !t7HasTool(rep, "search_requests") {
		t.Errorf("上游 429 应查渠道整体情况")
	}

	// 模型树里两类被分别列出
	rep = t7Tree(t, f, f.admin(), Input{Kind: "model", Ref: f.logX, WindowH: 1})
	if t7Find1(rep, "gw_quota") == nil || t7Find1(rep, "up_429") == nil {
		t.Errorf("同一窗口内应分别列出网关额度与上游 429:\n%s", t7Dump(rep))
	}
}

func TestT7UpstreamInsufficientQuotaSuspected(t *testing.T) {
	f := t4NewFixture(t)
	audit := t7Hint("You exceeded your current quota, please check your plan and billing details.", "insufficient_quota")
	for i := 1; i <= 4; i++ {
		t7Add(t, f, t7RID(f, i), f.userA, "provider_error", 429, 5+i, audit)
	}
	rep := t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 1)})
	b := t7Find1(rep, "up_billing")
	if b == nil || b.Level != LevelSuspected {
		t.Fatalf("应有疑似欠费:\n%s", t7Dump(rep))
	}
	if u := t7Find1(rep, "up_429"); u == nil || !strings.Contains(u.Impact, "整个渠道") {
		t.Errorf("整条渠道都在 429 应写明: %s", t7Dump(rep))
	}
}

// ---------- 其他请求分支 ----------

func TestT7RequestBranches(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()
	t7Add(t, f, t7RID(f, 1), f.userA, "provider_error", 502, 5, "")
	t7Add(t, f, t7RID(f, 2), f.userA, "provider_error", 401, 5, "")
	t7Add(t, f, t7RID(f, 3), f.userA, "model_not_found", 0, 5, "")
	t7Add(t, f, t7RID(f, 4), f.userA, "security_blocked", 0, 5, "")
	t7Add(t, f, t7RID(f, 5), f.userA, "success", 200, 5, "")
	t7Add(t, f, t7RID(f, 6), f.userA, "rate_limited", 0, 5, "")
	t4Exec(t, ctx, f.conn, `INSERT INTO quota_policies (id, tenant_id, scope_type, user_id, rpm_limit_canonical, overage_action) VALUES ($1,$2,'user',$3,30,'block')`,
		"t4q7r_"+f.sfx, f.tenant, f.userA)

	// 5xx：采集器未安装要写明
	rep := t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 1)})
	fd := t7Find1(rep, "up_5xx")
	if fd == nil || !strings.Contains(fd.Title, "502") {
		t.Fatalf("5xx 结论: %s", t7Dump(rep))
	}
	if !strings.Contains(strings.Join(fd.Excluded, "\n"), "未能查看宿主机日志：未安装采集器") {
		t.Errorf("应写明未装采集器: %v", fd.Excluded)
	}
	for _, tool := range []string{"search_requests", "get_provider", "host_container_logs"} {
		if !t7HasTool(rep, tool) {
			t.Errorf("5xx 缺少 %s", tool)
		}
	}
	rep = t7Tree(t, f, f.staff(f.userA), Input{Kind: "request", Ref: t7RID(f, 1)})
	if t7HasTool(rep, "host_container_logs") || t7HasTool(rep, "get_provider") {
		t.Errorf("员工不应调用管理员工具: %v", t7StepTools(rep))
	}

	// 鉴权失败
	rep = t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 2)})
	if fd = t7Find1(rep, "auth_failed"); fd == nil || !strings.Contains(fd.Title, "凭据") || !t7HasTool(rep, "get_provider") {
		t.Errorf("鉴权失败: %s", t7Dump(rep))
	}
	// 模型不存在
	rep = t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 3)})
	if fd = t7Find1(rep, "model_missing"); fd == nil || !t7HasTool(rep, "get_model_routes") {
		t.Errorf("模型缺失: %s", t7Dump(rep))
	}
	// 安全拦截
	rep = t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 4)})
	if fd = t7Find1(rep, "security_block"); fd == nil || fd.Title != "该请求被内容安全策略拦截" || fd.Advice[0].Link != "/security/alerts" {
		t.Errorf("安全拦截: %s", t7Dump(rep))
	}
	// 成功
	rep = t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 5)})
	if fd = t7Find1(rep, "request_ok"); fd == nil || fd.Severity != SevOK {
		t.Errorf("成功请求: %s", t7Dump(rep))
	}
	// 网关限流
	rep = t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 6)})
	if fd = t7Find1(rep, "gw_rate_limited"); fd == nil || !strings.Contains(fd.Title, "每分钟 30 次") {
		t.Errorf("网关限流: %s", t7Dump(rep))
	}
	// 从原文里提取编号
	rep = t7Tree(t, f, f.admin(), Input{Kind: "request", Text: "调用报错 " + t7RID(f, 5) + " 请看看"})
	if t7Find1(rep, "request_ok") == nil {
		t.Errorf("应能从原文提取编号: %s", t7Dump(rep))
	}
}

// ---------- 场景 4：员工查他人编号 ----------

func TestT7StaffCannotSeeOthersRequest(t *testing.T) {
	f := t4NewFixture(t)
	t7Add(t, f, t7RID(f, 1), f.userB, "provider_error", 400, 5, t7Hint(t7AzureHint, "x"))
	rep := t7Tree(t, f, f.staff(f.userA), Input{Kind: "request", Ref: t7RID(f, 1)})
	if len(rep.Findings) != 1 || rep.Findings[0].Level != LevelUnknown || rep.Findings[0].Title != "未找到该请求（可能不属于你，或超过 7 天）" {
		t.Fatalf("应返回 unknown 未找到:\n%s", t7Dump(rep))
	}
	if strings.Contains(t7Dump(rep), "max_tokens") {
		t.Errorf("不得泄露他人请求内容")
	}
	// 管理员可见；编号不存在也是未找到
	rep = t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 99)})
	if rep.Findings[0].Level != LevelUnknown {
		t.Errorf("不存在的编号应 unknown")
	}
}

// ---------- 场景 3：forbidden_model（用户树） ----------

func TestT7UserForbiddenModel(t *testing.T) {
	f := t4NewFixture(t)
	// userB 是应急账号，没有聊天资格，没有任何请求记录
	rep := t7Tree(t, f, f.admin(), Input{Kind: "user", Ref: f.userB, Text: "用户 " + f.userB + " 调用 " + f.logX + " 报 403 forbidden_model"})
	fd := t7Find1(rep, "user_access")
	if fd == nil || fd.Level != LevelConfirmed || !strings.Contains(fd.Title, "没有模型 "+f.logX+" 的使用权限") || !strings.Contains(fd.Title, "forbidden_model") {
		t.Fatalf("应给出 forbidden_model 结论:\n%s", t7Dump(rep))
	}
	for _, tool := range []string{"get_user_access", "get_quota_policies", "search_requests"} {
		if !t7HasTool(rep, tool) {
			t.Errorf("用户树缺少 %s", tool)
		}
	}
	if !strings.Contains(strings.Join(fd.Excluded, ""), "不会写入调用明细") {
		t.Errorf("应说明查不到请求记录的原因: %v", fd.Excluded)
	}

	// userA 有部门，但部门没授权 logY
	rep = t7Tree(t, f, f.admin(), Input{Kind: "user", Ref: f.nameA, Text: "我想用 " + f.logY})
	fd = t7Find1(rep, "user_access")
	if fd == nil || !strings.Contains(fd.Title, "没有模型 "+f.logY+" 的使用权限") || !strings.Contains(fd.Impact, "部门") {
		t.Fatalf("部门未授权:\n%s", t7Dump(rep))
	}

	// 授权的模型不报权限问题
	rep = t7Tree(t, f, f.admin(), Input{Kind: "user", Ref: f.nameA, Text: "我想用 " + f.logX})
	for _, x := range rep.Findings {
		if strings.Contains(x.Title, "没有模型") {
			t.Errorf("已授权的模型不应报无权限: %s", x.Title)
		}
	}

	// 员工自查：被强制为自己，不能查别人
	rep = t7Tree(t, f, f.staff(f.userB), Input{Kind: "user", Ref: f.userA, Text: "用 " + f.logX})
	if fd = t7Find1(rep, "user_access"); fd == nil || !strings.Contains(fd.Title, "没有") {
		t.Errorf("员工应被强制查自己: %s", t7Dump(rep))
	}
	if strings.Contains(t7Dump(rep), f.nameA) {
		t.Errorf("员工不应看到他人信息")
	}
}

func TestT7UserWithFailuresAndKeys(t *testing.T) {
	f := t4NewFixture(t)
	for i := 1; i <= 3; i++ {
		t7Add(t, f, t7RID(f, i), f.userA, "provider_error", 429, 5+i, "")
	}
	rep := t7Tree(t, f, f.admin(), Input{Kind: "user", Ref: f.nameA, WindowH: 2})
	if fd := t7Find1(rep, "up_429"); fd == nil || !strings.Contains(fd.Title, "3 条") {
		t.Errorf("用户树应列出失败分组: %s", t7Dump(rep))
	}
	// 全部正常
	f2 := t4NewFixture(t)
	rep = t7Tree(t, f2, f2.admin(), Input{Kind: "user", Ref: f2.nameA})
	if len(rep.Findings) != 1 || rep.Findings[0].Level != LevelUnknown || rep.Findings[0].Severity != SevOK {
		t.Errorf("一切正常时应坦白无法解释: %s", t7Dump(rep))
	}
}

// ---------- 模型 / 渠道树 ----------

func TestT7ModelAndProviderTrees(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()
	// logY 只有一条路由；停用渠道一
	t4Exec(t, ctx, f.conn, `UPDATE providers SET status='disabled' WHERE id=$1`, f.prov1)
	rep := t7Tree(t, f, f.admin(), Input{Kind: "model", Ref: f.logY})
	if fd := t7Find1(rep, "no_route"); fd == nil || !strings.Contains(fd.Title, "没有任何可用渠道") {
		t.Errorf("应判无可用渠道:\n%s", t7Dump(rep))
	}
	if fd := t7Find1(rep, "provider_down"); fd == nil || !strings.Contains(fd.Title, "已停用") {
		t.Errorf("应判渠道停用:\n%s", t7Dump(rep))
	}
	for _, tool := range []string{"get_model_routes", "search_requests", "get_provider"} {
		if !t7HasTool(rep, tool) {
			t.Errorf("模型树缺少 %s: %v", tool, t7StepTools(rep))
		}
	}
	rep = t7Tree(t, f, f.admin(), Input{Kind: "model", Ref: "no-such-model-" + f.sfx})
	if fd := t7Find1(rep, "model_missing"); fd == nil || fd.Level != LevelConfirmed {
		t.Errorf("不存在的模型: %s", t7Dump(rep))
	}
	rep = t7Tree(t, f, f.admin(), Input{Kind: "provider", Ref: f.prov1})
	if t7Find1(rep, "provider_down") == nil || !t7HasTool(rep, "get_provider") {
		t.Errorf("渠道树: %s", t7Dump(rep))
	}
	// 员工只能走请求搜索
	rep = t7Tree(t, f, f.staff(f.userA), Input{Kind: "model", Ref: f.logX})
	if t7HasTool(rep, "get_model_routes") || t7HasTool(rep, "get_provider") {
		t.Errorf("员工不应调用管理员工具: %v", t7StepTools(rep))
	}
}

// ---------- 体检 / 自然语言 ----------

func TestT7HealthAndQuestion(t *testing.T) {
	f := t4NewFixture(t)
	rep := t7Tree(t, f, f.admin(), Input{Kind: "health"})
	if rep.Degraded != "" || len(rep.Steps) == 0 {
		t.Errorf("体检应直接执行检查: %q steps=%d", rep.Degraded, len(rep.Steps))
	}
	rep = t7Tree(t, f, f.admin(), Input{Kind: "question", Text: "为什么最近很慢"})
	if rep.Degraded != "当前未启用智能排查，已改为全局体检" {
		t.Errorf("question 应注明降级: %q", rep.Degraded)
	}
	if len(rep.Steps) == 0 || !strings.HasPrefix(rep.Steps[len(rep.Steps)-1].Tool, "check:") {
		t.Errorf("question 应执行体检: %v", t7StepTools(rep))
	}
}

// ---------- 密钥模型白名单拒绝（请求树） ----------

func t7AddDenied(t *testing.T, f *t4Fix, rid, status, rejectReason, clientModel string, agoMin int) {
	t.Helper()
	routing := "{}"
	if rejectReason != "" || clientModel != "" {
		b, _ := json.Marshal(map[string]any{"reject_reason": rejectReason, "client_model": clientModel})
		routing = string(b)
	}
	t4Exec(t, context.Background(), f.conn, `
INSERT INTO request_logs (id, request_id, tenant_id, user_id, client_id, endpoint_type, request_status,
  upstream_status_code, latency_ms, created_at, routing_decision_json)
VALUES ($1,$2,$3,$4,$5,'chat',$6,403,5, now() - make_interval(mins => $7), $8::jsonb)`,
		"id_"+rid, rid, f.tenant, f.userA, f.keyA, status, agoMin, routing)
}

func TestT7RequestKeyAllowlistDenied(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()
	t4Exec(t, ctx, f.conn, `UPDATE internal_keys SET model_allowlist = ARRAY[$2]::text[] WHERE id = $1`, f.keyA, f.logY)

	// 1) 网关记录了 key_allowlist → 确定，点名密钥前缀与名称，不能是上游鉴权
	t7AddDenied(t, f, t7RID(f, 1), "key_model_not_allowed", "key_allowlist", f.logX, 3)
	rep := t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 1)})
	fd := t7Find1(rep, "key_model_allowlist")
	if fd == nil || fd.Level != LevelConfirmed {
		t.Fatalf("应有确定的密钥白名单结论:\n%s", t7Dump(rep))
	}
	for _, kw := range []string{"t4k" + f.sfx[:5], "我的密钥", f.logX, "白名单不含"} {
		if !strings.Contains(fd.Title, kw) {
			t.Errorf("标题缺少 %q: %s", kw, fd.Title)
		}
	}
	if !strings.Contains(fd.Impact, f.logY) {
		t.Errorf("影响里应列出密钥现有白名单: %s", fd.Impact)
	}
	if len(fd.Advice) == 0 || fd.Advice[0].Link != "/keys?key_id="+f.keyA {
		t.Errorf("建议应链到密钥管理页: %+v", fd.Advice)
	}
	if t7Find1(rep, "auth_failed") != nil {
		t.Errorf("不应误判成上游鉴权失败:\n%s", t7Dump(rep))
	}
	// 员工自查：不带后台链接
	rep = t7Tree(t, f, f.staff(f.userA), Input{Kind: "request", Ref: t7RID(f, 1)})
	if fd = t7Find1(rep, "key_model_allowlist"); fd == nil || fd.Advice[0].Link != "" {
		t.Fatalf("员工应得到结论但不带后台链接:\n%s", t7Dump(rep))
	}

	// 2) 旧版本没有拒绝原因、状态 forbidden_model，但密钥现在的白名单确实不含该模型 → 只能判疑似
	t7AddDenied(t, f, t7RID(f, 2), "forbidden_model", "", f.logX, 4)
	rep = t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 2)})
	if fd = t7Find1(rep, "key_model_allowlist"); fd == nil || fd.Level != LevelSuspected {
		t.Fatalf("旧记录应判疑似:\n%s", t7Dump(rep))
	}

	// 3) 拒绝原因是账号授权 → 走账号授权结论，不能算密钥白名单
	t7AddDenied(t, f, t7RID(f, 3), "forbidden_model", "user_grant", f.logY, 5)
	rep = t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 3)})
	if t7Find1(rep, "key_model_allowlist") != nil {
		t.Fatalf("user_grant 不应归到密钥白名单:\n%s", t7Dump(rep))
	}
	if fd = t7Find1(rep, "user_access"); fd == nil || fd.Level != LevelConfirmed || t7Find1(rep, "auth_failed") != nil {
		t.Fatalf("应有确定的账号授权结论:\n%s", t7Dump(rep))
	}

	// 4) 没有拒绝原因、密钥白名单为空 → 不能凭空归因给密钥，只给账号授权层面的疑似结论
	t4Exec(t, ctx, f.conn, `UPDATE internal_keys SET model_allowlist = '{}' WHERE id = $1`, f.keyA)
	rep = t7Tree(t, f, f.admin(), Input{Kind: "request", Ref: t7RID(f, 2)})
	if t7Find1(rep, "key_model_allowlist") != nil {
		t.Fatalf("白名单为空时不应归因到密钥:\n%s", t7Dump(rep))
	}
	if fd = t7Find1(rep, "user_access"); fd == nil || fd.Level == LevelConfirmed {
		t.Fatalf("证据不足应判疑似:\n%s", t7Dump(rep))
	}
}

func TestT7UserTreeKeyAllowlistStillExcludesOnlyUsableKeys(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()
	t4Exec(t, ctx, f.conn, `UPDATE internal_keys SET model_allowlist = ARRAY[$2]::text[] WHERE id = $1`, f.keyA, f.logY)
	rep := t7Tree(t, f, f.admin(), Input{Kind: "user", Ref: f.nameA, Text: "我想用 " + f.logX})
	if fd := t7Find1(rep, "user_key"); fd == nil || !strings.Contains(fd.Title, "白名单没有包含") {
		t.Fatalf("应提示该密钥白名单不含模型:\n%s", t7Dump(rep))
	}
	t4Exec(t, ctx, f.conn, `UPDATE internal_keys SET status = 'revoked' WHERE id = $1`, f.keyA)
	rep = t7Tree(t, f, f.admin(), Input{Kind: "user", Ref: f.nameA, Text: "我想用 " + f.logX})
	for _, x := range rep.Findings {
		if strings.Contains(x.Title, "白名单没有包含") {
			t.Errorf("已撤销的密钥不再生效，不应提示其白名单: %s", x.Title)
		}
	}
}
