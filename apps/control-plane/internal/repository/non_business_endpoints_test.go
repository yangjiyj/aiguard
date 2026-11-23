package repository

// 2.9.22 复审补充第 2 项：平台自建的请求日志（运行故障告警等，endpoint_type=runtime_fault）
// 不算业务请求，请求日志列表、小时汇总、智能体统计都要排除；排除名单是一个共享常量。

import (
	"strings"
	"testing"
	"time"
)

// 合流（批次 3）：平台自身出站被拒的事件挂靠的请求日志 endpoint_type=platform_egress 也不算业务请求。
const runtimeFaultExclusion = "COALESCE(rl.endpoint_type, '') NOT IN ('runtime_fault', 'platform_egress')"

// 代码质量审查第三轮改动：名单改为不导出、经 NonBusinessEndpointTypes() 返回副本，
// 本用例随之改读函数、改写不导出变量，断言不变；另加“返回副本”一条。
func TestNonBusinessEndpointTypesSharedPredicate(t *testing.T) {
	for _, want := range []string{"runtime_fault", "platform_egress"} {
		found := false
		for _, endpoint := range NonBusinessEndpointTypes() {
			found = found || endpoint == want
		}
		if !found {
			t.Fatalf("排除名单缺 %s：%v", want, NonBusinessEndpointTypes())
		}
	}
	if got := ExcludeNonBusinessEndpointsSQL("rl"); got != runtimeFaultExclusion {
		t.Fatalf("排除条件=%s", got)
	}
	NonBusinessEndpointTypes()[0] = "tampered"
	if got := ExcludeNonBusinessEndpointsSQL("rl"); got != runtimeFaultExclusion {
		t.Fatalf("调用方改返回值不能改到共享名单：%s", got)
	}
	saved := nonBusinessEndpointTypes
	nonBusinessEndpointTypes = append(append([]string{}, saved...), "future_internal")
	defer func() { nonBusinessEndpointTypes = saved }()
	if got := ExcludeNonBusinessEndpointsSQL("x"); got != "COALESCE(x.endpoint_type, '') NOT IN ('runtime_fault', 'platform_egress', 'future_internal')" {
		t.Fatalf("排除条件应随共享名单变化：%s", got)
	}
}

func TestBusinessStatisticsExcludeNonBusinessEndpoints(t *testing.T) {
	query, _, countQuery, _ := buildRequestLogListQuery(RequestLogListFilter{
		TenantID: "tenant-1", StartTime: time.Now().Add(-time.Hour), EndTime: time.Now(), Limit: 10,
	})
	usageWhere, _ := usageScopeWhere(UsageScope{TenantID: "tenant-1", FullTenant: true}, time.Now().Add(-time.Hour), time.Now())
	for name, sql := range map[string]string{
		"请求日志列表": query,
		"请求日志计数": countQuery,
		"小时汇总":   usageHourlyRollupInsertSQL,
		"智能体统计":  inferredAgentRequestsCTE,
		// 代码质量审查第三轮：用量治理建议、用量明细、按范围的智能体统计共用 usageScopeWhere。
		"用量治理与用量明细": usageWhere,
	} {
		if !strings.Contains(sql, runtimeFaultExclusion) {
			t.Errorf("%s 没有排除平台自建的请求日志：%s", name, sql)
		}
	}
	// 服务健康的审计管线统计按表名引用（无别名），主查询和子查询都要排除。
	healthExclusion := ExcludeNonBusinessEndpointsSQL("request_logs")
	if got, want := strings.Count(auditPipelineStatsSQL, healthExclusion), strings.Count(auditPipelineStatsSQL, "FROM request_logs"); got != want || want == 0 {
		t.Errorf("服务健康审计管线统计没有全部排除平台自建的请求日志（%d/%d）：%s", got, want, auditPipelineStatsSQL)
	}
}
