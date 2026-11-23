package diagnostics

// 2.9.22 复审补充第 2 项：诊断的请求失败统计排除平台自建的请求日志（endpoint_type=runtime_fault）。

import (
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestDiagnosticsRequestQueriesExcludeNonBusinessEndpoints(t *testing.T) {
	want := repository.ExcludeNonBusinessEndpointsSQL("rl")
	sql, _ := t6AggSQL(Scope{TenantID: "t", IsAdmin: true}, 1)
	if !strings.Contains(sql, want) {
		t.Errorf("t6 聚合没有排除平台自建的请求日志：%s", sql)
	}
	a := &t3Args{}
	where := t3Base(a, Scope{TenantID: "t", IsAdmin: true}, t3Filter{}, nil, nil, "$9", "$10")
	if !strings.Contains(where, want) {
		t.Errorf("t3 请求查询没有排除平台自建的请求日志：%s", where)
	}
}
