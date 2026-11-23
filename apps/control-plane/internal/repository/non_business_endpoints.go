package repository

import "strings"

// nonBusinessEndpointTypes 是不算业务请求的 endpoint_type：平台自建的请求日志（网关在日志留存
// 不可用时记运行告警挂靠的 runtime_fault，平台自身出站被拒记事件挂靠的 platform_egress，2.9.22）。
// 请求日志列表与计数、小时汇总、智能体统计、用量治理与用量明细、服务健康、异常扫描、诊断的请求统计、
// 模型运营质量统计和预测回放都按这一份名单排除（经 ExcludeNonBusinessEndpointsSQL）；新增此类日志时往这里加。
var nonBusinessEndpointTypes = []string{"runtime_fault", "platform_egress"}

// NonBusinessEndpointTypes 返回名单的副本。
func NonBusinessEndpointTypes() []string {
	return append([]string(nil), nonBusinessEndpointTypes...)
}

// ExcludeNonBusinessEndpointsSQL 返回排除这些请求日志的 SQL 条件，alias 是 request_logs 的别名
// （没有别名时传表名 request_logs）。名单里只有代码写死的标识符，直接拼成字面量。
func ExcludeNonBusinessEndpointsSQL(alias string) string {
	quoted := make([]string, 0, len(nonBusinessEndpointTypes))
	for _, endpoint := range nonBusinessEndpointTypes {
		quoted = append(quoted, "'"+strings.ReplaceAll(endpoint, "'", "''")+"'")
	}
	return "COALESCE(" + alias + ".endpoint_type, '') NOT IN (" + strings.Join(quoted, ", ") + ")"
}
