package anomaly

// 代码质量审查第三轮：异常扫描（日成本、活跃租户、密钥突增、新模型）只看业务请求，
// 排除平台自建的请求日志（endpoint_type=runtime_fault 等，名单见 repository）。

import (
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestAnomalyScanQueriesExcludeNonBusinessEndpoints(t *testing.T) {
	want := repository.ExcludeNonBusinessEndpointsSQL("request_logs")
	for name, sql := range map[string]string{
		"活跃租户": activeTenantsSQL,
		"日成本":  dailyCostsSQL,
		"密钥突增": keySurgeSQL,
		"新模型":  newModelSQL,
	} {
		froms := strings.Count(sql, "FROM request_logs")
		if froms == 0 || strings.Count(sql, want) != froms {
			t.Errorf("%s 的 %d 处请求日志读取没有全部排除平台自建日志：%s", name, froms, sql)
		}
	}
}
