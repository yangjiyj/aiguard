package forecast

import (
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 合流（批次 3/4）：预测回放只取业务请求，排除平台自建的请求日志（runtime_fault、platform_egress）。
func TestForecastReplayRowsExcludeNonBusinessEndpoints(t *testing.T) {
	if !strings.Contains(forecastReplayRowsSQL, repository.ExcludeNonBusinessEndpointsSQL("request_logs")) {
		t.Fatalf("forecast replay SQL must exclude platform-generated request logs:\n%s", forecastReplayRowsSQL)
	}
}
