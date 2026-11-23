package modelops

import (
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 合流（批次 3/4）：平台自建的请求日志（runtime_fault、platform_egress）不算业务请求，模型运营质量统计排除。
func TestModelOperationsQualityExcludesNonBusinessEndpoints(t *testing.T) {
	if !strings.Contains(modelOperationsQualitySQL, repository.ExcludeNonBusinessEndpointsSQL("r")) {
		t.Fatalf("quality SQL must exclude platform-generated request logs:\n%s", modelOperationsQualitySQL)
	}
}
