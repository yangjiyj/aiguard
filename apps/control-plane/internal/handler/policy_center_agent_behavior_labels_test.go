package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 阻断记录按托管规则 ID 显示策略页中文名，两处定义必须一致。
func TestBlockRecordBehaviorLabelsMatchThePolicyPage(t *testing.T) {
	if len(repository.PolicyCenterAgentBehaviorLabels) != len(policyCenterAgentBehaviorDefinitions) {
		t.Fatalf("label count %d != definitions %d", len(repository.PolicyCenterAgentBehaviorLabels), len(policyCenterAgentBehaviorDefinitions))
	}
	for _, definition := range policyCenterAgentBehaviorDefinitions {
		if got := repository.PolicyCenterAgentBehaviorLabels[definition.Key]; got != definition.Label {
			t.Fatalf("%s: block records label %q, policy page label %q", definition.Key, got, definition.Label)
		}
	}
}
