package handler

import (
	"fmt"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestMCPContractRedlineHardeningUsesSupportedRuntimeRules(t *testing.T) {
	contracts := buildMCPToolContracts("tenant", "server", "demo", []*repository.MCPTool{{ToolName: "run"}}, nil, false)
	if len(contracts) != 1 || fmt.Sprint(contracts[0]["redline_triggers"]) != fmt.Sprint(repository.MCPConfigurableRedlines) {
		t.Fatalf("contract claims unsupported runtime redlines: %v", contracts)
	}
}
