package rules

import (
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"testing"
)

func TestAgentShieldSourceIsRuntimeVersioned(t *testing.T) {
	rule := subjectPolicyRule(`{"scene":"data_leak","_authoring":{"source":"agentshield"},"subject_binding":{"key_ids":["key1"]}}`)
	with := Compile("tenant-a", []*repository.Rule{rule}, nil)
	b, _ := json.Marshal(with.Policies)
	var items []map[string]any
	json.Unmarshal(b, &items)
	if len(items) != 1 || items[0]["authoring_source"] != "agentshield" {
		t.Fatalf("运行策略未携带来源：%s", b)
	}
	rule.ScopeJSON = []byte(`{"scene":"data_leak","subject_binding":{"key_ids":["key1"]}}`)
	without := Compile("tenant-a", []*repository.Rule{rule}, nil)
	if with.Version == without.Version {
		t.Fatal("来源变化未改变运行版本")
	}
}
