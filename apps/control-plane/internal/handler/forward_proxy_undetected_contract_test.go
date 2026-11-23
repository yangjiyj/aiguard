package handler

import (
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestForwardProxyUndetectedMetricIsPresentInSummaryContract(t *testing.T) {
	for _, count := range []int{0, 3} {
		summary := repository.ForwardProxyAccessSummary{UndetectedCount: count}
		encoded, err := json.Marshal(mapForwardProxySummaryToInfo(summary))
		if err != nil {
			t.Fatal(err)
		}
		var values map[string]any
		if err := json.Unmarshal(encoded, &values); err != nil {
			t.Fatal(err)
		}
		if value, ok := values["undetected_count"]; !ok || value != float64(count) {
			t.Fatalf("summary must explicitly distinguish undetected coverage: %s", encoded)
		}
	}
}
