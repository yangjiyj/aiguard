package handler

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

type staticProtectionStore struct {
	ProtectionSettingsStore
	settings protection.Settings
}

func (s staticProtectionStore) Settings(context.Context, string) (protection.Settings, error) {
	return s.settings, nil
}

// 批次 2B：旧 behavior_json 里配过的突发阈值兼容成 agent.burst=确认（2.9.21 的执行结果）；
// 已保存 agent.burst 时以保存的为准；只配序列规则窗口的不算。
func TestProtectionsForEffectivePolicyKeepsLegacyBurstThresholds(t *testing.T) {
	ctx := context.Background()
	deps := &Dependencies{}
	got, err := protectionsForEffectivePolicy(ctx, deps, "tenant-a", nil, map[string]any{"file_read_burst_10s": 20})
	if err != nil || got["agent.burst"].Action != protection.ActionConfirm {
		t.Fatalf("legacy burst thresholds keep confirming: %+v err=%v", got, err)
	}
	if got, _ := protectionsForEffectivePolicy(ctx, deps, "tenant-a", nil, map[string]any{"sensitive_read_egress_window_seconds": 60}); len(got) != 0 {
		t.Fatalf("a sequence window alone is not a burst configuration: %+v", got)
	}
	if got, _ := protectionsForEffectivePolicy(ctx, deps, "tenant-a", nil, nil); len(got) != 0 {
		t.Fatalf("no legacy configuration, no setting: %+v", got)
	}
	deps.ProtectionSettingsStore = staticProtectionStore{settings: protection.Settings{"agent.burst": {Action: protection.ActionAlertAllow}}}
	if got, _ := protectionsForEffectivePolicy(ctx, deps, "tenant-a", nil, map[string]any{"file_read_burst_10s": 20}); got["agent.burst"].Action != protection.ActionAlertAllow {
		t.Fatalf("a saved agent.burst wins over the legacy fallback: %+v", got)
	}
}
