package handler

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/executionmode"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type agentRiskModeSettingReader struct {
	values map[string]string
	err    error
	keys   []string
}

func (r *agentRiskModeSettingReader) GetByKeys(_ context.Context, keys []string) ([]*repository.SystemSetting, error) {
	r.keys = append([]string(nil), keys...)
	if r.err != nil {
		return nil, r.err
	}
	var out []*repository.SystemSetting
	for _, key := range keys {
		if value, ok := r.values[key]; ok {
			out = append(out, &repository.SystemSetting{Key: key, Value: value})
		}
	}
	return out, nil
}

// “配置意图”与其他地方同口径（executionmode.FromValues）：控制台显式模式优先；没有显式模式时部署变量
// SECURITY_AUDIT_ONLY=true 作初值；其次旧键；都没有按观察留痕。来源标明是哪一种；读不到配置时为 unknown。
func TestAgentRiskModeSeparatesConfiguredIntentFromUnverifiedRuntime(t *testing.T) {
	mode := func(v string) map[string]string { return map[string]string{executionmode.SettingKey: v} }
	tests := []struct {
		name        string
		env         string
		reader      *agentRiskModeSettingReader
		wantMode    string
		wantCeiling *bool
		wantSource  string
	}{
		{name: "explicit record", reader: &agentRiskModeSettingReader{values: mode("record")}, wantMode: "audit_only", wantCeiling: boolPointer(true), wantSource: "system_settings.security_execution_mode"},
		{name: "explicit protect wins over legacy", reader: &agentRiskModeSettingReader{values: map[string]string{executionmode.SettingKey: "protect", executionmode.LegacySettingKey: "true"}}, wantMode: "per_policy", wantCeiling: boolPointer(false), wantSource: "system_settings.security_execution_mode"},
		{name: "explicit protect wins over deployment", env: "true", reader: &agentRiskModeSettingReader{values: mode("protect")}, wantMode: "per_policy", wantCeiling: boolPointer(false), wantSource: "system_settings.security_execution_mode"},
		{name: "deployment initial value", env: "true", reader: &agentRiskModeSettingReader{values: map[string]string{executionmode.LegacySettingKey: "false"}}, wantMode: "audit_only", wantCeiling: boolPointer(true), wantSource: "deployment"},
		{name: "legacy false", reader: &agentRiskModeSettingReader{values: map[string]string{executionmode.LegacySettingKey: "false"}}, wantMode: "per_policy", wantCeiling: boolPointer(false), wantSource: "system_settings.security_audit_only"},
		{name: "legacy true", reader: &agentRiskModeSettingReader{values: map[string]string{executionmode.LegacySettingKey: "true"}}, wantMode: "audit_only", wantCeiling: boolPointer(true), wantSource: "system_settings.security_audit_only"},
		{name: "nothing configured", reader: &agentRiskModeSettingReader{}, wantMode: "audit_only", wantCeiling: boolPointer(true), wantSource: "safe_default"},
		{name: "read error", reader: &agentRiskModeSettingReader{err: errors.New("database unavailable")}, wantMode: "unknown", wantSource: "settings_unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", tt.env)
			overview := &repository.AgentRiskOverview{}
			applyAgentRiskModeMetadata(context.Background(), overview, tt.reader)
			if overview.ConfiguredModeSource != tt.wantSource || overview.ConfiguredMode != tt.wantMode {
				t.Fatalf("configured mode=%q source=%q want %q/%q", overview.ConfiguredMode, overview.ConfiguredModeSource, tt.wantMode, tt.wantSource)
			}
			if tt.wantCeiling == nil {
				if overview.ConfiguredAuditCeiling != nil {
					t.Fatalf("configured ceiling=%v want nil", *overview.ConfiguredAuditCeiling)
				}
			} else if overview.ConfiguredAuditCeiling == nil || *overview.ConfiguredAuditCeiling != *tt.wantCeiling {
				t.Fatalf("configured ceiling=%v want=%v", overview.ConfiguredAuditCeiling, *tt.wantCeiling)
			}
			if overview.EffectiveMode != "unknown" || overview.AuditCeiling != nil ||
				overview.EffectiveModeSource != "runtime_status_unavailable" || overview.RuntimeModeVerified {
				t.Fatalf("unverified runtime metadata=%#v", overview)
			}
			if !reflect.DeepEqual(tt.reader.keys, executionmode.Keys()) {
				t.Fatalf("both execution-mode keys must be read in one query: %v", tt.reader.keys)
			}
		})
	}
	nilOverview := &repository.AgentRiskOverview{}
	applyAgentRiskModeMetadata(context.Background(), nilOverview, nil)
	if nilOverview.ConfiguredMode != "unknown" || nilOverview.ConfiguredModeSource != "settings_unavailable" {
		t.Fatalf("no reader: %#v", nilOverview)
	}
}

func boolPointer(value bool) *bool {
	return &value
}
