package executionmode

import "testing"

// 优先级：显式模式 > 部署变量初值 > 旧键 > 安全默认（记录）。
func TestFromValuesPrecedence(t *testing.T) {
	cases := []struct {
		name       string
		values     map[string]string
		deployment bool
		wantAudit  bool
		wantSource string
	}{
		{"显式防护压过部署初值和旧键", map[string]string{SettingKey: Protect, LegacySettingKey: "true"}, true, false, SourceAdminSettings},
		{"显式记录", map[string]string{SettingKey: Record, LegacySettingKey: "false"}, false, true, SourceAdminSettings},
		{"部署初值", map[string]string{LegacySettingKey: "false"}, true, true, SourceDeployment},
		{"非法显式值不算显式", map[string]string{SettingKey: "block", LegacySettingKey: "false"}, false, false, SourceLegacy},
		{"旧键大写带空白", map[string]string{LegacySettingKey: " TRUE "}, false, true, SourceLegacy},
		{"旧键非法", map[string]string{LegacySettingKey: "0"}, false, true, SourceSafeDefault},
		{"旧键空值", map[string]string{LegacySettingKey: ""}, false, true, SourceSafeDefault},
		{"都没有", map[string]string{}, false, true, SourceSafeDefault},
		{"nil", nil, false, true, SourceSafeDefault},
	}
	for _, tc := range cases {
		audit, source := FromValues(tc.values, tc.deployment)
		if audit != tc.wantAudit || source != tc.wantSource {
			t.Errorf("%s：(%v,%q) want (%v,%q)", tc.name, audit, source, tc.wantAudit, tc.wantSource)
		}
	}
}

func TestKeysListsBothSettingKeys(t *testing.T) {
	keys := Keys()
	if len(keys) != 2 || keys[0] != "security_execution_mode" || keys[1] != "security_audit_only" {
		t.Fatalf("keys=%v", keys)
	}
	keys[0] = "tampered"
	if Keys()[0] != SettingKey {
		t.Fatal("Keys 必须返回副本")
	}
}

func TestDeploymentRecordInitialValue(t *testing.T) {
	for raw, want := range map[string]bool{"true": true, " YES ": true, "1": true, "on": true, "false": false, "": false, "maybe": false} {
		t.Setenv("SECURITY_AUDIT_ONLY", raw)
		if got := DeploymentRecordInitialValue(); got != want {
			t.Errorf("SECURITY_AUDIT_ONLY=%q got %v want %v", raw, got, want)
		}
	}
}

func TestModeName(t *testing.T) {
	if ModeName(true) != Record || ModeName(false) != Protect {
		t.Fatal("mode name")
	}
}
