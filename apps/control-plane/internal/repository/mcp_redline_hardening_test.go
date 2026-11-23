package repository

import "testing"

func TestMCPRedlineHardeningDestructiveCommandIsConfigurable(t *testing.T) {
	if !IsMCPConfigurableRedline("destructive_command") {
		t.Fatal("restored destructive command redline must be configurable")
	}
	got, err := NormalizeMCPRedlineUpdates(map[string]string{"destructive_command": "block"})
	if err != nil || got["destructive_command"] != "block" {
		t.Fatalf("destructive redline configuration rejected: %v %v", got, err)
	}
}

// 2.9.22：红线动作四档 off/record/alert/block（迁移 999 已放宽 CHECK），默认仍是 alert。
func TestMCPRedlineActionsAcceptFourLevels(t *testing.T) {
	got, err := NormalizeMCPRedlineUpdates(map[string]string{"cloud_metadata": "OFF", "reverse_shell": "record", "destructive_command": "alert", "private_key_egress": "block"})
	if err != nil || got["cloud_metadata"] != "off" || got["reverse_shell"] != "record" || got["destructive_command"] != "alert" || got["private_key_egress"] != "block" {
		t.Fatalf("four levels rejected: %v %v", got, err)
	}
	if _, err := NormalizeMCPRedlineUpdates(map[string]string{"cloud_metadata": "drop"}); err == nil {
		t.Fatal("unknown action accepted")
	}
}
