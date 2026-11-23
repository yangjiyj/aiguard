package repository

import (
	"strings"
	"testing"
)

func TestUpgradeVerificationEventsGoToEvalLane(t *testing.T) {
	rule := `WHEN project_id LIKE 'project\_upgrade\_verify\_%' THEN 'eval'`
	at := strings.Index(alertLaneMember, rule)
	if at < 0 {
		t.Fatalf("车道判定缺少升级自检规则：%s", alertLaneMember)
	}
	hardFloor := strings.Index(alertLaneMember, "'hard_floor'")
	secret := strings.Index(alertLaneMember, "LOWER(type)='secret'")
	if hardFloor < 0 || secret < 0 || !(hardFloor < at && at < secret) {
		t.Fatal("升级自检规则要排在硬底线之后、凭据类一律需行动之前")
	}
}
