package main

import (
	"os"
	"strings"
	"testing"
)

// TTL 开关改为每次 tick 读系统设置：启动时不得再按 env 决定是否起 goroutine。
func TestAlertTTLCronReadsSettingsEveryTick(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(source)
	if strings.Contains(s, `if strings.EqualFold(os.Getenv("ALERT_TTL_ENABLED"), "true")`) {
		t.Fatal("main.go still gates the TTL goroutine on env at startup")
	}
	if !strings.Contains(s, "alert.RunAlertTTLTick(ctx, alertTTLSettings, secEventAlertGroupRepo, os.Getenv,") {
		t.Fatal("main.go must run alert.RunAlertTTLTick on each tick")
	}
}
