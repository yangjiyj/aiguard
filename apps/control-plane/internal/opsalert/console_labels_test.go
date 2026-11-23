package opsalert

import (
	"os"
	"strings"
	"testing"
)

// 消息中心按类型显示中文名：每种运维告警都必须在控制台 alertInboxDisplay.ts 里有同名中文标签，
// 否则客户会看到英文类型 id。
func TestEveryOpsAlertTypeIsLabelledInConsole(t *testing.T) {
	raw, err := os.ReadFile("../../../web-console/src/utils/alertInboxDisplay.ts")
	if err != nil {
		t.Fatalf("read alertInboxDisplay.ts: %v", err)
	}
	src := string(raw)
	for _, typ := range Types() {
		kind, _ := KindOf(typ)
		if !strings.Contains(src, typ+": '"+kind.Label+"'") {
			t.Errorf("控制台缺少 %s 的中文标签 %q", typ, kind.Label)
		}
	}
}
