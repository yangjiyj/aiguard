package agentguard

import (
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 审查 6：网关在 tools/list、红线处找例外用 MatchingMCPException，与调用路径（resolveProtectionHits）
// 同一口径：rule_id 点名项键、原因码或旧原因码别名；目标为空、mcp:<服务>[/<工具>] 按段匹配，其余按子串。
func TestMatchingMCPExceptionAgreesWithCallPath(t *testing.T) {
	now := time.Now()
	item, _ := protection.ItemForReason("description_poison")
	target := "mcp:Files/read"
	for _, tc := range []struct {
		exception PolicyException
		want      bool
	}{
		{PolicyException{RuleID: item.Key}, true},
		{PolicyException{RuleID: "description_poison", TargetPattern: "mcp:files"}, true},
		{PolicyException{RuleID: item.Key, TargetPattern: "mcp:files/read"}, true},
		{PolicyException{RuleID: item.Key, TargetPattern: "files/re"}, true},
		{PolicyException{RuleID: item.Key, TargetPattern: "mcp:files/readall"}, false},
		{PolicyException{RuleID: item.Key, TargetPattern: "mcp:other"}, false},
		{PolicyException{RuleID: "mcp.drift"}, false},
		{PolicyException{RuleID: item.Key, ExpiresAt: now.Add(-time.Hour)}, false},
	} {
		exception := tc.exception
		if exception.ExpiresAt.IsZero() {
			exception.ExpiresAt = now.Add(time.Hour)
		}
		list := []PolicyException{exception}
		callPath := matchingHitExceptionIn(list, item, ProtectionHit{Reason: "description_poison", Target: target}, now, target) != nil
		got := MatchingMCPException(list, []string{item.Key, "description_poison"}, target, now) != nil
		if got != tc.want || callPath != tc.want {
			t.Errorf("%s/%q: shared=%v callPath=%v want %v", exception.RuleID, exception.TargetPattern, got, callPath, tc.want)
		}
	}
	alias := []PolicyException{{RuleID: "blocked_sensitive_local_file_path", ExpiresAt: now.Add(time.Hour)}}
	if MatchingMCPException(alias, []string{"sensitive_name_hint"}, target, now) == nil {
		t.Fatal("legacy reason aliases must be honored")
	}
}
