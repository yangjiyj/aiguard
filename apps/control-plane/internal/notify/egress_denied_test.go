package notify

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 平台自身出站（通知渠道）被防跳板拒绝时记安全事件（设计 5.2）。
func TestDispatchRecordsEgressDenial(t *testing.T) {
	var got []string
	original := EgressDeniedRecorder
	EgressDeniedRecorder = func(_ context.Context, tenantID, kind, target string) {
		got = append(got, tenantID+"|"+kind+"|"+target)
	}
	t.Cleanup(func() { EgressDeniedRecorder = original })
	for _, ch := range []*repository.NotifyChannel{
		{TenantID: "t1", Type: "webhook", ConfigJSON: map[string]any{"url": "http://127.0.0.1:9/hook"}},
		{TenantID: "t1", Type: "wecom", ConfigJSON: map[string]any{"webhook_url": "http://169.254.169.254/x"}},
	} {
		if err := dispatchChannel(context.Background(), ch, "high", "t", nil); err == nil {
			t.Fatalf("%s: internal target must be denied", ch.Type)
		}
	}
	if len(got) != 2 || got[0] != "t1|notify_channel:webhook|127.0.0.1" || got[1] != "t1|notify_channel:wecom|169.254.169.254" {
		t.Fatalf("recorded = %v", got)
	}
}
