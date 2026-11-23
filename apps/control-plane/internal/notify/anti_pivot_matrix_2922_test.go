package notify

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

type staticNotifyResolver map[string]string

func (r staticNotifyResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if ip, ok := r[host]; ok {
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	}
	return nil, errors.New("no such host")
}

// 行为矩阵 8.2（防跳板出站，不在防护项注册表里）：平台自身出站之通知渠道。默认拒绝内网、回环、
// 链路本地、元数据；渠道的“允许内网地址”只放开内网（私网段、内部主机名）；全局观察留痕不影响（设计 D5、D6）。
func TestAntiPivotNotifyChannelEgressMatrix(t *testing.T) {
	resolver := staticNotifyResolver{"hook.corp.internal": "10.0.0.7"}
	originalPrivate, originalDefault := notifyTargetResolver, webhookTargetResolver
	notifyTargetResolver = resolver
	webhookTargetResolver = func(ctx context.Context, rawURL string) (safetarget.Target, error) {
		return safetarget.Resolve(ctx, rawURL, false, resolver)
	}
	t.Cleanup(func() { notifyTargetResolver, webhookTargetResolver = originalPrivate, originalDefault })
	denied := func(err error) bool {
		return errors.Is(err, safetarget.ErrForbiddenAddress) || errors.Is(err, safetarget.ErrPrivateAddress)
	}
	for _, tc := range []struct {
		class, url  string
		switchOpens bool // 打开“允许内网地址”后放行
	}{
		{"private", "http://10.0.0.7:9/hook", true},
		{"internal hostname", "http://hook.corp.internal:9/hook", true},
		{"loopback", "http://127.0.0.1:9/hook", false},
		{"link local", "http://169.254.20.1:9/hook", false},
		{"metadata", "http://169.254.169.254/hook", false},
	} {
		t.Run(tc.class, func(t *testing.T) {
			if _, err := resolveNotifyTarget(context.Background(), tc.url, false); !denied(err) {
				t.Fatalf("default must deny by the egress policy: %v", err)
			}
			if _, err := resolveNotifyTarget(context.Background(), tc.url, true); (err == nil) != tc.switchOpens || (err != nil && !denied(err)) {
				t.Fatalf("allow_private_target opens=%v want %v (err=%v)", err == nil, tc.switchOpens, err)
			}
			t.Setenv("SECURITY_AUDIT_ONLY", "true")
			var denied []string
			recorder := EgressDeniedRecorder
			EgressDeniedRecorder = func(_ context.Context, _, kind, target string) { denied = append(denied, kind+"|"+target) }
			t.Cleanup(func() { EgressDeniedRecorder = recorder })
			ch := &repository.NotifyChannel{TenantID: "t1", Type: "webhook", ConfigJSON: map[string]any{"url": tc.url}}
			if err := dispatchChannel(context.Background(), ch, "high", "t", nil); err == nil || len(denied) != 1 {
				t.Fatalf("global record mode must still deny and record: err=%v denied=%v", err, denied)
			}
		})
	}
}
