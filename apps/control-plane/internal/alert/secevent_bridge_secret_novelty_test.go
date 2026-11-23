package alert

import (
	"context"
	"errors"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// fakeSecretSink 模拟 secret_flow_first_seen 表的幂等登记:
// (租户,指纹,目的地) 首次出现计为新对,重复出现返回 0。
type fakeSecretSink struct {
	seen  map[string]bool
	calls int
	err   error
}

func (f *fakeSecretSink) MarkSeen(ctx context.Context, tenantID string, pairs []repository.SecretFlowPair) (int, error) {
	f.calls++
	if f.err != nil {
		return 0, f.err
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	n := 0
	for _, p := range pairs {
		k := tenantID + "|" + p.SecretFP + "|" + p.TargetHost
		if !f.seen[k] {
			f.seen[k] = true
			n++
		}
	}
	return n, nil
}

// noveltyBridge 构造一个显式开启 secret 首见告警的桥,不依赖环境变量。
func noveltyBridge(src secEventSource, inbox secInboxPusher, notifier secNotifier, sink *fakeSecretSink) *SecEventBridge {
	b := gateBridge(src, inbox, notifier, 0.5)
	b.secretNovelty = true
	return b.WithSecretNovelty(sink)
}

// secretFlowEvent 构造一条正向代理路径的 secret 泄漏事件:
// 全部 finding type=secret 且带内容指纹,事件顶层带 target_host。
func secretFlowEvent(id, sha, host string) *repository.SecurityEvent {
	ev := secEventWithFindings(id, "audit", map[string]any{
		"confidence": 0.9, "type": "secret",
		"matched_text_preview_sha256": sha, "category": "generic_api_key",
	})
	ev.MatchedSummary["target_host"] = host
	return ev
}

func TestSecEventBridge_SecretFirstSeenSurfaces(t *testing.T) {
	sink := &fakeSecretSink{}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secretFlowEvent("sn1", "sha_key_a", "api.example.com"),
	}}
	pusher := &fakeDedupPusher{}
	notifier := &fakeNotifier{}

	n, err := noveltyBridge(src, pusher, notifier, sink).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || pusher.upserts != 1 || notifier.calls != 1 {
		t.Fatalf("first-seen secret flow must surface, got n=%d upserts=%d notify=%d", n, pusher.upserts, notifier.calls)
	}
	if sink.calls != 1 {
		t.Fatalf("expected one MarkSeen call, got %d", sink.calls)
	}
}

func TestSecEventBridge_SecretRepeatRemainsVisibleAndGroupFolds(t *testing.T) {
	// 凭据泄露属于红线：同 (指纹,目的地) 重复出现仍进入收件箱折叠，绝不静默。
	sink := &fakeSecretSink{}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secretFlowEvent("sn_a", "sha_key_a", "api.example.com"),
		secretFlowEvent("sn_b", "sha_key_a", "api.example.com"),
	}}
	pusher := &fakeDedupPusher{}
	notifier := &fakeNotifier{}
	groups := &fakeAlertGrouper{}

	n, err := noveltyBridge(src, pusher, notifier, sink).WithAlertGroups(groups).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected only the first-seen event to alert, got %d", n)
	}
	if pusher.upserts != 2 {
		t.Fatalf("repeat credential leak must reach inbox dedup, got %d upserts", pusher.upserts)
	}
	if notifier.calls != 1 {
		t.Fatalf("repeat flow must not notify, got %d", notifier.calls)
	}
	if len(groups.inputs) != 2 {
		t.Fatalf("repeat flow must still fold into the alert group (evidence intact), got %d group upserts", len(groups.inputs))
	}
	if len(src.markedIDs) != 1 || len(src.markedIDs[0]) != 2 {
		t.Fatalf("both events must be marked alerted, got %v", src.markedIDs)
	}
}

func TestSecEventBridge_SecretNewDestinationSurfacesAgain(t *testing.T) {
	// 旧密钥流向新目的地 = 新 (指纹,目的地) 对 → 照常提升。
	sink := &fakeSecretSink{}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secretFlowEvent("sn_h1", "sha_key_a", "api.example.com"),
		secretFlowEvent("sn_h2", "sha_key_a", "evil.example.org"),
	}}
	pusher := &fakeDedupPusher{}

	if _, err := noveltyBridge(src, pusher, &fakeNotifier{}, sink).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if pusher.upserts != 2 {
		t.Fatalf("new destination must reach inbox layer again, got %d upserts", pusher.upserts)
	}
}
func TestSecEventBridge_SecretNoveltyDisabledNoChange(t *testing.T) {
	// SECEVENT_SECRET_NOVELTY_ENABLED=false(默认)→ 完全不碰 sink,行为与现状一致。
	sink := &fakeSecretSink{seen: map[string]bool{"tenant_x|sha_key_a|api.example.com": true}}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secretFlowEvent("sn_off", "sha_key_a", "api.example.com"),
	}}
	pusher := &fakeDedupPusher{}

	b := gateBridge(src, pusher, &fakeNotifier{}, 0.5).WithSecretNovelty(sink)
	b.secretNovelty = false
	n, err := b.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if sink.calls != 0 {
		t.Fatalf("disabled gate must not consult sink, got %d calls", sink.calls)
	}
	if n != 1 || pusher.upserts != 1 {
		t.Fatalf("disabled gate must keep legacy behaviour, got n=%d upserts=%d", n, pusher.upserts)
	}
}

func TestSecEventBridge_SecretSinkErrorFailsOpen(t *testing.T) {
	// 登记失败 → fail open(按首见提升),绝不因存储故障静默密钥泄漏。
	sink := &fakeSecretSink{err: errors.New("db down")}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secretFlowEvent("sn_err", "sha_key_a", "api.example.com"),
	}}
	pusher := &fakeDedupPusher{}

	n, err := noveltyBridge(src, pusher, &fakeNotifier{}, sink).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || pusher.upserts != 1 {
		t.Fatalf("sink error must fail open to surfacing, got n=%d upserts=%d", n, pusher.upserts)
	}
}

func TestSecEventBridge_SecretWithoutTargetHostNotEligible(t *testing.T) {
	// gateway/反代 finding 无 target_host(或无 sha256)→ 自然不参与首见路径。
	sink := &fakeSecretSink{}
	ev := secEventWithFindings("sn_nh", "audit", map[string]any{
		"confidence": 0.9, "": false, "type": "secret",
		"matched_text_preview_sha256": "sha_key_a",
	})
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakeDedupPusher{}

	n, err := noveltyBridge(src, pusher, &fakeNotifier{}, sink).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if sink.calls != 0 {
		t.Fatalf("event without target_host must not consult sink, got %d calls", sink.calls)
	}
	if n != 1 || pusher.upserts != 1 {
		t.Fatalf("event without target_host must surface normally, got n=%d upserts=%d", n, pusher.upserts)
	}
}
