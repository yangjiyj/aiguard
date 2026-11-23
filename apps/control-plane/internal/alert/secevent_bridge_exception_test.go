package alert

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// findingException 构造一条 custom 规则命中 finding;exceptionID 非空表示数据面
// 已按运营配置的例外(exception)放行,finding 携带 exception_id 透传到 matched_summary。
func findingException(confidence float64, exceptionID string) map[string]any {
	fm := map[string]any{
		"confidence": confidence,
		"category": "custom_rule_hit", "type": "custom",
	}
	if exceptionID != "" {
		fm["exception_id"] = exceptionID
	}
	return fm
}

func TestShouldSurface_AllExceptionSuppressed(t *testing.T) {
	// (security_events 照常留证)。
	b := gateBridge(&fakeSecEventSource{}, &fakePusher{}, nil, 0.5)
	ev := secEventWithFindings("exc1", "audit",
		findingException(0.90, "exc_a"),
		findingException(0.95, "exc_b"),
	)
	ok, reason := b.shouldSurface(ev)
	if ok {
		t.Fatalf("fully exempted event must be suppressed, got surface=true")
	}
	if !strings.Contains(reason, "exception") {
		t.Fatalf("suppression reason should mention exception, got %q", reason)
	}
}

func TestRunOnce_ExceptionSuppressedStillMarkedAlerted(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("exc2", "audit", findingException(0.90, "exc_a")),
	}}
	pusher := &fakePusher{}
	notifier := &fakeNotifier{}

	n, err := gateBridge(src, pusher, notifier, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || len(pusher.pushedTypes) != 0 || notifier.calls != 0 {
		t.Fatalf("exception-suppressed event must not reach inbox/notify, got n=%d pushed=%v notify=%d", n, pusher.pushedTypes, notifier.calls)
	}
	if len(src.markedIDs) != 1 || src.markedIDs[0][0] != "exc2" {
		t.Fatalf("expected exc2 marked alerted (so it is not re-scanned), got %v", src.markedIDs)
	}
}

func TestShouldSurface_PartialExceptionSurfaces(t *testing.T) {
	// 只要有一条 finding 未被豁免,整事件照常提升(不能拿个别豁免藏掉真信号)。
	b := gateBridge(&fakeSecEventSource{}, &fakePusher{}, nil, 0.5)
	ev := secEventWithFindings("exc3", "audit",
		findingException(0.90, "exc_a"),
		findingException(0.90, ""),
	)
	if ok, _ := b.shouldSurface(ev); !ok {
		t.Fatalf("event with a non-exempted finding must surface")
	}
}
