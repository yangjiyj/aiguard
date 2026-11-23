package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// --- in-memory stub for NotifyChannelsRepository ---------------------------

// stubNotifyChannelsRepo is a minimal in-memory stub for Dispatcher tests.
type stubChannelRepo struct {
	channels []*repository.NotifyChannel
}

func (r *stubChannelRepo) ListEnabled(_ context.Context, tenantID string) ([]*repository.NotifyChannel, error) {
	var out []*repository.NotifyChannel
	for _, ch := range r.channels {
		if ch.TenantID == tenantID && ch.Enabled {
			out = append(out, ch)
		}
	}
	return out, nil
}

// Wrap stub in a real NotifyChannelsRepository shape via a thin adapter.
// Since Dispatcher takes *repository.NotifyChannelsRepository (concrete type),
// we use a real repo backed by the stub channels through a test-only approach:
// We embed the channels directly in an in-process mock by reusing the concrete
// type from the DB. For unit tests without DB, we test Dispatcher behaviour
// by wiring a real httptest.Server as the webhook target and using a real
// NotifyChannelsRepository backed by an in-memory pgxpool isn't feasible here.
//
// Instead, we test the dispatch logic by calling dispatchWithChannels directly.

// dispatchWithChannels is a testable variant that accepts channels inline.
func dispatchWithChannels(ctx context.Context, tenantID, severity, title string, body map[string]any, chs []*repository.NotifyChannel) error {
	var firstErr error
	for _, ch := range chs {
		if !ch.Enabled || ch.TenantID != tenantID {
			continue
		}
		// 走与生产相同的分发函数，避免测试副本与真实逻辑漂移。
		derr := dispatchChannel(ctx, ch, severity, title, body)
		if derr != nil && firstErr == nil {
			firstErr = derr
		}
	}
	return firstErr
}

// ---------------------------------------------------------------------------

func TestDispatcher_WebhookChannel(t *testing.T) {
	allowWebhookTestTarget(t)
	var hitCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	chs := []*repository.NotifyChannel{
		{
			ID:       "ch1",
			TenantID: "tenant-x",
			Type:     "webhook",
			Name:     "Test Webhook",
			ConfigJSON: map[string]any{
				"url":    srv.URL,
				"method": "POST",
			},
			Enabled: true,
		},
	}

	err := dispatchWithChannels(context.Background(), "tenant-x", "warning", "Budget Alert",
		map[string]any{"usage": 105.0}, chs)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if atomic.LoadInt32(&hitCount) != 1 {
		t.Errorf("expected 1 webhook hit, got %d", hitCount)
	}
}

func TestDispatcher_DisabledChannelSkipped(t *testing.T) {
	var hitCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	chs := []*repository.NotifyChannel{
		{
			ID:         "ch2",
			TenantID:   "tenant-y",
			Type:       "webhook",
			ConfigJSON: map[string]any{"url": srv.URL},
			Enabled:    false, // disabled
		},
	}

	err := dispatchWithChannels(context.Background(), "tenant-y", "info", "test", nil, chs)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if atomic.LoadInt32(&hitCount) != 0 {
		t.Errorf("expected 0 hits for disabled channel, got %d", hitCount)
	}
}

func TestDispatcher_EmailConfigInvalid_ContinuesOthers(t *testing.T) {
	allowWebhookTestTarget(t)
	var webhookHit int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&webhookHit, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	chs := []*repository.NotifyChannel{
		{
			ID:         "ch3",
			TenantID:   "tenant-z",
			Type:       "email",
			ConfigJSON: map[string]any{}, // invalid: no host/to
			Enabled:    true,
		},
		{
			ID:         "ch4",
			TenantID:   "tenant-z",
			Type:       "webhook",
			ConfigJSON: map[string]any{"url": srv.URL},
			Enabled:    true,
		},
	}

	// Email will error; webhook should still fire; dispatch returns first error (email)
	err := dispatchWithChannels(context.Background(), "tenant-z", "critical", "Test",
		map[string]any{}, chs)
	if err == nil {
		t.Error("expected error from email channel")
	}
	// Webhook should still have been called
	time.Sleep(10 * time.Millisecond)
	if atomic.LoadInt32(&webhookHit) != 1 {
		t.Errorf("expected webhook to be called despite email error, got %d hits", webhookHit)
	}
}

func TestDispatcher_DingtalkChannel(t *testing.T) {
	// 钉钉现在和其他渠道一样经过 SSRF 防护，测试服务器在回环地址上需要显式放行。
	allowWebhookTestTarget(t)
	var hitCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	chs := []*repository.NotifyChannel{
		{
			ID:       "ch5",
			TenantID: "tenant-d",
			Type:     "dingtalk",
			ConfigJSON: map[string]any{
				"access_token": "tok",
				"webhook":      srv.URL,
			},
			Enabled: true,
		},
	}

	err := dispatchWithChannels(context.Background(), "tenant-d", "high", "DingTalk Alert",
		map[string]any{"key": "value"}, chs)
	if err != nil {
		t.Fatalf("dispatch dingtalk: %v", err)
	}
	if atomic.LoadInt32(&hitCount) != 1 {
		t.Errorf("expected 1 dingtalk hit, got %d", hitCount)
	}
}
