package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

func allowWebhookTestTarget(t *testing.T) {
	t.Helper()
	original := webhookTargetResolver
	webhookTargetResolver = func(_ context.Context, rawURL string) (safetarget.Target, error) {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return safetarget.Target{}, err
		}
		ip, err := netip.ParseAddr(parsed.Hostname())
		if err != nil {
			return safetarget.Target{}, err
		}
		port := parsed.Port()
		return safetarget.Target{
			URL: parsed, Hostname: parsed.Hostname(), Port: port, IP: ip,
			DialAddress: net.JoinHostPort(ip.String(), port),
		}, nil
	}
	t.Cleanup(func() {
		webhookTargetResolver = original
	})
}

func TestSendWebhook_MissingURL(t *testing.T) {
	err := SendWebhook(WebhookConfig{}, "warning", "Test", nil)
	if err == nil {
		t.Error("expected error for missing URL")
	}
}

func TestSendWebhook_MockServer(t *testing.T) {
	allowWebhookTestTarget(t)
	var received map[string]any
	var receivedMethod string
	var receivedHeaders http.Header

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedHeaders = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := WebhookConfig{
		URL:    srv.URL,
		Method: "POST",
		Headers: map[string]string{
			"X-Custom-Header": "test-value",
		},
	}
	err := SendWebhook(cfg, "critical", "Alert Title", map[string]any{"cost": 99.9})
	if err != nil {
		t.Fatalf("SendWebhook: %v", err)
	}

	if receivedMethod != "POST" {
		t.Errorf("method: %s", receivedMethod)
	}
	if receivedHeaders.Get("X-Custom-Header") != "test-value" {
		t.Errorf("custom header not set: %v", receivedHeaders.Get("X-Custom-Header"))
	}
	if received["severity"] != "critical" {
		t.Errorf("severity: %v", received["severity"])
	}
	if received["title"] != "Alert Title" {
		t.Errorf("title: %v", received["title"])
	}
	if received["ts"] == nil {
		t.Errorf("ts should be present")
	}
}

func TestSendWebhook_Status400(t *testing.T) {
	allowWebhookTestTarget(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	err := SendWebhook(WebhookConfig{URL: srv.URL}, "info", "title", nil)
	if err == nil {
		t.Error("expected error for 400 status")
	}
}

func TestSendWebhook_DefaultMethodPOST(t *testing.T) {
	allowWebhookTestTarget(t)
	var receivedMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Method empty → should default to POST
	err := SendWebhook(WebhookConfig{URL: srv.URL}, "info", "t", nil)
	if err != nil {
		t.Fatalf("SendWebhook: %v", err)
	}
	if receivedMethod != "POST" {
		t.Errorf("expected POST, got %s", receivedMethod)
	}
}
func TestSendWebhookRejectsLoopbackBeforeDial(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := SendWebhook(WebhookConfig{URL: srv.URL}, "critical", "blocked", nil)
	if err == nil || hits != 0 {
		t.Fatalf("loopback webhook was not rejected before dial: err=%v hits=%d", err, hits)
	}
}
func TestSendWebhookContextHonorsCanceledResolverContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := SendWebhookContext(ctx, WebhookConfig{URL: "https://example.com/hook"}, "high", "blocked", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled resolver error=%v", err)
	}
}

func TestSendWebhookContextHonorsRequestDeadline(t *testing.T) {
	allowWebhookTestTarget(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := SendWebhookContext(ctx, WebhookConfig{URL: srv.URL}, "high", "deadline", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("webhook ignored caller deadline: %s", elapsed)
	}
}

func TestDispatchChannelPassesContextToWebhook(t *testing.T) {
	original := webhookTargetResolver
	webhookTargetResolver = func(ctx context.Context, _ string) (safetarget.Target, error) {
		if err := ctx.Err(); err != nil {
			return safetarget.Target{}, err
		}
		return safetarget.Target{}, errors.New("webhook resolver received an uncanceled context")
	}
	t.Cleanup(func() {
		webhookTargetResolver = original
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := dispatchChannel(ctx, &repository.NotifyChannel{
		Type: "webhook",
		ConfigJSON: map[string]any{
			"url": "https://example.com/hook",
		},
	}, "high", "blocked", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dispatcher dropped caller context: %v", err)
	}
}

type notifyStaticResolver map[string]string

func (r notifyStaticResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if ip, ok := r[host]; ok {
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	}
	return nil, errors.New("no such host")
}

// 通知渠道“允许内网地址”只放开内网（私网段、内部主机名）；回环、链路本地、元数据仍拒。
func TestNotifyPrivateTargetSwitchOpensOnlyPrivateNetworks(t *testing.T) {
	original := notifyTargetResolver
	notifyTargetResolver = notifyStaticResolver{"hook.corp.internal": "10.0.0.5", "loop.example": "127.0.0.1", "ll.example": "169.254.20.1", "imds.example": "169.254.169.254"}
	t.Cleanup(func() { notifyTargetResolver = original })
	ctx := context.Background()
	if _, err := resolveNotifyTarget(ctx, "http://hook.corp.internal/x", false); err == nil {
		t.Fatal("private target allowed without the switch")
	}
	if _, err := resolveNotifyTarget(ctx, "http://hook.corp.internal/x", true); err != nil {
		t.Fatalf("private target with the switch: %v", err)
	}
	for _, host := range []string{"loop.example", "ll.example", "imds.example", "localhost"} {
		if _, err := resolveNotifyTarget(ctx, "http://"+host+"/x", true); err == nil {
			t.Errorf("%s allowed by allow_private_target", host)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	if err := SendWebhookContext(ctx, WebhookConfig{URL: server.URL + "/hook", AllowPrivateTarget: true}, "high", "t", nil); err == nil {
		t.Fatal("loopback webhook must stay denied even with allow_private_target")
	}
	if err := SendWecomContext(ctx, WecomConfig{WebhookURL: server.URL + "/cgi-bin/webhook/send?key=k", AllowPrivateTarget: true}, "high", "t", nil); err == nil {
		t.Fatal("loopback wecom must stay denied even with allow_private_target")
	}
}
