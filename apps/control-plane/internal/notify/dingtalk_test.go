package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

func TestSendDingtalk_MissingAccessToken(t *testing.T) {
	err := SendDingtalkContext(context.Background(), DingtalkConfig{}, "warning", "Test", nil)
	if err == nil || !strings.Contains(err.Error(), "钉钉") {
		t.Errorf("expected Chinese error for missing access_token, got %v", err)
	}
}

func TestSendDingtalk_MockServer_WithoutSecret(t *testing.T) {
	allowWebhookTestTarget(t)
	var received map[string]any
	var queryParams url.Values

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryParams = r.URL.Query()
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &received)
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()

	cfg := DingtalkConfig{AccessToken: "test-token", Webhook: srv.URL}
	if err := SendDingtalkContext(context.Background(), cfg, "high", "预算告警", map[string]any{"rule_name": "部门预算"}); err != nil {
		t.Fatalf("SendDingtalk: %v", err)
	}
	if queryParams.Get("access_token") != "test-token" {
		t.Errorf("access_token not set: %v", queryParams.Get("access_token"))
	}
	if queryParams.Get("sign") != "" {
		t.Errorf("sign should not be set without secret")
	}
	if received["msgtype"] != "text" {
		t.Errorf("msgtype: %v", received["msgtype"])
	}
	textMap, _ := received["text"].(map[string]interface{})
	content, _ := textMap["content"].(string)
	for _, want := range []string{"【高危】", "预算告警", "命中规则：部门预算"} {
		if !strings.Contains(content, want) {
			t.Errorf("content missing %q: %s", want, content)
		}
	}
	if strings.Contains(content, "[high]") || strings.Contains(content, "rule_name") {
		t.Errorf("content must not leak raw enums: %s", content)
	}
}

func TestSendDingtalk_SignatureVerification(t *testing.T) {
	allowWebhookTestTarget(t)
	secret := "test-secret-123"
	var queryParams url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryParams = r.URL.Query()
		_, _ = w.Write([]byte(`{"errcode":0}`))
	}))
	defer srv.Close()

	cfg := DingtalkConfig{AccessToken: "tok", Secret: secret, Webhook: srv.URL}
	if err := SendDingtalkContext(context.Background(), cfg, "critical", "title", nil); err != nil {
		t.Fatalf("SendDingtalk: %v", err)
	}
	ts := queryParams.Get("timestamp")
	sign := queryParams.Get("sign")
	if ts == "" || sign == "" {
		t.Fatalf("timestamp or sign not set: ts=%s sign=%s", ts, sign)
	}
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(ts + "\n" + secret))
	if expected := base64.StdEncoding.EncodeToString(h.Sum(nil)); sign != expected {
		t.Errorf("signature mismatch: got %s, want %s", sign, expected)
	}
}

// 4xx 是配置错误：立即失败，不重试。
func TestSendDingtalk_Status4xxFailsWithoutRetry(t *testing.T) {
	allowWebhookTestTarget(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	err := SendDingtalkContext(context.Background(), DingtalkConfig{AccessToken: "tok", Webhook: srv.URL}, "info", "t", nil)
	if err == nil || hits != 1 {
		t.Fatalf("expected one attempt and an error, hits=%d err=%v", hits, err)
	}
}

// 5xx 按企微/飞书同样的规则有界重试。
func TestSendDingtalk_RetriesOn5xxThenSucceeds(t *testing.T) {
	allowWebhookTestTarget(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"errcode":0}`))
	}))
	defer srv.Close()
	if err := SendDingtalkContext(context.Background(), DingtalkConfig{AccessToken: "tok", Webhook: srv.URL}, "info", "t", nil); err != nil {
		t.Fatalf("expected success after retries: %v", err)
	}
	if hits != 3 {
		t.Fatalf("hits=%d want 3", hits)
	}
}

// 业务错误码（errcode != 0）不重试，并给出中文原因。
func TestSendDingtalk_NonZeroErrcodeFails(t *testing.T) {
	allowWebhookTestTarget(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"errcode":310000,"errmsg":"sign not match"}`))
	}))
	defer srv.Close()
	err := SendDingtalkContext(context.Background(), DingtalkConfig{AccessToken: "tok", Webhook: srv.URL}, "info", "t", nil)
	if err == nil || !strings.Contains(err.Error(), "310000") || !strings.Contains(err.Error(), "钉钉") || hits != 1 {
		t.Fatalf("hits=%d err=%v", hits, err)
	}
}

// 自定义 webhook 地址必须经过 SSRF 防护：内网、回环、云元数据地址一律拒绝，不发出请求。
func TestSendDingtalk_RejectsPrivateWebhookTarget(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:9/robot/send", "http://169.254.169.254/latest", "http://10.0.0.8/robot/send"} {
		err := SendDingtalkContext(context.Background(), DingtalkConfig{AccessToken: "tok", Webhook: target}, "info", "t", nil)
		if err == nil || !strings.Contains(err.Error(), "地址不被允许") {
			t.Fatalf("target %s must be rejected by SSRF guard, got %v", target, err)
		}
	}
}

// 默认官方地址也走同一个解析器（不绕过 SSRF 防护）。
func TestSendDingtalk_DefaultEndpointUsesGuardedResolver(t *testing.T) {
	var resolved string
	original := webhookTargetResolver
	webhookTargetResolver = func(_ context.Context, rawURL string) (safetarget.Target, error) {
		resolved = rawURL
		return safetarget.Target{}, errors.New("stop")
	}
	t.Cleanup(func() { webhookTargetResolver = original })
	_ = SendDingtalkContext(context.Background(), DingtalkConfig{AccessToken: "abc"}, "info", "t", nil)
	if !strings.HasPrefix(resolved, "https://oapi.dingtalk.com/robot/send?") || !strings.Contains(resolved, "access_token=abc") {
		t.Fatalf("resolved=%q", resolved)
	}
}
