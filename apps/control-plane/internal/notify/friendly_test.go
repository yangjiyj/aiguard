package notify

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

// 允许 HTTP/http(s)/Webhook/Key 这类专有名词，其余 4 字母以上英文单词视为泄露。
var asciiWord = regexp.MustCompile(`(?i)\b(?:[a-z]{4,})\b`)

func leaksEnglish(s string) bool {
	for _, w := range asciiWord.FindAllString(s, -1) {
		switch w {
		case "HTTP", "http", "Webhook":
			continue
		}
		return true
	}
	return false
}

func TestFriendlyErrorIsChinese(t *testing.T) {
	cases := []error{
		fmt.Errorf("webhook target rejected: %w", safetarget.ErrPrivateAddress),
		fmt.Errorf("x: %w", safetarget.ErrInvalidURL),
		context.DeadlineExceeded,
		fmt.Errorf("webhook status 400"),
		fmt.Errorf("dial tcp: something odd"),
	}
	for _, err := range cases {
		got := FriendlyError(err)
		if got == "" || leaksEnglish(got) {
			t.Errorf("FriendlyError(%v)=%q leaks english", err, got)
		}
	}
}

func TestFriendlyErrorKeepsChatbotChineseReasons(t *testing.T) {
	allowWebhookTestTarget(t)
	noRetryDelay(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	err := SendFeishuContext(context.Background(), FeishuConfig{WebhookURL: srv.URL}, "info", "t", nil)
	got := FriendlyError(err)
	if got != "飞书发送失败（已重试 3 次）：飞书接口返回 HTTP 502" {
		t.Fatalf("got %q", got)
	}
	// 被 SSRF 拦截时也只给中文
	original := webhookTargetResolver
	webhookTargetResolver = func(context.Context, string) (safetarget.Target, error) {
		return safetarget.Target{}, safetarget.ErrPrivateAddress
	}
	t.Cleanup(func() { webhookTargetResolver = original })
	got = FriendlyError(SendWecomContext(context.Background(), WecomConfig{Key: "k"}, "info", "t", nil))
	if leaksEnglish(got) {
		t.Fatalf("ssrf reason leaks english: %q", got)
	}
}
