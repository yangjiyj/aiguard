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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

func noRetryDelay(t *testing.T) {
	t.Helper()
	original := chatbotRetryBackoff
	chatbotRetryBackoff = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() { chatbotRetryBackoff = original })
}

func TestSendWecom_RequiresWebhookOrKey(t *testing.T) {
	if err := SendWecomContext(context.Background(), WecomConfig{}, "high", "t", nil); err == nil {
		t.Fatal("expected error for empty wecom config")
	}
}

func TestSendWecom_MarkdownPayload(t *testing.T) {
	allowWebhookTestTarget(t)
	var got map[string]any
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.URL.Query().Get("key")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()

	err := SendWecomContext(context.Background(), WecomConfig{WebhookURL: srv.URL + "/cgi-bin/webhook/send?key=k-123"},
		"high", "检测到敏感数据外发", map[string]any{"rule_name": "身份证号"})
	if err != nil {
		t.Fatalf("SendWecom: %v", err)
	}
	if gotKey != "k-123" {
		t.Fatalf("key query=%q", gotKey)
	}
	if got["msgtype"] != "markdown" {
		t.Fatalf("msgtype=%v", got["msgtype"])
	}
	md, _ := got["markdown"].(map[string]any)
	content, _ := md["content"].(string)
	for _, want := range []string{"检测到敏感数据外发", "高危", "身份证号"} {
		if !strings.Contains(content, want) {
			t.Errorf("content missing %q: %s", want, content)
		}
	}
}

func TestSendWecom_KeyOnlyUsesOfficialEndpoint(t *testing.T) {
	var resolved string
	original := webhookTargetResolver
	webhookTargetResolver = func(_ context.Context, rawURL string) (safetarget.Target, error) {
		resolved = rawURL
		return safetarget.Target{}, errors.New("stop")
	}
	t.Cleanup(func() { webhookTargetResolver = original })
	_ = SendWecomContext(context.Background(), WecomConfig{Key: "abc"}, "info", "t", nil)
	if resolved != "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc" {
		t.Fatalf("resolved=%q", resolved)
	}
}

func TestSendWecom_NonZeroErrcodeFails(t *testing.T) {
	allowWebhookTestTarget(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"errcode":93000,"errmsg":"invalid webhook url"}`))
	}))
	defer srv.Close()
	err := SendWecomContext(context.Background(), WecomConfig{WebhookURL: srv.URL}, "info", "t", nil)
	if err == nil || !strings.Contains(err.Error(), "93000") {
		t.Fatalf("expected errcode error, got %v", err)
	}
	if hits != 1 {
		t.Fatalf("business error must not retry, hits=%d", hits)
	}
}

func TestSendWecom_RetriesOn5xxThenSucceeds(t *testing.T) {
	allowWebhookTestTarget(t)
	noRetryDelay(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"errcode":0}`))
	}))
	defer srv.Close()
	if err := SendWecomContext(context.Background(), WecomConfig{WebhookURL: srv.URL}, "info", "t", nil); err != nil {
		t.Fatalf("expected success after retries: %v", err)
	}
	if hits != 3 {
		t.Fatalf("hits=%d want 3", hits)
	}
}

func TestSendWecom_GivesUpAfterMaxAttempts(t *testing.T) {
	allowWebhookTestTarget(t)
	noRetryDelay(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	if err := SendWecomContext(context.Background(), WecomConfig{WebhookURL: srv.URL}, "info", "t", nil); err == nil {
		t.Fatal("expected failure after max attempts")
	}
	if hits != int32(chatbotMaxAttempts) {
		t.Fatalf("hits=%d want %d", hits, chatbotMaxAttempts)
	}
}

func TestSendWecom_NoRetryOn4xx(t *testing.T) {
	allowWebhookTestTarget(t)
	noRetryDelay(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	if err := SendWecomContext(context.Background(), WecomConfig{WebhookURL: srv.URL}, "info", "t", nil); err == nil {
		t.Fatal("expected 400 failure")
	}
	if hits != 1 {
		t.Fatalf("hits=%d want 1", hits)
	}
}

func TestSendWecom_RejectsLoopbackBeforeDial(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()
	if err := SendWecomContext(context.Background(), WecomConfig{WebhookURL: srv.URL}, "info", "t", nil); err == nil || hits != 0 {
		t.Fatalf("loopback not rejected: err=%v hits=%d", err, hits)
	}
}

func TestSendFeishu_SignedTextPayload(t *testing.T) {
	allowWebhookTestTarget(t)
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = w.Write([]byte(`{"code":0,"msg":"success"}`))
	}))
	defer srv.Close()

	secret := "fs-secret"
	before := time.Now().Unix()
	err := SendFeishuContext(context.Background(), FeishuConfig{WebhookURL: srv.URL + "/open-apis/bot/v2/hook/x", Secret: secret},
		"critical", "检测到越权调用", map[string]any{"rule_name": "红线"})
	if err != nil {
		t.Fatalf("SendFeishu: %v", err)
	}
	if got["msg_type"] != "text" {
		t.Fatalf("msg_type=%v", got["msg_type"])
	}
	content, _ := got["content"].(map[string]any)
	text, _ := content["text"].(string)
	for _, want := range []string{"检测到越权调用", "严重", "红线"} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q: %s", want, text)
		}
	}
	tsStr, _ := got["timestamp"].(string)
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil || ts < before || ts > time.Now().Unix() {
		t.Fatalf("timestamp must be unix seconds string, got %v", got["timestamp"])
	}
	mac := hmac.New(sha256.New, []byte(tsStr+"\n"+secret))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if got["sign"] != want {
		t.Fatalf("sign=%v want %s", got["sign"], want)
	}
}

func TestSendFeishu_NoSecretOmitsSign(t *testing.T) {
	allowWebhookTestTarget(t)
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer srv.Close()
	if err := SendFeishuContext(context.Background(), FeishuConfig{WebhookURL: srv.URL}, "info", "t", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["sign"]; ok {
		t.Fatalf("sign must be omitted without secret: %v", got)
	}
	if _, ok := got["timestamp"]; ok {
		t.Fatalf("timestamp must be omitted without secret: %v", got)
	}
}

func TestSendFeishu_NonZeroCodeFails(t *testing.T) {
	allowWebhookTestTarget(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":19021,"msg":"sign match fail or timestamp is not within one hour from current time"}`))
	}))
	defer srv.Close()
	err := SendFeishuContext(context.Background(), FeishuConfig{WebhookURL: srv.URL, Secret: "x"}, "info", "t", nil)
	if err == nil || !strings.Contains(err.Error(), "19021") {
		t.Fatalf("expected code error, got %v", err)
	}
}

func TestSendFeishu_RequiresWebhook(t *testing.T) {
	if err := SendFeishuContext(context.Background(), FeishuConfig{}, "info", "t", nil); err == nil {
		t.Fatal("expected error for empty feishu config")
	}
}

func TestSendFeishu_RetriesOn5xx(t *testing.T) {
	allowWebhookTestTarget(t)
	noRetryDelay(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer srv.Close()
	if err := SendFeishuContext(context.Background(), FeishuConfig{WebhookURL: srv.URL}, "info", "t", nil); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Fatalf("hits=%d want 2", hits)
	}
}

func TestDispatchChannelRoutesWecomAndFeishu(t *testing.T) {
	allowWebhookTestTarget(t)
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write([]byte(`{"errcode":0,"code":0}`))
	}))
	defer srv.Close()
	for _, ch := range []*repository.NotifyChannel{
		{Type: "wecom", ConfigJSON: map[string]any{"webhook_url": srv.URL + "/wecom"}},
		{Type: "feishu", ConfigJSON: map[string]any{"webhook_url": srv.URL + "/feishu", "secret": "s"}},
	} {
		if err := dispatchChannel(context.Background(), ch, "info", "t", nil); err != nil {
			t.Fatalf("%s: %v", ch.Type, err)
		}
	}
	if strings.Join(paths, ",") != "/wecom,/feishu" {
		t.Fatalf("paths=%v", paths)
	}
}

func TestDispatchChannelRejectsUnknownType(t *testing.T) {
	if err := dispatchChannel(context.Background(), &repository.NotifyChannel{Type: "sms"}, "info", "t", nil); err == nil {
		t.Fatal("expected unsupported type error")
	}
}

func TestSeverityLabelUsesTheUnifiedNames(t *testing.T) {
	for in, want := range map[string]string{
		"critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
		"warning": "提醒", "warn": "提醒", "info": "提示", "": "提示",
	} {
		if got := severityLabel(in); got != want {
			t.Fatalf("severityLabel(%q)=%q want %q", in, got, want)
		}
	}
}

// 群机器人正文只显示中文叫法：event_type / action 是英文码，只给 Webhook 程序读；告警侧另给
// event_type_label / action_label，没有中文叫法的码整行不显示。
func TestChatbotBodyLinesShowChineseLabelsNotCodes(t *testing.T) {
	lines := strings.Join(chatbotBodyLines(map[string]any{
		"event_type": "security_check", "action": "tool_failure_loop", "rule_name": "Bash",
	}), "\n")
	for _, code := range []string{"security_check", "tool_failure_loop"} {
		if strings.Contains(lines, code) {
			t.Fatalf("English code %q leaked into the chatbot body:\n%s", code, lines)
		}
	}
	if !strings.Contains(lines, "命中规则：Bash") {
		t.Fatalf("other labelled fields must stay:\n%s", lines)
	}

	lines = strings.Join(chatbotBodyLines(map[string]any{
		"event_type": "agent_endpoint_risk", "event_type_label": "终端智能体风险",
		"action": "deny", "action_label": "已阻断",
	}), "\n")
	for _, want := range []string{"事件类型：终端智能体风险", "处置动作：已阻断"} {
		if !strings.Contains(lines, want) {
			t.Fatalf("missing %q:\n%s", want, lines)
		}
	}
	for _, code := range []string{"agent_endpoint_risk", "deny"} {
		if strings.Contains(lines, code) {
			t.Fatalf("English code %q leaked into the chatbot body:\n%s", code, lines)
		}
	}
}
