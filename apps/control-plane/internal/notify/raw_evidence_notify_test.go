package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 用户 11-17 定：告警外发的邮件和 Webhook 带命中原文（告警正文里的 matched、primary_finding 原样外发）；
// 钉钉、企业微信、飞书维持现状，正文只有带中文标签的字段，不带证据。

const rawNotifyHit = "AKIAIOSFODNN7EXAMPLE"

func rawEvidenceAlertBody() map[string]any {
	finding := map[string]any{
		"type": "secret", "category": "cloud_credential", "rule_name": "云凭据",
		"raw_evidence": rawNotifyHit, "evidence_context": "export AWS_ACCESS_KEY_ID=" + rawNotifyHit + " # deploy",
		"redacted_evidence": "AK****LE", "matched_text_preview": "AK****LE",
	}
	return map[string]any{
		"rule_name": "云凭据", "action": "block", "action_label": "已阻断", "event_type": "security_check",
		"primary_finding": finding,
		"matched":         map[string]any{"findings": []any{finding}, "primary_finding": finding},
	}
}

// fakeSMTP 收一封信并把 DATA 段交给调用方；不宣告任何扩展，客户端不会尝试 STARTTLS 或认证。
func fakeSMTP(t *testing.T) (int, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		reply := func(line string) { _, _ = rw.WriteString(line + "\r\n"); _ = rw.Flush() }
		reply("220 test")
		var data strings.Builder
		inData := false
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					received <- data.String()
					reply("250 OK")
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case cmd == "DATA":
				inData = true
				reply("354 go ahead")
			case cmd == "QUIT":
				reply("221 bye")
				return
			default:
				reply("250 OK")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, received
}

func TestEmailAlertBodyCarriesRawEvidence(t *testing.T) {
	port, received := fakeSMTP(t)
	ch := &repository.NotifyChannel{Type: "email", Enabled: true, ConfigJSON: map[string]any{
		"host": "127.0.0.1", "port": port, "from": "guard@example.com", "to": []any{"soc@example.com"},
	}}
	if err := dispatchChannel(context.Background(), ch, "high", "命中云凭据", rawEvidenceAlertBody()); err != nil {
		t.Fatalf("send email: %v", err)
	}
	select {
	case mail := <-received:
		for _, want := range []string{`"raw_evidence": "` + rawNotifyHit + `"`, "export AWS_ACCESS_KEY_ID=" + rawNotifyHit + " # deploy"} {
			if !strings.Contains(mail, want) {
				t.Fatalf("邮件正文应带命中原文 %q:\n%s", want, mail)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("邮件没有送达")
	}
}

func TestWebhookAlertBodyCarriesRawEvidence(t *testing.T) {
	allowWebhookTestTarget(t)
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ch := &repository.NotifyChannel{Type: "webhook", Enabled: true, ConfigJSON: map[string]any{"url": srv.URL}}
	if err := dispatchChannel(context.Background(), ch, "high", "命中云凭据", rawEvidenceAlertBody()); err != nil {
		t.Fatalf("send webhook: %v", err)
	}
	body, _ := payload["body"].(map[string]any)
	primary, _ := body["primary_finding"].(map[string]any)
	matched, _ := body["matched"].(map[string]any)
	findings, _ := matched["findings"].([]any)
	if primary["raw_evidence"] != rawNotifyHit || len(findings) != 1 || findings[0].(map[string]any)["raw_evidence"] != rawNotifyHit {
		t.Fatalf("Webhook 正文应带命中原文: %#v", payload)
	}
}

func TestChatbotAlertBodyCarriesNoEvidence(t *testing.T) {
	allowWebhookTestTarget(t)
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		_, _ = w.Write([]byte(`{"errcode":0,"code":0}`))
	}))
	defer srv.Close()
	for _, ch := range []*repository.NotifyChannel{
		{Type: "dingtalk", ConfigJSON: map[string]any{"access_token": "tok", "webhook": srv.URL + "/dingtalk"}},
		{Type: "wecom", ConfigJSON: map[string]any{"webhook_url": srv.URL + "/wecom"}},
		{Type: "feishu", ConfigJSON: map[string]any{"webhook_url": srv.URL + "/feishu"}},
	} {
		if err := dispatchChannel(context.Background(), ch, "high", "命中云凭据", rawEvidenceAlertBody()); err != nil {
			t.Fatalf("%s: %v", ch.Type, err)
		}
	}
	if len(bodies) != 3 {
		t.Fatalf("三个群机器人都应收到消息: %d", len(bodies))
	}
	for _, body := range bodies {
		if strings.Contains(body, rawNotifyHit) || strings.Contains(body, "AK****LE") || !strings.Contains(body, "云凭据") {
			t.Fatalf("群机器人正文不带证据，只带规则等中文字段: %s", body)
		}
	}
}
