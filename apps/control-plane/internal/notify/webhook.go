package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

// WebhookConfig holds configuration for generic webhook sending.
type WebhookConfig struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	// AllowPrivateTarget 是渠道的“允许内网地址”（config.allow_private_target），默认关。
	AllowPrivateTarget bool `json:"allow_private_target"`
}

var webhookTargetResolver = func(ctx context.Context, rawURL string) (safetarget.Target, error) {
	return safetarget.Resolve(ctx, rawURL, false, nil)
}

// privateTargetOptions 是渠道打开“允许内网地址”后的出站选项：只放开内网（私网段、内部主机名），
// 回环、链路本地、云元数据仍拒，证书照常校验，重定向照拒。
var privateTargetOptions = safetarget.Options{AllowPrivate: true, AllowInternalHostnames: true}

// notifyTargetResolver 只给测试注入解析结果；nil 用系统解析器。
var notifyTargetResolver safetarget.Resolver

// resolveNotifyTarget 校验通知渠道的发送地址。默认内网、回环、元数据一律拒绝（防跳板）；渠道
// 配置 allow_private_target=true 时放开内网类地址。
func resolveNotifyTarget(ctx context.Context, rawURL string, allowPrivate bool) (safetarget.Target, error) {
	if allowPrivate {
		return safetarget.ResolveWithOptions(ctx, rawURL, privateTargetOptions, notifyTargetResolver)
	}
	return webhookTargetResolver(ctx, rawURL)
}

// SendWebhook sends an alert payload to a webhook endpoint.
func SendWebhook(cfg WebhookConfig, severity, title string, body map[string]any) error {
	return SendWebhookContext(context.Background(), cfg, severity, title, body)
}

func SendWebhookContext(ctx context.Context, cfg WebhookConfig, severity, title string, body map[string]any) error {
	if cfg.URL == "" {
		return fmt.Errorf("webhook config invalid: url is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	target, err := resolveNotifyTarget(ctx, cfg.URL, cfg.AllowPrivateTarget)
	if err != nil {
		return fmt.Errorf("webhook target rejected: %w", err)
	}
	method := cfg.Method
	if method == "" {
		method = "POST"
	}
	payload, _ := json.Marshal(map[string]any{
		"severity": severity,
		"title":    title,
		"body":     body,
		"ts":       time.Now().Unix(),
	})
	req, err := http.NewRequestWithContext(ctx, method, target.URL.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	client := safetarget.Client(&http.Client{Timeout: 10 * time.Second}, target, false)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}
