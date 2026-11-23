package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

// ChannelStore 是 Dispatcher 依赖的最小仓储面（便于单测替换）。
type ChannelStore interface {
	GetForTenant(ctx context.Context, tenantID, id string) (*repository.NotifyChannel, error)
	ListEnabled(ctx context.Context, tenantID string) ([]*repository.NotifyChannel, error)
}

// Dispatcher dispatches alerts to all enabled notify channels for a tenant.
type Dispatcher struct {
	repo ChannelStore
}

// NewDispatcher creates a new Dispatcher.
func NewDispatcher(repo *repository.NotifyChannelsRepository) *Dispatcher {
	if repo == nil {
		return &Dispatcher{}
	}
	return &Dispatcher{repo: repo}
}

// NewDispatcherWithStore 用任意 ChannelStore 构造 Dispatcher（测试用）。
func NewDispatcherWithStore(store ChannelStore) *Dispatcher {
	return &Dispatcher{repo: store}
}

// TestMessageText 是渠道配置页「发送测试消息」的固定中文内容。
const TestMessageText = "【JJDGuard】这是一条测试消息，收到说明告警渠道配置正确"

// SendTestMessage 向本租户的指定渠道发送一条测试消息。
// 与 DispatchChannel 不同，禁用状态的渠道也允许测试（便于先验证再启用）；
// 渠道只按 (tenant_id, id) 查找，跨租户不可达。
func (d *Dispatcher) SendTestMessage(ctx context.Context, tenantID, channelID string) error {
	if d == nil || d.repo == nil {
		return fmt.Errorf("notification dispatcher repository is required")
	}
	ch, err := d.repo.GetForTenant(ctx, tenantID, channelID)
	if err != nil {
		return err
	}
	return dispatchChannel(ctx, ch, "info", TestMessageText, map[string]any{})
}
func (d *Dispatcher) DispatchChannel(ctx context.Context, tenantID, channelID, severity, title string, body map[string]any) error {
	if d == nil || d.repo == nil {
		return fmt.Errorf("notification dispatcher repository is required")
	}
	ch, err := d.repo.GetForTenant(ctx, tenantID, channelID)
	if err != nil {
		return err
	}
	if !ch.Enabled {
		return fmt.Errorf("notification channel is disabled")
	}
	return dispatchChannel(ctx, ch, severity, title, body)
}

// EgressDeniedRecorder 在通知渠道的发送地址被防跳板出站拒绝时记一条安全事件（控制面启动时装配）。
var EgressDeniedRecorder func(ctx context.Context, tenantID, kind, target string)

func dispatchChannel(ctx context.Context, ch *repository.NotifyChannel, severity, title string, body map[string]any) error {
	err := sendChannel(ctx, ch, severity, title, body)
	if err != nil && EgressDeniedRecorder != nil &&
		(errors.Is(err, safetarget.ErrForbiddenAddress) || errors.Is(err, safetarget.ErrPrivateAddress)) {
		EgressDeniedRecorder(ctx, ch.TenantID, "notify_channel:"+ch.Type, notifyChannelTargetHost(ch))
	}
	return err
}

// notifyChannelTargetHost 取渠道发送地址的主机名（只用于安全事件，不含路径和密钥）。
func notifyChannelTargetHost(ch *repository.NotifyChannel) string {
	for _, key := range []string{"url", "webhook_url", "webhook"} {
		if raw, ok := ch.ConfigJSON[key].(string); ok && strings.TrimSpace(raw) != "" {
			if parsed, err := url.Parse(strings.TrimSpace(raw)); err == nil {
				return parsed.Hostname()
			}
		}
	}
	return ""
}

func sendChannel(ctx context.Context, ch *repository.NotifyChannel, severity, title string, body map[string]any) error {
	cfgBytes, _ := json.Marshal(ch.ConfigJSON)
	switch ch.Type {
	case "email":
		var ec EmailConfig
		_ = json.Unmarshal(cfgBytes, &ec)
		return SendEmail(ec, "["+severity+"] "+title, formatBody(body))
	case "webhook":
		var wc WebhookConfig
		_ = json.Unmarshal(cfgBytes, &wc)
		return SendWebhookContext(ctx, wc, severity, title, body)
	case "dingtalk":
		var dc DingtalkConfig
		_ = json.Unmarshal(cfgBytes, &dc)
		return SendDingtalkContext(ctx, dc, severity, title, body)
	case "wecom":
		var wc WecomConfig
		_ = json.Unmarshal(cfgBytes, &wc)
		return SendWecomContext(ctx, wc, severity, title, body)
	case "feishu":
		var fc FeishuConfig
		_ = json.Unmarshal(cfgBytes, &fc)
		return SendFeishuContext(ctx, fc, severity, title, body)
	default:
		return fmt.Errorf("unsupported notification channel type %q", ch.Type)
	}
}

// Dispatch sends an alert to all enabled channels for the given tenant.
// It continues on individual channel errors and returns the first error encountered.
func (d *Dispatcher) Dispatch(ctx context.Context, tenantID, severity, title string, body map[string]any) error {
	chs, err := d.repo.ListEnabled(ctx, tenantID)
	if err != nil {
		return err
	}
	var firstErr error
	for _, ch := range chs {
		if derr := dispatchChannel(ctx, ch, severity, title, body); derr != nil && firstErr == nil {
			firstErr = derr
		}
	}
	return firstErr
}

// formatBody converts a body map to a pretty-printed JSON string.
func formatBody(body map[string]any) string {
	b, _ := json.MarshalIndent(body, "", "  ")
	return string(b)
}
