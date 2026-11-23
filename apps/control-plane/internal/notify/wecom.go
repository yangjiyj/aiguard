package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

const wecomDefaultEndpoint = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send"

// WecomConfig 企业微信群机器人配置：填完整 webhook_url，或只填 key。
type WecomConfig struct {
	WebhookURL string `json:"webhook_url"`
	Key        string `json:"key"`
	// AllowPrivateTarget 是渠道的“允许内网地址”，默认关。
	AllowPrivateTarget bool `json:"allow_private_target"`
}

func (c WecomConfig) endpoint() (string, error) {
	if u := strings.TrimSpace(c.WebhookURL); u != "" {
		return u, nil
	}
	if k := strings.TrimSpace(c.Key); k != "" {
		return wecomDefaultEndpoint + "?key=" + url.QueryEscape(k), nil
	}
	return "", cnErrorf(nil, "企业微信配置无效：需要填写机器人 Webhook 地址或 Key")
}

// SendWecomContext 通过企业微信群机器人发送 markdown 告警。
func SendWecomContext(ctx context.Context, cfg WecomConfig, severity, title string, body map[string]any) error {
	endpoint, err := cfg.endpoint()
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("**【" + severityLabel(severity) + "】" + title + "**")
	for _, line := range chatbotBodyLines(body) {
		b.WriteString("\n> " + line)
	}
	payload := map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]string{"content": b.String()},
	}
	respBody, err := postChatbotJSON(ctx, "企业微信", endpoint, cfg.AllowPrivateTarget, payload)
	if err != nil {
		return err
	}
	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &result); err != nil {
			return cnErrorf(err, "企业微信返回内容无法解析")
		}
	}
	if result.ErrCode != 0 {
		return cnErrorf(fmt.Errorf("wecom errcode %d: %s", result.ErrCode, result.ErrMsg),
			"企业微信拒绝了消息（错误码 %d），请检查机器人地址或 Key 是否有效", result.ErrCode)
	}
	return nil
}
