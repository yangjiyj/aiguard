package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// FeishuConfig 飞书自定义机器人配置：webhook_url 必填，secret 为可选签名密钥。
type FeishuConfig struct {
	WebhookURL string `json:"webhook_url"`
	Secret     string `json:"secret"`
	// AllowPrivateTarget 是渠道的“允许内网地址”，默认关。
	AllowPrivateTarget bool `json:"allow_private_target"`
}

// feishuSign 按飞书签名校验算法：以 timestamp+"\n"+secret 为 HMAC-SHA256 的 key，
// 对空消息签名后 base64。
func feishuSign(timestamp, secret string) string {
	mac := hmac.New(sha256.New, []byte(timestamp+"\n"+secret))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// SendFeishuContext 通过飞书自定义机器人发送文本告警。
func SendFeishuContext(ctx context.Context, cfg FeishuConfig, severity, title string, body map[string]any) error {
	endpoint := strings.TrimSpace(cfg.WebhookURL)
	if endpoint == "" {
		return cnErrorf(nil, "飞书配置无效：需要填写机器人 Webhook 地址")
	}
	lines := append([]string{"【" + severityLabel(severity) + "】" + title}, chatbotBodyLines(body)...)
	payload := map[string]any{
		"msg_type": "text",
		"content":  map[string]string{"text": strings.Join(lines, "\n")},
	}
	if secret := strings.TrimSpace(cfg.Secret); secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		payload["timestamp"] = ts
		payload["sign"] = feishuSign(ts, secret)
	}
	respBody, err := postChatbotJSON(ctx, "飞书", endpoint, cfg.AllowPrivateTarget, payload)
	if err != nil {
		return err
	}
	var result struct {
		Code *int   `json:"code"`
		Msg  string `json:"msg"`
	}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &result); err != nil {
			return cnErrorf(err, "飞书返回内容无法解析")
		}
	}
	if result.Code != nil && *result.Code != 0 {
		return cnErrorf(fmt.Errorf("feishu code %d: %s", *result.Code, result.Msg),
			"飞书拒绝了消息（错误码 %d），请检查机器人地址与签名密钥", *result.Code)
	}
	return nil
}
