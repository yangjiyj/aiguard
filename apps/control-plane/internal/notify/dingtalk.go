package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const dingtalkDefaultEndpoint = "https://oapi.dingtalk.com/robot/send"

// DingtalkConfig holds configuration for the DingTalk robot webhook.
type DingtalkConfig struct {
	AccessToken string `json:"access_token"`
	Secret      string `json:"secret"`
	Webhook     string `json:"webhook"` // optional; defaults to oapi.dingtalk.com
	// AllowPrivateTarget 是渠道的“允许内网地址”，默认关。
	AllowPrivateTarget bool `json:"allow_private_target"`
}

// endpoint 拼出带 access_token（以及加签时的 timestamp/sign）的发送地址。
func (c DingtalkConfig) endpoint(now time.Time) (string, error) {
	if strings.TrimSpace(c.AccessToken) == "" {
		return "", cnErrorf(nil, "钉钉配置无效：需要填写机器人 access_token")
	}
	base := strings.TrimSpace(c.Webhook)
	if base == "" {
		base = dingtalkDefaultEndpoint
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", cnErrorf(err, "钉钉 Webhook 地址格式不正确")
	}
	q := u.Query()
	q.Set("access_token", c.AccessToken)
	if c.Secret != "" {
		ts := strconv.FormatInt(now.UnixMilli(), 10)
		h := hmac.New(sha256.New, []byte(c.Secret))
		h.Write([]byte(ts + "\n" + c.Secret))
		q.Set("timestamp", ts)
		q.Set("sign", base64.StdEncoding.EncodeToString(h.Sum(nil)))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// SendDingtalkContext 通过钉钉群机器人发送告警。与企业微信/飞书共用发送骨架：
// SSRF 防护（禁止内网、回环、云元数据地址，禁止跳转）、10 秒超时、对网络错误与 5xx/429 有界重试。
// 配置了加签密钥时按钉钉算法签名（HMAC-SHA256 + base64）。
func SendDingtalkContext(ctx context.Context, cfg DingtalkConfig, severity, title string, body map[string]any) error {
	endpoint, err := cfg.endpoint(time.Now())
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("【" + severityLabel(severity) + "】" + title)
	for _, line := range chatbotBodyLines(body) {
		b.WriteString("\n" + line)
	}
	payload := map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": b.String()},
	}
	respBody, err := postChatbotJSON(ctx, "钉钉", endpoint, cfg.AllowPrivateTarget, payload)
	if err != nil {
		return err
	}
	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &result); err != nil {
			return cnErrorf(err, "钉钉返回内容无法解析")
		}
	}
	if result.ErrCode != 0 {
		return cnErrorf(fmt.Errorf("dingtalk errcode %d: %s", result.ErrCode, result.ErrMsg),
			"钉钉拒绝了消息（错误码 %d），请检查 access_token 与加签密钥是否有效", result.ErrCode)
	}
	return nil
}
