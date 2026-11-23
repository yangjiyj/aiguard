package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

// 群机器人（企业微信/飞书）共用的发送骨架：SSRF 防护 + 超时 + 有界重试。
// 重试只针对网络错误与 5xx/429；4xx 与业务错误码（errcode/code != 0）立即失败，
// 避免把配置错误放大成重复打扰。

const chatbotMaxAttempts = 3

var chatbotRetryBackoff = func(attempt int) time.Duration {
	return time.Duration(attempt) * 300 * time.Millisecond
}

// chatbotStatusError 表示对端返回了非 2xx 状态码。
type chatbotStatusError struct {
	channel string
	status  int
}

func (e *chatbotStatusError) Error() string {
	return fmt.Sprintf("%s接口返回 HTTP %d", e.channel, e.status)
}

func (e *chatbotStatusError) retryable() bool {
	return e.status == http.StatusTooManyRequests || e.status >= 500
}

// postChatbotJSON 发送 JSON 并返回响应体；channel 是用于报错的中文渠道名。
func postChatbotJSON(ctx context.Context, channel, rawURL string, allowPrivate bool, payload any) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	target, err := resolveNotifyTarget(ctx, rawURL, allowPrivate)
	if err != nil {
		return nil, cnErrorf(err, "%s地址不被允许：%s", channel, FriendlyError(err))
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	client := safetarget.Client(&http.Client{Timeout: 10 * time.Second}, target, false)

	var lastErr error
	for attempt := 1; attempt <= chatbotMaxAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(chatbotRetryBackoff(attempt - 1)):
			}
		}
		respBody, err := postChatbotOnce(ctx, client, channel, target.URL.String(), body)
		if err == nil {
			return respBody, nil
		}
		lastErr = err
		if !chatbotRetryable(ctx, err) {
			return nil, err
		}
	}
	return nil, cnErrorf(lastErr, "%s发送失败（已重试 %d 次）：%s", channel, chatbotMaxAttempts, FriendlyError(lastErr))
}

func postChatbotOnce(ctx context.Context, client *http.Client, channel, rawURL string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &chatbotStatusError{channel: channel, status: resp.StatusCode}
	}
	return respBody, nil
}

func chatbotRetryable(ctx context.Context, err error) bool {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var se *chatbotStatusError
	if errors.As(err, &se) {
		return se.retryable()
	}
	return true // 网络错误
}

// severityLabel 把严重度枚举转成中文，客户可见消息不露英文枚举。
func severityLabel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "warning", "warn":
		return "提醒"
	case "low":
		return "低危"
	case "info", "":
		return "提示"
	default:
		return severity
	}
}

// event_type / action 是英文码，留给 Webhook 程序读，群机器人不显示；告警侧把中文叫法写在
// event_type_label / action_label，没有中文叫法时不写，这一行就不出现。
var chatbotFieldLabels = map[string]string{
	"rule_name":            "命中规则",
	"event_type_label":     "事件类型",
	"action_label":         "处置动作",
	"message":              "说明",
	"detail":               "详情",
	"occurrence_count":     "发生次数",
	"distinct_occurrences": "去重次数",
	"affected_users":       "涉及用户数",
	"daily_count":          "当日累计",
	"date":                 "日期",
	"first_seen_at":        "首次发生",
	"last_seen_at":         "最近发生",
	"username":             "用户",
	"user_name":            "用户",
	"model":                "模型",
	"cost":                 "费用",
	"budget":               "预算",
	// 运维告警（opsalert）外发时直接使用中文字段名。
	"类型":   "类型",
	"范围":   "范围",
	"次数":   "次数",
	"处置建议": "处置建议",
}

// chatbotBodyLines 把告警 body 转成「标签：值」行；只展示有中文标签的字段，
// 避免把内部字段名、技术 id 推到客户群里。
func chatbotBodyLines(body map[string]any) []string {
	keys := make([]string, 0, len(body))
	for k := range body {
		if _, ok := chatbotFieldLabels[k]; ok {
			keys = append(keys, k)
		}
	}
	// 运维告警字段按阅读顺序（类型 → 范围 → 次数 → 处置建议），其余字段在后按字母序。
	rank := map[string]int{"类型": 1, "范围": 2, "次数": 3, "处置建议": 4}
	sort.Slice(keys, func(i, j int) bool {
		ri, rj := rank[keys[i]], rank[keys[j]]
		if ri == 0 {
			ri = 100
		}
		if rj == 0 {
			rj = 100
		}
		if ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		v := body[k]
		if v == nil {
			continue
		}
		s := strings.TrimSpace(fmt.Sprint(v))
		if s == "" {
			continue
		}
		lines = append(lines, chatbotFieldLabels[k]+"："+s)
	}
	return lines
}
