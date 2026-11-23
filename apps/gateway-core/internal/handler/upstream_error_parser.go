package handler

import (
	"encoding/json"
	"html"
	"regexp"
	"strings"
)

// upstreamErrorDetail 仅承载响应错误字段，不读取或记录请求正文。
type upstreamErrorDetail struct{ Message, Type, Code string }

var (
	upstreamHTMLPage  = regexp.MustCompile(`(?i)<!doctype\s+html|<\s*(?:html|head|body|title)(?:\s|>)`)
	upstreamHTMLTitle = regexp.MustCompile(`(?is)<title(?:\s[^>]*)?>(.*?)</title\s*>`)
	upstreamHTMLTag   = regexp.MustCompile(`(?s)</?[A-Za-z][^>]*>`)
)

// parseUpstreamError 按供应商常见结构顺序提取；未知 JSON 不整体落盘，避免夹带无关内容。
func parseUpstreamError(body []byte) upstreamErrorDetail {
	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) == nil && root != nil {
		read := func(raw json.RawMessage) string {
			var value string
			if json.Unmarshal(raw, &value) == nil {
				return strings.TrimSpace(value)
			}
			var number json.Number
			if json.Unmarshal(raw, &number) == nil {
				return string(number)
			}
			return ""
		}
		detail := func(raw json.RawMessage) upstreamErrorDetail {
			var obj map[string]json.RawMessage
			if json.Unmarshal(raw, &obj) != nil {
				return upstreamErrorDetail{}
			}
			return upstreamErrorDetail{read(obj["message"]), read(obj["type"]), read(obj["code"])}
		}
		nested := detail(root["error"])
		top := upstreamErrorDetail{read(root["message"]), read(root["type"]), read(root["code"])}
		result := nested
		if result.Message == "" {
			result = top
		}
		if result.Message == "" {
			result.Message = read(root["error"])
		}
		if result.Message == "" {
			result.Message = read(root["detail"])
		}
		if result.Message == "" {
			result = detail(root["detail"])
		}
		if result.Message == "" {
			result.Message = read(root["msg"])
		}
		if result.Message == "" {
			var errors []json.RawMessage
			if json.Unmarshal(root["errors"], &errors) == nil && len(errors) > 0 {
				result = detail(errors[0])
			}
		}
		if result.Type == "" {
			result.Type = nested.Type
			if result.Type == "" {
				result.Type = top.Type
			}
		}
		if result.Code == "" {
			result.Code = nested.Code
			if result.Code == "" {
				result.Code = top.Code
			}
		}
		return result
	}
	// 合法但没有已知错误结构的 JSON 不当作自由文本保存。
	if json.Valid(body) {
		return upstreamErrorDetail{}
	}
	text := string(body)
	if upstreamHTMLPage.MatchString(text) {
		title := upstreamHTMLTitle.FindStringSubmatch(text)
		if title == nil {
			return upstreamErrorDetail{}
		}
		text = title[1]
	}
	text = html.UnescapeString(upstreamHTMLTag.ReplaceAllString(text, ""))
	return upstreamErrorDetail{Message: strings.TrimSpace(text)}
}

// 规则按顺序匹配：服务故障、鉴权、额度等明确原因优先，避免误归类为参数错误。
var upstreamHintRules = []struct {
	statuses  []int
	minStatus int
	pattern   *regexp.Regexp
	hint      string
}{
	{minStatus: 500, hint: "上游服务暂时不可用、超时或过载，请稍后重试"},
	{statuses: []int{401}, pattern: regexp.MustCompile(`(?i)authentication_error|invalid_api_key|api[ _-]?key|凭据|令牌无效`), hint: "上游凭据无效，请联系管理员"},
	{statuses: []int{402}, pattern: regexp.MustCompile(`(?i)insufficient_quota|balance|credit|billing|余额|额度|欠费|充值`), hint: "上游账号额度不足，请联系管理员"},
	{statuses: []int{403}, pattern: regexp.MustCompile(`(?i)model_not_found|model[^\n]*not found|permission_error|organization[^\n]*disabled`), hint: "上游模型不存在或无访问权限，请联系管理员"},
	{pattern: regexp.MustCompile(`(?i)prompt is too long|context_length_exceeded|maximum context length|context limit|tokens?\s*>\s*[\d,]+\s+maximum`), hint: "对话上下文超过模型上限，请压缩上下文或新开对话"},
	{statuses: []int{429}, pattern: regexp.MustCompile(`(?i)rate[_ -]?limit|quota[^\n]*for this minute|限流`), hint: "上游请求过于频繁，请稍后重试"},
	{pattern: regexp.MustCompile(`(?i)content_filter|safety|敏感`), hint: "上游内容审核拒绝了本次请求，请调整内容后重试"},
	{statuses: []int{408}, pattern: regexp.MustCompile(`(?i)overloaded_error|overload|timeout|timed out|超时`), hint: "上游服务暂时不可用、超时或过载，请稍后重试"},
	{pattern: regexp.MustCompile(`(?i)unsupported parameter|invalid_request_error`), hint: "请求参数不受上游模型支持，请检查参数后重试"},
}

var upstreamContextCounts = []*regexp.Regexp{
	regexp.MustCompile(`(?i)([\d,]+)\s*tokens?\s*>\s*([\d,]+)\s+maximum`),
	regexp.MustCompile(`(?i)maximum context length[^\d]*([\d,]+)\s*tokens?.*?(?:requested|resulted in|messages resulted in)[^\d]*([\d,]+)`),
}

func upstreamErrorHint(status int, detail upstreamErrorDetail) string {
	// 解释只使用净化后的有限文本，动态数字也不能绕过长度和密钥遮盖。
	detail.Message = sanitizeClientUpstreamMessage(detail.Message)
	text := strings.Join([]string{detail.Message, sanitizeClientUpstreamMessage(detail.Type), sanitizeClientUpstreamMessage(detail.Code)}, " ")
	for _, rule := range upstreamHintRules {
		matched := rule.minStatus > 0 && status >= rule.minStatus
		if rule.pattern != nil && rule.pattern.MatchString(text) {
			matched = true
		}
		for _, code := range rule.statuses {
			if status == code {
				matched = true
			}
		}
		if !matched {
			continue
		}
		if strings.HasPrefix(rule.hint, "对话上下文") {
			for index, pattern := range upstreamContextCounts {
				if counts := pattern.FindStringSubmatch(detail.Message); counts != nil {
					actual, maximum := counts[1], counts[2]
					if index == 1 {
						actual, maximum = maximum, actual
					}
					return "对话上下文超过模型上限（本次 " + strings.ReplaceAll(actual, ",", "") + " token，上限 " + strings.ReplaceAll(maximum, ",", "") + "），请压缩上下文或新开对话"
				}
			}
		}
		return rule.hint
	}
	return "上游拒绝了本次请求，请检查请求或联系管理员"
}
