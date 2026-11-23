package mcpupstream

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// SummaryLimit 是上游响应摘要的字数上限（脱敏后截断）。
const SummaryLimit = 300

const redacted = "***"

var (
	urlPattern    = regexp.MustCompile(`https?://[^\s"'<>)\]]+`)
	kvSecret      = regexp.MustCompile(`(?i)\b(api[_-]?key|apikey|access[_-]?token|token|authorization|secret|password|key|ak|sk)=([^&\s"'<>]+)`)
	bearerPattern = regexp.MustCompile(`(?i)\bbearer(\s|\+|%20)+[A-Za-z0-9._~+/=-]{4,}`)
	spaceRun      = regexp.MustCompile(`\s+`)
)

// safeQueryParams 是已知的、不含密钥的 query 参数名（小写、去掉 - _ . 后比较）。
// 脱敏策略是“默认全部遮蔽”，只有出现在这张表里的参数才保留原值，便于排障。
// 注意：这是展示 / 日志用的脱敏白名单，与“自动拆分成鉴权密钥”的名单（secretQueryNames）是两件事。
var safeQueryParams = map[string]bool{
	// 注意：不含 sessionid / session —— 会话 id 可能被当作凭据重放，默认遮蔽。
	"version": true, "v": true, "format": true,
	"lang": true, "language": true, "locale": true, "region": true, "regionid": true,
	"page": true, "pagesize": true, "limit": true, "offset": true, "cursor": true,
	"type": true, "mode": true, "output": true, "tools": true, "toolset": true,
}

func normalizeQueryName(name string) string {
	return strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(name))
}

// IsSafeQueryParam 判断 query 参数名是否在脱敏白名单内（大小写不敏感）。
func IsSafeQueryParam(name string) bool { return safeQueryParams[normalizeQueryName(name)] }

// RedactURL 对 URL 脱敏：query 值默认全部替换为 ***，仅白名单内的已知非密钥参数保留原值；
// 去掉 userinfo 与 fragment。解析失败时丢弃 ? 之后的全部内容。
// 路径里直接嵌密钥（如 /mcp/<token>/sse）不在此处理，见交付报告的已知限制。
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		base, _, _ := strings.Cut(raw, "?")
		base, _, _ = strings.Cut(base, "#")
		return base
	}
	u.User = nil
	u.Fragment, u.RawFragment = "", ""
	if u.RawQuery != "" {
		var parts []string
		for _, pair := range strings.Split(u.RawQuery, "&") {
			if pair == "" {
				continue
			}
			k, v, has := strings.Cut(pair, "=")
			if !has {
				parts = append(parts, k)
				continue
			}
			name, derr := url.QueryUnescape(k)
			if derr == nil && IsSafeQueryParam(name) && !strings.Contains(v, "***") {
				parts = append(parts, k+"="+v)
			} else {
				parts = append(parts, k+"="+redacted)
			}
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	return u.String()
}

// RedactText 对任意文本（错误信息、日志、上游响应体）脱敏：
// 已知密钥原文（含 URL 编码形态）→ ***；URL 的 query 值 → ***；k=v 形态的敏感参数 → ***；Bearer 令牌 → ***。
func RedactText(s string, secrets ...string) string {
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if len(secret) < 4 {
			continue
		}
		for _, form := range secretForms(secret) {
			s = strings.ReplaceAll(s, form, redacted)
		}
	}
	s = urlPattern.ReplaceAllStringFunc(s, RedactURL)
	s = kvSecret.ReplaceAllString(s, "$1="+redacted)
	s = bearerPattern.ReplaceAllString(s, "Bearer "+redacted)
	return s
}

// Summarize 生成上游响应体摘要：脱敏 → 折叠空白 → 按字数截断（默认 300 字）。
func Summarize(body []byte, secrets ...string) string {
	text := strings.ToValidUTF8(string(body), "")
	text = spaceRun.ReplaceAllString(strings.TrimSpace(text), " ")
	text = RedactText(text, secrets...)
	if utf8.RuneCountInString(text) > SummaryLimit {
		runes := []rune(text)
		text = string(runes[:SummaryLimit]) + "…"
	}
	if text == "" {
		return "（空）"
	}
	return text
}

// secretQueryNames 是“明确的密钥参数名”（规范化后比较：小写、去掉 - _ .）。
// 只有命中这张表的参数才会被自动拆成鉴权密钥；普通参数（lang、region、sessionId……）不会被误拆。
var secretQueryNames = map[string]bool{
	"key": true, "ak": true, "sk": true, "apikey": true, "accesskey": true, "secretkey": true,
	"accesstoken": true, "authtoken": true, "apitoken": true, "refreshtoken": true, "idtoken": true,
	"token": true, "authorization": true, "auth": true, "bearer": true, "secret": true,
	"appkey": true, "appsecret": true, "clientsecret": true, "password": true, "passwd": true, "pwd": true,
	"signature": true, "sign": true, "jwt": true, "xapikey": true, "xauthtoken": true,
}

// IsSensitiveQueryName 判断 query 参数名是否是明确的密钥参数名（大小写不敏感）。
func IsSensitiveQueryName(name string) bool { return secretQueryNames[normalizeQueryName(name)] }

// ExtractedAuth 是从 server_url 的 query 中拆出来的密钥。
type ExtractedAuth struct {
	ParamName string
	Secret    string
	// Template 是推断出的值模板：值带 "Bearer " 前缀时为 Bearer 模板（百度 AppBuilder 形态），否则原样。
	Template string
}

// SplitURLSecrets 把 server_url 里的明文密钥拆出来：返回去掉密钥参数后的干净 URL 与拆出的鉴权。
// URL 中没有敏感参数时 extracted 为 nil。出现多个敏感参数时拒绝（无法确定哪个是鉴权）。
func SplitURLSecrets(raw string) (string, *ExtractedAuth, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", nil, errBadURL
	}
	if u.RawQuery == "" {
		return u.String(), nil, nil
	}
	var extracted *ExtractedAuth
	var keep []string
	for _, pair := range strings.Split(u.RawQuery, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		name, e1 := url.QueryUnescape(k)
		val, e2 := url.QueryUnescape(v)
		if e1 != nil || e2 != nil || !IsSensitiveQueryName(name) {
			keep = append(keep, pair)
			continue
		}
		if val == "" {
			continue
		}
		if extracted != nil {
			return "", nil, errMultiSecret
		}
		extracted = &ExtractedAuth{ParamName: name, Secret: val, Template: TemplateRaw}
		if len(val) > 7 && strings.EqualFold(val[:7], "bearer ") {
			extracted.Secret = strings.TrimSpace(val[7:])
			extracted.Template = TemplateBearer
		}
		if extracted.Secret == "" {
			return "", nil, errBadURL
		}
	}
	u.RawQuery = strings.Join(keep, "&")
	return u.String(), extracted, nil
}

// secretForms 返回一个密钥在 URL / 日志 / 错误里可能出现的各种编码形态（长的优先，避免短形态把长形态切碎）：
// 原文、query 转义、路径段转义，以及它们的二次编码（如服务端再次转义了 %）。
func secretForms(secret string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	base := []string{secret, url.QueryEscape(secret), url.PathEscape(secret)}
	for _, b := range base {
		add(b)
		add(url.QueryEscape(b))
		add(url.PathEscape(b))
	}
	// 按长度降序，先替换长形态。
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if len(out[j]) > len(out[i]) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// RedactPathSecret 把 URL 路径里与已知密钥吻合的整段替换为 ***（任何编码形态）。
// 用于“已经替换成真实密钥的 URL”万一进入展示 / 日志的兜底；正常路径下展示与日志永远使用占位形态。
func RedactPathSecret(raw string, secrets ...string) string {
	out := raw
	for _, secret := range secrets {
		if len(strings.TrimSpace(secret)) < 4 {
			continue
		}
		for _, form := range secretForms(secret) {
			out = strings.ReplaceAll(out, form, redacted)
		}
	}
	return out
}
