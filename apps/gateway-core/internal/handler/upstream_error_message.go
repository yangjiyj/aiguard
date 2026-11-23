package handler

import (
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

// 客户端只允许请求类错误透传定点遮盖后的原文；账号类错误返回中文解释。
const maxClientUpstreamErrorRunes = 1000

// 净化前先把输入收敛到有界长度，避免超大 message 拖慢正则；超出时回退到最后一个空白，不留半截密钥。
const maxClientUpstreamErrorScanRunes = 4000

// clientErrorPassthroughStatuses 是允许透传上游文案的状态码白名单。
var clientErrorPassthroughStatuses = map[int]struct{}{
	http.StatusBadRequest:            {},
	http.StatusNotFound:              {},
	http.StatusRequestEntityTooLarge: {},
	http.StatusUnprocessableEntity:   {},
}

// clientErrorSensitiveWords 命中任一词时仅对客户端改用中文解释，审计仍保留原文；这类文案描述的是
// 网关账号、额度、计费或凭据状态，对终端客户既不可行动，也可能暴露上游账号信息。
var clientErrorSensitiveWords = []string{
	"api key", "api_key", "apikey", "credit", "balance", "quota", "billing", "organization",
	"余额", "额度", "令牌", "欠费", "充值",
}

// 点分标识符无法靠形态与字段路径区分（relay.internal.corp 与 thinking.type.disabled 形态相同），
// 所以只在末段「像域名后缀」时才当主机名替换：2 位字母（国家码）、常见 gTLD、内部 / 集群后缀。
// 末段是常见文件扩展名（app.js、config.yaml）或不在这些集合里（thinking.type.disabled 的 disabled、
// output_config.effort 的 effort）时保留，模型名（claude-3.5-sonnet）、版本号（2.1.280）同理不受影响。
var clientErrorHostSuffixes = map[string]struct{}{
	"com": {}, "net": {}, "org": {}, "edu": {}, "gov": {}, "mil": {}, "int": {}, "info": {}, "biz": {}, "xyz": {},
	"cloud": {}, "tech": {}, "dev": {}, "app": {}, "online": {}, "site": {}, "store": {}, "pro": {}, "top": {},
	"local": {}, "localhost": {}, "internal": {}, "intranet": {}, "lan": {}, "corp": {}, "svc": {}, "arpa": {}, "home": {}, "test": {},
}

// 2 位字母后缀按国家码处理，但这些同时是常见文件扩展名 / 语言后缀，保留不替换。
var clientErrorTwoLetterKeep = map[string]struct{}{
	"js": {}, "ts": {}, "py": {}, "sh": {}, "md": {}, "go": {}, "rs": {}, "rb": {}, "pl": {}, "cs": {}, "cc": {}, "hh": {},
	"kt": {}, "gz": {}, "xz": {}, "7z": {}, "db": {}, "so": {}, "ps": {}, "pb": {}, "tf": {}, "mk": {}, "ex": {},
}

var (
	clientErrorURLPattern    = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]*://[^\s"'<>)\]]+`)
	clientErrorARNPattern    = regexp.MustCompile(`(?i)\barn:aws[a-z\-]*:[^\s"'<>,;)\]]*`)
	clientErrorBearerPattern = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]+`)
	// org-xxx / proj-xxx / sk-xxx（含 sk-ant-xxx）：不论长度都视为密钥或组织标识。
	// \b 保证只匹配独立词开头，task-1、disk-full、risk-score 不受影响。
	clientErrorPrefixedKeyPattern = regexp.MustCompile(`(?i)\b(?:org|proj|sk)-[A-Za-z0-9_\-]+`)
	// 32 位及以上的连续字母数字串基本都是令牌 / 哈希 / 密钥，不是自然语言或模型名。
	clientErrorLongTokenPattern = regexp.MustCompile(`\b[A-Za-z0-9_\-]{32,}\b`)
	// [addr]:port 形式的 IPv6；括号内必须能被解析成 IPv6 才替换。
	clientErrorBracketIPv6Pattern = regexp.MustCompile(`\[[0-9A-Fa-f:.]+\](?::\d{1,5})?`)
	// 裸 IPv6 候选：只收十六进制、冒号、点，且至少含一个冒号；是否真是 IPv6 交给 netip 判断，
	// 所以 12:30:45 这样的时间、std::vector 这样的标识符不会被误替换。
	clientErrorIPv6CandidatePattern = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?:%[A-Za-z0-9_.\-]+)?`)
	clientErrorIPv4Pattern          = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b`)
	// 带点的主机名或 localhost 加端口；不含点的 "field:123" 之类不会被误伤。
	clientErrorHostPortPattern = regexp.MustCompile(`(?i)\b(?:(?:[a-z0-9\-]+\.)+[a-z0-9\-]+|localhost):\d{2,5}\b`)
	// 点分 token 候选：末段是否在 clientErrorInternalSuffixes 内由代码判断。
	clientErrorDottedPattern = regexp.MustCompile(`[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+`)
	// 上游对过旧 Claude Code 的拒绝文案，例如：
	// "Claude Code 2.1.241 does not support this model; version 2.1.280 or newer is required"
	clientErrorClaudeCodeTooOld = regexp.MustCompile(`Claude Code (\d+(?:\.\d+)*) does not support this model; version (\d+(?:\.\d+)*) or newer is required`)
)

// clientUpstreamErrorMessage 返回应展示给客户端的错误文案；不适合透传时返回 fallback。
func clientUpstreamErrorMessage(upstreamErr *provider.UpstreamHTTPError, fallback string) string {
	if upstreamErr == nil {
		return fallback
	}
	detail := parseUpstreamError(upstreamErr.Body)
	if _, allowed := clientErrorPassthroughStatuses[upstreamErr.StatusCode]; !allowed {
		return upstreamErrorHint(upstreamErr.StatusCode, detail)
	}
	raw := detail.Message
	if raw == "" {
		return fallback
	}
	if containsSensitiveClientErrorWord(raw) {
		return upstreamErrorHint(upstreamErr.StatusCode, detail)
	}
	message := sanitizeClientUpstreamMessage(raw)
	if message == "" {
		return fallback
	}
	if match := clientErrorClaudeCodeTooOld.FindStringSubmatch(message); match != nil {
		return "当前 Claude Code 版本 " + match[1] + " 不支持该模型，请升级到 " + match[2] + " 或更高版本（上游原文：" + message + "）"
	}
	return message
}

func containsSensitiveClientErrorWord(message string) bool {
	lowered := strings.ToLower(strings.Join(strings.Fields(message), " "))
	for _, word := range clientErrorSensitiveWords {
		if strings.Contains(lowered, word) {
			return true
		}
	}
	return false
}

// upstreamJSONErrorMessage 保留旧入口，统一使用多形态解析。
func upstreamJSONErrorMessage(body []byte) string {
	return parseUpstreamError(body).Message
}

func sanitizeClientUpstreamMessage(message string) string {
	runes := []rune(message)
	if len(runes) > maxClientUpstreamErrorScanRunes {
		runes = runes[:maxClientUpstreamErrorScanRunes]
		if cut := strings.LastIndexAny(string(runes), " \t\r\n"); cut > 0 {
			runes = []rune(string(runes)[:cut])
		}
	}
	text := strings.Join(strings.Fields(string(runes)), " ")
	text = clientErrorURLPattern.ReplaceAllString(text, "<url>")
	text = clientErrorARNPattern.ReplaceAllString(text, "<arn>")
	text = clientErrorBearerPattern.ReplaceAllString(text, "<redacted:secret>")
	text = redactMCPResultString(text)
	text = clientErrorPrefixedKeyPattern.ReplaceAllString(text, "<redacted:secret>")
	text = clientErrorLongTokenPattern.ReplaceAllString(text, "<redacted:secret>")
	text = redactIPv6Addresses(text)
	text = clientErrorIPv4Pattern.ReplaceAllString(text, "<ip>")
	text = clientErrorHostPortPattern.ReplaceAllString(text, "<host>")
	text = redactDottedHostnames(text)
	text = strings.TrimSpace(text)
	if out := []rune(text); len(out) > maxClientUpstreamErrorRunes {
		text = string(out[:maxClientUpstreamErrorRunes-3]) + "..."
	}
	return text
}

func isClientErrorWordByte(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_' || b == '-'
}

// replaceMatchesWhere 只替换通过 shouldRedact 判定的匹配，用来补 RE2 没有的前后断言。
func replaceMatchesWhere(text string, pattern *regexp.Regexp, shouldRedact func(text string, start, end int) bool, replacement string) string {
	locations := pattern.FindAllStringIndex(text, -1)
	if len(locations) == 0 {
		return text
	}
	var builder strings.Builder
	last := 0
	for _, location := range locations {
		if !shouldRedact(text, location[0], location[1]) {
			continue
		}
		builder.WriteString(text[last:location[0]])
		builder.WriteString(replacement)
		last = location[1]
	}
	builder.WriteString(text[last:])
	return builder.String()
}

// redactIPv6Addresses 替换 [addr]:port 与裸 IPv6（含 ::1、IPv4 映射）。
func redactIPv6Addresses(text string) string {
	text = clientErrorBracketIPv6Pattern.ReplaceAllStringFunc(text, func(match string) string {
		inner := match[1:strings.Index(match, "]")]
		if address, err := netip.ParseAddr(inner); err == nil && address.Is6() {
			return "<ip>"
		}
		return match
	})
	return replaceMatchesWhere(text, clientErrorIPv6CandidatePattern, func(text string, start, end int) bool {
		if start > 0 && isClientErrorWordByte(text[start-1]) {
			return false
		}
		if end < len(text) && isClientErrorWordByte(text[end]) {
			return false
		}
		address, err := netip.ParseAddr(text[start:end])
		return err == nil && address.Is6()
	}, "<ip>")
}

// redactDottedHostnames 替换末段在内部后缀词表内的点分主机名（不带端口也替换）。
func redactDottedHostnames(text string) string {
	return replaceMatchesWhere(text, clientErrorDottedPattern, func(text string, start, end int) bool {
		if start > 0 && (isClientErrorWordByte(text[start-1]) || text[start-1] == '.') {
			return false
		}
		if end < len(text) && isClientErrorWordByte(text[end]) {
			return false
		}
		token := text[start:end]
		suffix := strings.ToLower(token[strings.LastIndex(token, ".")+1:])
		if _, known := clientErrorHostSuffixes[suffix]; known {
			return true
		}
		// 复合后缀 *.co.uk / *.com.cn 的末段是 uk / cn，落入下面的国家码规则。
		if _, keep := clientErrorTwoLetterKeep[suffix]; keep {
			return false
		}
		return len(suffix) == 2 && suffix[0] >= 'a' && suffix[0] <= 'z' && suffix[1] >= 'a' && suffix[1] <= 'z'
	}, "<host>")
}
