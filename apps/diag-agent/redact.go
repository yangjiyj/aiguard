package main

import (
	"regexp"
	"strings"
)

// 规则复制自 deploy/docker-compose/diagnose.sh 的 sanitize_sensitive，
// 另补两条 JSON 键值与 URL 查询参数规则（日志里常见）。

const maxLineBytes = 16 * 1024

var (
	pemBeginRe   = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	pemEndRe     = regexp.MustCompile(`-----END [A-Z ]*PRIVATE KEY-----`)
	urlCredRe    = regexp.MustCompile(`//[^/@\s]+:[^@\s]*@`)
	sensHeaderRe = regexp.MustCompile(`(?i)^[ \t]*(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token)[ \t]*:`)
	bearerRe     = regexp.MustCompile(`(?i)bearer[ \t]+[A-Za-z0-9._~+/=-]+`)
	basicRe      = regexp.MustCompile(`(?i)basic[ \t]+[A-Za-z0-9._~+/=-]+`)
	kvLineRe     = regexp.MustCompile(`^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=`)
	sensKeyRe    = regexp.MustCompile(`(PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|AUTHKEY|_KEY|KEY$|PRIVATE|CREDENTIAL|LICENSE|HMAC|SALT|PASS)`)
	jsonPairRe   = regexp.MustCompile(`(?i)("[^"]*(?:password|passwd|secret|token|api_?key|authorization|credential|hmac|private|salt)[^"]*"[ \t]*:[ \t]*)"(?:[^"\\]|\\.)*"`)
	queryPairRe  = regexp.MustCompile(`(?i)\b([A-Za-z0-9_]*(?:password|passwd|secret|token|apikey|api_key|credential|hmac)[A-Za-z0-9_]*)=[^&\s"']+`)
)

// redactor 逐行脱敏，PEM 私钥块跨行，所以带状态。
type redactor struct{ inKey bool }

// line 返回脱敏后的行；keep=false 表示整行应丢弃。
func (r *redactor) line(s string) (string, bool) {
	if len(s) > maxLineBytes {
		s = s[:maxLineBytes] + "...<截断>"
	}
	if pemBeginRe.MatchString(s) {
		r.inKey = true
		return "-----BEGIN PRIVATE KEY----- <redacted>", true
	}
	if r.inKey {
		if pemEndRe.MatchString(s) {
			r.inKey = false
			return "-----END PRIVATE KEY-----", true
		}
		return "", false
	}
	s = urlCredRe.ReplaceAllString(s, "//<redacted>@")
	if sensHeaderRe.MatchString(s) {
		if i := strings.Index(s, ":"); i >= 0 {
			s = s[:i] + ": <redacted>"
		}
	}
	s = bearerRe.ReplaceAllString(s, "Bearer <redacted>")
	s = basicRe.ReplaceAllString(s, "Basic <redacted>")
	if kvLineRe.MatchString(s) {
		eq := strings.Index(s, "=")
		key := s[:eq]
		if sensKeyRe.MatchString(strings.ToUpper(key)) {
			return key + "=<redacted>", true
		}
	}
	s = jsonPairRe.ReplaceAllString(s, `${1}"<redacted>"`)
	s = queryPairRe.ReplaceAllString(s, "${1}=<redacted>")
	return s, true
}

// redactText 对多行文本脱敏。
func redactText(s string) string {
	var r redactor
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if v, ok := r.line(strings.TrimRight(l, "\r")); ok {
			out = append(out, v)
		}
	}
	return strings.Join(out, "\n")
}

// 漂移比对中判定"敏感环境变量"的规则（沿用 drift4.sh）。
var driftSensRe = regexp.MustCompile(`(?i)SECRET|PASSWORD|TOKEN|KEY|DATABASE_URL|CREDENTIAL|DSN|PASS|HMAC|SALT|LICENSE`)

func isSensitiveEnvKey(k string) bool { return driftSensRe.MatchString(k) }
