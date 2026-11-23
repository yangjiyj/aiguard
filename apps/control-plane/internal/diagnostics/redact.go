package diagnostics

import (
	"regexp"
	"strings"
)

const redacted = "<redacted>"

var (
	pemBeginRe = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----`)
	pemEndRe   = regexp.MustCompile(`-----END [A-Z ]*PRIVATE KEY( BLOCK)?-----`)
	urlUserRe  = regexp.MustCompile(`//[^/@\s]+:[^@\s]*@`)
	headerRe   = regexp.MustCompile(`(?i)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token)\s*):.*$`)
	bearerRe   = regexp.MustCompile(`(?i)\bbearer[ \t]+[A-Za-z0-9._~+/=-]+`)
	basicRe    = regexp.MustCompile(`(?i)\bbasic[ \t]+([A-Za-z0-9._~+/=-]+)`)
	skRe       = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{4,}`)
	kvRe       = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.-]*)([ \t]*=[ \t]*)("[^"]*"|'[^']*'|[^\s,;&"']+)`)
	jsonKVRe   = regexp.MustCompile(`("[A-Za-z_][A-Za-z0-9_.-]*"[ \t]*:[ \t]*)"(?:[^"\\]|\\.)*"`)
	jsonKeyRe  = regexp.MustCompile(`^"([A-Za-z_][A-Za-z0-9_.-]*)"`)
	plainWord  = regexp.MustCompile(`^[A-Za-z][a-z]*$`)
	sensitiveK = regexp.MustCompile(`PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|APIKEY|API_KEY|AUTHKEY|_KEY|^KEY|KEY$|PRIVATE|CREDENTIAL|HMAC|SALT|AUTHORIZATION|COOKIE`)
)

// sensitiveKey 判断 KEY=VALUE 中的键名是否指向敏感值。
// 排除计数类（max_tokens、prompt_tokens）与非密钥的标识类（key_prefix、key_id）。
func sensitiveKey(k string) bool {
	u := strings.ToUpper(k)
	if strings.HasSuffix(u, "TOKENS") || strings.Contains(u, "KEY_PREFIX") ||
		strings.Contains(u, "KEY_ID") || strings.Contains(u, "KEY_NAME") {
		return false
	}
	return sensitiveK.MatchString(u)
}

// Redact 对文本脱敏：私钥块、URL 口令、敏感请求头、Bearer/Basic、sk- 密钥、
// 键名含 PASSWORD/SECRET/TOKEN/KEY/HMAC 等的 KEY=VALUE 与 JSON 字段。规则参照 diagnose.sh。
func Redact(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	inKey := false
	for _, line := range lines {
		if inKey {
			if pemEndRe.MatchString(line) {
				inKey = false
				out = append(out, pemEndRe.FindString(line))
			}
			continue
		}
		if pemBeginRe.MatchString(line) {
			out = append(out, pemBeginRe.FindString(line)+" "+redacted)
			if !pemEndRe.MatchString(line) {
				inKey = true
			}
			continue
		}
		out = append(out, redactLine(line))
	}
	return strings.Join(out, "\n")
}

func redactLine(line string) string {
	line = urlUserRe.ReplaceAllString(line, "//"+redacted+"@")
	if m := headerRe.FindStringSubmatch(line); m != nil {
		return strings.TrimRight(m[1], " \t") + ": " + redacted
	}
	line = skRe.ReplaceAllString(line, "sk-"+redacted)
	line = bearerRe.ReplaceAllString(line, "Bearer "+redacted)
	line = basicRe.ReplaceAllStringFunc(line, func(m string) string {
		tok := basicRe.FindStringSubmatch(m)[1]
		// 普通英文单词（Basic information）不是凭据。
		if len(tok) < 8 || plainWord.MatchString(tok) {
			return m
		}
		return "Basic " + redacted
	})
	line = jsonKVRe.ReplaceAllStringFunc(line, func(m string) string {
		sub := jsonKVRe.FindStringSubmatch(m)
		key := jsonKeyRe.FindStringSubmatch(sub[1])
		if key != nil && sensitiveKey(key[1]) {
			return sub[1] + `"` + redacted + `"`
		}
		return m
	})
	line = kvRe.ReplaceAllStringFunc(line, func(m string) string {
		sub := kvRe.FindStringSubmatch(m)
		if sensitiveKey(sub[1]) {
			return sub[1] + sub[2] + redacted
		}
		return m
	})
	return line
}
