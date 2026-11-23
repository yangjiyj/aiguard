package handler

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// 2.9.22 起（用户 11-17 定）告警前后文按原样落库，“凭据明文不进告警库”作废。本文件的打码只用于两处：
// 语义类、运行类命中落库的 evidence_context（形态与 2.9.21 相同），以及按 2.9.21 落库内容算证据身份
// （putFindingEvidence），保证升级前后同一命中的证据身份不变。下面是 2.9.21 的打码口径，不要改动，
// 改了会让升级前后的证据身份对不上。
//
// 凭据类命中的告警上下文：保留命中点周围的正常文字（含 key=/secret=/password= 这类判断线索），
// 把凭据本体替换成「<已隐藏 N 字>」。
//
// 为什么需要：原先落库的 evidence_context 对所有 finding 都只是 "<category>:<MASKED>" 占位，
// 管理员点进告警只能看到一句"已脱敏"，无法判断是真凭据还是示例串。
//
// 引擎给了秘密本体（secret_text）的类别都生效；没给时只有凭据类按旧口径处理，私钥类只存占位；
// 其它类别（邮箱、涉密词等）沿用原有占位，不扩大落库内容。
// 任何一步没把握（无原文、原文太短、上下文里找不到原文）都退回占位，宁可信息少也不冒泄露风险。

const (
	evidenceContextWindow  = 120 // 命中点前后各保留的字符数
	evidenceContextMinSecr = 6   // 短于此长度的"凭据"不做替换：容易把普通单词整批打码
)

var credentialEvidenceCategories = map[string]bool{
	"cloud_credential": true, "plain_password": true, "openai_key": true, "anthropic_key": true,
	"generic_api_key": true, "github_token": true, "aws_access_key": true, "aws_secret_key": true,
	"jwt_token": true, "ssh_private_key": true, "code_leak_database_url": true,
	"code_leak_password_in_code": true, "code_leak_api_key_leak": true, "code_leak_token_leak": true,
	"debug_secret_template": true,
}

func isCredentialEvidence(f SecurityFinding) bool {
	return credentialEvidenceCategories[strings.ToLower(strings.TrimSpace(f.Category))]
}

const hiddenMarkerPrefix = "<已隐藏"

// 私钥类命中的是头行，正文在头行后面。旧引擎不告诉网关正文在哪，这几类只能不存前后文。
var privateKeyMarkerCategories = map[string]bool{
	"ssh_private_key": true, "openssh_private_key": true, "private_key": true,
}

// redactedEvidenceContext 返回 2.9.21 口径的打码 evidence_context（语义类落库、证据身份计算用）。
//   - 引擎给了秘密本体（SecretText）：把前后文里的秘密本体换成「<已隐藏 N 字>」，标记和周围文字保留。
//   - 引擎没给（旧版本）：凭据类沿用“命中文本就是凭据”的口径；私钥类只存占位。
//   - 任何一步没把握都退回占位，宁可信息少也不泄露。
func redactedEvidenceContext(f SecurityFinding) string {
	fallback := redactedFindingEvidence(f)
	category := strings.ToLower(strings.TrimSpace(f.Category))
	secret := strings.TrimSpace(f.SecretText)
	if secret == "" {
		if !isCredentialEvidence(f) || privateKeyMarkerCategories[category] {
			return fallback
		}
		secret = strings.TrimSpace(f.RawEvidence)
	}
	ctx := f.EvidenceContext
	if utf8.RuneCountInString(secret) < evidenceContextMinSecr || ctx == "" || !strings.Contains(ctx, secret) {
		return fallback
	}
	masked := strings.ReplaceAll(ctx, secret, fmt.Sprintf("%s %d 字>", hiddenMarkerPrefix, utf8.RuneCountInString(secret)))
	if strings.Contains(masked, secret) {
		return fallback
	}
	bounded := boundAroundMask(masked)
	// 先检查再做保底扫描：保底扫描会把别的行换成标记，影响“第一个标记”的位置。
	if containsForeignPrivateKey(category, bounded) {
		return fallback
	}
	// 先扫长串再做补充遮盖：长串里夹的数字不该被第 3 步切碎留下前半段。
	return scrubContextSecrets(hideLongTokenRuns(bounded))
}

// containsForeignPrivateKey 判断窗口里是否还夹着秘密本体之外的私钥（引擎只给一把的正文）。
//   - 私钥类：BEGIN 出现多次，或第一个隐藏标记之前出现 END。
//   - 其他类别：只要出现 PRIVATE KEY-----（BEGIN 行或 END 行）。
func containsForeignPrivateKey(category, bounded string) bool {
	if !privateKeyMarkerCategories[category] {
		return strings.Contains(bounded, "PRIVATE KEY-----")
	}
	first := strings.Index(bounded, hiddenMarkerPrefix)
	return strings.Count(bounded, "-----BEGIN ") > 1 || (first >= 0 && strings.Contains(bounded[:first], "-----END "))
}

var longTokenRun = regexp.MustCompile(`[A-Za-z0-9+/_=]{16,}`)

// hideLongTokenRuns 是保底：前后文里除了已知秘密，还可能挨着别的密钥、令牌或第二把私钥的正文。
// 16 位以上、同时含字母和数字的连续串一律隐藏。会误遮哈希和长编号；前后文只用于辅助判断，可以接受。
func hideLongTokenRuns(text string) string {
	return longTokenRun.ReplaceAllStringFunc(text, func(run string) string {
		hasDigit, hasLetter := false, false
		for _, r := range run {
			switch {
			case r >= '0' && r <= '9':
				hasDigit = true
			case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
				hasLetter = true
			}
		}
		if !hasDigit || !hasLetter {
			return run
		}
		return fmt.Sprintf("%s %d 字>", hiddenMarkerPrefix, utf8.RuneCountInString(run))
	})
}

// isTokenRune 与 longTokenRun 的字符集一致。
func isTokenRune(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '_' || r == '='
}

// boundAroundMask 只保留第一个打码标记前后各 evidenceContextWindow 个字符。
func boundAroundMask(masked string) string {
	runes := []rune(masked)
	marker := []rune(hiddenMarkerPrefix)
	at := -1
	for i := 0; i+len(marker) <= len(runes); i++ {
		if string(runes[i:i+len(marker)]) == string(marker) {
			at = i
			break
		}
	}
	if at < 0 {
		return masked
	}
	start := at - evidenceContextWindow
	if start < 0 {
		start = 0
	}
	end := at + evidenceContextWindow + 12
	if end > len(runes) {
		end = len(runes)
	}
	// 窗口边界切在令牌中间时，残段可能不足 16 位而逃过 hideLongTokenRuns：把边界上的那段令牌整段丢掉。
	// 丢掉的是窗口外本来就不保存的内容，不写标记；以第一个隐藏标记为中心的定位不变。
	if start > 0 && isTokenRune(runes[start-1]) && isTokenRune(runes[start]) {
		for start < at && isTokenRune(runes[start]) {
			start++
		}
	}
	if end < len(runes) && isTokenRune(runes[end-1]) && isTokenRune(runes[end]) {
		for end > at && isTokenRune(runes[end-1]) {
			end--
		}
	}
	prefix, suffix := "", ""
	if start > 0 {
		prefix = "…"
	}
	if end < len(runes) {
		suffix = "…"
	}
	return prefix + string(runes[start:end]) + suffix
}

const secretFieldNames = `password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|authorization|密码|口令|密钥|秘钥|令牌`

// 取值：已是标记 | 双引号到闭引号（同一行内）| 单引号到闭引号 | 不带引号取到空白、引号、逗号、分号、右括号。
const secretValuePattern = `<已隐藏 \d+ 字>|"[^"\n]*"?|'[^'\n]*'?|[^\s"',;)]+`

var (
	connStringPassword = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@]*:)(\S*)@`)
	fieldValueAssign   = regexp.MustCompile(`(?i)((?:` + secretFieldNames + `)(?:\s*["']?\s*(?:=>|[=:：＝])|\(\s*|["']\s*,\s*)\s*(?:(?:bearer|basic|token)\s+)?)(` + secretValuePattern + `)`)
	cliSecretFlag      = regexp.MustCompile(`(?i)(--?(?:` + secretFieldNames + `)\s+)(` + secretValuePattern + `)`)
	bearerValue        = regexp.MustCompile(`(?i)(\bbearer\s+)(` + secretValuePattern + `)`)
	xmlSecretElement   = regexp.MustCompile(`(?i)(<[\w.-]*(?:` + secretFieldNames + `)[\w.-]*(?:\s[^>]*)?>)(<!\[CDATA\[.*?\]\]>|[^<]+)(</)`)
	goDSNPassword      = regexp.MustCompile(`([A-Za-z0-9_.-]*:)([^\s@"'/]+)(@(?:tcp|unix)\()`)
	longDigitRun       = regexp.MustCompile(`(^|[^0-9])((?:\+86[ -]?)?\d(?:[ -]?\d){6,})`)
	markerTail         = regexp.MustCompile(`<已隐藏 (\d+) 字>([A-Za-z0-9+/=._-]+)`)
)

func hiddenMarker(n int) string { return fmt.Sprintf("%s %d 字>", hiddenMarkerPrefix, n) }

// maskValueAfterPrefix 把「前缀 + 取值」里的取值换成隐藏标记；取值已是标记的原样保留。
func maskValueAfterPrefix(re *regexp.Regexp, text string) string {
	return re.ReplaceAllStringFunc(text, func(m string) string {
		sub := re.FindStringSubmatch(m)
		if strings.HasPrefix(sub[2], hiddenMarkerPrefix) {
			return m
		}
		return sub[1] + hiddenMarker(utf8.RuneCountInString(sub[2]))
	})
}

// scrubContextSecrets 是落库前对前后文的补充遮盖：引擎只标出一个秘密本体，窗口里还可能有别的。
//  1. 连接串 scheme://[user]:密码@ 的密码换成 ****（用户名可空，取到最后一个 @ 之前，不跨空白）；
//     Go MySQL 驱动的 user:密码@tcp(host) 写法同样处理。
//  2. 常见字段名（password、token、api_key、密码、口令 等）后面的取值换成隐藏标记：
//     分隔符支持 = : ： ＝ =>，也支持 setPassword("值") 的括号、Setenv("X_PASSWORD", "值") 的「闭引号加逗号」，
//     （逗号只在字段名带闭引号时才算分隔符，避免误遮 “user, password, token” 这类普通文字），命令行 --password 值 和 Bearer/Basic/token 值；
//     取值以引号开头时取到同一行内的闭引号，不带引号时取到空白、引号、逗号、分号、右括号；
//     XML 里 <password>值</password> 同样处理，标签名可带前后缀（<db_password>、<jdbc.password>）、属性和 CDATA。
//  3. 7 位以上的数字串（可含空格、连字符、+86，前面不紧挨数字）整段隐藏：卡号、手机号、证件号。
//  4. 紧跟在隐藏标记后面的令牌字符并入隐藏，兜住被引擎在点号等处截断的密钥后半段；遇到 ----- 停止。
//
// 前后文只用于辅助判断，宁可多遮：日期（如 2026-11-14）、长订单号、UUID 末段的纯数字也会被遮掉。
// 调用方先做 hideLongTokenRuns，再调本函数：否则长密钥里的 10 位数字会先被第 3 步切走，留下前半段字母。
//
// 已知局限（不修）：
//   - 不带引号的值里含逗号（password=ab,cd9Q）只遮到逗号，因为把逗号算进值会吞掉 JSON 的下一个字段；
//   - YAML 块标量（password: > 或 | 下一行才是值）；
//   - 不在字段名清单里的写法（pass=、「密码是 xxx」）；
//   - 命令行的 -pSh0rt9（短选项与值连写）；
//   - 只用空格分隔的写法（.netrc 的 password Sh0rt9）、转义引号后再跟空格的值；
//   - DSN 密码里本身带 @（root:p@ss9@tcp(db)/x）、省略地址的写法（root:Sh0rt9@/dbname）。
func scrubContextSecrets(text string) string {
	text = connStringPassword.ReplaceAllString(text, "${1}****@")
	text = goDSNPassword.ReplaceAllString(text, "${1}****${3}")
	text = maskValueAfterPrefix(fieldValueAssign, text)
	text = maskValueAfterPrefix(cliSecretFlag, text)
	text = maskValueAfterPrefix(bearerValue, text)
	text = xmlSecretElement.ReplaceAllStringFunc(text, func(m string) string {
		sub := xmlSecretElement.FindStringSubmatch(m)
		return sub[1] + hiddenMarker(utf8.RuneCountInString(sub[2])) + sub[3]
	})
	text = longDigitRun.ReplaceAllStringFunc(text, func(m string) string {
		sub := longDigitRun.FindStringSubmatch(m)
		return sub[1] + hiddenMarker(utf8.RuneCountInString(sub[2]))
	})
	return markerTail.ReplaceAllStringFunc(text, func(m string) string {
		sub := markerTail.FindStringSubmatch(m)
		n, _ := strconv.Atoi(sub[1])
		tail, rest := sub[2], ""
		if i := strings.Index(tail, "-----"); i >= 0 {
			tail, rest = tail[:i], tail[i:]
		}
		if tail == "" {
			return m
		}
		return hiddenMarker(n+utf8.RuneCountInString(tail)) + rest
	})
}
