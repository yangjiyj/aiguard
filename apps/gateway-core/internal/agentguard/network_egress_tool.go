package agentguard

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// 2.9.21：不可逆网络外发（W5 5.6 D3）仍按 2.9.20 的判法（isIrreversibleNetworkTool），
// 这里只放现场误拦写法的一条窄例外。满足例外、同时满足全部共同前提，才不算不可逆外发；
// 拿不准的一律照 2.9.20 算外发。第二轮的例外 (b)（只读动词开头）、(c)（已知非外发词）
// 第三轮已删掉，这两类工具名回到 2.9.20 判法。
//
// 例外 (a)：工具名里 upload/post/put/request/curl 的子串命中只来自合并请求、拉取请求词组
// （mergeRequestPhrases）。目前创建和查看都放开（mergeRequestActionIsReadOnly 已备好，暂不接入）。
//
// 共同前提（narrowEgressException）：
//   - 参数个数、嵌套深度在扫描上限内（egressArgumentsFullyScanned）；
//   - 参数里没有外发目标（egressExceptionHasDestination）；
//   - method/http_method 没写，或是 GET、HEAD、OPTIONS；
//   - 工具名整词里没有明确的发送类动词（egressGuardWords）；
//   - 参数（含嵌套、键名和值）看起来不带凭据（egressArgumentsLookCredentialLike，第四轮由
//     “没有高可信密钥”扩成八条规则，见 egressCredentialLikeRule）。

// legacyEgressNameFragments 是 2.9.20 按工具名子串判外发的词。
var legacyEgressNameFragments = []string{"upload", "post", "put", "request", "curl"}

// mergeRequestPhrases：例外 (a) 认的合并请求、拉取请求词组（与工具名小写后比较）。
var mergeRequestPhrases = []string{"merge_request", "pull_request", "merge-request", "mergerequest", "pullrequest"}

// egressGuardWords：工具名整词里出现这些发送类动词时，例外不适用（复数也算）。
// post、put、upload、curl、request 不在其中，它们由例外自己处理。
var egressGuardWords = map[string]bool{
	"send": true, "sendmail": true, "email": true, "mail": true, "smtp": true, "message": true,
	"reply": true, "submit": true, "notify": true, "forward": true, "share": true, "publish": true,
	"push": true, "webhook": true, "sms": true, "deliver": true, "dispatch": true, "transmit": true,
	"relay": true, "transfer": true, "tweet": true, "broadcast": true, "paste": true,
	"exfil": true, "exfiltrate": true, "wget": true, "scp": true, "sftp": true, "ftp": true, "rsync": true,
}

// egressDestinationKeyWords：参数键名拆词后含这些词，值像网络地址就算外发目标。
var egressDestinationKeyWords = map[string]bool{
	"url": true, "urls": true, "uri": true, "uris": true, "endpoint": true, "endpoints": true,
	"host": true, "hosts": true, "hostname": true, "hostnames": true, "server": true, "servers": true,
	"remote": true, "destination": true, "destinations": true, "dest": true, "domain": true, "domains": true,
	"recipient": true, "recipients": true, "to": true, "cc": true, "bcc": true, "email": true, "emails": true,
	"address": true, "addresses": true, "addr": true, "ip": true, "webhook": true, "webhooks": true,
	"callback": true, "callbacks": true,
}

// egressAlwaysDestinationKeys：2.9.20 的目标键。url/uri/endpoint/host 有非空值就算外发目标
// （值是对象也算）；target 只在值像网络地址时算（main、release/2.9.21 这类分支名不算）。
var egressAlwaysDestinationKeys = map[string]bool{"url": true, "uri": true, "endpoint": true, "host": true}

func narrowEgressException(toolName string, args map[string]any) bool {
	// 例外 (a)。以后只放查看类时，把下一行改成
	//   if !nameHitsOnlyMergeRequestPhrase(strings.ToLower(toolName)) || !mergeRequestActionIsReadOnly(toolName) {
	if !nameHitsOnlyMergeRequestPhrase(strings.ToLower(toolName)) {
		return false
	}
	return egressArgumentsFullyScanned(args) && egressExceptionReadMethod(args) && !egressExceptionHasDestination(args) &&
		!hasEgressGuardWord(toolName) && !egressArgumentsLookCredentialLike(args)
}

// egressArgumentsFullyScanned：参数个数、嵌套深度都在扫描上限内（maxScannedArgumentValues、
// maxScannedArgumentDepth）。超出时无法确认没有外发目标，例外不适用。
func egressArgumentsFullyScanned(args map[string]any) bool {
	values := 0
	var walk func(value any, depth int) bool
	walk = func(value any, depth int) bool {
		switch typed := value.(type) {
		case map[string]any:
			if depth >= maxScannedArgumentDepth {
				return len(typed) == 0
			}
			for _, child := range typed {
				if !walk(child, depth+1) {
					return false
				}
			}
		case []any:
			if depth >= maxScannedArgumentDepth {
				return len(typed) == 0
			}
			for _, child := range typed {
				if !walk(child, depth+1) {
					return false
				}
			}
		case []string:
			if depth >= maxScannedArgumentDepth {
				return len(typed) == 0
			}
			values += len(typed)
		default:
			values++
		}
		return values < maxScannedArgumentValues
	}
	return walk(args, 0)
}

// 例外 (a) “参数看起来带凭据”的规则编号（egressCredentialLikeRule 的返回值）。
const (
	egressRuleScanBound   = "0-scan-bound"   // 嵌套超出扫描深度，无法确认
	egressRuleDetector    = "1-detector"     // DetectHighConfidenceSecrets 有任何发现（confirm 级也算）
	egressRuleKeyValue    = "2-key-value"    // 文本里键值形式的凭据
	egressRuleKeyName     = "2-key-name"     // 参数本身的键名含凭据词且值非空
	egressRuleBearer      = "3-bearer-basic" // Bearer/Basic 后接 16 字以上令牌
	egressRuleTokenPrefix = "4-token-prefix" // 已知令牌前缀、JWT
	egressRulePrivateKey  = "5-private-key"  // 私钥材料迹象
	egressRuleURLPassword = "6-url-password" // scheme://用户:口令@主机
	egressRuleHex         = "7-hex"          // 32 字以上十六进制，或 16 组以上冒号分隔十六进制字节
	egressRuleBase64      = "8-base64"       // 40 字以上 base64/base64url 串，大写、小写、数字都有
)

// egressCredentialKeyWords：参数键名去掉空白、- 和 _、转小写后含这些词，算凭据类键名。
var egressCredentialKeyWords = []string{
	"password", "passwd", "pwd", "passphrase", "secret", "token", "apikey", "accesskey",
	"credential", "privatekey", "auth", "cookie", "session",
}

var (
	// 规则 2：键名（可为复合名，如 aws_secret_access_key、DB_PASSWORD、"client_secret"、PrivateKey）
	// 含凭据词，后接可选引号，再接 = 或 :（两边可有空白），再接至少 6 个非空白字符。
	// api/access/private 与 key 之间允许空白、- 或 _（API Key、api-key、access_key、private_key）。
	egressCredentialKeyValuePattern = regexp.MustCompile(`(?i)(?:password|passwd|pwd|passphrase|secret|token|api[\s_-]?key|access[\s_-]?key|credential|private[\s_-]?key|auth|cookie|session)[A-Za-z0-9_.\-]*["']?\s*[:=]\s*\S{6,}`)
	// 规则 3。
	egressBearerTokenPattern = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/\-]{16,}`)
	// 规则 4：已知令牌前缀（前面不是字母数字，后接至少 8 个令牌字符）；JWT（eyJ 开头三段，每段至少
	// 8 个 base64url 字符；头和载荷都以 eyJ 开头、签名为空的未签名 JWT 也算）。
	egressTokenPrefixPattern = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(?:glpat-|gldt-|glrt-|glptt-|glsoat-|GR1348941|xox[abeoprs]-|sk_live_|rk_live_|AIza|ya29\.|npm_|pypi-|hf_|dop_v1_|shpat_|SG\.)[A-Za-z0-9_\-]{8,}`)
	egressJWTPattern         = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.`)
	// 规则 5：PEM/OpenSSH/PuTTY 私钥、openssl -text 的 privateExponent、WireGuard 的 PrivateKey =；
	// JWK 的 "kty" 与 "d" 同现另判。b3BlbnNzaC1rZXktdjE 是 openssh-key-v1 的 base64。
	egressPrivateKeyPattern = regexp.MustCompile(`PRIVATE KEY|openssh-key-v1|b3BlbnNzaC1rZXktdjE|PuTTY-User-Key-File|(?i:privateexponent)|(?i:privatekey)\s*=`)
	egressJWKTypePattern    = regexp.MustCompile(`["']kty["']`)
	egressJWKPrivatePattern = regexp.MustCompile(`["']d["']`)
	// 规则 6：scheme://用户:口令@主机（用户可为空）。
	egressURLPasswordPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://[^\s/@:]*:[^\s@]+@[^\s@]`)
	// 规则 7：连续 32 个以上十六进制字符（0x 前缀不影响），或 16 组以上冒号分隔的十六进制字节（可换行）。
	egressHexRunPattern   = regexp.MustCompile(`[0-9a-fA-F]{32,}`)
	egressHexColonPattern = regexp.MustCompile(`(?:[0-9a-fA-F]{2}:\s*){15,}[0-9a-fA-F]{2}`)
	// 规则 8：连续 40 个以上 base64 或 base64url 字符。
	egressBase64RunPattern    = regexp.MustCompile(`[A-Za-z0-9+/=]{40,}`)
	egressBase64URLRunPattern = regexp.MustCompile(`[A-Za-z0-9_\-]{40,}`)
)

// egressArgumentsLookCredentialLike：参数看起来带凭据时例外 (a) 不适用，按 2.9.20 算外发。
// 只用于例外 (a) 的前提，不改变 DetectHighConfidenceSecrets、AnalyzeDataEgress 的判定。
func egressArgumentsLookCredentialLike(args map[string]any) bool {
	return egressCredentialLikeRule(args) != ""
}

// egressCredentialLikeRule 返回参数命中的第一条“像凭据”规则，没有命中返回 ""。
// 参数全文含嵌套的键名和值、[]string、数字，值不截断；嵌套超出扫描深度时按像凭据算。规则：
//  1. DetectHighConfidenceSecrets 有任何发现，confirm 级（邮箱、手机号、身份证号）也算；
//  2. 键值形式的凭据（egressCredentialKeyValuePattern）；参数本身的键名含凭据词且值非空；
//  3. Bearer 或 Basic 后接 16 个以上字符的令牌；
//  4. 已知令牌前缀（glpat-、xoxb-、sk_live_、AIza、npm_、hf_、SG. 等）或 JWT；
//  5. 私钥材料迹象（PRIVATE KEY、openssh-key-v1、PuTTY-User-Key-File、"kty" 与 "d" 同现、
//     privateExponent、PrivateKey =）；
//  6. 带口令的连接串 scheme://用户:口令@主机；
//  7. 连续 32 个以上十六进制字符，或 16 组以上冒号分隔的十六进制字节（完整提交号、镜像摘要也算）；
//  8. 连续 40 个以上 base64 或 base64url 字符，且同时含大写、小写和数字。
func egressCredentialLikeRule(args map[string]any) string {
	var parts []string
	keyHit, tooDeep := false, false
	var walk func(value any, depth int)
	walk = func(value any, depth int) {
		if depth > maxScannedArgumentDepth {
			tooDeep = true
			return
		}
		switch typed := value.(type) {
		case nil, bool:
		case string:
			parts = append(parts, typed)
		case []string:
			parts = append(parts, typed...)
		case map[string]any:
			for key, child := range typed {
				parts = append(parts, key)
				if egressCredentialKeyName(key) && !egressArgumentEmpty(child) {
					keyHit = true
				}
				walk(child, depth+1)
			}
		case []any:
			for _, child := range typed {
				walk(child, depth+1)
			}
		case []byte:
			parts = append(parts, string(typed))
		case float64:
			parts = append(parts, strconv.FormatFloat(typed, 'f', -1, 64))
		case json.Number:
			parts = append(parts, typed.String())
		default:
			// 其他 map、切片、指针（map[string]string、[]map[string]any 等）同样逐层看键名和值。
			rv := reflect.ValueOf(typed)
			switch rv.Kind() {
			case reflect.Map:
				iter := rv.MapRange()
				for iter.Next() {
					key, child := fmt.Sprint(iter.Key().Interface()), iter.Value().Interface()
					parts = append(parts, key)
					if egressCredentialKeyName(key) && !egressArgumentEmpty(child) {
						keyHit = true
					}
					walk(child, depth+1)
				}
			case reflect.Slice, reflect.Array:
				for i := 0; i < rv.Len(); i++ {
					walk(rv.Index(i).Interface(), depth+1)
				}
			case reflect.Pointer, reflect.Interface:
				if !rv.IsNil() {
					walk(rv.Elem().Interface(), depth+1)
				}
			default:
				parts = append(parts, fmt.Sprint(typed))
			}
		}
	}
	walk(args, 0)
	if tooDeep {
		return egressRuleScanBound
	}
	text := strings.Join(parts, "\n")
	switch {
	case len(DetectHighConfidenceSecrets(text)) > 0:
		return egressRuleDetector
	case egressCredentialKeyValuePattern.MatchString(text):
		return egressRuleKeyValue
	case keyHit:
		return egressRuleKeyName
	case egressBearerTokenPattern.MatchString(text):
		return egressRuleBearer
	case egressTokenPrefixPattern.MatchString(text) || egressJWTPattern.MatchString(text):
		return egressRuleTokenPrefix
	case egressPrivateKeyPattern.MatchString(text) || (egressJWKTypePattern.MatchString(text) && egressJWKPrivatePattern.MatchString(text)):
		return egressRulePrivateKey
	case egressURLPasswordPattern.MatchString(text):
		return egressRuleURLPassword
	case egressHexRunPattern.MatchString(text) || egressHexColonPattern.MatchString(text):
		return egressRuleHex
	case egressHasMixedBase64Run(text):
		return egressRuleBase64
	}
	return ""
}

// egressCredentialKeyName：键名去掉空白、- 和 _、转小写后含凭据词（egressCredentialKeyWords）。
func egressCredentialKeyName(key string) bool {
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '-' || r == '_' {
			return -1
		}
		return unicode.ToLower(r)
	}, key)
	for _, word := range egressCredentialKeyWords {
		if strings.Contains(normalized, word) {
			return true
		}
	}
	return false
}

// egressHasMixedBase64Run：有连续 40 个以上 base64 或 base64url 字符的串，同时含大写、小写和数字。
func egressHasMixedBase64Run(text string) bool {
	for _, pattern := range []*regexp.Regexp{egressBase64RunPattern, egressBase64URLRunPattern} {
		for _, run := range pattern.FindAllString(text, -1) {
			if strings.IndexFunc(run, unicode.IsUpper) >= 0 && strings.IndexFunc(run, unicode.IsLower) >= 0 &&
				strings.IndexFunc(run, unicode.IsDigit) >= 0 {
				return true
			}
		}
	}
	return false
}

func containsAnyFragment(text string, fragments []string) bool {
	for _, fragment := range fragments {
		if strings.Contains(text, fragment) {
			return true
		}
	}
	return false
}

// nameHitsOnlyMergeRequestPhrase：例外 (a) 的工具名部分。
func nameHitsOnlyMergeRequestPhrase(lowerName string) bool {
	stripped, found := lowerName, false
	for _, phrase := range mergeRequestPhrases {
		if strings.Contains(stripped, phrase) {
			found = true
			stripped = strings.ReplaceAll(stripped, phrase, " ")
		}
	}
	return found && !containsAnyFragment(stripped, legacyEgressNameFragments)
}

// mergeRequestReadVerbs：动作名（去掉合并请求词组后）首词是这些词，算查看。
var mergeRequestReadVerbs = map[string]bool{
	"get": true, "list": true, "search": true, "view": true, "show": true, "describe": true, "find": true, "read": true,
}

// mergeRequestReadSuffixes：动作名以合并请求词组开头、末词是这些词（merge_request_detail、
// pull_request_diff、mergeRequestChanges、merge_request_commits 等），算查看。
var mergeRequestReadSuffixes = map[string]bool{
	"detail": true, "details": true, "diff": true, "diffs": true, "changes": true, "commits": true,
}

// mergeRequestWriteWords：动作名里出现任一词就算写（只读前缀、后缀都不再算数）。
// and/or/then 表示组合动作（get_or_create 等），也按写算。
var mergeRequestWriteWords = map[string]bool{
	"create": true, "update": true, "edit": true, "merge": true, "close": true, "reopen": true,
	"approve": true, "unapprove": true, "comment": true, "note": true, "review": true, "add": true,
	"delete": true, "remove": true, "rebase": true, "assign": true, "push": true, "post": true, "put": true,
	"and": true, "or": true, "then": true,
}

// mergeRequestActionIsReadOnly 判断合并请求、拉取请求类工具的动作是不是只读查看。
// 动作名取 egressActionName（去掉服务器前缀），拆成整词后去掉合并请求词组
// （merge request、pull request、mergerequest、pullrequest，复数也算）：
//   - 剩下的词里有任一写类词（mergeRequestWriteWords），算写；
//   - 否则首词是 get/list/search/view/show/describe/find/read，算只读；
//   - 否则动作名以合并请求词组开头、末词是 detail/diff/changes/commits 等，算只读；
//   - 其余（没有只读信号）都算写。
//
// 2.9.21 第三轮暂不接入判定：例外 (a) 仍对创建和查看都适用。接入方法见 narrowEgressException。
func mergeRequestActionIsReadOnly(toolName string) bool {
	words, leadsWithPhrase := mergeRequestActionWords(egressActionName(toolName))
	if len(words) == 0 {
		return false
	}
	for _, word := range words {
		if mergeRequestWriteWords[word] {
			return false
		}
	}
	return mergeRequestReadVerbs[words[0]] || (leadsWithPhrase && mergeRequestReadSuffixes[words[len(words)-1]])
}

// mergeRequestActionWords 把动作名拆成整词并去掉合并请求词组；leadsWithPhrase 表示动作名
// 以合并请求词组开头。
func mergeRequestActionWords(action string) (words []string, leadsWithPhrase bool) {
	all := toolNameWords(action)
	for i := 0; i < len(all); i++ {
		word := all[i]
		phrase := false
		switch word {
		case "mergerequest", "mergerequests", "pullrequest", "pullrequests":
			phrase = true
		case "merge", "pull":
			if i+1 < len(all) && (all[i+1] == "request" || all[i+1] == "requests") {
				phrase = true
				i++
			}
		}
		if phrase {
			leadsWithPhrase = leadsWithPhrase || len(words) == 0
			continue
		}
		words = append(words, word)
	}
	return words, leadsWithPhrase
}

// egressActionName 取工具名里表示动作的那一段：最后一个 "__" 之后（mcp__<服务器>__<工具>、
// <服务器>__<工具> 两种写法都去掉服务器名），再取最后一个 . / : 之后的部分。
func egressActionName(name string) string {
	action := strings.TrimSpace(name)
	if idx := strings.LastIndex(action, "__"); idx >= 0 {
		action = action[idx+2:]
	}
	if idx := strings.LastIndexAny(action, "./:"); idx >= 0 {
		action = action[idx+1:]
	}
	return action
}

func hasEgressGuardWord(toolName string) bool {
	for _, word := range toolNameWords(toolName) {
		if egressGuardWords[word] ||
			(strings.HasSuffix(word, "es") && egressGuardWords[strings.TrimSuffix(word, "es")]) ||
			(strings.HasSuffix(word, "s") && egressGuardWords[strings.TrimSuffix(word, "s")]) {
			return true
		}
	}
	return false
}

// visitEgressArguments 遍历参数（含嵌套），对每个键值对调用 visit；visit 返回 true 时停止。
func visitEgressArguments(args map[string]any, visit func(key string, value any) bool) bool {
	var walk func(value any, depth int) bool
	walk = func(value any, depth int) bool {
		if depth > maxScannedArgumentDepth {
			return false
		}
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if visit(key, child) || walk(child, depth+1) {
					return true
				}
			}
		case []any:
			for _, child := range typed {
				if walk(child, depth+1) {
					return true
				}
			}
		}
		return false
	}
	return walk(args, 0)
}

func egressArgumentEmpty(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(typed) == ""
	case map[string]any:
		return len(typed) == 0
	case []any:
		return len(typed) == 0
	case []string:
		return len(typed) == 0
	default:
		return false
	}
}

// egressArgumentStrings 取一个参数值下的全部字符串（含嵌套）。
func egressArgumentStrings(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []string:
		return typed
	case map[string]any:
		return stringValues(collectStringArguments(typed))
	case []any:
		return stringValues(collectStringArguments(map[string]any{"": typed}))
	default:
		return nil
	}
}

func stringValues(arguments []scannedArgument) []string {
	out := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		out = append(out, argument.Value)
	}
	return out
}

// egressExceptionReadMethod：method/http_method（含嵌套）没写，或是 GET、HEAD、OPTIONS。
func egressExceptionReadMethod(args map[string]any) bool {
	return !visitEgressArguments(args, func(key string, value any) bool {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "method", "http_method":
		default:
			return false
		}
		if egressArgumentEmpty(value) {
			return false
		}
		method, ok := value.(string)
		if !ok {
			return true
		}
		switch strings.ToUpper(strings.TrimSpace(method)) {
		case "GET", "HEAD", "OPTIONS":
			return false
		default:
			return true
		}
	})
}

// egressExceptionHasDestination 判断参数里有没有外发目标（含嵌套）：
//   - url/uri/endpoint/host 键有非空值（值是对象也算）；
//   - target 键，或键名拆词后含 destination、hostname、server、remote、to、email、
//     callback 等词的键，值像网络地址；
//   - 任一字符串参数整体是 URL（不含空白，scheme://host 或 //host，scheme 不限于 http）。
func egressExceptionHasDestination(args map[string]any) bool {
	if visitEgressArguments(args, func(key string, value any) bool {
		if egressArgumentEmpty(value) {
			return false
		}
		lowerKey := strings.ToLower(strings.TrimSpace(key))
		if egressAlwaysDestinationKeys[lowerKey] {
			return true
		}
		destinationKey := lowerKey == "target"
		for _, word := range toolNameWords(key) {
			destinationKey = destinationKey || egressDestinationKeyWords[word]
		}
		if !destinationKey {
			return false
		}
		for _, text := range egressArgumentStrings(value) {
			if looksLikeNetworkDestination(text) {
				return true
			}
		}
		return false
	}) {
		return true
	}
	for _, argument := range collectStringArguments(args) {
		if isWholeNetworkURL(argument.Value) {
			return true
		}
	}
	return false
}

// isWholeNetworkURL：整个值（不含空白）是 scheme://host... 或 //host...，scheme 不限于
// http。file:///path 这类没有主机的不算。
func isWholeNetworkURL(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	rest := ""
	if strings.HasPrefix(value, "//") {
		rest = value[2:]
	} else if idx := strings.Index(value, "://"); idx > 0 {
		for i, r := range value[:idx] {
			if !(unicode.IsLetter(r) || (i > 0 && (unicode.IsDigit(r) || r == '+' || r == '-' || r == '.'))) {
				return false
			}
		}
		rest = value[idx+3:]
	} else {
		return false
	}
	return rest != "" && rest[0] != '/'
}

// looksLikeNetworkDestination：值（按空白拆开的任一段）像网络地址：URL、//host、
// 域名（末尾带点也算）、IP、localhost、邮箱地址或 user@host:path。
func looksLikeNetworkDestination(value string) bool {
	for _, token := range strings.Fields(value) {
		if looksLikeNetworkDestinationToken(strings.Trim(token, "<>\"'(),;")) {
			return true
		}
	}
	return false
}

func looksLikeNetworkDestinationToken(value string) bool {
	if value == "" {
		return false
	}
	if isWholeNetworkURL(value) {
		return true
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return true
	}
	host := value
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:]
	}
	if end := strings.IndexAny(host, "/?#"); end >= 0 {
		host = host[:end]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "localhost" {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" {
			return false
		}
		for _, r := range label {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if strings.HasPrefix(tld, "xn--") {
		return true
	}
	if len([]rune(tld)) < 2 {
		return false
	}
	for _, r := range tld {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// toolNameWords 把工具名（或参数键名）拆成小写整词：非字母数字字符（_ - . : / 空白等）
// 都是分隔符，驼峰和缩写边界（chatPostMessage、HTTPRequest、s3Upload）也拆开。
func toolNameWords(name string) []string {
	var words []string
	var current []rune
	flush := func() {
		if len(current) > 0 {
			words = append(words, strings.ToLower(string(current)))
			current = current[:0]
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if unicode.IsUpper(r) && len(current) > 0 {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		current = append(current, r)
	}
	flush()
	return words
}
