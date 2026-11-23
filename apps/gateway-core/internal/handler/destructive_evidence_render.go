package handler

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// 告警证据的骨架渲染。不去“认凭据”，而是只显示白名单里的东西，其余一律写 …：
//   - 可执行文件名；
//   - 紧跟其后、全小写字母的至多 2 个子命令词（push、delete、volume rm）；
//   - 选项：--flag 原样，--flag=值 写 --flag=…，总长不超过 3 的短选项原样，更长的写首字母加 …；
//   - 分析器认定的破坏目标、重定向的操作符与目标；
//   - 前置赋值只写变量名（NAME=…）；heredoc 写“正文已省略 N 行”，here-string 写 <<< …。
// 渲染结果最后再过一遍纵深检测（令牌前缀、JWT、私钥、邮箱、高熵串），主要防护目标本身含凭据的极端情况。

const evidenceEllipsis = "…"

var (
	evidenceAssignWord     = regexp.MustCompile(`^(\$?[A-Za-z_][A-Za-z0-9_.:\-]*)\+?=`)
	evidencePascalOption   = regexp.MustCompile(`^-[A-Z][A-Za-z]{1,30}$`)
	evidenceAssignName     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	evidenceShortCluster   = regexp.MustCompile(`^-[A-Za-z]+$`)
	evidenceSlashOption    = regexp.MustCompile(`^(/[A-Za-z?]+)([:=].*)?$`)
	evidenceAssignPrefix   = regexp.MustCompile(`^(-{0,2}[A-Za-z0-9_.:$-]+=)(.*)$`)
	evidenceSubcommandWord = regexp.MustCompile(`^[a-z][a-z0-9-]{0,19}$`)
	evidenceCommandWord    = regexp.MustCompile(`^[a-z./~][A-Za-z0-9._/+~-]*$`)
)

// 只有已知带子命令的可执行文件才显示子命令词；其它可执行文件后的位置参数一律写 …，
// 这样 htpasswd -b file user pass、./deploy.sh 口令 这类位置参数里的口令不会被当成子命令显示。
var evidenceSubcommandExes = map[string]bool{
	"git": true, "docker": true, "podman": true, "nerdctl": true, "kubectl": true, "oc": true, "helm": true,
	"terraform": true, "tofu": true, "pulumi": true, "aws": true, "az": true, "gcloud": true, "gsutil": true,
	"bq": true, "ossutil": true, "s3cmd": true, "rclone": true, "mc": true, "npm": true, "pnpm": true, "yarn": true,
	"pip": true, "pip3": true, "uv": true, "conda": true, "cargo": true, "go": true, "systemctl": true,
	"service": true, "journalctl": true, "brew": true, "apt": true, "apt-get": true, "yum": true, "dnf": true,
	"zypper": true, "snap": true, "make": true, "gh": true, "glab": true, "kind": true, "minikube": true,
	"docker-compose": true,
}

// 包装命令：真正执行的是它后面的第一个位置参数，那个词按可执行文件显示（sudo rm -rf x）。
var evidenceWrapperExes = map[string]bool{
	"sudo": true, "doas": true, "env": true, "nohup": true, "time": true, "nice": true, "exec": true, "command": true, "builtin": true,
}

// 包装命令自己带值的短选项（sudo -u root）；其它选项（-S、-E、-n）不带值。
var evidenceWrapperValueOptions = map[string]bool{"-u": true, "-g": true, "-h": true, "-p": true, "-r": true, "-t": true, "-C": true, "-D": true, "-U": true, "-T": true}

// 已知的布尔长选项：后面紧跟的词是子命令而不是它的值（docker --tlsverify rm）。其它长选项后的词一律当值。
var evidenceBooleanLongOptions = map[string]bool{
	"--tlsverify": true, "--force": true, "--all": true, "--recursive": true, "--dry-run": true,
	"--yes": true, "--quiet": true, "--verbose": true,
}

func evidenceToolBase(text string) string {
	text = strings.ToLower(text)
	if index := strings.LastIndexAny(text, `/\`); index >= 0 {
		text = text[index+1:]
	}
	return strings.TrimSuffix(text, ".exe")
}

func evidenceSafeBare(text string) bool {
	for _, r := range text {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("_@%+=:,./~*\\-", r):
		case r > 127:
		default:
			return false
		}
	}
	return text != ""
}

func evidenceShellQuote(text string) string {
	if text == "" {
		return "''"
	}
	if evidenceSafeBare(text) {
		return text
	}
	if match := evidenceAssignPrefix.FindStringSubmatch(text); match != nil && match[2] != "" {
		return match[1] + evidenceShellQuote(match[2])
	}
	switch {
	case !strings.Contains(text, "'"):
		return "'" + text + "'"
	case !strings.ContainsAny(text, "\"$`\\!"):
		return `"` + text + `"`
	}
	return "'" + strings.ReplaceAll(text, "'", `'\''`) + "'"
}

func renderEvidenceSegment(segment agentguard.EvidenceSegment, depth int) string {
	if segment.SQL != "" {
		return redactEvidenceString(evidenceSQLSkeleton(segment.SQL))
	}
	var parts []string
	ellipsis := func() {
		if len(parts) == 0 || parts[len(parts)-1] != evidenceEllipsis {
			parts = append(parts, evidenceEllipsis)
		}
	}
	exe, exeSeen := "", false
	subOK, skipValue, endOptions := true, false, false
	valueOption := "" // skipValue 为真时，正在等值的那个选项
	subcommands, parenDepth := 0, 0
	wrapper := false
	var subWords []string
	words := segment.Words
	for index := 0; index < len(words); index++ {
		word := words[index]
		switch word.Kind {
		case agentguard.EvidenceAssign:
			parts = append(parts, word.Text+"=…")
			continue
		case agentguard.EvidenceRedirectOp:
			parts = append(parts, word.Text)
			skipValue = false
			continue
		case agentguard.EvidenceRedirectTarget:
			if word.Dynamic {
				parts = append(parts, evidenceEllipsis)
			} else {
				parts = append(parts, evidenceWordSpelling(word))
			}
			continue
		case agentguard.EvidenceHeredoc:
			parts = append(parts, fmt.Sprintf("%s（正文已省略 %d 行）", word.Text, word.Lines))
			continue
		case agentguard.EvidenceHereString:
			parts = append(parts, word.Text+" …")
			continue
		}

		text := word.Text
		isOption := !endOptions && !word.Dynamic && len(text) > 1 && strings.HasPrefix(text, "-")
		if !isOption && segment.Lexical && !word.Dynamic && exeSeen {
			// cmd 的斜杠开关先于目标判断：/user:…、/p:… 带冒号的整体按选项处理，值写 …。
			if match := evidenceSlashOption.FindStringSubmatch(text); match != nil && (match[2] != "" || !word.Target) {
				if match[2] != "" {
					parts = append(parts, match[1]+match[2][:1]+evidenceEllipsis)
				} else {
					parts = append(parts, match[1])
				}
				skipValue = false
				continue
			}
		}
		if !exeSeen {
			if match := evidenceAssignWord.FindStringSubmatch(text); match != nil {
				parts = append(parts, match[1]+"=…")
				continue
			}
			exeSeen = true
			exe = evidenceToolBase(text)
			wrapper = evidenceWrapperExes[exe]
			if word.Dynamic {
				ellipsis()
			} else {
				parts = append(parts, text)
			}
			continue
		}
		if segment.Lexical && !isOption && exeSeen {
			// PowerShell 的 (…)、$(…) 子表达式里常内联凭据（-Credential (New-Object …)），括号内的词一律不显示。
			opens, closes := strings.Count(text, "(")+strings.Count(text, ")"), 0
			if parenDepth > 0 || opens > 0 {
				closes = strings.Count(text, ")")
				parenDepth += strings.Count(text, "(") - closes
				if parenDepth < 0 {
					parenDepth = 0
				}
				ellipsis()
				continue
			}
		}
		if skipValue && !isOption {
			skipValue = false
			switch {
			case evidenceBooleanLongOptions[valueOption] && subOK && subcommands == 0 &&
				evidenceSubcommandExes[exe] && !word.Dynamic && evidenceSubcommandWord.MatchString(text):
				// 布尔长选项（--tlsverify、--force）后面紧跟的子命令词，不是它的值。
				parts = append(parts, text)
				subcommands++
				subWords = append(subWords, text)
			case word.Target && !evidenceCredentialAssignment(text) &&
				(evidenceBooleanLongOptions[valueOption] || evidenceValueMayShow(exe, valueOption, text)):
				parts = append(parts, evidenceWordSpelling(word))
			default:
				ellipsis()
			}
			if subcommands > 0 {
				subOK = false // 子命令之后出现的选项值，其后的词不再当子命令（git push -f origin main）
			}
			continue
		}
		skipValue = false
		if wrapper && !isOption && !word.Dynamic {
			if match := evidenceAssignWord.FindStringSubmatch(text); match != nil {
				parts = append(parts, match[1]+"=…")
				continue
			}
			if !evidenceCommandWord.MatchString(text) {
				ellipsis() // 不像命令名（argv 被空格拼接后拆出的口令片段），仍等真正的命令
				continue
			}
			exe = evidenceToolBase(text)
			wrapper = evidenceWrapperExes[exe]
			parts = append(parts, text)
			continue
		}
		if isOption {
			if text == "--" {
				endOptions = true
				parts = append(parts, "--")
				continue
			}
			if (exe == "powershell" || exe == "pwsh") && evidenceEncodedCommandOption(text) {
				parts = append(parts, "-EncodedCommand")
				if index+1 < len(words) && words[index+1].Kind == agentguard.EvidenceArg {
					index++
					parts = append(parts, evidenceDecodedScript(words[index].Text, depth))
				}
				continue
			}
			if exe == "find" {
				switch text {
				case "-delete", "-empty":
					parts = append(parts, text)
					continue
				case "-name", "-iname", "-mtime", "-mmin", "-type", "-path", "-maxdepth", "-mindepth", "-size":
					parts = append(parts, text)
					if index+1 < len(words) && words[index+1].Kind == agentguard.EvidenceArg {
						index++
						if words[index].Dynamic {
							parts = append(parts, evidenceEllipsis)
						} else {
							parts = append(parts, evidenceWordSpelling(words[index]))
						}
					}
					continue
				case "-exec", "-execdir", "-ok":
					// 要执行的命令写 …，直到 ; 或 +。
					parts = append(parts, text, evidenceEllipsis)
					for index+1 < len(words) {
						index++
						if end := words[index].Text; end == ";" || end == "+" {
							parts = append(parts, end)
							break
						}
					}
					continue
				}
			}
			if (exe == "terraform" || exe == "tofu") && (text == "-auto-approve" || strings.HasPrefix(text, "-target=") || strings.HasPrefix(text, "-var-file=")) {
				parts = append(parts, text)
				continue
			}
			if exe == "git" && len(subWords) > 0 && subWords[0] == "clean" && evidenceShortCluster.MatchString(text) {
				parts = append(parts, text)
				// -e <排除模式>（也可在簇末尾，如 -fdxe）带一个值：值写 …，不当成子命令。
				if strings.HasSuffix(text, "e") {
					skipValue, valueOption = true, "-e"
				}
				continue
			}
			parts = append(parts, evidenceOptionSkeleton(text, segment.Lexical))
			skipValue = !strings.Contains(text, "=") // --flag=值 的值已在词里，没有等号时下一个词可能是它的值
			valueOption = text
			if wrapper && !evidenceWrapperValueOptions[text] {
				skipValue = false
			}
			continue
		}
		if word.Target && !evidenceCredentialAssignment(text) {
			parts = append(parts, evidenceWordSpelling(word)) // 含 dd 的 of=/dev/sdb：值是目标时整词显示
			subOK = false
			continue
		}
		if match := evidenceAssignWord.FindStringSubmatch(text); match != nil && !word.Dynamic {
			parts = append(parts, match[1]+"=…")
			continue
		}
		if subOK && subcommands < 2 && evidenceSubcommandExes[exe] && !word.Dynamic && evidenceSubcommandWord.MatchString(text) {
			parts = append(parts, text)
			subcommands++
			subWords = append(subWords, text)
			continue
		}
		subOK = false
		ellipsis()
	}
	return redactEvidenceString(strings.Join(parts, " "))
}

func evidenceWordSpelling(word agentguard.EvidenceWord) string {
	if word.Source != "" && !word.Dynamic {
		return word.Source
	}
	return evidenceShellQuote(word.Text)
}

func evidenceLongOption(option string) bool { return strings.HasPrefix(option, "--") }

// evidenceCredentialOption 判断选项名是否像凭据；这类选项后面的词一律当值，不当子命令也不当目标。
// -id、-name、-arn、-file、-path 结尾的是标识或文件，不是凭据（--secret-id prod/db/main 是删除目标）。
func evidenceCredentialOption(option string) bool {
	lowered := strings.ToLower(strings.TrimLeft(option, "-"))
	for _, suffix := range []string{"-id", "_id", "-name", "_name", "-arn", "_arn", "-file", "_file", "-path", "_path"} {
		if strings.HasSuffix(lowered, suffix) {
			return false
		}
	}
	for _, fragment := range []string{"pass", "pwd", "secret", "token", "key", "cred", "auth", "login", "user", "account", "private", "cert", "sig"} {
		if strings.Contains(lowered, fragment) {
			return true
		}
	}
	return false
}

// evidenceCredentialAssignment：NAME=值 形式的词，名字像凭据时即使被分析器认定为目标也不显示。
func evidenceCredentialAssignment(text string) bool {
	name, _, ok := strings.Cut(text, "=")
	return ok && !strings.HasPrefix(text, "-") && evidenceAssignName.MatchString(name) && evidenceCredentialOption(name)
}

// 破坏性工具没有口令类选项：选项后面的目标（wipefs -a /dev/sdb、shred -u 文件）照样显示。
var evidencePlainExes = map[string]bool{
	"rm": true, "rmdir": true, "shred": true, "wipefs": true, "parted": true, "dd": true, "truncate": true, "find": true,
	"del": true, "rd": true, "erase": true, "lvremove": true, "vgremove": true, "pvremove": true, "zfs": true, "zpool": true,
	"mv": true, "cp": true, "ln": true, "umount": true, "swapoff": true, "sgdisk": true, "fdisk": true, "mdadm": true,
	"cryptsetup": true, "blkdiscard": true, "diskutil": true, "format": true, "cipher": true, "sdelete": true, "git": true,
	"mkswap": true, "tune2fs": true, "sfdisk": true, "gdisk": true, "dmsetup": true,
}

// 带口令类短选项的可执行文件：只有它们自己的口令选项后面的目标才隐藏。
var evidenceCredentialShortOptions = func() map[string]string {
	table := map[string]string{
		"mongo": "p", "mongosh": "p", "mongodump": "p", "mongorestore": "p", "sshpass": "p", "redis-cli": "a", "openssl": "k",
		"zip": "P", "7z": "p", "7za": "p", "7zr": "p", "sqlcmd": "P", "bcp": "P", "az": "p", "docker": "p", "podman": "p",
		"curl": "uU", "smbclient": "U", "rpcclient": "U", "lftp": "u", "ssh-keygen": "NP", "mosquitto_pub": "P", "mosquitto_sub": "P",
	}
	for _, tool := range []string{"mysql", "mysqldump", "mysqladmin", "mysqlimport", "mysqlcheck", "mysqlpump", "mysqlshow", "mariadb", "mycli"} {
		table[tool] = "p"
	}
	for _, tool := range []string{"ldapsearch", "ldapdelete", "ldapmodify", "ldapadd", "ldappasswd", "ldapwhoami", "ldapcompare", "ldapmodrdn"} {
		table[tool] = "wW"
	}
	return table
}()

// evidenceValueMayShow：选项后面的词即使被分析器认定为目标，也只在它不像是该选项的值时才显示。
//   - 长选项后只显示带路径分隔符、且选项名不像凭据的目标（--force /opt/app）；
//   - 多字母的单横线选项（-Path、-var）按名字判断；
//   - 单字母短选项：破坏性工具一律显示；已知带口令选项的工具只隐藏它自己的口令选项；
//     其它工具保留通用的口令选项字母表。
func evidenceValueMayShow(exe, option, text string) bool {
	if evidenceLongOption(option) {
		return !evidenceCredentialOption(option) && strings.ContainsAny(text, `/\`)
	}
	if len(option) != 2 {
		return !evidenceCredentialOption(option)
	}
	letter := rune(option[1])
	switch {
	case evidencePlainExes[exe] || strings.HasPrefix(exe, "mkfs"):
		return true
	case evidenceCredentialShortOptions[exe] != "":
		return !strings.ContainsRune(evidenceCredentialShortOptions[exe], letter)
	}
	return !strings.ContainsRune("pPkwaNuUWKsST", letter)
}

// evidenceOptionSkeleton：长选项只留名字，短选项总长不超过 3 原样，更长的只留首字母；
// 词法兜底（PowerShell）的 -Name 是长参数名，原样显示名字。
func evidenceOptionSkeleton(text string, lexical bool) string {
	if strings.HasPrefix(text, "--") {
		if name, _, hasValue := strings.Cut(text, "="); hasValue {
			return name + "=…"
		}
		return text
	}
	if lexical && evidencePascalOption.MatchString(text) {
		return text
	}
	if len(text) <= 3 && !strings.ContainsAny(text, "=:") {
		return text
	}
	return text[:2] + evidenceEllipsis
}

func evidenceEncodedCommandOption(text string) bool {
	lowered := strings.ToLower(text)
	return lowered == "-ec" || (len(lowered) >= 2 && strings.HasPrefix("-encodedcommand", lowered))
}

// evidenceDecodedScript 解码 -EncodedCommand 的值（base64 的 UTF-16LE），只留解码出的脚本里判定为破坏性的那几段的骨架；
// 解不开或没有触发段就只写 …。
func evidenceDecodedScript(value string, depth int) string {
	if depth >= 2 {
		return evidenceEllipsis
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) < 2 || len(raw)%2 != 0 {
		return evidenceEllipsis
	}
	units := make([]uint16, 0, len(raw)/2)
	for index := 0; index+1 < len(raw); index += 2 {
		units = append(units, uint16(raw[index])|uint16(raw[index+1])<<8)
	}
	analysis := agentguard.AnalyzeDestructiveOperation(agentguard.DestructiveInput{
		ToolName: "powershell", ToolType: "shell", Arguments: map[string]any{"command": string(utf16.Decode(units))},
	})
	if rendered := joinEvidenceSegments(analysis.EvidenceSegments, depth+1); rendered != "" {
		return "<已解码：" + rendered + ">"
	}
	return evidenceEllipsis
}

var evidenceSQLIdentifierPrevious = map[string]bool{
	"SET": true, "FROM": true, "TABLE": true, "INTO": true, "UPDATE": true, "JOIN": true, "DATABASE": true,
	"SCHEMA": true, "INDEX": true, "ON": true, "USER": true, "ROLE": true, "AS": true, "TRUNCATE": true,
	"WHERE": true, "AND": true, "OR": true, "IF": true, "EXISTS": true, "COLUMN": true, "ADD": true,
	"ALTER": true, "CREATE": true, "DROP": true, "DELETE": true, "VIEW": true, ".": true,
}

// evidenceSQLSkeleton 把一条语句规范化：字符串、数字、美元引用字面量都替换为 ?，注释去掉，
// 关键字与标识符（含引号标识符）保留，空白折叠。双引号在标准 SQL 里是标识符，在 MySQL 里是字符串，
// 只有紧跟在 SET、FROM、WHERE 这类关键字之后或后面接 . 时当标识符，其余当字面量。
func evidenceSQLSkeleton(statement string) string {
	var out strings.Builder
	pendingSpace := false
	previous := ""
	emit := func(token string) {
		if pendingSpace && out.Len() > 0 {
			out.WriteByte(' ')
		}
		pendingSpace = false
		out.WriteString(token)
		previous = strings.ToUpper(token)
	}
	isWordChar := func(c byte) bool {
		return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
	}
	// skipQuoted 返回结束引号之后的位置；找不到结束引号时吃到末尾。
	skipQuoted := func(start int, quote byte) int {
		for index := start + 1; index < len(statement); index++ {
			switch {
			case statement[index] == '\\' && quote != '`':
				index++
			case statement[index] == quote:
				if index+1 < len(statement) && statement[index+1] == quote {
					index++
					continue
				}
				return index + 1
			}
		}
		return len(statement)
	}
	for index := 0; index < len(statement); {
		ch := statement[index]
		switch {
		case ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n':
			pendingSpace = true
			index++
		case ch == '-' && index+1 < len(statement) && statement[index+1] == '-',
			ch == '#' && !(index+1 < len(statement) && strings.IndexByte(">-", statement[index+1]) >= 0):
			for index < len(statement) && statement[index] != '\n' {
				index++
			}
			pendingSpace = true
		case ch == '/' && index+1 < len(statement) && statement[index+1] == '*':
			depth := 1
			index += 2
			for index < len(statement) && depth > 0 {
				switch {
				case statement[index] == '/' && index+1 < len(statement) && statement[index+1] == '*':
					depth++
					index += 2
				case statement[index] == '*' && index+1 < len(statement) && statement[index+1] == '/':
					depth--
					index += 2
				default:
					index++
				}
			}
			pendingSpace = true
		case ch == '\'':
			index = skipQuoted(index, '\'')
			emit("?")
		case ch == '"':
			end := skipQuoted(index, '"')
			if evidenceSQLIdentifierPrevious[previous] || (end < len(statement) && statement[end] == '.') {
				emit(statement[index:end])
			} else {
				emit("?")
			}
			index = end
		case ch == '`':
			end := skipQuoted(index, '`')
			emit(statement[index:end])
			index = end
		case ch == '$' && index+1 < len(statement) && statement[index+1] >= '0' && statement[index+1] <= '9':
			end := index + 1
			for end < len(statement) && statement[end] >= '0' && statement[end] <= '9' {
				end++
			}
			emit(statement[index:end])
			index = end
		case ch == '$':
			end := index + 1
			for end < len(statement) && (statement[end] == '_' || statement[end] >= 'a' && statement[end] <= 'z' || statement[end] >= 'A' && statement[end] <= 'Z' || statement[end] >= '0' && statement[end] <= '9') {
				end++
			}
			if end < len(statement) && statement[end] == '$' {
				tag := statement[index : end+1]
				if close := strings.Index(statement[end+1:], tag); close >= 0 {
					index = end + 1 + close + len(tag)
				} else {
					index = len(statement)
				}
				emit("?")
			} else {
				emit("$")
				index++
			}
		case ch >= '0' && ch <= '9':
			for index < len(statement) && (isWordChar(statement[index]) || statement[index] == '.') {
				index++
			}
			emit("?")
		case isWordChar(ch):
			end := index
			for end < len(statement) && isWordChar(statement[end]) {
				end++
			}
			emit(statement[index:end])
			index = end
		default:
			emit(string(ch))
			index++
		}
	}
	return out.String()
}

// 纵深检测：骨架里本不该有凭据，这里只防分析器认定的目标（路径、URL、重定向目标）本身含凭据的极端情况。
var (
	evidenceURLUserinfo = regexp.MustCompile(`(\b[A-Za-z][A-Za-z0-9+.\-]*://)[^\s/@'"]+@`)
	evidenceQueryParam  = regexp.MustCompile(`(?i)([?&](?:token|key|sig|signature|access_token|password|secret|auth)=)[^&\s'";#]+`)
	evidencePEMBlock    = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`)
	evidenceRunPattern  = regexp.MustCompile(`[A-Za-z0-9+/=_.\-]{40,}`)
	evidenceBase64Only  = regexp.MustCompile(`^[A-Za-z0-9+=]{40,}$`)
	evidenceHexOnly     = regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	// 手机号、身份证号（地区码 + 出生日期形态，或 17 位数字加 X）：路径里也遮。
	evidencePersonalDigitRun = regexp.MustCompile(`(^|[^A-Za-z0-9_.\-])(1[3-9][0-9]{9}|[1-9][0-9]{5}(?:18|19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx]|[0-9]{17}[Xx])($|[^A-Za-z0-9_.\-])`)
	// 银行卡形态的 13–19 位长数字：紧挨路径分隔符时是路径段（时间戳、编号命名的文件和目录），不遮。
	evidenceLongDigitRun = regexp.MustCompile(`(^|[^A-Za-z0-9_.\-/\\])([0-9]{13,19})($|[^A-Za-z0-9_.\-/\\])`)

	// 令牌前缀表，与 security-engine 的 SECRET_LITERAL_PATTERNS 对齐并补了常见平台前缀。
	evidenceTokenPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{12,}`),
		regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{10,}`),
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{12,}`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),
		regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{12,}`),
		regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9\-]{10,}`),
		regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{20,}`),
		regexp.MustCompile(`\bhf_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`\bnpm_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`\bpypi-[A-Za-z0-9_\-]{20,}`),
		regexp.MustCompile(`\bLTAI[A-Za-z0-9]{12,}`),
		regexp.MustCompile(`\bAKID[A-Za-z0-9]{12,}`),
		regexp.MustCompile(`\bdop_v1_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}`),
		regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{12,}`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9._\-]{8,}(?:\.[A-Za-z0-9._\-]*)?`),
	}
)

func redactEvidenceString(text string) string {
	if text == "" {
		return text
	}
	text = evidencePEMBlock.ReplaceAllString(text, "***")
	text = evidenceURLUserinfo.ReplaceAllString(text, "${1}***@")
	text = evidenceQueryParam.ReplaceAllString(text, "${1}***")
	for _, pattern := range evidenceTokenPatterns {
		text = pattern.ReplaceAllString(text, "***")
	}
	for _, pattern := range reverseProxySecretPatterns {
		text = pattern.ReplaceAllString(text, "***")
	}
	// 复用 MCP 结果脱敏里的邮箱规则；手机号、身份证、银行卡的数字规则不用它的（会误伤文件名里的时间戳），见下。
	for _, redactor := range mcpResultSensitiveStringPatterns {
		if strings.Contains(redactor.replacement, "email") {
			text = redactor.pattern.ReplaceAllString(text, redactor.replacement)
		}
	}
	for _, pattern := range []*regexp.Regexp{evidencePersonalDigitRun, evidenceLongDigitRun} {
		for pass := 0; pass < 2; pass++ { // 相邻的两个数字串共用一个分隔符，分两遍处理
			text = pattern.ReplaceAllStringFunc(text, func(match string) string {
				groups := pattern.FindStringSubmatch(match)
				return groups[1] + "<redacted:digits>" + groups[3]
			})
		}
	}
	return evidenceRunPattern.ReplaceAllStringFunc(text, func(run string) string {
		// 高熵令牌：只遮由字母数字组成、三类字符齐全的长串；含 / . 或被 - _ 分成多段的词（路径、模型名、UUID）放行。
		if !evidenceBase64Only.MatchString(run) || evidenceHexOnly.MatchString(run) {
			return run
		}
		if strings.IndexFunc(run, func(r rune) bool { return r >= 'a' && r <= 'z' }) < 0 ||
			strings.IndexFunc(run, func(r rune) bool { return r >= 'A' && r <= 'Z' }) < 0 ||
			strings.IndexFunc(run, func(r rune) bool { return r >= '0' && r <= '9' }) < 0 {
			return run
		}
		return "***"
	})
}
