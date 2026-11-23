package agentguard

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
)

// 日常开发操作（2026-11-22 用户拍板）：清临时文件与构建产物、工作区里的具体文件或子目录、系统目录下的单个
// 运行时文件。它们的删除与覆盖写只在工具日志留痕，不进告警；删系统目录、家目录、整个仓库仍照常告警。

// routineExtraTarget 补充 lowImpactDeleteTarget 的认定范围：
//   - /var/run、/run、/var/lock、/var/log 下的单个运行时文件（.pid/.log/.lock/.sock/.tmp，不含审计与认证类日志）；
//   - ~/<项目>/…、/home/<用户>/<项目>/…、/root/<项目>/… 下的具体文件或子目录（项目目录不能是点开头，
//     顶层整个 src/lib/tests 等源码目录、通配符不认）；
//   - 任意位置的 *.log、*.pid、*.lock、*.tmp 文件（系统目录除外）。
func routineExtraTarget(segments []string) bool {
	return systemRuntimeFile(segments) || homeWorkspaceTarget(segments) || routineArtifactFile(segments)
}

var runtimeFileSuffixes = []string{".pid", ".log", ".lock", ".sock", ".tmp"}

// systemLogSensitivePrefixes 是 /var/log 下审计、认证、系统日志文件名前缀：清它们等同于清审计，不算日常。
var systemLogSensitivePrefixes = []string{"audit", "auth", "secure", "wtmp", "btmp", "lastlog", "syslog", "messages", "sudo", "faillog", "kern", "journal"}

func hasRuntimeFileSuffix(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range runtimeFileSuffixes {
		if strings.HasSuffix(lower, suffix) && len(lower) > len(suffix) {
			return true
		}
	}
	return false
}

func systemRuntimeFile(segments []string) bool {
	if len(segments) < 3 || segments[0] != "" {
		return false
	}
	var rest []string
	logDir := false
	switch {
	case segments[1] == "run":
		rest = segments[2:]
	case segments[1] == "var" && len(segments) >= 4 && (segments[2] == "run" || segments[2] == "lock"):
		rest = segments[3:]
	case segments[1] == "var" && len(segments) >= 4 && segments[2] == "log":
		rest, logDir = segments[3:], true
	default:
		return false
	}
	for _, segment := range rest {
		if segment == "" || strings.ContainsAny(segment, "*?[]{}~") {
			return false
		}
		if logDir {
			lower := strings.ToLower(segment)
			for _, prefix := range systemLogSensitivePrefixes {
				if strings.HasPrefix(lower, prefix) {
					return false
				}
			}
		}
	}
	return hasRuntimeFileSuffix(rest[len(rest)-1])
}

func homeWorkspaceTarget(segments []string) bool {
	var project string
	var inner []string
	switch {
	case len(segments) >= 5 && segments[0] == "" && segments[1] == "home":
		project, inner = segments[3], segments[4:]
	case len(segments) >= 4 && segments[0] == "" && segments[1] == "root":
		project, inner = segments[2], segments[3:]
	case len(segments) >= 3 && segments[0] == "~":
		project, inner = segments[1], segments[2:]
	default:
		return false
	}
	if project == "" || strings.HasPrefix(project, ".") || strings.ContainsAny(project, "*?[]{}~") {
		return false
	}
	return workdirRelativeTarget(inner)
}

// systemRoots 下的 *.log 等文件不按日常产物认（/var/log 另由 systemRuntimeFile 处理）。
var systemRoots = map[string]struct{}{
	"etc": {}, "boot": {}, "usr": {}, "bin": {}, "sbin": {}, "lib": {}, "lib64": {}, "proc": {}, "sys": {}, "dev": {}, "var": {},
}

func routineArtifactFile(segments []string) bool {
	if len(segments) == 0 {
		return false
	}
	if len(segments) > 1 && segments[0] == "" {
		if _, system := systemRoots[segments[1]]; system {
			return false
		}
	}
	last := segments[len(segments)-1]
	if !hasRuntimeFileSuffix(last) {
		return false
	}
	for _, segment := range segments[:len(segments)-1] {
		if strings.ContainsAny(segment, "*?[]{}~") {
			return false
		}
	}
	return !strings.ContainsAny(last, "[]{}~")
}

// readOnlyInspectionCommands 是只读查看类命令：不在内置 allowlist 里，但没有任何写入或外发能力。
var readOnlyInspectionCommands = map[string]struct{}{
	"cat": {}, "head": {}, "tail": {}, "less": {}, "more": {}, "ls": {}, "pwd": {}, "wc": {}, "stat": {}, "file": {},
	"grep": {}, "rg": {}, "diff": {}, "du": {}, "df": {}, "tree": {}, "which": {}, "whoami": {}, "date": {}, "uname": {},
	"basename": {}, "dirname": {}, "realpath": {}, "readlink": {}, "sort": {}, "uniq": {}, "nl": {},
}

// ReadOnlyInspectionCall 判断工具调用里的命令是否全是只读查看类命令（cat/ls/grep…）。
// 它们没有写入能力，是否触及敏感文件由防护项命中另行判定，这里不看目标。
func ReadOnlyInspectionCall(args map[string]any) bool {
	if executable := getAnyStringArg(args, "executable", "program", "bin"); executable != "" {
		_, ok := readOnlyInspectionCommands[strings.ToLower(filepath.Base(executable))]
		return ok
	}
	commands, _ := filerestrict.ExtractCommandTexts(args)
	if len(commands) == 0 {
		return false
	}
	for _, command := range commands {
		fields := strings.Fields(command)
		if len(fields) == 0 {
			return false
		}
		if _, ok := readOnlyInspectionCommands[strings.ToLower(filepath.Base(fields[0]))]; !ok {
			return false
		}
		// 只认单条纯查看命令：带管道、重定向、串接、替换的整条脚本不能只凭第一个词判成只读。
		if strings.ContainsAny(command, "|;&<>`$\n") {
			return false
		}
	}
	return true
}

// dataOutCompositionPattern：管道把数据交给网络工具、重定向到 /dev/tcp、下载内容直接交给解释器执行、curl 上传本地数据。
var dataOutCompositionPattern = regexp.MustCompile(`(?i)\|\s*(?:sudo\s+)?(?:nc|ncat|netcat|socat|curl|wget|scp|sftp|ftp|rsync|ssh|telnet)\b` +
	`|/dev/(?:tcp|udp)/` +
	`|\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python[0-9.]*|perl|ruby|node)\b` +
	`|\bcurl\b[^|;&\n]*\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)[\s=]*@`)

// CompositionSendsDataOut 判断命令拼接是否在往外送数据或下载即执行；这类不算普通 shell 拼接，照常告警。
func CompositionSendsDataOut(args map[string]any) bool {
	commands, coarse := filerestrict.ExtractCommandTexts(args)
	if len(commands) == 0 {
		return coarse != "" && dataOutCompositionPattern.MatchString(coarse)
	}
	for _, command := range commands {
		if dataOutCompositionPattern.MatchString(command) {
			return true
		}
	}
	return false
}

var homeWholeDeletePattern = regexp.MustCompile(`(?:^|[\s;&|(])rm\s+(?:-[A-Za-z-]+\s+)*"?(?:\$HOME|\$\{HOME\})"?/?(?:\s|$|[;&|)])`)

// wholeTreeDeleteUnknown：整个工作区或家目录会被删，但目标写不出字面路径，只能按“目标不完整”处理的几种写法：
// rm -rf $HOME、git clean -x（连同被忽略的文件一起清，不限定路径）、没有任何筛选条件的 find [.] -delete。
// 处置口径不变（目标不完整的不拦、不确认），只把告警级别提到高危。
func wholeTreeDeleteUnknown(raw string, words []string) bool {
	if homeWholeDeletePattern.MatchString(raw) {
		return true
	}
	words = destructiveCommandWords(words)
	if len(words) == 0 {
		return false
	}
	switch strings.ToLower(filepath.Base(words[0])) {
	case "git":
		return gitCleanIgnoredWholeTree(words[1:])
	case "find":
		return findWholeTreeDelete(words[1:])
	}
	return false
}

// gitCleanIgnoredWholeTree：git clean 带 -x/-X 且不限定路径。
func gitCleanIgnoredWholeTree(words []string) bool {
	clean := -1
	for index, word := range words {
		if strings.EqualFold(word, "clean") {
			clean = index
			break
		}
	}
	if clean < 0 {
		return false
	}
	ignored := false
	for index := clean + 1; index < len(words); index++ {
		word := words[index]
		switch {
		case word == "--":
			return false
		case word == "-e" || word == "--exclude":
			index++
		case strings.HasPrefix(word, "--"):
		case strings.HasPrefix(word, "-"):
			if strings.ContainsAny(word, "xX") {
				ignored = true
			}
		default:
			return false
		}
	}
	return ignored
}

// findWholeTreeDelete：find 的起点是当前目录或其上级（缺省、.、..），表达式里除 -delete 和遍历选项外没有任何筛选条件。
func findWholeTreeDelete(words []string) bool {
	index := 0
	for index < len(words) && !strings.HasPrefix(words[index], "-") && words[index] != "!" && words[index] != "(" {
		if words[index] != "." && words[index] != ".." && words[index] != "./" {
			return false
		}
		index++
	}
	deletes := false
	for ; index < len(words); index++ {
		switch strings.ToLower(words[index]) {
		case "-delete":
			deletes = true
		case "-depth", "-xdev", "-mount":
		case "-maxdepth", "-mindepth":
			index++
		default:
			return false
		}
	}
	return deletes
}

// credentialFileTarget：凭据类文件（真实 .env、SSH 私钥与授权公钥、云凭据、kubeconfig、证书私钥）。
// 对它们的删除或覆盖不按日常清理算，维持原来的告警口径；.env.example/.sample 这类模板不算。
func credentialFileTarget(target string) bool {
	name := strings.ToLower(filepath.Base(strings.TrimRight(strings.TrimSpace(target), "/")))
	switch {
	case name == ".env":
		return true
	case strings.HasPrefix(name, ".env."):
		for _, template := range []string{".example", ".sample", ".template", ".dist", ".tpl"} {
			if strings.HasSuffix(name, template) {
				return false
			}
		}
		return true
	case name == "authorized_keys", name == "credentials", name == ".netrc", name == ".pgpass", name == "kubeconfig":
		return true
	case strings.HasPrefix(name, "id_") && !strings.HasSuffix(name, ".pub"):
		return true
	case strings.HasSuffix(name, ".pem"), strings.HasSuffix(name, ".key"), strings.HasSuffix(name, ".p12"), strings.HasSuffix(name, ".pfx"):
		return true
	}
	return strings.Contains(strings.ToLower(target), "/.kube/") || strings.Contains(strings.ToLower(target), "/.ssh/") || strings.Contains(strings.ToLower(target), "/.aws/")
}
