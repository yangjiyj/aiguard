package agentguard

import (
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

// 2.9.21：模型输出方向的密级标记只在“工具参数不会外发”时改成留证。
// ToolCallMayEgress 判断一次工具调用的参数会不会离开本机，供网关在送检工具参数时
// 写 context.tool_may_egress。只做收窄：只认精确名字的本地文件工具，拿不准一律 true（照 2.9.20 拦）。
//
// shell 工具（Bash、execute_command 等）的命令一律按外发，照 2.9.20 拦。r2921f 曾按命令白名单逐条
// 解析，对抗复核多轮仍能用单次调用绕过（zsh 的下标与 printf %d 算术求值、glob 限定符 *(e:...:)、
// git grep -e -- --open=sh、tee $'//server/share' 等），按事先约定退到只放模型回答和本地文件工具。
//
// 本地文件工具的路径口径（r2921i）：只认本地写法，拿不准一律算外发。r2921g 以前是反过来“认出远端写法”
// （UNC、//、://）逐条补，复核仍找到没列到的写法（NT 命名空间 \??\UNC\、@\\srv、自动挂载的 /net/srv、
// codex 补丁的 Environment ID）。现在路径参数只有写成普通相对路径、盘符路径、~/、单个分隔符开头的
// 绝对路径才算本地，规则见 egressLocalPathForm；其余写法照 2.9.20 拦。
//
// r2921i 复核补充：/proc/self/root、/dev/fd、macOS 的 /System/Volumes/Data、/.resolve、/.nofollow、/.file、
// /Volumes/<启动卷> 这些别名也能进到 /net、/Network，一并算外发；参数里带 _host、environment_id 这类分派到别的机器
// 或执行环境的键算外发；codex 补丁 Add/Update File 之后的正文行不当文件头；../ 开头的相对路径只看跳出后的第一段。
//
// 已知并接受的残余：写到已有的网络挂载、映射盘符、/Volumes 下的挂载、云盘同步目录；先写入钩子、配置、
// 别名、脚本再触发的多步外发；客户端自定义的与本地工具同名的工具；模型凭自身知识编出的密级字样；
// 知识库类上游应用；Claude Code 自动模式安全监视请求里的密级字样照员工输入拦（与 2.9.20 一致）。

// egressLocalFileTools：只在本机读写文件的工具，名字大小写按原样精确匹配。
var egressLocalFileTools = map[string]bool{
	"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true, "Read": true, "Glob": true,
	"Grep": true, "LS": true, "TodoWrite": true, "apply_patch": true, "read_file": true,
	"write_to_file": true, "replace_in_file": true, "list_dir": true, "search_file": true,
	"search_content": true, "view_image": true,
}

// egressShellTools：执行 shell 命令的工具，一律按外发。单列出来是为了写明口径，测试也按它逐个核对。
var egressShellTools = map[string]bool{
	"Bash": true, "bash": true, "shell": true, "local_shell": true, "local_shell_call": true,
	"shell_command": true, "exec_command": true, "run_shell": true, "execute_command": true,
}

// egressGlobTools：pattern、glob 参数能写成目录的工具（Glob、search_file）。这类键的值也按路径判；
// 只限这两个工具，Grep 的 pattern 是正则、Write 的 content 以 // 开头都是正文，不按路径判。
var egressGlobTools = map[string]bool{"Glob": true, "search_file": true}

const egressPatchHeaderMax = 4096

// ToolCallMayEgress 判断工具参数会不会外发。args 为 nil（参数解析失败）按 true。
// 只有 egressLocalFileTools 里的工具可能返回 false；shell 工具和其他一切工具都是 true。
func ToolCallMayEgress(toolName string, args map[string]any) bool {
	if toolName == "" || args == nil {
		return true
	}
	if egressShellTools[toolName] || !egressLocalFileTools[toolName] {
		return true
	}
	if !egressArgumentsFullyScanned(args) || egressExceptionHasDestination(args) || egressRoutingArgument(args) {
		return true
	}
	return egressPathArgumentRemote(args) || (egressGlobTools[toolName] && egressGlobArgumentRemote(args)) ||
		(toolName == "apply_patch" && egressPatchTargetsRemote(args))
}

// egressRoutingKeyWords：键名拆词后含这些词、值非空时，这次调用会分派到别的机器或执行环境上执行
// （Claude Code 挂接机器时的 _host，codex 多执行环境的 environment_id），与补丁 *** Environment ID 同一口径。
var egressRoutingKeyWords = map[string]bool{
	"host": true, "hosts": true, "hostname": true, "machine": true, "machines": true,
	"environment": true, "environments": true, "env": true, "remote": true,
}

// egressRoutingArgument：参数里（含嵌套）有分派到别的机器或执行环境的键，且值非空。
func egressRoutingArgument(args map[string]any) bool {
	return visitEgressArguments(args, func(key string, value any) bool {
		if egressArgumentEmpty(value) {
			return false
		}
		for _, word := range toolNameWords(key) {
			if egressRoutingKeyWords[word] {
				return true
			}
		}
		return false
	})
}

// egressPathKey：键名像路径（file_path、path、notebook_path、target_directory、cwd、workdir……）。
func egressPathKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "", " ", "").Replace(key))
	switch normalized {
	case "cwd", "uri", "url", "target", "location", "destination", "dest":
		return true
	}
	if strings.Contains(normalized, "path") || strings.Contains(normalized, "dir") || strings.Contains(normalized, "folder") {
		return true
	}
	return strings.Contains(normalized, "file") && !strings.Contains(normalized, "text") && !strings.Contains(normalized, "content")
}

// egressRemotePath：路径参数的值不是“看得出是本机”的写法，一律算外发。
func egressRemotePath(value string) bool {
	return !egressLocalPathForm(value)
}

// egressLocalPathForm：只认下面几种本地写法，拿不准一律算外发（返回 false）。
//   - 空串：参数没填，沿用原行为算本地；
//   - 含 "://"：算外发；
//   - 首字符是字母、数字（含中文目录名；盘符 C:\x、c:/x 也由此放行）、'.'、'_'、'-'：相对路径或盘符路径；
//   - 首字符是中文标点、带圈数字、罗马数字（egressLocalSymbolStart）：顶层目录叫【设计】、（草稿）、①需求的相对路径；
//   - "~" 本身、"~/"、"~\" 开头：当前用户主目录（~user 可能是别人在网络上的主目录，算外发）；
//   - 单个 '/' 或 '\' 开头：第二个字符不能是 '/'、'\'（UNC、//srv）、'?'（NT 命名空间 \??\UNC\、\\?\），
//     也不能是不可见字符（客户端 trim 后可能拼成 UNC）；
//   - 其余首字符一律算外发：不可见字符（客户端各自 trim 的集合不同）、'@'（@\\srv、@//srv）、'?'、
//     '$'、'%'（环境变量）、'*'、'['、'{'、引号等。
//
// 开头通过后，再看规范化后的路径是不是落在自动挂载目录下（egressAutoMountTarget）。
func egressLocalPathForm(value string) bool {
	if value == "" {
		return true
	}
	return !strings.Contains(value, "://") && egressLocalPathStart(value) && !egressAutoMountTarget(value)
}

func egressLocalPathStart(value string) bool {
	first, size := utf8.DecodeRuneInString(value)
	switch {
	case first == '~':
		return value == "~" || strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`)
	case first == '/' || first == '\\':
		if len(value) == size {
			return true
		}
		second, _ := utf8.DecodeRuneInString(value[size:])
		return second != '/' && second != '\\' && second != '?' && !egressInvisible(second)
	case first == '.' || first == '_' || first == '-':
		return true
	default:
		// utf8.RuneError（非法编码）不是字母、数字，算外发。
		return unicode.IsLetter(first) || unicode.IsDigit(first) || egressLocalSymbolStart(first)
	}
}

// egressLocalSymbolStart：中文文档目录常见的起首符号，只按区段精确放行。全角斜杠、全角反斜杠、∕、∖、⧵、﹨、¥、₩
// 这些会被 Windows best-fit 映射成 / 或 \ 的字符不在其中，全角空格 U+3000 也不在其中，仍算外发。
func egressLocalSymbolStart(r rune) bool {
	switch {
	case r >= 0x3001 && r <= 0x303f: // CJK 符号和标点：、。〃〇《》「」『』【】〔〕〖〗〜
		return true
	case r == 0xff08 || r == 0xff09: // 全角括号（）
		return true
	case r >= 0x2460 && r <= 0x24ff: // 带圈、带括号的数字和字母：①⑴⒈ⓐ
		return true
	case r >= 0x2160 && r <= 0x2188: // 罗马数字：ⅠⅡⅰ
		return true
	}
	return false
}

// egressAutoMountRoots：根目录下第一段是这些名字就算外发，已转小写。net、network 是访问即按需挂载网络共享的
// autofs 目录（Linux、macOS 的 /net，macOS 的 /Network/Servers）；.vol、.file、.nofollow、.resolve 是 macOS 按卷号、
// 文件号访问或绕开路径解析的根，能重新进到 /net（Claude Code 自己也把它们当网络路径）。
var egressAutoMountRoots = map[string]bool{"net": true, "network": true, ".vol": true, ".file": true, ".nofollow": true, ".resolve": true}

// egressMagicLinkDirs：内核魔术链接所在目录。/proc/self/root/net、/proc/self/cwd/../..、/dev/fd/N/net 由内核解析，
// 字面看不出落点，一律算外发（读写文件用不着经过它们）。
var egressMagicLinkDirs = []string{"/proc", "/dev/fd"}

// egressAutoMountTarget：转小写、path.Clean 后看会不会落到自动挂载目录：
//   - 绝对路径按 egressRootAutoMount 判；
//   - 以 ../ 开头的相对路径，开头那串 .. 可能一直退到根，去掉这串 .. 后的其余部分当成根下的绝对路径判
//     （../../../../net/srv 算外发；../linux/net/core 只是兄弟目录里叫 net 的普通目录，不算）；
//   - 其余相对路径落在工作目录下，不算（工作目录本身在网络挂载上属于已接受的残余）。
//
// 反斜杠按两种口径各判一次，任一判外发就算外发：Windows 下是分隔符（换成 /）；POSIX 下是普通字符，
// "/home\x/.." 这一段整体被 .. 抵消，实际退到根。
// "~" 开头的层数未知：HOME=/ 时 "~/net" 就是 /net，root 的 HOME=/root 时 "~/../net" 就是 /net，
// 所以 "~" 按零层（换成根）和任意层（换成 "../~"，走上面那条去掉开头 .. 的规则）各判一次。
// /tmp/../net、/./net、~/../../net 都由 Clean 规范化后认出。
func egressAutoMountTarget(value string) bool {
	lower := strings.ToLower(value)
	forms := []string{strings.ReplaceAll(lower, `\`, "/")}
	if strings.Contains(lower, `\`) {
		forms = append(forms, lower)
	}
	for _, form := range forms {
		if egressAutoMountForm(form) {
			return true
		}
		if form == "~" || strings.HasPrefix(form, "~/") {
			rest := strings.TrimPrefix(form, "~")
			if egressAutoMountForm("/"+rest) || egressAutoMountForm("../~"+rest) {
				return true
			}
		}
	}
	return false
}

// egressAutoMountForm：form 已转小写，按 / 分段（其中的反斜杠当普通字符）。
func egressAutoMountForm(form string) bool {
	cleaned := path.Clean(form)
	if !strings.HasPrefix(cleaned, "/") {
		if cleaned != ".." && !strings.HasPrefix(cleaned, "../") {
			return false
		}
		for cleaned == ".." || strings.HasPrefix(cleaned, "../") {
			cleaned = strings.TrimPrefix(strings.TrimPrefix(cleaned, ".."), "/")
		}
		cleaned = "/" + cleaned
	}
	return egressRootAutoMount(cleaned)
}

// egressRootAutoMount：cleaned 是规范化后的绝对路径。落在 egressMagicLinkDirs 下，或根下第一段是 egressAutoMountRoots，
// 算外发。macOS 的 /System/Volumes/Data（根目录下自动挂载点的真实位置）和 /Volumes/<卷名>（启动卷指向 /，卷名可改）
// 先去掉再判，可以叠用。
func egressRootAutoMount(cleaned string) bool {
	for {
		for _, dir := range egressMagicLinkDirs {
			if egressUnderDir(cleaned, dir) {
				return true
			}
		}
		first, rest, _ := strings.Cut(strings.TrimPrefix(cleaned, "/"), "/")
		if egressAutoMountRoots[first] {
			return true
		}
		switch {
		case egressUnderDir(cleaned, "/system/volumes/data"):
			cleaned = "/" + strings.TrimPrefix(strings.TrimPrefix(cleaned, "/system/volumes/data"), "/")
		case first == "volumes" && rest != "":
			_, after, _ := strings.Cut(rest, "/")
			cleaned = "/" + after
		default:
			return false
		}
	}
}

// egressUnderDir：cleaned 等于 dir 或在 dir 下。
func egressUnderDir(cleaned, dir string) bool {
	return cleaned == dir || strings.HasPrefix(cleaned, dir+"/")
}

// egressInvisible：空白、控制字符（C0、C1，含 U+001C–001F）和格式字符（Cf：U+FEFF、U+200B、U+2060……）。
// 客户端各自 trim 的集合不同：JS 的 trim 去 U+FEFF，Python 的 strip 去 U+001C–001F，Rust 的 trim 去 U+3000，
// 这里取并集再放宽，只会多判外发。
func egressInvisible(r rune) bool {
	return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}

func egressTrimLeading(value string) string {
	return strings.TrimLeftFunc(value, egressInvisible)
}

// egressASCIIBlank：补丁文件头里路径前只去掉 ASCII 空格和 TAB，别的不可见字符留给 egressLocalPathForm 判外发。
func egressASCIIBlank(r rune) bool { return r == ' ' || r == '\t' }

// egressGlobArgumentRemote：Glob、search_file 的 pattern、glob 类键指向网络路径（列目录时路径名随 SMB 请求
// 发到远端），按 egressGlobValueRemote 判。
func egressGlobArgumentRemote(args map[string]any) bool {
	return visitEgressArguments(args, func(key string, value any) bool {
		normalized := strings.ToLower(key)
		if !strings.Contains(normalized, "pattern") && !strings.Contains(normalized, "glob") {
			return false
		}
		for _, text := range egressArgumentStrings(value) {
			if egressGlobValueRemote(text) {
				return true
			}
		}
		return false
	})
}

// egressGlobValueRemote：通配写法的值。带花括号的一律算外发：花括号展开能把 / 和 /srv 拼成 //srv，这里不逐条展开。
// 以 '*' 开头的按相对路径算（不含 "://"、不会落到自动挂载目录才算本地），其余按 egressLocalPathForm 判。
func egressGlobValueRemote(text string) bool {
	if strings.Contains(text, "{") {
		return true
	}
	if strings.HasPrefix(text, "*") {
		return strings.Contains(text, "://") || egressAutoMountTarget(text)
	}
	return egressRemotePath(text)
}

// egressPathArgumentRemote：路径键的值不是本地写法。键名同时带 pattern、glob、type 的（CodeBuddy search_content 的
// fileTypes 等）值是文件名通配，按 egressGlobValueRemote 判，"*.py" 不算外发。
func egressPathArgumentRemote(args map[string]any) bool {
	return visitEgressArguments(args, func(key string, value any) bool {
		if !egressPathKey(key) {
			return false
		}
		remote := egressRemotePath
		if egressPatternKey(key) {
			remote = egressGlobValueRemote
		}
		for _, text := range egressArgumentStrings(value) {
			if remote(text) {
				return true
			}
		}
		return false
	})
}

// egressPatternKey：键名含 pattern、glob、type（fileTypes、filePattern、file_glob……）。
func egressPatternKey(key string) bool {
	normalized := strings.ToLower(key)
	return strings.Contains(normalized, "pattern") || strings.Contains(normalized, "glob") || strings.Contains(normalized, "type")
}

// egressPatchTargetsRemote：补丁正文里的文件头（*** Add File: 等、+++/---、diff --git）不是本地写法，
// 或补丁带 *** Environment ID:（codex 会把补丁路由到用户注册的执行环境，不一定在本机）。
//
// codex 补丁（*** Begin Patch 之后）的 Add File、Update File（含 Move to）文件头之后是正文：codex 只把 '+'、'-'、' '
// 开头的行和 @@ 行当正文，从不当文件头解析。删掉一行 "-- 注释" 在补丁里就是 "--- 注释"，上下文行也可能是 " --- "，
// 这些行不再按 +++、---、diff --git 取路径。正文里出现别的行（含 *** End Patch、Delete File 之后）就回到逐行认文件头。
func egressPatchTargetsRemote(args map[string]any) bool {
	var texts []string
	var walk func(value any, depth int)
	walk = func(value any, depth int) {
		if depth > maxScannedArgumentDepth {
			return
		}
		switch typed := value.(type) {
		case string:
			texts = append(texts, typed)
		case []string:
			texts = append(texts, typed...)
		case []any:
			for _, child := range typed {
				walk(child, depth+1)
			}
		case map[string]any:
			for _, child := range typed {
				walk(child, depth+1)
			}
		}
	}
	walk(args, 0)
	for _, text := range texts {
		begun, inBody := false, false
		// 按各种换行拆行（codex 只认 \n，多拆只会多判外发），行首的不可见字符先去掉：codex 认文件头前会 trim。
		for _, raw := range strings.FieldsFunc(text, egressLineBreak) {
			line := egressTrimLeading(raw)
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "*") && strings.HasPrefix(egressCompactLower(line), egressPatchEnvironmentHeader) {
				return true
			}
			var targets []string
			header := false
			if target, ok := egressPatchFileHeaderTarget(line); ok {
				targets, header = []string{target}, true
			} else {
				switch strings.TrimRightFunc(line, egressInvisible) {
				case "*** Begin Patch":
					begun, inBody = true, false
					continue
				case "*** End Patch":
					begun, inBody = false, false
					continue
				case "*** End of File":
					continue
				}
				if inBody && egressPatchBodyLine(raw) {
					continue
				}
				inBody = false
				if rest, ok := egressCutPrefixSpace(line, "+++"); ok {
					targets = []string{rest}
				} else if rest, ok := egressCutPrefixSpace(line, "---"); ok {
					targets = []string{rest}
				} else if rest, ok := egressCutPrefixSpace(line, "diff --git"); ok {
					// 按 ASCII 空格和 TAB 拆字段（git 的拆法），再并上按任意空白拆的字段，两种拆法任一判外发都算外发。
					targets = append(strings.FieldsFunc(rest, egressASCIIBlank), strings.Fields(rest)...)
					if len(targets) == 0 {
						return true
					}
				} else {
					continue
				}
			}
			for _, target := range targets {
				if len(target) > egressPatchHeaderMax {
					return true
				}
				// 路径前只去 ASCII 空格和 TAB；去完是空串（例如路径前的 \v 被当成换行拆开）也拿不准，算外发。
				target = strings.TrimLeftFunc(target, egressASCIIBlank)
				if target == "" || egressRemotePath(target) {
					return true
				}
			}
			if header {
				inBody = begun && !strings.HasPrefix(egressCompactLower(line), "***deletefile:")
			}
		}
	}
	return false
}

// egressPatchBodyLine：codex 补丁的正文行（按原样看，不 trim）：'+'、'-'、' ' 开头，或 @@ 开头。
func egressPatchBodyLine(raw string) bool {
	return raw[0] == '+' || raw[0] == '-' || raw[0] == ' ' || strings.HasPrefix(raw, "@@")
}

// egressLineBreak：\n、\r、\v、\f、U+0085、U+2028、U+2029。
func egressLineBreak(r rune) bool {
	switch r {
	case 0x0a, 0x0d, 0x0b, 0x0c, 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// egressPatchFileHeaders：codex 补丁的文件头，去掉空白和格式字符、转小写后比较（codex 只认原样的写法，
// 这里放宽到大小写、空格不同也算，只会多判外发）。
var egressPatchFileHeaders = []string{"***addfile:", "***updatefile:", "***deletefile:", "***moveto:"}

// egressPatchEnvironmentHeader：codex 补丁的 *** Environment ID: 行，比较方式同 egressPatchFileHeaders。
const egressPatchEnvironmentHeader = "***environmentid:"

// egressCompactLower：去掉空白、控制和格式字符后转小写。
func egressCompactLower(line string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		if egressInvisible(r) {
			return -1
		}
		return r
	}, line))
}

// egressPatchFileHeaderTarget：line 是文件头时返回冒号后的原文（前导空白由调用方处理）。
func egressPatchFileHeaderTarget(line string) (string, bool) {
	if !strings.HasPrefix(line, "*") {
		return "", false
	}
	compact := egressCompactLower(line)
	for _, prefix := range egressPatchFileHeaders {
		if strings.HasPrefix(compact, prefix) {
			_, target, _ := strings.Cut(line, ":")
			return target, true
		}
	}
	return "", false
}

// egressCutPrefixSpace：line 以 prefix 开头且后面紧跟空白时返回其余部分。
func egressCutPrefixSpace(line, prefix string) (string, bool) {
	rest, ok := strings.CutPrefix(line, prefix)
	if first, _ := utf8.DecodeRuneInString(rest); !ok || rest == "" || !egressInvisible(first) {
		return "", false
	}
	return rest, true
}
