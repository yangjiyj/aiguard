// Package filerestrict 提供"受限文件模式"的共享匹配能力，以及从智能体
// 工具调用参数中抽取命令文本的通用解析（Codex argv / JS 自由格式等形态）。
// 纯函数、无 I/O、无全局状态、无第三方依赖，gateway-core 与 proxy-server 共用。
package filerestrict

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode/utf16"
)

// ExtractCommandTexts 从工具调用参数中抽取可独立分析的命令文本列表，
// 以及供粗略层扫描的整段文本（coarseText）。
//
// 覆盖形态：
//   - command|argv|args 为数组：bash|sh|zsh|fish|dash + -c|-lc|-ic|-lic 取其后一个元素；
//     powershell|pwsh + -Command|-c|-EncodedCommand（EncodedCommand 做 base64+UTF-16LE 解码，
//     失败则原样）；cmd|cmd.exe + /c|/k 取其后拼接；其余 argv 用空格拼成一条。
//   - input|code|script|source 字符串含 exec_command( / tools. / write_stdin( 时，
//     抽每个 cmd: 字面量（先 JSON unquote，失败退回原文）各一条命令，整段代码作为 coarseText。
//   - command|cmd|script|input 为字符串时按一条命令处理（保持向后兼容）。
func ExtractCommandTexts(arguments map[string]any) (commands []string, coarseText string) {
	scripts, coarseText := extractCommandScripts(arguments)
	for _, script := range scripts {
		commands = append(commands, script.Text)
	}
	return commands, coarseText
}

// 命令文本由哪种解释器执行。只有 argv 数组形态能看出来；字符串形态和 JS 字面量是 InterpreterNone。
const (
	InterpreterNone       = ""
	InterpreterPOSIX      = "posix"
	InterpreterPowerShell = "powershell"
	InterpreterCmd        = "cmd"
)

// CommandScript 是抽出的一条命令文本及其解释器。
type CommandScript struct {
	Text        string
	Interpreter string
}

// ExtractCommandScripts 与 ExtractCommandTexts 抽取同样的命令、同样的顺序，另外标出 argv 数组形态的解释器：
// bash -c 的脚本是 POSIX，powershell -Command / -EncodedCommand 的脚本是 PowerShell，cmd /c 之后是 cmd。
func ExtractCommandScripts(arguments map[string]any) []CommandScript {
	scripts, _ := extractCommandScripts(arguments)
	return scripts
}

func extractCommandScripts(arguments map[string]any) (scripts []CommandScript, coarseText string) {
	if arguments == nil {
		return nil, ""
	}
	add := func(text, interpreter string) {
		scripts = append(scripts, CommandScript{Text: text, Interpreter: interpreter})
	}

	// 1. argv 形态：command|argv|args 为数组。
	for _, key := range []string{"command", "argv", "args"} {
		if argv, ok := toStringSlice(arguments[key]); ok && len(argv) > 0 {
			if script, interpreter := scriptFromArgvWithInterpreter(argv); script != "" {
				add(script, interpreter)
			}
		}
	}

	// 2. JS/代码自由格式：input|code|script|source 字符串里藏 exec_command 调用。
	for _, key := range []string{"input", "code", "script", "source"} {
		raw, ok := arguments[key].(string)
		if !ok || raw == "" {
			continue
		}
		if isAgentCodeBlob(raw) {
			for _, literal := range extractCmdLiterals(raw) {
				add(literal, InterpreterNone)
			}
			if coarseText == "" {
				coarseText = raw
			} else {
				coarseText += "\n" + raw
			}
			continue
		}
		// 普通字符串参数（如老形态 {"command":"rm -rf /"} / {"input":"ls"}）按一条命令。
		if key == "input" || key == "script" {
			add(raw, InterpreterNone)
		}
	}

	// 3. command|cmd 为字符串（未在 1 中作为数组命中时）。
	// 注意 script 已在第 2 步处理过，这里不重复收集。
	for _, key := range []string{"command", "cmd"} {
		if s, ok := arguments[key].(string); ok && strings.TrimSpace(s) != "" {
			add(s, InterpreterNone)
		}
	}

	return scripts, coarseText
}

// ExtractCommandTextsFromJSON 解析 JSON 参数串后调用 ExtractCommandTexts；
// 解不开 JSON 时把整串当作 coarseText 返回（不丢信息）。
func ExtractCommandTextsFromJSON(arguments string) (commands []string, coarseText string) {
	trimmed := strings.TrimSpace(arguments)
	if trimmed == "" {
		return nil, ""
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil, trimmed
	}
	return ExtractCommandTexts(parsed)
}

// isAgentCodeBlob 判断字符串是否是智能体代码包装（Codex JS 自由格式等）。
func isAgentCodeBlob(s string) bool {
	return strings.Contains(s, "exec_command(") ||
		strings.Contains(s, "tools.") ||
		strings.Contains(s, "write_stdin(")
}

// extractCmdLiterals 从代码文本中抽出每个 cmd: "..." 字面量的值。
// 先按 JSON 字符串规则 unquote（能处理 \" \\ \n 等转义），失败退回原文。
func extractCmdLiterals(code string) []string {
	var out []string
	rest := code
	for {
		idx := strings.Index(rest, "cmd:")
		if idx < 0 {
			return out
		}
		rest = rest[idx+len("cmd:"):]
		rest = strings.TrimLeft(rest, " \t")
		if len(rest) == 0 || (rest[0] != '"' && rest[0] != '\'') {
			continue
		}
		quote := rest[0]
		// 找匹配结束引号（尊重反斜杠转义）。
		end := -1
		for i := 1; i < len(rest); i++ {
			if rest[i] == '\\' {
				i++
				continue
			}
			if rest[i] == quote {
				end = i
				break
			}
		}
		if end < 0 {
			return out
		}
		literal := rest[:end+1]
		rest = rest[end+1:]
		value := literal[1 : len(literal)-1]
		if quote == '"' {
			var unquoted string
			if err := json.Unmarshal([]byte(literal), &unquoted); err == nil {
				value = unquoted
			}
		}
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
}

// scriptFromArgv 按解释器语义把 argv 折叠成一条脚本/命令文本。
func scriptFromArgv(argv []string) string {
	script, _ := scriptFromArgvWithInterpreter(argv)
	return script
}

// scriptFromArgvWithInterpreter 折叠 argv 并返回脚本的解释器。没有 -c、-Command、/c 时把 argv 拼成一条命令，
// 含空白或 shell 元字符的元素加引号，元素不会在后续按词切分时被拆开（"/opt/My Dir" 仍是一个词）。
func scriptFromArgvWithInterpreter(argv []string) (string, string) {
	if len(argv) == 0 {
		return "", InterpreterNone
	}
	shell := baseName(argv[0])
	switch shell {
	case "bash", "sh", "zsh", "fish", "dash":
		for i := 1; i < len(argv); i++ {
			switch argv[i] {
			case "-c", "-lc", "-ic", "-lic":
				if i+1 < len(argv) {
					return argv[i+1], InterpreterPOSIX
				}
				return "", InterpreterNone
			}
		}
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		for i := 1; i < len(argv); i++ {
			flag := strings.ToLower(argv[i])
			switch flag {
			case "-command", "-c":
				if i+1 < len(argv) {
					return argv[i+1], InterpreterPowerShell
				}
				return "", InterpreterNone
			case "-encodedcommand", "-ec", "-e":
				if i+1 < len(argv) {
					if decoded, ok := decodeEncodedCommand(argv[i+1]); ok {
						return decoded, InterpreterPowerShell
					}
					return argv[i+1], InterpreterPowerShell
				}
				return "", InterpreterNone
			}
		}
	case "cmd", "cmd.exe":
		for i := 1; i < len(argv); i++ {
			flag := strings.ToLower(argv[i])
			if flag == "/c" || flag == "/k" {
				rest := argv[i+1:]
				switch len(rest) {
				case 0:
					return "", InterpreterNone
				case 1:
					return rest[0], InterpreterCmd // 唯一的元素就是整条命令行
				}
				quoted := make([]string, 0, len(rest))
				for _, word := range rest {
					quoted = append(quoted, quoteCmdWord(word))
				}
				return strings.Join(quoted, " "), InterpreterCmd
			}
		}
	}
	return joinPOSIXWords(argv), InterpreterNone
}

// joinPOSIXWords 用空格拼接 argv，含空白或 shell 元字符的元素加引号。
func joinPOSIXWords(argv []string) string {
	quoted := make([]string, 0, len(argv))
	for _, word := range argv {
		quoted = append(quoted, quotePOSIXWord(word))
	}
	return strings.Join(quoted, " ")
}

func quotePOSIXWord(word string) string {
	if word == "" {
		return "''"
	}
	safe := true
	for _, r := range word {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r > 127:
		case strings.ContainsRune("_@%+=:,./-", r):
		default:
			safe = false
		}
	}
	switch {
	case safe:
		return word
	case !strings.Contains(word, "'"):
		return "'" + word + "'"
	case !strings.ContainsAny(word, "\"$`\\!"):
		return `"` + word + `"`
	}
	return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
}

// quoteCmdWord 按 Windows 命令行规则给含空白或 cmd 元字符的元素加双引号。
func quoteCmdWord(word string) string {
	if word != "" && !strings.ContainsAny(word, " \t&|<>^()") {
		return word
	}
	return `"` + strings.ReplaceAll(word, `"`, `\"`) + `"`
}

// decodeEncodedCommand 解码 PowerShell -EncodedCommand（base64 + UTF-16LE），失败返回原样。
func decodeEncodedCommand(encoded string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", false
	}
	if len(raw)%2 != 0 {
		return "", false
	}
	u16 := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		u16 = append(u16, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	return string(utf16.Decode(u16)), true
}

func toStringSlice(value any) ([]string, bool) {
	switch typed := value.(type) {
	case []string:
		if len(typed) == 0 {
			return nil, false
		}
		return append([]string(nil), typed...), true
	case []any:
		if len(typed) == 0 {
			return nil, false
		}
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}
