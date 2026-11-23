package agentguard

import "strings"

type destructiveCommandSegment struct {
	Words           []string
	Redirects       []string
	AppendRedirects []string
	// AppendMode 仅由 POSIX 解析设置（动态目标的追加写）；词法兜底不设置。
	AppendMode bool
	// BaseDirs 是相对目标可能对应的工作目录：脚本里的字面 cd/pushd 目标和调用方给出的工作目录。
	BaseDirs         []string
	Redirect         bool
	DynamicArguments bool
	ParseRejected    bool
	// Evidence 是这一段在告警证据里的写法（命令词、前置赋值、重定向），脱敏前的解析结果。
	Evidence []EvidenceWord
	// EvidenceLexical 表示 Evidence 来自词法兜底（PowerShell、cmd）。
	EvidenceLexical bool
	// RawWords、RawRedirects、RawAppendRedirects 是词在源码里的原始写法（含引号、反斜杠），与对应的值一一对应，
	// 告警证据显示目标时用它保留 \\h\s\x 这样的原样。
	RawWords, RawRedirects, RawAppendRedirects []string
}

type destructiveExecutableInput struct {
	Command string
	Argv    []string
	Field   string
	// Lexical 表示 Command 是 PowerShell 脚本（Codex 数组里 powershell -Command 的值），走词法兜底解析。
	Lexical bool
}

func parseShellCommand(command string) ([]destructiveCommandSegment, bool) {
	reliable := true
	if len(command) > maxDestructiveCommandBytes {
		command = command[:maxDestructiveCommandBytes]
		reliable = false
	}
	segments := make([]destructiveCommandSegment, 0, 2)
	segment := destructiveCommandSegment{}
	var token strings.Builder
	var quote byte
	escaped := false
	redirectPending := false
	discardPending := false
	appendPending := false
	tokens := 0
	rawStart, pos := -1, 0
	touch := func(index int) {
		if rawStart < 0 {
			rawStart = index
		}
	}

	flushToken := func() {
		if token.Len() == 0 {
			rawStart = -1
			return
		}
		value := token.String()
		raw := value
		if rawStart >= 0 && pos >= rawStart && pos <= len(command) {
			raw = command[rawStart:pos]
		}
		rawStart = -1
		token.Reset()
		if tokens >= maxDestructiveSyntaxNodes {
			reliable = false
			redirectPending = false
			return
		}
		tokens++
		if discardPending {
			discardPending = false
			return
		}
		if redirectPending {
			if appendPending {
				segment.AppendRedirects = append(segment.AppendRedirects, value)
				segment.RawAppendRedirects = append(segment.RawAppendRedirects, raw)
				segment.Redirect = true
			} else {
				segment.Redirects = append(segment.Redirects, value)
				segment.RawRedirects = append(segment.RawRedirects, raw)
			}
			redirectPending = false
			appendPending = false
			return
		}
		segment.Words = append(segment.Words, value)
		segment.RawWords = append(segment.RawWords, raw)
	}
	flushSegment := func() {
		flushToken()
		if len(segment.Words) > 0 || len(segment.Redirects) > 0 {
			segment.Evidence = lexerEvidenceWords(segment)
			segments = append(segments, segment)
		}
		segment = destructiveCommandSegment{}
		redirectPending = false
		appendPending = false
		discardPending = false
	}

	for index := 0; index < len(command); index++ {
		pos = index
		ch := command[index]
		if escaped {
			token.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' && quote != '\'' {
			touch(index)
			if index+2 < len(command) && command[index+1] == '\\' && command[index+2] == '?' {
				token.WriteByte(ch)
				continue
			}
			if index+1 < len(command) && isShellEscapedByte(command[index+1]) {
				escaped = true
				continue
			}
			token.WriteByte(ch)
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
				continue
			}
			token.WriteByte(ch)
			continue
		}
		if ch == '\'' || ch == '"' {
			touch(index)
			quote = ch
			continue
		}
		switch ch {
		case ' ', '\t', '\r':
			flushToken()
		case ';', '|', '&', '\n':
			flushSegment()
		case '>':
			if isFileDescriptorToken(token.String()) {
				// 2>、1> 前面的数字是文件描述符，不是命令参数。
				token.Reset()
				rawStart = -1
			}
			flushToken()
			if index+1 < len(command) && command[index+1] == '&' {
				// 2>&1、>&2：复制文件描述符，不写文件；紧跟的描述符数字一并丢弃。
				index++
				discardPending = true
				continue
			}
			if index+1 < len(command) && command[index+1] == '>' {
				// >> 追加写：目标词记入追加目标，由目标敏感度决定是否报告。
				index++
				redirectPending = true
				appendPending = true
				continue
			}
			segment.Redirect = true
			redirectPending = true
			appendPending = false
		default:
			touch(index)
			token.WriteByte(ch)
		}
	}
	pos = len(command)
	if escaped {
		token.WriteByte('\\')
	}
	flushSegment()
	applyLexerChangeDirs(segments)
	return segments, reliable
}

func argvCommandSegment(argv []string) destructiveCommandSegment {
	segment := destructiveCommandSegment{Words: append([]string(nil), argv...)}
	segment.Evidence = plainEvidenceWords(segment.Words)
	return segment
}

func isShellEscapedByte(ch byte) bool {
	switch ch {
	case ' ', '\t', '\r', '\n', '\\', '\'', '"', ';', '|', '&', '>':
		return true
	default:
		return false
	}
}

func isFileDescriptorToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// applyLexerChangeDirs 把脚本里字面参数的 cd、chdir、pushd、Set-Location、sl 目标记为所有重定向段的候选工作目录；
// 目标过多无法逐个拼接时，带相对目标的段按解析不完整处理。
func applyLexerChangeDirs(segments []destructiveCommandSegment) {
	var bases []string
	overflow := false
	for _, segment := range segments {
		if len(segment.Words) < 2 {
			continue
		}
		switch strings.ToLower(segment.Words[0]) {
		case "cd", "chdir", "pushd", "push-location", "set-location", "sl":
		default:
			continue
		}
		for _, word := range segment.Words[1:] {
			lowered := strings.ToLower(word)
			if strings.HasPrefix(lowered, "-") || lowered == "/d" {
				continue
			}
			if !strings.ContainsAny(word, "$%") {
				duplicate := false
				for _, existing := range bases {
					duplicate = duplicate || existing == word
				}
				if duplicate {
					break
				}
				if len(bases) >= maxCDTargets {
					overflow = true
				} else {
					bases = append(bases, word)
				}
			}
			break
		}
	}
	if len(bases) == 0 && !overflow {
		return
	}
	for index := range segments {
		if !segments[index].Redirect {
			continue
		}
		segments[index].BaseDirs = bases
		if overflow && (anyRelativeTarget(segments[index].Redirects) || anyRelativeTarget(segments[index].AppendRedirects)) {
			segments[index].ParseRejected = true
		}
	}
}
