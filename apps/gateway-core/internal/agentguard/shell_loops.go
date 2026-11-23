package agentguard

import (
	"regexp"
	"sort"
	"strings"
)

// for 循环字面列表（设计第 6 节）：for NAME in 后面全是字面词、只含 [A-Za-z0-9._-]、都是
// ~/.ssh 下的公开文件（known_hosts*、config、authorized_keys*、*.pub），且整条命令行没有别的写法
// 能改 NAME 的值（另一处赋值或 for、带操作符的 ${NAME...}、IFS、${!、eval、source、.、
// declare、typeset、local、readonly、export、unset、let、read、mapfile、readarray、
// printf -v、trap、select、getopts、((...))）时，循环体里的 $NAME、${NAME} 逐个代入再判定。
// 其余写法照旧从严（~/.ssh/$f 按凭据目录里的变量判定）。

type shellLoopBinding struct {
	name   string
	values []string
}

var (
	shellLoopLiteralValue = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	shellLoopIdentifier   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	shellLoopUnsafeLine   = regexp.MustCompile(`\b(eval|source|declare|typeset|local|readonly|export|unset|let|read|mapfile|readarray|trap|select|getopts)\b|IFS|\$\{!|\(\(`)
)

// maxShellLoopVariants bounds how many substituted variants one word yields;
// maxShellLoopHeaders bounds the loops of a line whose values are substituted
// (more than that, none is: strictly).
const (
	maxShellLoopVariants = 64
	maxShellLoopHeaders  = 32
)

// shellLoopRange binds a loop variable for the commands from..to of a line.
type shellLoopRange struct {
	from, to int
	binding  shellLoopBinding
}

// shellLineLoops are the loop bindings of a line, as ranges of commands.
type shellLineLoops []shellLoopRange

// at returns the bindings of command index, in the order of the loops.
func (ranges shellLineLoops) at(index int) []shellLoopBinding {
	var out []shellLoopBinding
	for _, r := range ranges {
		if index >= r.from && index <= r.to {
			out = append(out, r.binding)
		}
	}
	return out
}

// literalLoopBindings returns the loop variables the words of each command
// of the line may substitute, as ranges of commands (a binding per command
// cost the square of the line on "for v in config; " repeated). The commands
// each loop spans count as work.
func literalLoopBindings(raw string, commands []shellSimpleCommand, work *shellWork) shellLineLoops {
	var out shellLineLoops
	type header struct {
		index  int
		name   string
		values []string
	}
	var headers []header
	perName := map[string]int{}
	unsafe := false
	for index, simple := range commands {
		program, args := shellProgram(simple.Words)
		switch {
		case program == ".":
			unsafe = true
		case program == "printf":
			for _, arg := range args {
				if strings.HasPrefix(arg, "-v") {
					unsafe = true
				}
			}
		case program == "for" && len(args) > 0:
			perName[args[0]]++
			if values, ok := publicSSHLoopValues(args); ok {
				headers = append(headers, header{index: index, name: args[0], values: values})
			}
		}
	}
	// 没有可代入的循环时不必再扫整行（长命令行上这条正则很费时）。
	if unsafe || len(headers) == 0 || len(headers) > maxShellLoopHeaders || shellLoopUnsafeLine.MatchString(raw) {
		return out
	}
	uses := scanLoopNameUses(raw)
	for _, h := range headers {
		if perName[h.name] > 1 || !uses.untouched(h.name) {
			continue
		}
		end := loopEnd(commands, h.index)
		work.add(end - h.index)
		out = append(out, shellLoopRange{from: h.index + 1, to: end, binding: shellLoopBinding{name: h.name, values: h.values}})
	}
	return out
}

// publicSSHLoopValues accepts "NAME in v1 v2 ..." whose values are literal
// public ~/.ssh file names.
func publicSSHLoopValues(args []string) ([]string, bool) {
	if len(args) < 3 || !shellLoopIdentifier.MatchString(args[0]) || args[1] != "in" {
		return nil, false
	}
	values := args[2:]
	for _, value := range values {
		if !shellLoopLiteralValue.MatchString(value) || !isPublicSSHFileName(value) {
			return nil, false
		}
	}
	return values, true
}

func isPublicSSHFileName(name string) bool {
	return name == "config" || strings.HasPrefix(name, "known_hosts") || strings.HasPrefix(name, "authorized_keys") ||
		strings.HasSuffix(name, ".pub")
}

// loopNameUses holds, from one pass over a command line, the names it
// assigns (NAME=, NAME+=, NAME[...]=, not after "$") and the names after
// "${" with what follows them, for every loop header to look up (before, a
// regular expression was compiled and run over the line per header).
type loopNameUses struct {
	assigned map[string]bool
	// braced: the names right after "${", sorted; open: those followed by
	// something other than "}".
	braced []string
	open   map[string]bool
}

func scanLoopNameUses(raw string) loopNameUses {
	uses := loopNameUses{assigned: map[string]bool{}, open: map[string]bool{}}
	nextClose := -1
	for i := 0; i < len(raw); i++ {
		if !isShellNameByte(raw[i]) {
			continue
		}
		end := i
		for end < len(raw) && isShellNameByte(raw[end]) {
			end++
		}
		name, start := raw[i:end], i
		i = end - 1
		if start >= 2 && raw[start-1] == '{' && raw[start-2] == '$' {
			uses.braced = append(uses.braced, name)
			if end >= len(raw) || raw[end] != '}' {
				uses.open[name] = true
			}
		}
		if start > 0 && raw[start-1] == '$' {
			continue
		}
		at := end
		if at < len(raw) && raw[at] == '[' {
			if nextClose < at {
				if found := strings.IndexByte(raw[at:], ']'); found >= 0 {
					nextClose = at + found
				} else {
					nextClose = len(raw)
				}
			}
			if nextClose >= len(raw) {
				continue
			}
			at = nextClose + 1
		}
		if at < len(raw) && raw[at] == '+' {
			at++
		}
		if at < len(raw) && raw[at] == '=' {
			uses.assigned[name] = true
		}
	}
	sort.Strings(uses.braced)
	return uses
}

// untouched: the line assigns name nowhere else and every ${name...} is a
// plain ${name} (${nameX...} counts as touching it, as before).
func (uses loopNameUses) untouched(name string) bool {
	if uses.assigned[name] || uses.open[name] {
		return false
	}
	at := sort.SearchStrings(uses.braced, name)
	for ; at < len(uses.braced) && strings.HasPrefix(uses.braced[at], name); at++ {
		if len(uses.braced[at]) > len(name) {
			return false
		}
	}
	return true
}

// loopEnd returns the index of the command holding the "done" that closes the
// loop opened at header, or the last command.
func loopEnd(commands []shellSimpleCommand, header int) int {
	depth := 1
	for index := header + 1; index < len(commands); index++ {
		for _, word := range commands[index].Words {
			// Only the leading keywords of a command open or close a loop.
			if !shellKeywords[word] && !compoundOpeners[word] && !compoundClosers[word] {
				break
			}
			switch word {
			case "for", "while", "until", "select":
				depth++
			case "done":
				depth--
				if depth == 0 {
					return index
				}
			}
		}
	}
	return len(commands) - 1
}

// expandLoopWord substitutes each loop value for $NAME / ${NAME} in word.
// A word that names no loop variable is returned as is.
func expandLoopWord(word string, loops []shellLoopBinding) []string {
	var active []shellLoopBinding
	for _, binding := range loops {
		if strings.Contains(word, "$"+binding.name) || strings.Contains(word, "${"+binding.name+"}") {
			active = append(active, binding)
		}
	}
	if len(active) == 0 {
		return []string{word}
	}
	// The first maxShellLoopVariants combinations in loop order, depth first:
	// a prefix is substituted once and shared by the combinations below it
	// (substituting loop by loop rebuilt up to 64 strings per loop: with 32
	// loops of 60 values that was two thousand strings per word).
	out := make([]string, 0, maxShellLoopVariants)
	var walk func(depth int, text string)
	walk = func(depth int, text string) {
		if depth == len(active) {
			out = append(out, text)
			return
		}
		for _, value := range active[depth].values {
			if len(out) >= maxShellLoopVariants {
				return
			}
			walk(depth+1, substituteShellVariable(text, active[depth].name, value))
		}
	}
	walk(0, word)
	return out
}

// substituteShellVariable replaces ${name} and $name (not followed by another
// identifier character) with value.
func substituteShellVariable(text, name, value string) string {
	text = strings.ReplaceAll(text, "${"+name+"}", value)
	var out strings.Builder
	token := "$" + name
	for {
		at := strings.Index(text, token)
		if at < 0 {
			out.WriteString(text)
			return out.String()
		}
		end := at + len(token)
		if end < len(text) && isShellIdentifierByte(text[end]) {
			out.WriteString(text[:end])
			text = text[end:]
			continue
		}
		out.WriteString(text[:at])
		out.WriteString(value)
		text = text[end:]
	}
}

func isShellIdentifierByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
