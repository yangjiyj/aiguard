package agentguard

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// 第八轮性能：整行开关原来用正则在整行上匹配（64KB 以上的行很慢），改成一遍扫描。这里保留原来
// 的正则，逐条确认：原正则认出来的，扫描一定也认出来（只会更严，不会放过）。
var (
	oldShellFunctionKeyword     = regexp.MustCompile(`(^|[\s;&|(){}])function\s+\S`)
	oldShellAlias               = regexp.MustCompile(`(^|[\s;&|(){}])alias(\s|$)`)
	oldShellEmptyParens         = regexp.MustCompile(`\(\s*\)`)
	oldShellTracing             = regexp.MustCompile(`(^|[\s;&|(){}'"])((set|sh|bash|zsh|dash|ksh|mksh|ash)\s+(-[A-Za-z]*[xvT][A-Za-z]*\b|-o\s+(xtrace|verbose|functrace)\b)|trap(\s|$))`)
	oldShellOptsAssignment      = regexp.MustCompile(`(^|[^A-Za-z0-9_])SHELLOPTS\+?=`)
	oldShellRewritingAssignment = regexp.MustCompile(`(^|[^A-Za-z0-9_$])(BASH_[A-Za-z0-9_]*|DYLD_[A-Za-z0-9_]*|PATH|ENV|PS4|PROMPT_COMMAND|SHELLOPTS|BASHOPTS|GLOBIGNORE|IFS|LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT)(\[[^\]]*\])?\+?=|\$\{(BASH_[A-Za-z0-9_]*|DYLD_[A-Za-z0-9_]*|PATH|ENV|PS4|PROMPT_COMMAND|SHELLOPTS|BASHOPTS|GLOBIGNORE|IFS|LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT):?=`)
)

func oldRedefinesCommands(command string) bool {
	if oldShellFunctionKeyword.MatchString(command) || oldShellAlias.MatchString(command) {
		return true
	}
	for _, match := range oldShellEmptyParens.FindAllStringIndex(command, -1) {
		before := strings.TrimRight(command[:match[0]], " \t")
		if before != "" && strings.IndexByte("$=<>(", before[len(before)-1]) < 0 {
			return true
		}
	}
	return false
}

func requireScannerCoversRegex(t *testing.T, raw string) {
	t.Helper()
	tokens := shellSwitchTokens(raw)
	if oldRedefinesCommands(raw) && !redefinesCommandsIn(raw, tokens) {
		t.Fatalf("redefines: regex matches, scanner does not: %q", raw)
	}
	if oldShellTracing.MatchString(raw) && !tracingInText(tokens) {
		t.Fatalf("tracing: regex matches, scanner does not: %q", raw)
	}
	if (oldShellRewritingAssignment.MatchString(raw) || oldShellOptsAssignment.MatchString(raw)) && !rewritesVariableInText(raw, tokens) {
		t.Fatalf("rewriting: regex matches, scanner does not: %q", raw)
	}
}

func TestLineSwitchScannersCoverOldRegexps2922(t *testing.T) {
	fixed := []string{
		"function f { :; }", "x;function  g", "alias ll='ls -l'", "(alias)", "grep () { :; }", "\\grep(){ sh; }",
		"\"grep\"()", "a=()", "$( )", "<( )", "(( ))", "set -x", "set -euxo pipefail", "bash -T -c x", "sh -o  xtrace",
		"'set -v'", "trap 'x' DEBUG", "x;trap", "set -o functrace", "PATH=/x", "PATH+=:/x", "BASH_CMDS[grep]=sed",
		"${PATH:=x}", "${IFS=x}", "export LD_PRELOAD=x", "DYLD_X=1", "a=1 IFS= read", "SHELLOPTS=xtrace bash",
		"echo $PATH=x", "MYPATH=x", "1PATH=x", "x_PATH=1", "BASH_A[[x]]=1", "BASH_A[x]+=1", "\tIFS=\n",
	}
	for _, raw := range fixed {
		requireScannerCoversRegex(t, raw)
	}
	pieces := []string{"set", "bash", "sh", "trap", "-x", "-e", "-o", "xtrace", "verbose", "-T", "functrace", "alias",
		"function", "f", "(", ")", "()", " ", "  ", "\t", "\n", ";", "&", "|", "{", "}", "'", "\"", "$", "${", ":=", "=",
		"+=", "[", "]", "PATH", "IFS", "BASH_ENV", "BASH_CMDS", "LD_PRELOAD", "DYLD_X", "ENV", "SHELLOPTS", "x", "_", "1",
		"<", ">", "$(", "grep", "for", "in"}
	random := rand.New(rand.NewSource(2922))
	for round := 0; round < 20000; round++ {
		var b strings.Builder
		for n := random.Intn(8) + 1; n > 0; n-- {
			b.WriteString(pieces[random.Intn(len(pieces))])
		}
		requireScannerCoversRegex(t, b.String())
	}
}
