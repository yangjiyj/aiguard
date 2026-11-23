package agentguard

import (
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
)

// 2.9.22 起 shell 命令的每个参数先按程序理解它的角色，再决定怎么判定（设计 5.1、第 6 节）：
//   - 读：照 2.9.21 逐词判定；
//   - 不是文件：表达式、搜索模式、资源名、提交说明等，跳过；
//   - 写：只有私钥和云凭据算命中（覆盖、追加、拷入）；
//   - 使用：kubeconfig 被 kube 客户端拿来认证、.env 被 source / --env-file 加载，不算读
//     这一类凭据，别的类照旧算读。
// 程序和选项认不全时回到 2.9.21 的整词判定（全部按读）。

type shellArgRole uint8

const (
	shellArgRead shellArgRole = iota
	shellArgSkip
	shellArgWrite
	shellArgUseKubeconfig
	shellArgUseEnvFile
	// shellArgReadCode: a word of code (a here-document an interpreter runs,
	// an ssh remote command judged whole): read, but a name that only looks
	// sensitive counts only for a path-like word (pathLikeWord), not for an
	// identifier such as secrets.token_hex or process.env.
	shellArgReadCode
	// shellArgReadLineSwitched: a word the program's roles call "not a file"
	// (data, pattern, resource name) read anyway because a line-wide switch is
	// on (a pipe into a shell or interpreter, eval, source ...). It is read,
	// but a name that only looks sensitive counts only when the word itself
	// may name a file (wordMayNameFile): the JSON curl -d sends
	// ('{"tool":"../etc/passwd"}') is not /etc/passwd (2026-11-21 客户现场).
	shellArgReadLineSwitched
)

// admits reports whether a hit of reason on path counts for a word in this
// role. storeRef: the hit is a whole credential store directory or a glob or
// variable inside one, not one named file.
//
// 使用只对与用法对应的目标类别不算读（协调方 11-17 决定）：source、.、--env-file、
// compose 的 env_file 只放开 .env 类；--kubeconfig、KUBECONFIG= 只放开 kubeconfig 类文件
// （路径在 .kube/ 下，或文件名含 kubeconfig）。其余照读判：bash、docker、kubectl 解析失败
// 会把行内容打到错误输出里。
func (role shellArgRole) admits(reason string, storeRef bool, path string) bool {
	switch role {
	case shellArgSkip:
		return false
	case shellArgWrite:
		// 写只算私钥和云凭据文件本身；往 ~/.ssh 目录里放公钥不算。
		return !storeRef && (reason == targetReasonSSHPrivateKey || reason == targetReasonCloudCredential)
	case shellArgUseKubeconfig:
		if !isKubeconfigPath(path) {
			return true
		}
		switch reason {
		case targetReasonCloudCredential, targetReasonSecretMount, targetReasonSensitiveName:
			return false
		}
		return true
	case shellArgUseEnvFile:
		return reason != targetReasonEnvFile
	case shellArgReadCode:
		return reason != targetReasonSensitiveName || pathLikeWord(path)
	}
	return true
}

// pathLikeExtensions are the file extensions that make a bare word look like
// a file name (env is not one: process.env is code).
var pathLikeExtensions = flagSet("json", "yaml", "yml", "toml", "ini", "conf", "cfg", "txt", "pem", "key", "crt",
	"cer", "der", "p12", "pfx", "jks", "gpg", "asc", "db", "sqlite", "log", "csv", "xml", "properties", "sh",
	"py", "js", "ts", "go", "rb")

// pathLikeWord: a word that reads as a path, not as code: no blank, quote,
// parenthesis, brace, operator or assignment in it, and it holds "/" or "\",
// starts with "~" or ".", or ends in a common file extension.
func pathLikeWord(word string) bool {
	word = strings.TrimSpace(word)
	if word == "" || strings.ContainsAny(word, " \t\n\"'`(){}+,;<>|&=") {
		return false
	}
	if strings.ContainsAny(word, `/\`) || strings.HasPrefix(word, "~") || strings.HasPrefix(word, ".") {
		return true
	}
	dot := strings.LastIndexByte(word, '.')
	return dot >= 0 && pathLikeExtensions[strings.ToLower(word[dot+1:])]
}

// isKubeconfigPath: a kubeconfig file by location or name, a path under a
// .kube directory (~/.kube/config, ~/.kube/config-prod) or a file whose name
// holds "kubeconfig".
func isKubeconfigPath(path string) bool {
	normalized := strings.ToLower(normalizeFilePath(strings.TrimSpace(path)))
	// The whole word "--kubeconfig=x" / "KUBECONFIG=x" is a candidate too.
	for _, prefix := range []string{"--kubeconfig=", "kubeconfig="} {
		normalized = strings.TrimPrefix(normalized, prefix)
	}
	return strings.Contains("/"+normalized, "/.kube/") || strings.Contains(filepath.Base(normalized), "kubeconfig")
}

// maxShellNesting bounds how deep remote and inline command strings (ssh
// host "...", sh -c "...", kubectl exec -- sh -c "...", here-documents fed to
// a shell) are parsed again. Deeper strings are judged word by word as in
// 2.9.21.
const maxShellNesting = 3

// shellLineContext carries what one command line (the whole command, or a
// nested remote or inline command) knows across its simple commands.
type shellLineContext struct {
	commands []shellSimpleCommand
	// code: the text of the commands that run code, built on first use
	// (codeText); mentioned: per base name, whether code names it.
	code               *string
	mentioned          map[string]bool
	keyUse             sshKeyUseContext
	kubeconfigMentions int
	// kubeconfigUse: KUBECONFIG set on this line is only read by kube
	// clients (kubeconfigVariableUse).
	kubeconfigUse bool
	storeDir      string
	depth         int
	// consumed: the output of this line feeds the enclosing line where it
	// may become file names (captured, piped into xargs, ...).
	consumed bool
	// mentions counts every word, redirection target and whitespace-separated
	// token of nested command strings and here-document bodies, to see
	// whether a file one command writes is named again on the line.
	mentions map[string]int
	// guarded[i]: what command i prints may become file names of another
	// command (see outputConsumed).
	guarded []bool
	// intoFile: what this line prints lands in a regular file of the
	// enclosing line ("ssh h 'jq -n ...' > list.txt").
	intoFile bool
	// dataOnly[i]: command i and the commands its pipeline feeds only filter,
	// store, send or apply text (see heredocDataOnly).
	dataOnly []bool
	// switches: the line-wide switches (see lineSwitches); wholeWords is
	// switches.wholeWords.
	switches   lineSwitches
	wholeWords bool
	// compose[i]: command i, or a command its pipeline feeds, is docker
	// compose / docker-compose / docker stack deploy reading its compose file
	// from standard input (only there env_file: loads environment files).
	compose []bool
	// writesFile[i]: command i, or a command its pipeline feeds, writes its
	// output to a regular file (not /dev/null, not an ignore file).
	writesFile []bool
	// instructions[i]: command i, or a command its pipeline feeds, takes
	// standard input as a configuration, build or compose file, or a list of
	// file names (curl -K -, ...).
	instructions []bool
	// loops holds, per command, the literal for-loop values its words may
	// substitute for a loop variable.
	loops shellLineLoops
	// shellish / interpreter: some command of the line runs a shell or an
	// interpreter (decides how here-document bodies are judged).
	shellish, interpreter bool
}

// shellTargetScan collects protection-item hits of one shell call. The
// first hit leads the merged finding; all hits are kept.
type shellTargetScan struct {
	merged Decision
	found  bool
	// switches: what the command lines seen so far make unclear; nested
	// lines inherit it.
	switches lineSwitches
	// writes: what the command lines seen so far write; nested lines see
	// what an enclosing line writes.
	writes shellWrites
	// work bounds the work of the whole call (shell_work.go).
	work *shellWork
}

func (s *shellTargetScan) add(next Decision) {
	if !s.found {
		s.merged, s.found = next, true
		return
	}
	s.merged = mergeAnalyzerDecision(s.merged, next)
}

// analyzeShellCommandTargets records a protection-item hit for every secret
// file a shell command reads, credential store it reads or ships, private key
// or cloud credential it writes, and git credential dump.
func analyzeShellCommandTargets(command string) (Decision, bool) {
	decision, found, _ := analyzeShellCommandTargetsWork(command)
	return decision, found
}

// analyzeShellCommandTargetsWork is analyzeShellCommandTargets returning its
// work meter. Past the limit the precise parse stops and the whole command
// is judged word by word as reads (2.9.21), the hits found so far kept.
func analyzeShellCommandTargetsWork(command string) (Decision, bool, *shellWork) {
	scan := shellTargetScan{work: newShellWork(command)}
	scan.line(command, 0, false)
	if scan.work.over() {
		scan.work.fellBack = true
		scan.work.limit = int(^uint(0) >> 1) // the fallback is linear; keep counting it
		scan.judgeWithoutLookahead(command)
	}
	return scan.merged, scan.found, scan.work
}

// judgeWithoutLookahead judges a command the precise parse gave up on, the
// 2.9.21 way and no looser: judgeFallbackLine, plus the raw text split at
// separators (judgeWords). The hits the precise parse recorded before it
// stopped are kept.
func (s *shellTargetScan) judgeWithoutLookahead(command string) {
	s.judgeFallbackLine(command, 0)
	s.judgeWords(command, 0)
}

// judgeFallbackLine splits text with the splitter's lookahead scans off ($(,
// ${, $((, $[, (( and `...` inside quotes are taken as unclosed: linear),
// which still removes quotes and escapes and decodes $'...', and judges
// every word (also the value attached to a short option, and the word decoded
// as echo -e / printf would), redirection target and here-document word as a
// read; follows a cd into a credential store; and finds git credential dumps
// and kubectl config view --raw. Here-document bodies and words that may hold
// a command line (a blank, a command separator, $( or a backquote: sh -c
// "...", ssh h "...", "$(...)") are split again the same way, up to
// maxShellNesting levels deeper.
func (s *shellTargetScan) judgeFallbackLine(text string, depth int) {
	s.work.add(len(text))
	// A word was just judged whole; split again only when it may hold more
	// than one word or command (a blank, a command separator, a substitution).
	// Quotes alone are not enough: a 55KB brace word wrapped in four layers of
	// quotes was otherwise judged once per layer.
	nested := func(word string) {
		if depth < maxShellNesting && strings.ContainsAny(word, " \t\n;&|()<>`") {
			s.judgeFallbackLine(word, depth+1)
		}
	}
	storeDir := ""
	for _, simple := range splitShellSimpleCommandsWork(text, &shellWork{limit: s.work.limit, noLookahead: true}) {
		words := simple.Words
		if dump, ok := gitCredentialDump(words); ok {
			s.add(protectionFindingWithConfidence(reasonGitCredentialDump, "", "critical", 0.9,
				[]Evidence{sanitizedEvidence(reasonGitCredentialDump, "command", "command", dump)}))
		}
		start := commandStart(words)
		program, args := shellProgramAt(words, start)
		s.fallbackKubeReads(program, words[:start], args)
		for _, word := range append(append(append([]string(nil), words...), simple.InputRedirects...), simple.OutputRedirects...) {
			s.judge(word, shellArgRead, storeDir, nil)
			if len(word) > 2 && word[0] == '-' && word[1] != '-' {
				s.judge(word[2:], shellArgRead, storeDir, nil) // the value attached to a short option (-g.env)
			}
			if strings.Contains(word, "\\") {
				s.judge(decodeBackslashEscapes(word), shellArgRead, storeDir, nil)
				s.judge(decodeEchoEscapes(word), shellArgRead, storeDir, nil)
			}
			nested(word)
		}
		for _, doc := range simple.Heredocs {
			s.judgeFields(doc.Body, shellArgRead)
			if depth < maxShellNesting {
				s.judgeFallbackLine(doc.Body, depth+1)
			}
		}
		if (program == "cd" || program == "pushd") && len(args) > 0 {
			storeDir = ""
			if _, ok := credentialStoreReference(args[len(args)-1]); ok {
				storeDir = args[len(args)-1]
			}
		}
	}
}

// nestedLine judges a remote or inline command string one level deeper, or
// word by word (2.9.21) beyond maxShellNesting.
func (s *shellTargetScan) nestedLine(text string, depth int, consumed bool) {
	s.nestedLineInto(text, depth, consumed, false)
}

// nestedLineInto is nestedLine for a line whose output may land in a
// regular file of the enclosing line (intoFile).
func (s *shellTargetScan) nestedLineInto(text string, depth int, consumed, intoFile bool) {
	if depth > maxShellNesting {
		s.judge(text, shellArgRead, "", nil)
		return
	}
	s.lineInto(text, depth, consumed, intoFile)
}

func (s *shellTargetScan) line(command string, depth int, consumed bool) {
	s.lineInto(command, depth, consumed, false)
}

func (s *shellTargetScan) lineInto(command string, depth int, consumed, intoFile bool) {
	if s.work.over() {
		return
	}
	if len(command) > maxDestructiveCommandBytes {
		s.judgeOverflow(command)
	}
	commands := splitShellSimpleCommandsWork(command, s.work)
	if s.work.over() {
		return
	}
	for _, simple := range commands {
		s.writes.add(simple)
	}
	s.switches = s.switches.or(lineSwitchesOf(command, commands))
	ctx := newShellLineContext(commands, command, depth, consumed, intoFile, s.switches)
	redirectedStdin := false
	for _, simple := range commands {
		if simple.StdinFeed || len(simple.InputRedirects) > 0 {
			redirectedStdin = true
		}
	}
	ctx.loops = literalLoopBindings(command, commands, s.work)
	pipedStdin := false
	for index, simple := range commands {
		pipedStdin = pipedStdin || simple.PipesIn
		ctx.keyUse.stdinFed = redirectedStdin || pipedStdin
		s.simpleCommand(ctx, index)
	}
	for index, simple := range commands {
		for _, heredoc := range simple.Heredocs {
			s.heredoc(ctx, index, heredoc)
		}
	}
}

// judgeOverflow judges the part of a command line beyond the parse limit
// (splitShellSimpleCommands only parses the first maxDestructiveCommandBytes)
// word by word as reads, as 2.9.21 judged every word: a long line must not
// hide a read after the limit. It starts at the word that crosses the limit.
func (s *shellTargetScan) judgeOverflow(command string) {
	s.judgeWords(command, overflowTailStart(command))
}

// judgeWords judges the words of command from start as reads, each distinct
// word once.
func (s *shellTargetScan) judgeWords(command string, start int) {
	isSeparator := func(r rune) bool { return strings.ContainsRune(overflowWordSeparators, r) }
	seen := map[string]bool{}
	for _, word := range strings.FieldsFunc(command[start:], isSeparator) {
		if seen[word] {
			continue // 同一个词判一次就够（1MB 的重复词不必判 6 万遍）
		}
		seen[word] = true
		s.judge(word, shellArgRead, "", nil)
	}
}

// newShellLineContext gathers the line-wide facts in one pass over the
// commands, then the per-command guards in one backward pass.
func newShellLineContext(commands []shellSimpleCommand, raw string, depth int, consumed, intoFile bool, switches lineSwitches) *shellLineContext {
	ctx := &shellLineContext{
		intoFile:           intoFile,
		switches:           switches,
		wholeWords:         switches.wholeWords,
		commands:           commands,
		keyUse:             sshKeyUseContext{gitSSHCommandMentions: strings.Count(raw, "GIT_SSH_COMMAND")},
		kubeconfigMentions: strings.Count(raw, "KUBECONFIG"),
		kubeconfigUse:      kubeconfigVariableUse(commands, switches),
		depth:              depth,
		consumed:           consumed,
		mentions:           map[string]int{},
	}
	mention := func(word string) {
		ctx.mentions[shellPathKey(word)]++
		if strings.ContainsAny(word, " \t\n") {
			for _, token := range strings.Fields(word) {
				ctx.mentions[shellPathKey(token)]++
			}
		}
	}
	var written []string
	consumer := false
	for _, simple := range commands {
		program, args := shellProgram(simple.Words)
		consumer = consumer || readsBackFile(simple, program, args)
		for _, word := range simple.Words {
			mention(word)
			base := strings.ToLower(filepath.Base(word))
			// A shell named anywhere (kubectl exec -i p -- sh, sudo bash) may
			// read the here-document; eval, source, . and ssh only as the
			// program ("." as an argument is a directory). A program named
			// through a variable ($SHELL) is taken as a shell.
			ctx.shellish = ctx.shellish || shellInterpreterPrograms[base]
			ctx.interpreter = ctx.interpreter || isWordScanConsumer(base)
		}
		ctx.shellish = ctx.shellish || shellEvalPrograms[program] || strings.HasPrefix(program, "$")
		for _, source := range simple.InputRedirects {
			mention(source)
		}
		for _, target := range simple.OutputRedirects {
			mention(target)
			written = append(written, target)
		}
		if program == "tee" {
			for _, arg := range args {
				if !strings.HasPrefix(arg, "-") {
					written = append(written, arg)
				}
			}
		}
		for _, doc := range simple.Heredocs {
			for _, token := range strings.Fields(doc.Body) {
				ctx.mentions[shellPathKey(token)]++
			}
		}
	}
	// A file written on the line and named again (read back, executed,
	// listed in a here-document; compared after path.Clean) may carry printed
	// text into file names of any command, also through exec or group
	// redirections. So may any written file when the line also reads a file
	// back as names or commands (xargs < file, $(cat file), ./file, sh file,
	// source file): the name may differ after a cd. Then no command's words
	// are taken as mere patterns or names.
	reused := false
	writes := false
	for _, target := range written {
		if ignoredOutputTarget(target) {
			continue
		}
		writes = true
		if ctx.mentions[shellPathKey(target)] > 1 {
			reused = true
		}
	}
	reused = reused || (writes && consumer)
	ctx.guarded = make([]bool, len(commands))
	ctx.dataOnly = make([]bool, len(commands))
	ctx.instructions = make([]bool, len(commands))
	ctx.writesFile = make([]bool, len(commands))
	ctx.compose = make([]bool, len(commands))
	for index := len(commands) - 1; index >= 0; index-- {
		current := commands[index]
		program, args := shellProgram(current.Words)
		feedsNext := current.PipesOut && !current.Captured && index+1 < len(commands) && commands[index+1].PipesIn
		nextFilter := false
		if feedsNext {
			nextFilter = !ctx.wholeWords && isSafeConsumer(commands[index+1])
		}
		ctx.writesFile[index] = writesRegularFile(current, program, args) || (feedsNext && ctx.writesFile[index+1]) ||
			(intoFile && !feedsNext && !current.Captured)
		switch {
		case consumed || reused || current.Captured:
			ctx.guarded[index] = true
		case (program == "echo" || program == "printf") && (ctx.writesFile[index] || current.PipesOut) &&
			!teesOnlyIntoIgnoreFiles(commands, index):
			// 写进普通文件或接进管道的文字可能被别处当文件名或命令读回（cd 后名字对不上、
			// make -f、tar -T、source 都挡不住）：参数按读判定；只有输出到终端、
			// /dev/null 或忽略文件时才放开。
			ctx.guarded[index] = true
		case current.PipesOut:
			ctx.guarded[index] = !feedsNext || !nextFilter || ctx.guarded[index+1]
		}
		ownInstructions := readsStdinAsInstructions(program, args)
		ctx.instructions[index] = ownInstructions || (feedsNext && ctx.instructions[index+1])
		ctx.compose[index] = (ownInstructions && isComposeReader(program, args)) || (feedsNext && ctx.compose[index+1])
		ownWritesReused := false
		for _, target := range current.OutputRedirects {
			if ignoredOutputTarget(target) {
				continue
			}
			ownWritesReused = ownWritesReused || consumer || ctx.mentions[shellPathKey(target)] > 1 || isShellStartupOrScript(target)
		}
		dataProgram := !ctx.wholeWords && (isSafeConsumer(current) || heredocDataProgram(trustedProgramAt(current.Words, commandStart(current.Words)), args))
		switch {
		case current.Captured || !dataProgram || ownWritesReused || ctx.instructions[index]:
		case !current.PipesOut:
			ctx.dataOnly[index] = true
		case feedsNext:
			ctx.dataOnly[index] = ctx.dataOnly[index+1]
		}
	}
	return ctx
}

// shellPathKey compares words as paths: "./l" and "l", "/tmp/./l" and
// "/tmp/l" name the same file.
func shellPathKey(word string) string {
	word = strings.TrimSpace(word)
	if word == "" {
		return ""
	}
	return path.Clean(word)
}

// ignoredOutputTarget: output thrown away or shown, never read back.
func ignoredOutputTarget(target string) bool {
	switch shellPathKey(target) {
	case "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/fd/1", "/dev/fd/2":
		return true
	}
	return false
}

// ignoreFileNames list paths for tools to skip; writing ".env" or "secrets/"
// into them is the usual way to keep secrets out of a repository or image.
var ignoreFileNames = flagSet(".gitignore", ".dockerignore", ".helmignore", ".npmignore", ".prettierignore", ".eslintignore")

// writesRegularFile: the command writes its output (a redirection, or tee's
// file operands) to a file that may be read back, i.e. not to /dev/null or
// the terminal and not to an ignore file.
func writesRegularFile(simple shellSimpleCommand, program string, args []string) bool {
	regular := func(target string) bool {
		return !ignoredOutputTarget(target) && !ignoreFileNames[filepath.Base(shellPathKey(target))]
	}
	for _, target := range simple.OutputRedirects {
		if regular(target) {
			return true
		}
	}
	if program == "tee" {
		for _, arg := range args {
			if !strings.HasPrefix(arg, "-") && regular(arg) {
				return true
			}
		}
	}
	return false
}

// shellWrites are the files the command lines seen so far write and whether
// one of them changes directory (cd, pushd, popd).
type shellWrites struct {
	// The regular written files (not "", "-", /dev/null and the like),
	// indexed once as they are recorded so that every source/. compares in
	// constant time: count, the names after path.Clean, per base name the
	// ways it was written, whether a name is not readable ($F), the globs.
	count   int
	keys    map[string]bool
	bases   map[string]*writtenBase
	unknown bool
	globs   []string
	cd      bool
	// workspace: a command wrote files whose names are not on the line
	// (git checkout / stash pop, tar -x, unzip, patch, rsync, cp -r, curl -O,
	// wget ...), or more than maxShellWriteTargets files were written.
	workspace bool
}

// writtenBase records how the files with one base name were written: from
// the root, from a home directory (~), relative; and whether a relative one
// leaves the working directory with "..".
type writtenBase struct {
	forms  map[byte]bool
	dotdot bool
}

// maxShellWriteTargets bounds the written files recorded per call; beyond it
// any source/. counts as loading a written file (workspace).
const maxShellWriteTargets = 4096

// record adds written file names to the index.
func (w *shellWrites) record(targets ...string) {
	for _, target := range targets {
		if target == "" || target == "-" || ignoredOutputTarget(target) {
			continue
		}
		if w.count >= maxShellWriteTargets {
			w.workspace = true
			return
		}
		w.count++
		if strings.ContainsAny(target, "$`") {
			w.unknown = true
		}
		key := shellPathKey(target)
		if w.keys == nil {
			w.keys, w.bases = map[string]bool{}, map[string]*writtenBase{}
		}
		w.keys[key] = true
		base := path.Base(key)
		entry := w.bases[base]
		if entry == nil {
			entry = &writtenBase{forms: map[byte]bool{}}
			w.bases[base] = entry
		}
		entry.forms[pathForm(key)] = true
		entry.dotdot = entry.dotdot || strings.HasPrefix(key, "..")
		if strings.ContainsAny(target, "*?[") {
			w.globs = append(w.globs, key)
		}
	}
}

// loads reports that the file name source/. loads may be one of the written
// files: the same after path.Clean; the same base name written differently
// (one relative and one absolute, one with ~ and one with /home/..., or a
// relative one leaving the working directory with ..); matched by a written
// glob; not readable ($F) on either side; or any written file after a cd.
// Every glob comparison counts on work; past its limit the name counts as
// loaded (the scan then falls back anyway).
func (w *shellWrites) loads(name string, work *shellWork) bool {
	if w.workspace {
		return true
	}
	if w.count == 0 {
		return false
	}
	key := shellPathKey(name)
	if w.cd || w.unknown || strings.ContainsAny(name, "$`") || w.keys[key] {
		return true
	}
	if base := path.Base(key); base != "." && base != "/" && base != ".." {
		if entry := w.bases[base]; entry != nil {
			form := pathForm(key)
			for written := range entry.forms {
				if written != form {
					return true
				}
			}
			if entry.dotdot || strings.HasPrefix(key, "..") {
				return true
			}
		}
	}
	for _, glob := range w.globs {
		if !work.add(len(glob) + len(key)) {
			return true
		}
		if matched, _ := path.Match(glob, key); matched {
			return true
		}
	}
	return false
}

// maxCopyOperandPairs bounds the "directory/base name" destinations tried for
// a copy with many operands.
const maxCopyOperandPairs = 64

// add records what one simple command writes: its output redirections, tee's
// files, every operand of cp, mv, ln, install, link, rsync and scp (and
// "operand/base name of another operand", the copy into a directory), dd's
// of=, and the value of an output option (-o FILE, -qO FILE, -o.env,
// --output[=]FILE, --output-document, -out FILE).
func (w *shellWrites) add(simple shellSimpleCommand) {
	if w.workspace {
		return // every source/. already counts as loading a written file
	}
	w.record(simple.OutputRedirects...)
	program, args := shellProgram(simple.Words)
	if (program == "busybox" || program == "toybox") && len(args) > 0 {
		program, args = strings.ToLower(filepath.Base(args[0])), args[1:]
	}
	w.workspace = w.workspace || writesWorkspace(program, args)
	if createsDirectoryAlias(program, args) {
		w.cd = true // 符号链接、绑定挂载让目录有了别名，相对名字对不上，按 cd 处理
	}
	switch program {
	case "cd", "pushd", "popd":
		w.cd = true
	case "tee", "sponge":
		for _, arg := range args {
			if !strings.HasPrefix(arg, "-") {
				w.record(arg)
			}
		}
	case "sed", "perl":
		// In-place edits (sed -i, perl -pi) write their file operands.
		for _, arg := range args {
			if strings.HasPrefix(arg, "--in-place") || (len(arg) > 1 && arg[0] == '-' && arg[1] != '-' && strings.Contains(arg, "i")) {
				for _, operand := range args {
					if !strings.HasPrefix(operand, "-") {
						w.record(operand)
					}
				}
				break
			}
		}
	case "docker", "podman", "kubectl", "oc":
		if operands, ok := containerCopyOperands(args); ok {
			w.record(operands...)
		}
	case "cp", "mv", "ln", "install", "link", "rsync", "scp":
		var operands []string
		for _, arg := range args {
			if !strings.HasPrefix(arg, "-") {
				operands = append(operands, arg)
			}
		}
		w.record(operands...)
		if len(operands) <= maxCopyOperandPairs {
			for _, directory := range operands {
				for _, source := range operands {
					if source != directory {
						w.record(path.Join(directory, path.Base(source)))
					}
				}
			}
		}
	}
	for index, arg := range args {
		next := index+1 < len(args)
		switch {
		case strings.HasPrefix(arg, "of="):
			w.record(arg[len("of="):])
		case strings.HasPrefix(arg, "--out"):
			if _, value, ok := strings.Cut(arg, "="); ok {
				w.record(value)
			} else if next {
				w.record(args[index+1])
			}
		case strings.HasPrefix(arg, "-out"):
			if next {
				w.record(args[index+1])
			}
		case len(arg) > 1 && arg[0] == '-' && arg[1] != '-':
			if at := strings.IndexAny(arg, "oO"); at > 0 {
				if rest := arg[at+1:]; rest != "" {
					w.record(rest)
				}
				if next {
					w.record(args[index+1])
				}
			}
		}
	}
}

// createsDirectoryAlias reports a command that gives a directory another
// name: a symbolic link (ln -s / -sf / -sfn / --symbolic, cp -s /
// --symbolic-link) or a bind mount (mount --bind / --rbind / -B / -o bind,
// bindfs).
func createsDirectoryAlias(program string, args []string) bool {
	switch program {
	case "ln":
		for _, arg := range args {
			if arg == "--symbolic" || shortCluster(arg, "s") {
				return true
			}
		}
	case "cp":
		for _, arg := range args {
			if arg == "--symbolic-link" || shortCluster(arg, "s") {
				return true
			}
		}
	case "mount":
		for index, arg := range args {
			if arg == "--bind" || arg == "--rbind" || shortCluster(arg, "B") ||
				(arg == "-o" && index+1 < len(args) && strings.Contains(args[index+1], "bind")) {
				return true
			}
		}
	case "bindfs":
		return true
	}
	return false
}

// containerCopyOperands returns the operands of docker / podman / kubectl /
// oc cp (also docker container cp).
func containerCopyOperands(args []string) ([]string, bool) {
	if len(args) > 1 && args[0] == "container" {
		args = args[1:]
	}
	if len(args) == 0 || args[0] != "cp" {
		return nil, false
	}
	var operands []string
	for _, arg := range args[1:] {
		if !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
		}
	}
	return operands, true
}

// pythonModuleExtracts: python -m zipfile / tarfile -e (--extract).
func pythonModuleExtracts(args []string) bool {
	module := ""
	for index, arg := range args {
		switch {
		case arg == "-m" && index+1 < len(args):
			module = args[index+1]
		case strings.HasPrefix(arg, "-m") && len(arg) > 2:
			module = arg[2:]
		case module != "" && (arg == "-e" || arg == "--extract"):
			return module == "zipfile" || module == "tarfile"
		}
	}
	return false
}

// svnWorkspaceSubcommands / hgWorkspaceSubcommands update or rewrite the
// working copy.
var (
	svnWorkspaceSubcommands = flagSet("checkout", "co", "export", "update", "up", "switch", "sw", "merge", "revert",
		"patch", "resolve", "cleanup", "relocate")
	hgWorkspaceSubcommands = flagSet("update", "up", "checkout", "co", "clone", "revert", "import", "unshelve",
		"merge", "backout", "graft", "rebase", "histedit", "strip", "shelve", "archive")
)

// gitWorkspaceSubcommands write tracked or stashed files back into the
// working tree (or a new one).
var gitWorkspaceSubcommands = flagSet("checkout", "restore", "stash", "reset", "switch", "merge", "pull",
	"rebase", "cherry-pick", "revert", "am", "apply", "clone", "worktree", "checkout-index", "read-tree",
	"submodule", "sparse-checkout", "bisect", "clean", "rm", "mv")

// gitSubcommandName returns git's subcommand after its global options.
func gitSubcommandName(args []string) string {
	for index := 0; index < len(args); index++ {
		word := args[index]
		name, _, attached := strings.Cut(word, "=")
		switch {
		case gitGlobalValues[name] && attached:
		case gitGlobalValues[word]:
			index++
		case strings.HasPrefix(word, "-"):
		default:
			return strings.ToLower(word)
		}
	}
	return ""
}

// shortCluster reports a single-dash option cluster holding any of letters.
func shortCluster(arg, letters string) bool {
	return len(arg) > 1 && arg[0] == '-' && arg[1] != '-' && strings.ContainsAny(arg[1:], letters)
}

// writesWorkspace reports a command that writes files whose names are not
// on the line: git checkout / restore / stash / reset / switch / merge /
// pull / rebase / apply ..., tar extracting (-x, x..., --extract, --get),
// unzip, unrar, 7z, ar x, cpio -i, patch, rsync, cp / scp -r / -R / -a,
// the decompressors, curl -O / -J / --remote-name, wget.
func writesWorkspace(program string, args []string) bool {
	switch program {
	case "git":
		return gitWorkspaceSubcommands[gitSubcommandName(args)]
	case "tar", "gtar", "bsdtar":
		for index, arg := range args {
			if arg == "--extract" || arg == "--get" || shortCluster(arg, "x") ||
				(index == 0 && !strings.HasPrefix(arg, "-") && strings.Contains(arg, "x")) {
				return true
			}
		}
	case "unzip", "unrar", "7z", "7za", "7zr", "patch", "rsync", "gunzip", "bunzip2", "unxz", "unzstd",
		"uncompress", "unlzma", "wget", "wget2", "unar", "cabextract", "unsquashfs":
		return true
	case "busybox", "toybox":
		return len(args) > 0 && writesWorkspace(strings.ToLower(filepath.Base(args[0])), args[1:])
	case "docker", "podman", "kubectl", "oc":
		// cp 的目标在本地（最后一个操作数不带 容器:路径）：拷回来的是整个目录还是单个文件看不出来。
		operands, ok := containerCopyOperands(args)
		return ok && len(operands) > 0 && !strings.Contains(operands[len(operands)-1], ":")
	case "svn":
		return svnWorkspaceSubcommands[gitSubcommandName(args)]
	case "hg":
		subcommand := gitSubcommandName(args)
		if subcommand == "pull" {
			for _, arg := range args {
				if arg == "-u" || arg == "--update" {
					return true
				}
			}
		}
		return hgWorkspaceSubcommands[subcommand]
	case "pax":
		for _, arg := range args {
			if shortCluster(arg, "r") {
				return true
			}
		}
	case "lha":
		return len(args) > 0 && strings.ContainsAny(strings.TrimPrefix(args[0], "-"), "xe")
	case "dpkg-deb":
		for _, arg := range args {
			if arg == "--extract" || arg == "--raw-extract" || arg == "--vextract" || shortCluster(arg, "xXR") {
				return true
			}
		}
	case "ar", "jar":
		return len(args) > 0 && strings.Contains(strings.TrimPrefix(args[0], "-"), "x")
	case "cpio":
		for _, arg := range args {
			if arg == "--extract" || shortCluster(arg, "i") {
				return true
			}
		}
	case "gzip", "bzip2", "xz", "zstd", "lzma":
		for _, arg := range args {
			if arg == "--decompress" || arg == "--uncompress" || shortCluster(arg, "d") {
				return true
			}
		}
	case "cp", "scp":
		for _, arg := range args {
			if arg == "--recursive" || arg == "--archive" || shortCluster(arg, "rRa") {
				return true
			}
		}
	case "curl":
		for _, arg := range args {
			if arg == "--remote-name" || arg == "--remote-name-all" || arg == "--remote-header-name" || shortCluster(arg, "OJ") {
				return true
			}
		}
	}
	if strings.HasPrefix(program, "python") || strings.HasPrefix(program, "pypy") {
		return pythonModuleExtracts(args)
	}
	return false
}

// pathForm tells how a path is written: from the root, from a home
// directory (~), or relative to the working directory.
func pathForm(cleaned string) byte {
	switch {
	case strings.HasPrefix(cleaned, "/"):
		return '/'
	case strings.HasPrefix(cleaned, "~"):
		return '~'
	}
	return '.'
}

// loadsWrittenFile reports that the file source/. loads (name) may have been
// written by this command line or an enclosing one, so loading it is judged
// as a read ("printf 'cat %s/.ssh/id_rsa\n' \"$HOME\" > .env; source .env"):
// a written name equal after path.Clean (or with the same base name when the
// two are written differently: relative and absolute, ~ and /home/..., ..),
// matching as a glob, or not readable ($F); a command that writes files
// whose names are not on the line (writesWorkspace); any written file when
// a cd may have moved relative names or the loaded name is not readable; or
// the loaded file's base name in the code of another command of the line
// (sh -c, eval, an interpreter, xargs, a here-document or here-string fed to
// one), which may write it.
func (s *shellTargetScan) loadsWrittenFile(ctx *shellLineContext, index int, name string) bool {
	if s.writes.loads(name, s.work) {
		return true
	}
	base := path.Base(shellPathKey(name))
	if base == "." || base == "/" {
		return false
	}
	if mentioned, ok := ctx.mentioned[base]; ok {
		return mentioned
	}
	code := ctx.codeText()
	s.work.add(len(code))
	mentioned := strings.Contains(code, base)
	if ctx.mentioned == nil {
		ctx.mentioned = map[string]bool{}
	}
	ctx.mentioned[base] = mentioned
	return mentioned
}

// codeText joins, once per line, the arguments and the here-document bodies
// of the commands that run code (sh -c, eval, an interpreter, xargs, a
// program named through a variable), which may write any file.
func (ctx *shellLineContext) codeText() string {
	if ctx.code != nil {
		return *ctx.code
	}
	var b strings.Builder
	for _, simple := range ctx.commands {
		program, args := shellProgram(simple.Words)
		if !shellInterpreterPrograms[program] && program != "eval" && !isWordScanConsumer(program) && !strings.HasPrefix(program, "$") {
			continue
		}
		for _, arg := range args {
			b.WriteString(arg)
			b.WriteByte(0)
		}
		for _, doc := range simple.Heredocs {
			b.WriteString(doc.Body)
			b.WriteByte(0)
		}
	}
	text := b.String()
	ctx.code = &text
	return text
}

// decodeBackslashEscapes decodes the backslash escapes that printf (in its
// format) and echo -e (sh's echo always) turn into characters.
func decodeBackslashEscapes(word string) string {
	var out strings.Builder
	for index := 0; index < len(word); index++ {
		if word[index] != '\\' || index+1 >= len(word) {
			out.WriteByte(word[index])
			continue
		}
		decoded, width := decodeANSICEscape(word[index+1:])
		out.WriteString(decoded)
		index += width
	}
	return out.String()
}

// decodeEchoEscapes decodes the escapes as echo -e and printf %b do: \0NNN
// (0 and up to three octal digits), \xHH and the others as in $'...', and \c
// ends the output.
func decodeEchoEscapes(word string) string {
	var out strings.Builder
	for index := 0; index < len(word); index++ {
		if word[index] != '\\' || index+1 >= len(word) {
			out.WriteByte(word[index])
			continue
		}
		switch word[index+1] {
		case 'c':
			return out.String()
		case '0':
			value, digits := 0, 0
			for digits < 3 && index+2+digits < len(word) && word[index+2+digits] >= '0' && word[index+2+digits] <= '7' {
				value = value*8 + int(word[index+2+digits]-'0')
				digits++
			}
			out.WriteByte(byte(value))
			index += 1 + digits
		default:
			decoded, width := decodeANSICEscape(word[index+1:])
			out.WriteString(decoded)
			index += width
		}
	}
	return out.String()
}

// fileReadingFilters print the content of the files they are given.
var fileReadingFilters = map[string]bool{
	"cat": true, "head": true, "tail": true, "tac": true, "nl": true, "sed": true, "awk": true, "gawk": true,
	"cut": true, "sort": true, "uniq": true, "grep": true, "egrep": true, "fgrep": true, "rg": true,
	"less": true, "more": true, "paste": true, "jq": true, "yq": true, "base64": true,
}

// readsBackFile reports a command that may take a file's content as file
// names or as commands: xargs reading a file (< file, -a file), a command
// substitution that prints a file ($(cat file), $(< file)), a program run by
// path (./file after chmod +x), a shell, source or "." given a file, a
// program named through a variable ($SHELL file), eval.
func readsBackFile(simple shellSimpleCommand, program string, args []string) bool {
	switch {
	case program == "xargs":
		if len(simple.InputRedirects) > 0 {
			return true
		}
		for _, arg := range args {
			if arg == "-a" || strings.HasPrefix(arg, "--arg-file") || (strings.HasPrefix(arg, "-a") && !strings.HasPrefix(arg, "--")) {
				return true
			}
		}
	case simple.Captured && (len(simple.InputRedirects) > 0 || fileReadingFilters[program]):
		return true
	case shellInterpreterPrograms[program] || program == "source" || program == "." || program == "eval":
		return true
	case strings.HasPrefix(program, "$"):
		return true
	}
	start := commandStart(simple.Words)
	return start < len(simple.Words) && strings.Contains(simple.Words[start], "/")
}

// outputConsumed reports whether what command index prints may become file
// names of another command: the enclosing line consumes this line's output,
// the command runs inside a substitution, its pipeline reaches anything
// other than a text filter, or a file written on the line is named again.
func (ctx *shellLineContext) outputConsumed(index int) bool {
	return ctx.guarded[index]
}

// teesOnlyIntoIgnoreFiles: command index writes nowhere itself and pipes only
// into "tee [-a] FILE..." whose files are all ignore files and whose output
// goes nowhere else (echo .env | tee -a .gitignore).
func teesOnlyIntoIgnoreFiles(commands []shellSimpleCommand, index int) bool {
	current := commands[index]
	if len(current.OutputRedirects) > 0 || current.Captured || !current.PipesOut || index+1 >= len(commands) {
		return false
	}
	next := commands[index+1]
	if !next.PipesIn || next.PipesOut || next.Captured || !isSafeConsumer(next) {
		return false
	}
	program, args := shellProgram(next.Words)
	if program != "tee" {
		return false
	}
	files := 0
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if !ignoreFileNames[filepath.Base(shellPathKey(arg))] {
			return false
		}
		files++
	}
	for _, target := range next.OutputRedirects {
		if !ignoredOutputTarget(target) {
			return false
		}
	}
	return files > 0
}

// isShellStartupOrScript: a here-document written to a script or a shell
// startup file runs later as commands.
func isShellStartupOrScript(target string) bool {
	base := strings.ToLower(filepath.Base(target))
	switch base {
	case ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile",
		".zshenv", ".zlogin", ".kshrc", ".cshrc", ".tcshrc", "crontab":
		return true
	}
	return strings.HasSuffix(base, ".sh") || strings.HasSuffix(base, ".bash") || strings.HasSuffix(base, ".zsh")
}

// jqUnsafeFilter: a jq or yq expression that loads files or names its input
// files (import/include, yq load*, eval, input_filename, $__loc__).
var jqUnsafeFilter = regexp.MustCompile(`import|include|load|eval|input_filename|filename|\$__loc__`)

func (s *shellTargetScan) simpleCommand(ctx *shellLineContext, index int) {
	if s.work.over() {
		return
	}
	simple := ctx.commands[index]
	loops := ctx.loops.at(index)
	words := simple.Words
	if dump, ok := gitCredentialDump(words); ok {
		s.add(protectionFindingWithConfidence(reasonGitCredentialDump, "", "critical", 0.9,
			[]Evidence{sanitizedEvidence(reasonGitCredentialDump, "command", "command", dump)}))
		return
	}
	start := commandStart(words)
	// 窄口径例外的候选：参数恰好是一段 "$(cat <<'EOF' … EOF\n)"（带引号定界符的 heredoc 原样
	// 输出）。是否放开要等知道该参数的角色后再定（只对“不算文件”且不是嵌套命令串的参数）。
	quotedText := map[int]bool{}
	for at := start + 1; at < len(words); at++ {
		if quotedHeredocText(words[at], s.work) {
			quotedText[at-start-1] = true
		}
	}
	// A command substitution runs wherever it stands (program word,
	// redirection target, assignment, inside quotes, ${...}, $((...)),
	// ((...))): its commands are judged, their output feeding this command.
	// 兜底：命令里有命令替换或进程替换、或程序词本身含 $（cat${IFS}...）时，看不懂实际执行
	// 的是什么，这条命令的“不算文件”“使用”角色全部作废，按 2.9.21 的整词方式判定。
	fallback := simple.SplitSubstitution
	recurse := func(word string) {
		for _, body := range commandSubstitutions(word, s.work) {
			s.nestedLine(body, ctx.depth+1, true)
		}
	}
	visit := func(word string) {
		if substitutionText([]string{word}) || strings.Contains(word, "<(") || strings.Contains(word, ">(") {
			fallback = true
			recurse(word)
		}
	}
	for at, word := range words {
		if at <= start || !quotedText[at-start-1] {
			visit(word)
		}
	}
	for _, word := range append(append([]string(nil), simple.InputRedirects...), simple.OutputRedirects...) {
		visit(word)
	}
	// Output redirections write: a private key or cloud credential they
	// overwrite counts whatever the program is.
	for _, target := range simple.OutputRedirects {
		s.judge(target, shellArgWrite, ctx.storeDir, loops)
	}
	program, args := shellProgramAt(words, start)
	// trusted: the program name the exemptions below may rely on (a bare
	// name or a standard bin directory); program drives the stricter checks.
	trusted := trustedProgramAt(words, start)
	var programWords []string
	if start < len(words) {
		programWords = expandShellBraces(words[start])
		for _, expanded := range programWords {
			s.work.add(len(expanded))
		}
	}
	if start < len(words) && (strings.Contains(words[start], "$") || len(programWords) > 1) {
		// The program itself comes from an expansion ($..., {cat,file}):
		// judge it like an argument.
		fallback = true
		s.judge(words[start], shellArgRead, ctx.storeDir, loops)
	}
	if program == "cd" || program == "pushd" {
		// Later relative words of the same command line resolve inside
		// the directory, e.g. "cd ~/.ssh && cat id_rsa".
		ctx.storeDir = ""
		if len(args) > 0 {
			if _, ok := credentialStoreReference(args[len(args)-1]); ok {
				ctx.storeDir = args[len(args)-1]
			}
		}
		return
	}
	if metadataOnlyPrograms[trusted] && !simple.PipesOut && !simple.Substitution && !substitutionText(args) {
		return
	}
	wrapped := false
	for _, word := range words[:start] {
		if !isShellAssignment(word) {
			wrapped = true
		}
	}
	roles, offsets := map[int]shellArgRole{}, map[int]int{}
	var nested []shellNested
	var printed map[int]bool
	if handler, ok := shellRoleHandlers[trusted]; ok {
		if handled, ok := handler(args); ok {
			roles, offsets, nested, printed = handled.roles, handled.offsets, handled.nested, handled.printed
		}
	}
	// The positions of the nested commands, once per command (looking each
	// argument up in the list cost the square of "ssh host x x x ...").
	nestedPositions := make(map[int]bool, len(nested))
	for _, item := range nested {
		nestedPositions[item.at] = true
	}
	switch {
	case ctx.outputConsumed(index):
		// What the program prints may be read back as file names
		// ("cat $(echo ~/.ssh/id_rsa)", "... | xargs cat"): its words are
		// judged as in 2.9.21 instead of as patterns or resource names.
		for at, role := range roles {
			if role == shellArgSkip && !nestedPositions[at] {
				roles[at] = shellArgRead
			}
		}
	case ctx.writesFile[index]:
		// 输出落到普通文件（重定向、tee）：照原样打印出来的表达式、模板、格式串以后可能被当
		// 文件名读回（jq -n '"~/.ssh/id_rsa"' > list.txt），按读判；资源名、搜索模式不在此列。
		for at := range printed {
			if roles[at] == shellArgSkip && !nestedPositions[at] {
				roles[at] = shellArgRead
			}
		}
	}
	if !wrapped {
		// Behind a keyword or a wrapper the parse may have stopped at an
		// option it does not know, so the destination is judged as a read.
		for at := range writtenDestinations(trusted, args) {
			roles[at] = shellArgWrite
		}
	}
	switch trusted {
	case "source", ".":
		if len(args) > 0 && !s.loadsWrittenFile(ctx, index, args[0]) {
			roles[0] = shellArgUseEnvFile
		}
	case "export":
		for at, word := range args {
			if ctx.kubeconfigUse && kubeconfigAssignment(word, ctx.kubeconfigMentions) {
				roles[at] = shellArgUseKubeconfig
			}
		}
	}
	markGenericUseOptions(trusted, args, roles)
	for at := range quotedText {
		if !ctx.wholeWords && roles[at] == shellArgSkip && !nestedPositions[at] && gitMessageArgument(trusted, args, at) {
			continue // git 提交说明：正文当数据，角色保留
		}
		fallback = true
		recurse(args[at])
	}
	// 兜底（这条命令看不懂）：“不算文件”“使用”角色都作废；整行开关（这一行看不懂）：
	// “不算文件”角色作废，“使用”只对对应类别放开，照旧保留（source .env）。
	voidSkip := fallback || ctx.wholeWords
	voidUse := fallback || ctx.switches.voidsUseOf(program)
	if voidSkip || voidUse {
		for at, role := range roles {
			switch {
			case voidSkip && role == shellArgSkip && !fallback:
				roles[at] = shellArgReadLineSwitched
			case (voidSkip && role == shellArgSkip) || (voidUse && (role == shellArgUseKubeconfig || role == shellArgUseEnvFile)):
				roles[at] = shellArgRead
			}
		}
	}
	if hit, ok := kubectlRawConfigView(program, words[:start], args); ok {
		s.add(hit)
	}
	if hit, ok := kubectlSecretRead(program, args); ok {
		s.add(hit)
	}
	used := sshKeyUseArguments(trusted, args, simple, ctx.keyUse)
	// Words before the program: leading assignments ("KEY=~/.ssh/id_rsa;
	// cat $KEY" names what a later word reads through a variable),
	// wrappers and their options. Shell keywords are syntax, not paths:
	// after "cd ~/.ssh" a "{" must not become the glob "~/.ssh/{". The
	// program word itself is executed, not read, unless a keyword or
	// wrapper precedes it: then the parse may have stopped at an option it
	// does not know.
	for _, word := range words[:start] {
		if shellKeywords[word] {
			continue
		}
		if trusted == "git" && sshKeyCommandAssignment(word, ctx.keyUse.gitSSHCommandMentions) {
			continue
		}
		role := shellArgRead
		if !voidUse && ctx.kubeconfigUse && isKubeClient(trusted, args) && kubeconfigAssignment(word, ctx.kubeconfigMentions) {
			role = shellArgUseKubeconfig
		}
		s.judge(word, role, ctx.storeDir, loops)
	}
	if wrapped && start < len(words) {
		s.judge(words[start], shellArgRead, ctx.storeDir, loops)
	}
	consumed := ctx.outputConsumed(index)
	for at, word := range args {
		if used[at] || (!voidSkip && nestedPositions[at]) {
			continue
		}
		role := roles[at]
		if trusted == "ssh" && nestedPositions[at] && (role == shellArgRead || role == shellArgReadLineSwitched) {
			role = shellArgReadCode // ssh 远端整段命令按整词判时，只有像路径的词算“名字像敏感文件”
		}
		if offset := offsets[at]; offset > 0 && offset < len(word) && role != shellArgSkip {
			word = word[offset:]
		}
		s.judge(word, role, ctx.storeDir, loops)
		if (role == shellArgRead || role == shellArgReadLineSwitched) && (program == "echo" || program == "printf") && strings.Contains(word, "\\") {
			// printf 的格式串、echo -e 的参数：\n 这类转义执行时才变成换行，再按转义后的样子判一次。
			// echo -e、printf %b 另有自己的规则（\0NNN、\c 截断），两种解法都判。
			for _, decoded := range []string{decodeBackslashEscapes(word), decodeEchoEscapes(word)} {
				if decoded != word {
					s.judge(decoded, role, ctx.storeDir, loops)
				}
			}
		}
	}
	intoFile := ctx.writesFile[index]
	for _, item := range nested {
		if item.argv == nil && item.text == "" {
			continue // a later word of a nested command
		}
		if item.argv != nil {
			s.nestedArgv(item.argv, ctx.depth+1, consumed, intoFile, loops)
			continue
		}
		for _, text := range expandLoopWord(item.text, loops) {
			if trusted == "ssh" && ctx.depth+1 > maxShellNesting {
				s.judge(text, shellArgReadCode, "", nil)
				continue
			}
			s.nestedLineInto(text, ctx.depth+1, consumed, intoFile)
		}
	}
	for _, source := range simple.InputRedirects {
		s.judge(source, shellArgRead, ctx.storeDir, loops)
	}
}

// nestedArgv judges one command vector that runs elsewhere (kubectl exec --
// cmd ...): as one simple command one level deeper, or word by word beyond
// maxShellNesting.
func (s *shellTargetScan) nestedArgv(argv []string, depth int, consumed, intoFile bool, loops []shellLoopBinding) {
	if depth > maxShellNesting {
		for _, word := range argv {
			s.judge(word, shellArgRead, "", loops)
		}
		return
	}
	ctx := newShellLineContext([]shellSimpleCommand{{Words: argv}}, strings.Join(argv, " "), depth, consumed, intoFile, s.switches)
	for _, binding := range loops {
		ctx.loops = append(ctx.loops, shellLoopRange{from: 0, to: 0, binding: binding})
	}
	s.simpleCommand(ctx, 0)
}

// heredoc judges a here-document body or here-string by what reads it: a
// shell (anywhere on the line, also after the body was written to a file)
// runs it as commands; an interpreter runs it as code, judged word by word;
// text filters and clients that only send or apply it (cat, kubectl apply -f
// -, curl -T -) take it as data, except for command substitutions the shell
// runs in an unquoted body. Anything else is parsed as commands, as in
// 2.9.21.
func (s *shellTargetScan) heredoc(ctx *shellLineContext, index int, doc shellHeredoc) {
	switch {
	case ctx.shellish:
		s.nestedLineInto(doc.Body, ctx.depth+1, ctx.outputConsumed(index), ctx.writesFile[index])
	case ctx.interpreter:
		// 解释器跑的是代码：标识符（secrets.token_hex、process.env）不算“名字像敏感文件”。
		s.judgeFields(doc.Body, shellArgReadCode)
	case ctx.instructions[index]:
		s.scanBody(doc.Body, ctx.compose[index])
	case ctx.copiesHeredocToFile(index):
		// cat/tee 把正文写进普通文件：正文一律按读判（同 echo/printf 的参数）。
		s.scanBody(doc.Body, false)
	case ctx.consumed || ctx.commands[index].Captured:
		// 正文经命令输出被上层当文件名或命令用（cat $(cat <<EOF …)、eval "$(cat <<EOF …)"）：
		// 逐词按读判，也按命令解析。
		s.scanBody(doc.Body, false)
		s.nestedLine(doc.Body, ctx.depth+1, true)
	case ctx.heredocDataOnly(index):
		if doc.Expands {
			for _, body := range commandSubstitutions(doc.Body, s.work) {
				s.nestedLine(body, ctx.depth+1, true)
			}
		}
	default:
		s.nestedLineInto(doc.Body, ctx.depth+1, ctx.outputConsumed(index), ctx.writesFile[index])
	}
}

// composeEnvFileKey matches a compose "env_file:" key and what follows it.
var composeEnvFileKey = regexp.MustCompile(`^(\s*)-?\s*env_file:\s*(.*)$`)

// isComposeReader: docker/podman/nerdctl compose, docker stack deploy,
// docker-compose, podman-compose.
func isComposeReader(program string, args []string) bool {
	switch program {
	case "docker-compose", "podman-compose":
		return true
	case "docker", "podman", "nerdctl":
		sub := firstOperandIndex(args)
		if sub < 0 {
			return false
		}
		return args[sub] == "compose" || (args[sub] == "stack" && sub+1 < len(args) && args[sub+1] == "deploy")
	}
	return false
}

// scanBody judges a here-document body word by word as reads. When compose is
// set (the body is a compose file read by docker compose / docker stack
// deploy), the files env_file loads (a scalar, a [flow] list, or a block list
// of "- path" / "- path: path" entries) are env-file uses.
func (s *shellTargetScan) scanBody(body string, compose bool) {
	if !compose {
		s.judgeFields(body, shellArgRead)
		return
	}
	listIndent := -1
	for _, line := range strings.Split(body, "\n") {
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		trimmed := strings.TrimSpace(line)
		if listIndent >= 0 {
			if entry, ok := strings.CutPrefix(trimmed, "- "); ok && indent > listIndent {
				entry = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(entry), "path:"))
				s.judgeFields(entry, shellArgUseEnvFile)
				continue
			}
			if strings.HasPrefix(trimmed, "required:") && indent > listIndent {
				continue
			}
			listIndent = -1
		}
		if match := composeEnvFileKey.FindStringSubmatch(line); match != nil {
			if value := strings.TrimSpace(match[2]); value != "" {
				s.judgeFields(value, shellArgUseEnvFile)
			} else {
				listIndent = len(match[1])
			}
			continue
		}
		s.judgeFields(line, shellArgRead)
	}
}

func (s *shellTargetScan) judgeFields(text string, role shellArgRole) {
	for _, word := range strings.FieldsFunc(text, func(r rune) bool { return strings.ContainsRune(" \t\n[],", r) }) {
		s.judge(strings.Trim(word, `"'`), role, "", nil)
	}
}

// copiesHeredocToFile: the here-document is fed to cat or tee whose output
// ends up in a regular file.
func (ctx *shellLineContext) copiesHeredocToFile(index int) bool {
	program, _ := shellProgram(ctx.commands[index].Words)
	return (program == "cat" || program == "tee") && ctx.writesFile[index]
}

// heredocDataOnly: the command fed by the here-document and every command its
// pipeline feeds only filter, store, send or apply text, and nothing they
// write is named again on the line or is a script or shell startup file.
func (ctx *shellLineContext) heredocDataOnly(index int) bool {
	return ctx.dataOnly[index]
}

// readsStdinAsInstructions reports a program that takes standard input as a
// configuration, build or compose file (curl -K -, docker build -f-, docker
// compose -f -, docker stack deploy -c -), or as a list of file names (tar
// -T -, rsync --files-from=-, zip -@, cpio -o): a here-document fed to it is
// judged word by word.
func readsStdinAsInstructions(program string, args []string) bool {
	switch program {
	case "curl":
		return optionValueIsStdin(args, "-K", "--config")
	case "docker", "podman", "nerdctl", "docker-compose", "podman-compose":
		// compose -f -, build -f- / --file=- / "-", stack deploy -c -.
		if optionValueIsStdin(args, "-f", "--file", "-c", "--compose-file") {
			return true
		}
		for index, arg := range args {
			if isStdinPath(arg) && (index == 0 || (args[index-1] != "-o" && args[index-1] != "--output")) {
				return true
			}
		}
	case "tar":
		if optionValueIsStdin(args, "-T", "--files-from") {
			return true
		}

	case "rsync":
		return optionValueIsStdin(args, "--files-from")
	case "git":
		// cat-file --batch、hash-object --stdin-paths、update-index --stdin、
		// --pathspec-from-file=- 等按路径读 stdin 里的名字。
		return true
	case "sort", "wc", "du":
		return optionValueIsStdin(args, "--files0-from")
	case "zip":
		for _, arg := range args {
			if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg, "@") {
				return true // -@ reads the names from stdin
			}
		}
	case "cpio":
		for _, arg := range args {
			if arg == "--create" || (strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg, "o")) {
				return true // copy-out mode reads the names from stdin
			}
		}
	}
	return false
}

// isStdinPath: "-" and the device paths of standard input.
func isStdinPath(value string) bool {
	switch strings.TrimSpace(value) {
	case "-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0":
		return true
	}
	return false
}

// optionValueIsStdin reports one of the options given standard input as its
// value ("-", /dev/stdin, /dev/fd/0, /proc/self/fd/0): as the next word,
// attached with "=", or for a short option inside a cluster (-sK -, -sK-,
// -K/dev/stdin).
func optionValueIsStdin(args []string, names ...string) bool {
	next := func(index int) bool { return index+1 < len(args) && isStdinPath(args[index+1]) }
	for index, word := range args {
		for _, name := range names {
			if strings.HasPrefix(name, "--") {
				if (word == name && next(index)) || (strings.HasPrefix(word, name+"=") && isStdinPath(word[len(name)+1:])) {
					return true
				}
				continue
			}
			if !strings.HasPrefix(word, "-") || strings.HasPrefix(word, "--") {
				continue
			}
			at := strings.IndexByte(word[1:], name[1])
			if at < 0 {
				continue
			}
			rest := strings.TrimPrefix(word[at+2:], "=")
			if (rest == "" && next(index)) || isStdinPath(rest) {
				return true
			}
		}
	}
	return false
}

// heredocDataPrograms take a here-document as data to apply or send, whatever
// the subcommand.
var heredocDataPrograms = map[string]bool{
	"helm": true, "curl": true, "wget": true, "nc": true, "ncat": true, "envsubst": true, "patch": true, "diff": true,
}

// heredocDataProgram reports a program that takes a here-document as data:
// heredocDataPrograms; a kubectl-compatible client only for apply, create,
// replace and diff with -f -; docker / podman / nerdctl only for build -f -
// and compose -f - (which read it as instructions). kubectl run / exec /
// attach / debug -i and docker run -i hand it to a program in the container,
// and git may read names from it (cat-file --batch, hash-object
// --stdin-paths, update-index --stdin): those are parsed or judged.
func heredocDataProgram(program string, args []string) bool {
	if heredocDataPrograms[program] {
		return true
	}
	if kubectlArgs, ok := kubectlLikeArgs(program, args); ok {
		switch kubectlSubcommandOf(kubectlArgs) {
		case "apply", "create", "replace", "diff":
			return optionValueIsStdin(kubectlArgs, "-f", "--filename")
		}
		return false
	}
	switch program {
	case "docker", "podman", "nerdctl", "docker-compose", "podman-compose":
		sub := firstOperandIndex(args)
		build := sub >= 0 && (args[sub] == "build" || args[sub] == "buildx")
		return (build || isComposeReader(program, args)) && optionValueIsStdin(args, "-f", "--file")
	}
	return false
}

// shellInterpreterPrograms are shells that run a command string or script;
// shellEvalPrograms run their input or arguments as shell commands.
var (
	shellInterpreterPrograms = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true, "ash": true}
	shellEvalPrograms        = map[string]bool{"eval": true, "source": true, ".": true, "ssh": true}
)

// isWordScanConsumer reports a program that runs code it reads (a script, -c
// or -e text, or standard input) and can open files from it, or that takes
// the lines it reads as file names (xargs, read): a here-document fed to it
// is judged word by word.
func isWordScanConsumer(program string) bool {
	switch program {
	case "node", "nodejs", "deno", "bun", "perl", "ruby", "irb", "php", "lua", "luajit", "rscript", "r",
		"tclsh", "osascript", "pwsh", "powershell", "awk", "gawk", "mawk", "nawk",
		"psql", "mysql", "mariadb", "sqlite3", "groovy", "jshell", "julia", "gdb",
		"xargs", "parallel", "read", "mapfile", "readarray":
		return true
	}
	return strings.HasPrefix(program, "python") || strings.HasPrefix(program, "pypy")
}

// commandSubstitutions returns the bodies of the $(...) and `...` command
// substitutions in text, also those inside $((...)) arithmetic. An
// unterminated one runs to the end of the text.
func commandSubstitutions(text string, work *shellWork) []string {
	if !work.add(len(text)) {
		return nil
	}
	return commandSubstitutionsIn(text, work)
}

// commandSubstitutionsIn is commandSubstitutions without charging text again
// (the arithmetic it recurses into lies inside text).
func commandSubstitutionsIn(text string, work *shellWork) []string {
	var out []string
	// No scan for an end can succeed past the last ")" or "`" (see
	// splitShellSimpleCommands).
	lastParen, lastTick := strings.LastIndexByte(text, ')'), strings.LastIndexByte(text, '`')
	for i := 0; i < len(text); i++ {
		if text[i] == '$' && i+1 < lastParen {
			if end, ok := shellArithmeticEnd(text, i+1, work); ok {
				out = append(out, commandSubstitutionsIn(text[i+3:end-2], work)...)
				i = end - 1
				continue
			}
		}
		switch {
		case text[i] == '`':
			// The closing backquote is the first one not escaped; \` inside
			// is a nested substitution and becomes ` in the body.
			end := i + 1
			if i >= lastTick || work.over() {
				end = len(text)
			}
			for end < len(text) && text[end] != '`' {
				if text[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(text) {
				return append(out, backquoteBody(text[i+1:]))
			}
			out = append(out, backquoteBody(text[i+1:end]))
			i = end
		case text[i] == '$' && i+1 < len(text) && text[i+1] == '(':
			end, ok := 0, false
			if i+1 < lastParen {
				end, ok = substitutionSpanEnd(text, i+1, work)
			}
			if !ok {
				return append(out, text[i+2:])
			}
			out = append(out, text[i+2:end-1])
			i = end - 1
		}
	}
	return out
}

// redefinesCommands: the command line defines a function or an alias, so a
// later program name (cat, grep, git ...) may run something else. Anywhere in
// the text, also inside quotes (strictly): a word "function" or "alias", or a
// "()" after any word (\grep(), "grep"(),
// gr\ep (), "grep ()" then "{" on the next line), except after $, =, <, > or
// ( ($(), arr=(), <(), (( ))). One pass over the text, no regular expression
// (a line may be 64KB or more).
func redefinesCommands(command string) bool {
	return redefinesCommandsIn(command, shellSwitchTokens(command))
}

func redefinesCommandsIn(command string, tokens []string) bool {
	for _, token := range tokens {
		if token == "alias" || token == "function" {
			return true
		}
	}
	for index := 0; index < len(command); index++ {
		if command[index] != '(' {
			continue
		}
		next := index + 1
		for next < len(command) && isRegexpSpace(command[next]) {
			next++
		}
		if next >= len(command) || command[next] != ')' {
			continue
		}
		before := strings.TrimRight(command[:index], " \t")
		if before != "" && strings.IndexByte("$=<>(", before[len(before)-1]) < 0 {
			return true
		}
		index = next
	}
	return false
}

// isRegexpSpace is \s of Go regular expressions.
func isRegexpSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

// shellSwitchTokens splits a command line at blanks, ; & | ( ) { } and quotes:
// the words the line-wide switches look at, inside quotes too (strictly).
func shellSwitchTokens(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '\v', '\f', ';', '&', '|', '(', ')', '{', '}', '\'', '"':
			return true
		}
		return false
	})
}

// rebindsCommands: hash -p binds a program name to any file, enable loads
// (-f), turns off (-n) or turns on builtins; either changes what a later
// program name runs, like a function or an alias.
func rebindsCommands(program string, args []string) bool {
	switch program {
	case "enable":
		return true
	case "hash":
		for _, arg := range args {
			if strings.ContainsAny(arg, "$`") || (len(arg) > 1 && arg[0] == '-' && arg[1] != '-' && strings.Contains(arg, "p")) {
				return true
			}
		}
	}
	return false
}

// lineSwitches are the line-wide switches. wholeWords: every command is
// judged word by word as in 2.9.21 (no text filter, no data-only reader, no
// quoted-heredoc exception). The "use" roles (source .env, --env-file,
// --kubeconfig) are voided too when the line may change what a program is
// (voidUseAll); a sourced file may redefine the other programs
// (voidOtherUse); the source/. command's own use is voided when what it loads
// may be printed or shipped (voidSourceUse).
type lineSwitches struct {
	wholeWords, voidUseAll, voidOtherUse, voidSourceUse bool
}

func (a lineSwitches) or(b lineSwitches) lineSwitches {
	return lineSwitches{
		wholeWords: a.wholeWords || b.wholeWords, voidUseAll: a.voidUseAll || b.voidUseAll,
		voidOtherUse: a.voidOtherUse || b.voidOtherUse, voidSourceUse: a.voidSourceUse || b.voidSourceUse,
	}
}

// voidsUseOf reports whether the use roles of a command running program
// are voided.
func (a lineSwitches) voidsUseOf(program string) bool {
	if a.voidUseAll {
		return true
	}
	if program == "source" || program == "." {
		return a.voidSourceUse
	}
	return a.voidOtherUse
}

// tracingInText reports, anywhere in the line (inside quotes too), a word
// trap, or set / sh / bash ... followed by an option cluster with x, v or T
// (-x, -ex, -T) or by -o xtrace / verbose / functrace: the shell echoes what
// it runs, or runs a trap before each command, a sourced .env included.
func tracingInText(tokens []string) bool {
	for index, token := range tokens {
		if token == "trap" {
			return true
		}
		if zshOptionCommands[token] && zshTracing(token, tokens[index+1:min(index+1+zshTextOptionWindow, len(tokens))]) {
			return true
		}
		if (token != "set" && !shellInterpreterPrograms[token]) || index+1 >= len(tokens) {
			continue
		}
		option := tokens[index+1]
		if len(option) < 2 || option[0] != '-' {
			continue
		}
		letters := option[1:]
		if end := strings.IndexFunc(letters, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') }); end >= 0 {
			letters = letters[:end]
		}
		if strings.ContainsAny(letters, "xvT") {
			return true
		}
		if option == "-o" && index+2 < len(tokens) {
			name := tokens[index+2]
			if strings.HasPrefix(name, "xtrace") || strings.HasPrefix(name, "verbose") || strings.HasPrefix(name, "functrace") {
				return true
			}
		}
	}
	return false
}

// rewritesVariableInText reports, anywhere in the line (inside quotes too),
// an assignment to a rewriting variable: NAME=, NAME+=, NAME[key]=,
// ${NAME=...}, ${NAME:=...}, exec {NAME}>file (a prefix assignment, env
// NAME=... prog, export / declare NAME=... all contain one), or a word that
// names one after for, select, coproc or wait -p. One pass over the text.
func rewritesVariableInText(raw string, tokens []string) bool {
	for index, token := range tokens {
		switch token {
		case "for", "select", "coproc":
			if index+1 < len(tokens) && rewritingVariable(tokens[index+1]) {
				return true
			}
		case "-p":
			if index+1 < len(tokens) && rewritingVariable(tokens[index+1]) {
				for back := index - 1; back >= 0 && back >= index-3; back-- {
					if tokens[back] == "wait" {
						return true
					}
				}
			}
		}
	}
	nextClose := -1 // index of the next "]" at or after the scan, cached
	for index := 0; index < len(raw); index++ {
		if !isShellNameByte(raw[index]) {
			continue
		}
		end := index
		for end < len(raw) && isShellNameByte(raw[end]) {
			end++
		}
		name := raw[index:end]
		start := index
		index = end - 1
		if name[0] >= '0' && name[0] <= '9' || !rewritingVariable(name) {
			continue
		}
		at := end
		if at < len(raw) && raw[at] == '[' {
			if nextClose < at {
				nextClose = strings.IndexByte(raw[at:], ']')
				if nextClose < 0 {
					nextClose = len(raw)
				} else {
					nextClose += at
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
			return true
		}
		braced := start >= 2 && raw[start-1] == '{' && raw[start-2] == '$'
		if braced && at+1 < len(raw) && raw[at] == ':' && raw[at+1] == '=' {
			return true
		}
		if start >= 1 && raw[start-1] == '{' && !braced && end < len(raw) && raw[end] == '}' && end+1 < len(raw) &&
			(raw[end+1] == '>' || raw[end+1] == '<') {
			return true
		}
	}
	return false
}

// isShellNameByte: a byte of a shell variable name.
func isShellNameByte(c byte) bool {
	return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// rewritingVariableNames, with every BASH_* variable (BASH_ENV, BASH_CMDS,
// BASH_ALIASES, BASH_LOADABLES_PATH ...) and every DYLD_* variable, change
// what a program name runs, what a starting shell runs, what runs before a
// prompt or a traced command, what code the dynamic loader injects
// (LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, DYLD_INSERT_LIBRARIES ...), or how
// later words split and glob.
var rewritingVariableNames = flagSet("PATH", "ENV", "PS4", "PROMPT_COMMAND", "SHELLOPTS", "BASHOPTS", "GLOBIGNORE", "IFS",
	"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")

// rewritingVariable reports a variable name (NAME, NAME+, NAME[key]) of the
// class; a name with an expansion ("$n") may be any of them.
func rewritingVariable(name string) bool {
	if strings.ContainsAny(name, "$`") {
		return true
	}
	name, _, _ = strings.Cut(name, "[")
	name = strings.TrimSuffix(name, "+")
	return strings.HasPrefix(name, "BASH_") || strings.HasPrefix(name, "DYLD_") || rewritingVariableNames[name]
}

// variableDeclarers take NAME or NAME=VALUE operands; declare, typeset and
// local also take -n (a name reference: any later assignment may land in any
// variable).
var (
	variableDeclarers = flagSet("declare", "typeset", "local", "export", "readonly")
	nameReferencers   = flagSet("declare", "typeset", "local")
)

// setsRewritingVariable: a builtin that stores into a rewriting variable by
// name, or makes a name reference: declare / typeset / local -n, declare /
// typeset / local / export / readonly NAME[=...], read [-a] NAME, mapfile /
// readarray NAME, printf -v NAME (also -vNAME and after --), getopts OPTS
// NAME.
func setsRewritingVariable(program string, args []string) bool {
	nameOf := func(word string) bool {
		name, _, _ := strings.Cut(word, "=")
		return rewritingVariable(name)
	}
	switch {
	case variableDeclarers[program]:
		for _, arg := range args {
			if len(arg) > 1 && (arg[0] == '-' || arg[0] == '+') && arg[1] != '-' {
				if nameReferencers[program] && strings.ContainsRune(arg[1:], 'n') {
					return true
				}
				continue
			}
			if arg != "--" && nameOf(arg) {
				return true
			}
		}
	case program == "read" || program == "mapfile" || program == "readarray":
		// Options with a value: read -a NAME (an array name) -d -i -n -N -p
		// -t -u; mapfile -d -n -O -s -u -C -c. Every other operand is a name.
		valued, nameOption := "dinNptua", byte('a')
		if program != "read" {
			valued, nameOption = "dnOsuCc", 0
		}
		for index := 0; index < len(args); index++ {
			arg := args[index]
			if arg == "--" {
				for _, rest := range args[index+1:] {
					if nameOf(rest) {
						return true
					}
				}
				return false
			}
			if len(arg) > 1 && arg[0] == '-' {
				for at := 1; at < len(arg); at++ {
					if strings.IndexByte(valued, arg[at]) < 0 {
						continue
					}
					value := arg[at+1:]
					if value == "" && index+1 < len(args) {
						index++
						value = args[index]
					}
					if arg[at] == nameOption && nameOf(value) {
						return true
					}
					break
				}
				continue
			}
			if nameOf(arg) {
				return true
			}
		}
	case program == "printf":
		for index, arg := range args {
			if !strings.HasPrefix(arg, "-v") {
				continue
			}
			names := []string{arg[2:]}
			for next := index + 1; next < len(args) && next <= index+2; next++ {
				names = append(names, args[next])
				if args[next] != "--" {
					break
				}
			}
			for _, name := range names {
				if name != "" && name != "--" && nameOf(name) {
					return true
				}
			}
		}
	case program == "getopts":
		if len(args) > 1 && nameOf(args[1]) {
			return true
		}
	}
	return false
}

// tracingOption: one option word (or option name) that may turn tracing on:
// a short cluster with x, v or T (functrace: the DEBUG and RETURN traps run
// inside sourced files), xtrace, verbose, functrace or extdebug (-o xtrace,
// --verbose, shopt -s extdebug), or a word with an expansion that cannot be
// read (set -$X).
func tracingOption(word string) bool {
	for _, name := range []string{"xtrace", "verbose", "functrace", "extdebug"} {
		if strings.Contains(word, name) {
			return true
		}
	}
	if strings.ContainsAny(word, "$`") {
		return true
	}
	return len(word) > 1 && word[0] == '-' && word[1] != '-' && strings.ContainsAny(word[1:], "xvT")
}

// tracingCommand reports a command that turns tracing on: set or shopt with
// any such word (set -e -x, set -eu -o xtrace, shopt -o -s xtrace, set -$X),
// or a shell started with such an option before its command string or
// script (bash -e -x -c, bash -o verbose, bash --verbose; an operand with an
// expansion counts too).
func tracingCommand(program string, args []string) bool {
	switch {
	case program == "trap":
		// Any trap: DEBUG, RETURN and ERR run with $BASH_COMMAND set to each
		// command of a sourced file; the others run code at a signal.
		return true
	case zshOptionCommands[program]:
		return zshTracing(program, args)
	case program == "set" || program == "shopt":
		for _, arg := range args {
			if tracingOption(arg) {
				return true
			}
		}
	case shellInterpreterPrograms[program]:
		for index := 0; index < len(args); index++ {
			arg := args[index]
			if arg == "--" || arg == "-" {
				return false
			}
			if !strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "+") {
				return strings.ContainsAny(arg, "$`")
			}
			if strings.HasPrefix(arg, "-") && tracingOption(arg) {
				return true
			}
			if last := arg[len(arg)-1]; (last == 'o' || last == 'O') && !strings.HasPrefix(arg, "--") && index+1 < len(args) {
				index++
				if tracingOption(args[index]) {
					return true
				}
			}
		}
	}
	return false
}

// lineSwitchesOf decides the switches of one command line:
//   - a function or alias definition, eval, hash -p, enable, an assignment
//     to a rewriting variable (BASH_*, PATH, ENV, PS4, PROMPT_COMMAND,
//     SHELLOPTS, BASHOPTS, GLOBIGNORE, IFS) or a name reference (declare -n),
//     or a program named through a variable ($X ...): what a program name
//     runs is unknown (whole words, all use roles voided; the file BASH_ENV /
//     ENV names is then judged as a read like any other word);
//   - source or "." runs a file as commands (whole words, other commands'
//     use roles voided);
//   - a process substitution <(...) / >(...), or a pipe into a command that
//     is not a safe data consumer (isSafeConsumer): text may become commands
//     or file names (whole words; a source/. on the line has its use voided);
//   - tracing (set -x, set -e -x, shopt -o -s xtrace, bash -e -x -c,
//     SHELLOPTS=..., set -T, set -o functrace, shopt -s extdebug, any trap):
//     a source/. use is voided.
func lineSwitchesOf(raw string, commands []shellSimpleCommand) lineSwitches {
	var sw lineSwitches
	unsafePipe := strings.Contains(raw, "<(") || strings.Contains(raw, ">(")
	tokens := shellSwitchTokens(raw)
	redefines := redefinesCommandsIn(raw, tokens) || rewritesVariableInText(raw, tokens)
	tracing := tracingInText(tokens)
	sourcing := false
	for _, simple := range commands {
		start := commandStart(simple.Words)
		program, _ := shellProgramAt(simple.Words, start)
		args := simple.Words[min(start+1, len(simple.Words)):]
		if program == "eval" || (start < len(simple.Words) && strings.Contains(simple.Words[start], "$")) ||
			rebindsCommands(program, args) || setsRewritingVariable(program, args) {
			redefines = true
		}
		tracing = tracing || tracingCommand(program, args)
		if program == "source" || program == "." {
			sourcing = true
		}
		if (program == "for" || program == "select") && len(args) > 0 && rewritingVariable(args[0]) {
			redefines = true
		}
		if simple.PipesIn && !isSafeConsumer(simple) {
			unsafePipe = true
		}
	}
	sw.wholeWords = redefines || sourcing || unsafePipe
	sw.voidUseAll = redefines
	sw.voidOtherUse = sourcing
	sw.voidSourceUse = unsafePipe || tracing
	return sw
}

// gitMessageArgument: args[at] is the value of -m/--message (also in a short
// cluster such as -am) of git commit, tag, merge or stash, the only places the
// quoted-heredoc exception applies.
func gitMessageArgument(program string, args []string, at int) bool {
	if program != "git" || at == 0 {
		return false
	}
	option := args[at-1]
	if option != "--message" && !(len(option) > 1 && option[0] == '-' && option[1] != '-' && strings.HasSuffix(option, "m")) {
		return false
	}
	for index := 0; index < len(args); index++ {
		word := args[index]
		switch {
		case gitGlobalValues[word]:
			index++
		case strings.HasPrefix(word, "-"):
		default:
			switch strings.ToLower(word) {
			case "commit", "tag", "merge", "stash":
				return true
			}
			return false
		}
	}
	return false
}

// backquoteBody undoes the escapes the shell removes from `...` text before
// running it: \`, \\ and \$.
func backquoteBody(text string) string {
	return strings.NewReplacer("\\`", "`", "\\\\", "\\", "\\$", "$").Replace(text)
}

// quotedHeredocText reports a word that is exactly one command substitution
// printing a here-document as it is: "$(cat <<'EOF'\n...\nEOF\n)" (or
// printf '%s'), with no other argument or redirection, a quoted delimiter (the
// body is not expanded) and the delimiter line present. Claude Code writes
// commit messages this way; the body is text, not commands or file names.
func quotedHeredocText(word string, work *shellWork) bool {
	if !strings.HasPrefix(word, "$(") {
		return false
	}
	end, ok := substitutionSpanEnd(word, 1, work)
	if !ok || end != len(word) {
		return false
	}
	commands := splitShellSimpleCommandsWork(word[2:len(word)-1], work)
	if len(commands) != 1 {
		return false
	}
	only := commands[0]
	if only.Substitution || len(only.InputRedirects) > 0 || len(only.OutputRedirects) > 0 || len(only.Heredocs) != 1 {
		return false
	}
	doc := only.Heredocs[0]
	if doc.Expands || !doc.Terminated || doc.Delimiter == "" {
		return false
	}
	// 正文里有以定界符开头的行（EOF)、EOF2 …）：bash 版本之间结束位置不一，不走窄口径。
	for _, line := range strings.Split(doc.Body, "\n") {
		if doc.StripTabs {
			line = strings.TrimLeft(line, "\t")
		}
		if strings.HasPrefix(line, doc.Delimiter) {
			return false
		}
	}
	switch {
	case len(only.Words) == 1 && only.Words[0] == "cat":
		return true
	case len(only.Words) == 2 && only.Words[0] == "printf" && only.Words[1] == "%s":
		return true
	}
	return false
}

func (s *shellTargetScan) judge(word string, role shellArgRole, storeDir string, loops []shellLoopBinding) {
	if role == shellArgSkip || s.work.over() {
		return
	}
	for _, variant := range expandLoopWord(word, loops) {
		if !s.work.add(len(variant)) {
			return
		}
		if decision, ok := protectedShellWordWork(variant, storeDir, role, s.work); ok {
			s.add(decision)
			return
		}
	}
}

// kubeconfigAssignment reports KUBECONFIG=<path> on a command line that names
// the variable only there: anything else ("cat $KUBECONFIG") could read the
// file back through it, and the assignment is then judged as a read.
func kubeconfigAssignment(word string, mentions int) bool {
	return mentions == 1 && strings.HasPrefix(word, "KUBECONFIG=")
}

// markGenericUseOptions marks the values of --kubeconfig of a kube client and
// of --env-file of a program that loads it into the environment of what it
// runs (envFileUseLimit). Other programs (gh secret set --env-file, docker
// compose config) may print or ship the file: their values stay reads.
// Positions a program handler already gave a role keep it.
func markGenericUseOptions(program string, args []string, roles map[int]shellArgRole) {
	kube := isKubeClient(program, args)
	envLimit := envFileUseLimit(program, args)
	for index := 0; index < len(args); index++ {
		word := args[index]
		if word == "--" {
			return
		}
		name, _, attached := strings.Cut(word, "=")
		var role shellArgRole
		switch {
		case name == "--kubeconfig" && kube:
			role = shellArgUseKubeconfig
		case name == "--env-file" && index < envLimit:
			role = shellArgUseEnvFile
		default:
			continue
		}
		at := index
		if !attached {
			if index+1 >= len(args) {
				return
			}
			index++
			at = index
		}
		if current, ok := roles[at]; !ok || current == shellArgRead {
			roles[at] = role
		}
	}
}

// kubectlLikeArgs returns the kubectl arguments of a kubectl-compatible
// client: kubectl, oc, kubecolor, microk8s.kubectl, and "k3s / k0s /
// microk8s kubectl ...".
func kubectlLikeArgs(program string, args []string) ([]string, bool) {
	switch program {
	case "kubectl", "oc", "kubecolor", "microk8s.kubectl":
		return args, true
	case "k3s", "k0s", "microk8s":
		if len(args) > 0 && args[0] == "kubectl" {
			return args[1:], true
		}
	}
	return nil, false
}

// kubectlBoolFlag reports a boolean flag that is on: "--raw", or "--raw=V"
// with any V but an explicit false (strconv.ParseBool: 0, f, F, false, FALSE,
// False); kubectl rejects the other values, and they are taken as on.
func kubectlBoolFlag(word, name string) bool {
	if word == name {
		return true
	}
	value, ok := strings.CutPrefix(word, name+"=")
	if !ok {
		return false
	}
	on, err := strconv.ParseBool(value)
	return err != nil || on
}

// kubectlRawConfigView finds "kubectl config view --raw" (or --flatten, which
// inlines the certificate and key files), which prints the kubeconfig with
// its tokens and keys (otherwise they are redacted). The
// hit names the file it reads: --kubeconfig, a KUBECONFIG= assignment before
// the program, or the default ~/.kube/config, which an exception for a path
// cannot pin down (KUBECONFIG may be set outside the command).
func kubectlRawConfigView(program string, before, args []string) (Decision, bool) {
	args, ok := kubectlLikeArgs(program, args)
	if !ok {
		return Decision{}, false
	}
	config, view, raw := false, false, false
	kubeconfig := ""
	for index, word := range args {
		switch {
		case word == "config":
			config = true
		case word == "view" && config:
			view = true
		case kubectlBoolFlag(word, "--raw") || kubectlBoolFlag(word, "--flatten"):
			raw = true
		case word == "--kubeconfig" && index+1 < len(args):
			kubeconfig = args[index+1]
		case strings.HasPrefix(word, "--kubeconfig="):
			kubeconfig = strings.TrimPrefix(word, "--kubeconfig=")
		}
	}
	if !view || !raw {
		return Decision{}, false
	}
	if kubeconfig == "" {
		for _, word := range before {
			if value, ok := strings.CutPrefix(word, "KUBECONFIG="); ok {
				kubeconfig = value
			}
		}
	}
	hit := ProtectionHit{Reason: targetReasonCloudCredential, Target: "~/.kube/config", RiskLevel: "critical", Confidence: 0.9}
	if kubeconfig != "" {
		hit.Target = normalizeFilePath(kubeconfig)
		if !strings.Contains(kubeconfig, ":") {
			hit.MatchTarget = filerestrict.ExceptionTarget(kubeconfig)
		}
	}
	evidence := sanitizedEvidence(targetEvidenceRuleBlockedFS, "target", "command", program+" config view --raw")
	evidence.LiteralPath = filerestrict.LiteralPath(kubeconfig)
	return protectionFindingFor(hit, []Evidence{evidence}), true
}

// kubectlSecretRead finds a kubectl-compatible client printing Secret data:
// "get secret(s)" (also secret/NAME, a list with secrets, secrets.v1) with an
// output format that prints the object (-o yaml, json, jsonpath=...,
// go-template=..., custom-columns=..., anything but name or wide), or
// "get --raw" of an API path with a "secrets" segment. The hit is a cloud
// credential; an exception for a path cannot pin it down.
func kubectlSecretRead(program string, args []string) (Decision, bool) {
	args, ok := kubectlLikeArgs(program, args)
	if !ok {
		return Decision{}, false
	}
	var operands []string
	output, template, rawPath, get := "", "", "", false
	for index := 0; index < len(args); index++ {
		word := args[index]
		next := func() string {
			if index+1 < len(args) {
				index++
				return args[index]
			}
			return ""
		}
		name, value, attached := strings.Cut(word, "=")
		switch {
		case word == "--":
			index = len(args)
		case name == "-o" || name == "--output":
			if !attached {
				value = next()
			}
			output = value
		case strings.HasPrefix(word, "-o") && !strings.HasPrefix(word, "--"):
			output = strings.TrimPrefix(word[2:], "=")
		case name == "--raw":
			if !attached {
				value = next()
			}
			rawPath = value
		case name == "--template":
			if !attached {
				value = next()
			}
			template = value
		case strings.HasPrefix(word, "-"):
			if _, takesValue := kubectlValueOptions[name]; takesValue && !attached && !kubectlFlags[name] {
				index++
			}
		case !get:
			get = word == "get"
			if !get {
				return Decision{}, false
			}
		default:
			operands = append(operands, word)
		}
	}
	if !get {
		return Decision{}, false
	}
	secret := false
	for position, operand := range operands {
		if position > 0 && !strings.Contains(operands[0], "/") {
			break // 其余操作数是资源名
		}
		for _, item := range strings.Split(operand, ",") {
			kind, _, _ := strings.Cut(item, "/")
			kind, _, _ = strings.Cut(strings.ToLower(kind), ".")
			secret = secret || kind == "secret" || kind == "secrets"
		}
	}
	format, inline, hasInline := strings.Cut(strings.Trim(output, `'"`), "=")
	format = strings.ToLower(format)
	if hasInline {
		template = inline
	}
	printsData := secret && format != "" && format != "name" && format != "wide" &&
		!(kubectlInlineTemplateFormats[format] && kubectlTemplateMetadataOnly(template))
	rawSecrets := false
	for _, segment := range strings.Split(rawPath, "/") {
		rawSecrets = rawSecrets || strings.EqualFold(segment, "secrets")
	}
	if !printsData && !rawSecrets {
		return Decision{}, false
	}
	hit := ProtectionHit{Reason: targetReasonCloudCredential, Target: "kubernetes:secrets", RiskLevel: "critical", Confidence: 0.9}
	evidence := sanitizedEvidence(targetEvidenceRuleBlockedFS, "target", "command", program+" get secret")
	return protectionFindingFor(hit, []Evidence{evidence}), true
}

// kubectlInlineTemplateFormats carry their template on the line (-o
// jsonpath=..., or -o go-template with --template=...).
var kubectlInlineTemplateFormats = flagSet("jsonpath", "jsonpath-as-json", "go-template", "template", "custom-columns")

var (
	// kubectlMetadataPath: a field under metadata, or type, kind, apiVersion,
	// also of each list item (.items[*].metadata.name).
	kubectlMetadataPath = regexp.MustCompile(`^(\.items(\[(\*|\d+)\])?)?\.(metadata(\.[A-Za-z0-9_-]+)*|type|kind|apiVersion)$`)
	// kubectlTemplateText: a plain string literal of a template ({"\n"}).
	kubectlTemplateText = regexp.MustCompile(`"(\\[nt]|[ ,:;|/=-])*"`)
)

// kubectlTemplateMetadataOnly: the template prints only metadata, type, kind
// or apiVersion fields ({.metadata.name}, {range .items[*]}{.metadata.name}
// {"\n"}{end}, NAME:.metadata.name,TYPE:.type, {{.metadata.name}}). Anything
// else (data, a filter, recursive descent, functions) may print the data.
func kubectlTemplateMetadataOnly(template string) bool {
	text := kubectlTemplateText.ReplaceAllString(strings.Trim(template, `'"`), " ")
	fields := strings.FieldsFunc(text, func(r rune) bool { return strings.ContainsRune("{} \t\n,", r) })
	afterRange := false
	for _, field := range fields {
		header, path, column := strings.Cut(field, ":")
		switch {
		case field == "range":
			afterRange = true
			continue
		case field == "end":
		case afterRange && (field == ".items" || field == ".items[*]"):
		case kubectlMetadataPath.MatchString(field):
		case column && header != "" && strings.Trim(header, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") == "" &&
			kubectlMetadataPath.MatchString(path):
		default:
			return false
		}
		afterRange = false
	}
	return len(fields) > 0
}

// fallbackKubeReads finds kubectl config view --raw and Secret reads for the
// fallback, also of a kubectl run behind "--" (kubectl exec p -- kubectl get
// secret ...), up to maxShellNesting commands deep.
func (s *shellTargetScan) fallbackKubeReads(program string, before, args []string) {
	for depth := 0; depth <= maxShellNesting; depth++ {
		if hit, ok := kubectlRawConfigView(program, before, args); ok {
			s.add(hit)
		}
		if hit, ok := kubectlSecretRead(program, args); ok {
			s.add(hit)
		}
		s.work.add(len(args))
		separator := -1
		for index, word := range args {
			if word == "--" {
				separator = index
				break
			}
		}
		if separator < 0 || separator+1 >= len(args) {
			return
		}
		before, args = nil, args[separator+1:]
		start := commandStart(args)
		program, args = shellProgramAt(args, start)
	}
}

// zshOptionCommands set zsh options by name: setopt, unsetopt, emulate -o.
var zshOptionCommands = flagSet("setopt", "unsetopt", "emulate")

// zshTextOptionWindow bounds the words after setopt / unsetopt / emulate
// that the line-wide text scan looks at.
const zshTextOptionWindow = 8

// zshOptionName normalizes a zsh option name as zsh compares them: case and
// underscores do not matter (XTRACE, X_TRACE, xtrace; NO_XTRACE, noxtrace).
func zshOptionName(word string) string {
	return strings.ReplaceAll(strings.ToLower(word), "_", "")
}

// zshTracing reports setopt / unsetopt / emulate turning on XTRACE or
// VERBOSE (zsh then echoes what a sourced file runs): setopt xtrace, verbose
// or -x / -v; unsetopt noxtrace, noverbose; setopt / emulate -o / +o with
// such a name (either sign, strictly); a pattern (-m) or an unreadable word
// ($OPTS) may name any option.
func zshTracing(command string, args []string) bool {
	on := map[string]bool{"xtrace": true, "verbose": true}
	if command == "unsetopt" {
		on = map[string]bool{"noxtrace": true, "noverbose": true}
	}
	for index := 0; index < len(args); index++ {
		word := args[index]
		if strings.ContainsAny(word, "$`") {
			return true
		}
		switch {
		case word == "-o" || word == "+o":
			if index+1 < len(args) {
				index++
				switch zshOptionName(args[index]) {
				case "xtrace", "verbose", "noxtrace", "noverbose":
					return true
				}
			}
		case len(word) > 1 && (word[0] == '-' || word[0] == '+'):
			if command != "emulate" && strings.ContainsAny(word[1:], "xvm") {
				return true
			}
		case command != "emulate" && on[zshOptionName(word)]:
			return true
		}
	}
	return false
}
