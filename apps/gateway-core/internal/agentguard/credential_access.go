package agentguard

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
)

// reasonGitCredentialDump: a git credential helper is asked to print a stored
// secret ("git credential fill", "git credential-<helper> get").
const reasonGitCredentialDump = "blocked_git_credential_dump"

// Shell commands are judged word by word. The whole command line is never a
// path: treating it as one made the text after its last "/" look like a file
// name, so "git config --get credential.helper" became a "credential" file and
// "ls ~/.ssh" blocked while "cat ~/.ssh/id_rsa | base64" passed.
//
// A word names a protected target when it is a secret file (AnalyzeTarget) or
// a whole credential store directory (~/.ssh, ~/.aws, ~/.gnupg, or a glob or
// variable inside one). The program of a simple command is the first word
// after leading assignments, shell keywords (if, then, do, !, { ...) and
// wrappers (sudo, time, env, timeout, nice, nohup, command, exec) with the
// options they are known to take. Keywords are syntax and never read; the
// words of wrappers are. These facts decide whether the access exposes
// content:
//   - metadata-only programs (ls, stat, test, chmod, ...) never print file
//     content, so listing or stating a store is recorded, not blocked, unless
//     their output feeds another command (also as part of a { }, if, loop or
//     case group whose output does), a substitution runs inside them, or an
//     argument carries the text of one;
//   - the destination of cp/mv/install/ln, the files tee writes and output
//     redirections are written, not read. Behind a keyword or a wrapper the
//     destination is judged like every other word;
//   - a private key that ssh, scp, sftp, rsync -e, ssh-add, ssh-keygen -l/-y
//     or GIT_SSH_COMMAND only authenticates with is used, not read
//     (ssh_key_use.go);
//   - "git credential fill" and helper "get" print stored passwords.

// shellSimpleCommand is one simple command of a shell command line.
type shellSimpleCommand struct {
	Words           []string
	InputRedirects  []string
	OutputRedirects []string
	// PipesOut: stdout feeds another command ("|", "|&", or the command
	// runs inside $(...), `...` or <(...) whose output is consumed).
	PipesOut bool
	// Substitution: a command substitution or process substitution runs
	// inside this command, so its words are not all literal.
	Substitution bool
	// StdinFeed: a here-document, a here-string or a duplicated descriptor
	// feeds standard input. Its body is not one of the words.
	StdinFeed bool
	// PipesIn: standard input is the output of the previous command ("|",
	// "|&"), including a group or subshell that the pipe feeds.
	PipesIn bool
	// Captured: the command runs inside $(...), `...` or <(...), so its
	// output becomes words or input of the enclosing command.
	Captured bool
	// SplitSubstitution: an unquoted command or process substitution in this
	// command was split out into commands of its own (its text is no longer
	// in the words).
	SplitSubstitution bool
	// Heredocs are the here-document bodies and here-strings feeding
	// standard input, in order.
	Heredocs []shellHeredoc
}

// shellHeredoc is one here-document body or here-string.
type shellHeredoc struct {
	Body string
	// Expands: the shell expands parameters and runs command substitutions
	// in the body (unquoted delimiter, or a here-string).
	Expands bool
	// Terminated: the delimiter line was found.
	Terminated bool
	// Delimiter is the delimiter word after quote removal; StripTabs: <<-.
	Delimiter string
	StripTabs bool
}

// pendingHeredoc is a here-document whose body starts after the current line.
type pendingHeredoc struct {
	delim     string
	stripTabs bool
	quoted    bool
	owner     int // index in the command list of the command it feeds
}

// metadataOnlyPrograms never print the content of the files they are given.
// file (-f) and du (--files0-from) are excluded: they read a file as a list
// of names and echo its lines back in their errors. [[ is excluded: its
// arithmetic operands (-eq, -v a[...]) run the command substitutions of an
// array subscript even when the shell quoted them.
var metadataOnlyPrograms = map[string]bool{
	"ls": true, "dir": true, "vdir": true, "stat": true,
	"test": true, "[": true, "realpath": true, "readlink": true, "dirname": true, "basename": true,
	"mkdir": true, "chmod": true, "chown": true, "chgrp": true,
}

// credentialStoreReasons maps a credential directory name to its protection reason.
var credentialStoreReasons = map[string]string{
	".ssh":   targetReasonSSHPrivateKey,
	".aws":   targetReasonCloudCredential,
	".gnupg": targetReasonSensitiveName,
}

// substitutionText reports an argument that carries the text of a command
// substitution the splitter kept literal (quoted). test, [ and [[ evaluate
// "-v 'a[$(cmd)]'" and arithmetic operands as array subscripts, and running
// the subscript runs cmd.
func substitutionText(args []string) bool {
	for _, arg := range args {
		if strings.Contains(arg, "$(") || strings.Contains(arg, "`") {
			return true
		}
	}
	return false
}

// protectedShellWord checks one word read by a command and the paths
// embedded in it.
func protectedShellWord(word, storeDir string) (Decision, bool) {
	return protectedShellWordAs(word, storeDir, shellArgRead)
}

// isPublicKeyName: a name whose every expansion ends with ".pub" (a literal
// name, a glob or a brace list before the literal suffix) names public keys
// only. A variable or substitution in it may split into further words
// ("$f.pub" with f="id_rsa x"), so it does not count.
func isPublicKeyName(base string) bool {
	return strings.HasSuffix(base, ".pub") && !strings.ContainsAny(base, "$`")
}

// isPublicKeyGlobWord: the whole word is one path to public keys under ~/.ssh
// (~/.ssh/*.pub, ~/.ssh/{id_rsa,id_ed25519}.pub); its pieces split at "," or
// "{" are not paths of their own.
func isPublicKeyGlobWord(word string) bool {
	trimmed := strings.TrimSpace(word)
	if trimmed == "" || strings.ContainsAny(trimmed, " \t'\"()<>;|&") {
		return false
	}
	normalized := strings.ToLower(normalizeFilePath(trimmed))
	return isPublicKeyName(filepath.Base(normalized)) && filepath.Base(filepath.Dir(normalized)) == ".ssh"
}

// protectedShellWordAs checks one word in the given role: the first embedded
// path whose hit counts for that role decides.
func protectedShellWordAs(word, storeDir string, role shellArgRole) (Decision, bool) {
	return protectedShellWordWork(word, storeDir, role, nil)
}

// protectedShellWordWork is protectedShellWordAs counting the candidates it
// builds (brace expansions, option values, embedded paths) on work during
// the precise parse; past the limit it stops and the scan falls back. The
// fallback judges every word once per nesting layer and is not cut short, so
// it does not count them again.
func protectedShellWordWork(word, storeDir string, role shellArgRole, work *shellWork) (Decision, bool) {
	if isPublicKeyGlobWord(word) {
		return Decision{}, false
	}
	candidates := shellWordCandidates(word)
	if work != nil && !work.fellBack {
		total := 0
		for _, candidate := range candidates {
			total += len(candidate)
		}
		if !work.add(total) {
			return Decision{}, false
		}
	}
	// A line-switched word that cannot name a file itself only counts for the
	// exact classes (private key, cloud credential, .env, /etc/shadow ...).
	nameHint := role != shellArgReadLineSwitched || wordMayNameFile(word)
	for _, candidate := range candidates {
		paths := []string{candidate}
		if storeDir != "" && !strings.HasPrefix(candidate, "/") && !strings.HasPrefix(candidate, "~") && !strings.HasPrefix(candidate, "$") {
			paths = append(paths, strings.TrimSuffix(storeDir, "/")+"/"+candidate)
		}
		for _, path := range paths {
			if reason, ok := credentialStoreReference(path); ok && role.admits(reason, true, path) {
				return shellTargetDecision(reason, path, normalizeFilePath(path)), true
			}
			if !looksLikeFileTarget(path) || looksLikeURLArgument(path) {
				continue
			}
			if target := AnalyzeTarget(path); target.Hit && target.Kind == TargetFile && role.admits(target.Reason, false, path) &&
				(nameHint || target.Reason != targetReasonSensitiveName) {
				return shellTargetDecision(target.Reason, path, target.NormalizedTarget), true
			}
		}
	}
	return Decision{}, false
}

// wordMayNameFile: the word as the shell passes it, or one alternative of its
// {a,b} brace list, holds no blank, quote, parenthesis, brace or operator, so
// it may be a file name. JSON text ({"tool":"../etc/passwd"}) and prose are
// not.
func wordMayNameFile(word string) bool {
	const notInName = " \t\n\"'`(){};<>|&"
	if !strings.ContainsAny(word, notInName) {
		return true
	}
	for _, expanded := range expandShellBraces(word) {
		if expanded != word && !strings.ContainsAny(expanded, notInName) {
			return true
		}
	}
	return false
}

// shellTargetDecision 记一条命令目标命中：target 是命中的规范化路径，证据只存脱敏的原词；
// 例外比对用未经 URL 解码的原词（filerestrict.ExceptionTarget）。
func shellTargetDecision(reason, path, target string) Decision {
	return protectionFindingFor(ProtectionHit{
		Reason: reason, Target: target, RiskLevel: "critical", Confidence: 0.9, MatchTarget: filerestrict.ExceptionTarget(path),
	}, []Evidence{fileTargetEvidence(path)})
}

// shellWordSeparators split a word into the parts that may each name a path
// (inline code such as python -c "open('/root/.ssh/id_rsa')", option values,
// lists, multi-line text). "[" and "]" no longer split: jsonpath subscripts
// (.env[*]) name no file.
const shellWordSeparators = "'\"(),;= \t\n"

var shellIFSReplacer = strings.NewReplacer("${IFS}", " ", "$IFS", " ")

// shellWordCandidates yields the word, its option value (--opt=x, f=@x), the
// file of a curl-style "@file" argument, and the paths embedded in it. A part
// is not cut at every ":" (jsonpath, host:port, image:tag); only a piece
// between colons that looks like a path is added (docker -v /root/.ssh:/k,
// scp host:.ssh/id_rsa, git show HEAD:.env). A word only a program that
// takes URLs treats as a URL (curl, wget) is skipped by that program's
// roles; to any other program "http://home/u/.ssh/id_rsa" is a local path
// (after "ln -s / http:"), so its pieces are still judged here.
func shellWordCandidates(word string) []string {
	// {a,b} brace expansion: every alternative is a word of its own and is
	// judged first; the word as written follows.
	expansions := expandShellBraces(word)
	if len(expansions) == 1 && expansions[0] == word {
		return shellWordPieces(word)
	}
	var out []string
	for _, expanded := range expansions {
		out = append(out, shellWordPieces(expanded)...)
	}
	return append(out, shellWordPieces(word)...)
}

// maxBraceExpansions bounds the words one brace expression yields.
const maxBraceExpansions = 64

// expandShellBraces expands {a,b,...} lists (not ${...}) as bash does. When
// the expansion would exceed maxBraceExpansions words it is not cut short:
// instead every alternative of every brace list is put into the word once
// (the other lists take their first alternative), so each alternative is
// still judged. A word without such a list is returned as is.
func expandShellBraces(word string) []string {
	if out, complete := expandBracesLimited(word, maxBraceExpansions); complete {
		return out
	}
	return braceAlternativeVariants(word, 0)
}

// braceGroup is one top-level {a,b,...} list of a word.
type braceGroup struct {
	open, close  int
	alternatives []string
}

// braceIndex finds the brace lists of a word. It scans from each "{" as
// bash reads them (cheap on ordinary words, no allocation); once those scans
// together have looked at more than braceScanFactor times the word, which
// only "{{{{..." and the like do (the square of the length), it builds in one
// pass the "}" that closes each "{" (the first one where the depth counted
// from it returns to zero) and the commas directly inside, and answers from
// that. Both ways give the same lists.
type braceIndex struct {
	word    string
	scanned int
	built   bool
	closeOf map[int]int
	commas  map[int][]int
}

const braceScanFactor = 4

func newBraceIndex(word string) *braceIndex {
	return &braceIndex{word: word}
}

// groupFrom returns the first brace list starting at or after from: a "{"
// not after "$", closed, with at least one comma directly inside.
func (index *braceIndex) groupFrom(from int) (braceGroup, bool) {
	if !index.built {
		if group, ok, done := index.scanFrom(from); done {
			return group, ok
		}
		index.build()
	}
	word := index.word
	for i := from; i < len(word); i++ {
		if word[i] != '{' || (i > 0 && word[i-1] == '$') {
			continue
		}
		closing, closed := index.closeOf[i]
		commas := index.commas[i]
		if !closed || len(commas) == 0 {
			continue
		}
		parts := make([]string, 0, len(commas)+1)
		start := i + 1
		for _, comma := range commas {
			parts = append(parts, word[start:comma])
			start = comma + 1
		}
		return braceGroup{open: i, close: closing, alternatives: append(parts, word[start:closing])}, true
	}
	return braceGroup{}, false
}

// scanFrom scans from each "{" at or after from; done is false when the scans
// passed their share of the word before finding the answer.
func (index *braceIndex) scanFrom(from int) (braceGroup, bool, bool) {
	word := index.word
	for i := from; i < len(word); i++ {
		if word[i] != '{' || (i > 0 && word[i-1] == '$') {
			continue
		}
		depth, start := 0, i+1
		var parts []string
		for j := i; j < len(word); j++ {
			index.scanned++
			if index.scanned > braceScanFactor*len(word) {
				return braceGroup{}, false, false
			}
			switch word[j] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					if len(parts) > 0 {
						return braceGroup{open: i, close: j, alternatives: append(parts, word[start:j])}, true, true
					}
					j = len(word)
				}
			case ',':
				if depth == 1 {
					parts = append(parts, word[start:j])
					start = j + 1
				}
			}
		}
	}
	return braceGroup{}, false, true
}

// build finds the closing "}" and the direct commas of every "{" in one pass.
func (index *braceIndex) build() {
	index.built = true
	index.closeOf, index.commas = map[int]int{}, map[int][]int{}
	var open []int
	for j := 0; j < len(index.word); j++ {
		switch index.word[j] {
		case '{':
			open = append(open, j)
		case '}':
			if len(open) > 0 {
				index.closeOf[open[len(open)-1]] = j
				open = open[:len(open)-1]
			}
		case ',':
			if len(open) > 0 {
				top := open[len(open)-1]
				index.commas[top] = append(index.commas[top], j)
			}
		}
	}
}

// foldLiteralPath folds the part of text between its first and last "/" as
// path.Clean does ("." and empty segments dropped, "x/.." removed), keeping a
// leading ".." that applies to what comes before, and keeping the partial
// segments at both ends that join the neighboring brace lists.
func foldLiteralPath(text string) string {
	first, last := strings.IndexByte(text, '/'), strings.LastIndexByte(text, '/')
	if first < 0 || first == last {
		return text
	}
	var kept []string
	for _, segment := range strings.Split(text[first+1:last], "/") {
		switch {
		case segment == "" || segment == ".":
		case segment == ".." && len(kept) > 0 && kept[len(kept)-1] != "..":
			kept = kept[:len(kept)-1]
		default:
			kept = append(kept, segment)
		}
	}
	folded := "/"
	if len(kept) > 0 {
		folded = "/" + strings.Join(kept, "/") + "/"
	}
	return text[:first] + folded + text[last+1:]
}

// expandBracesLimited expands every brace list; complete is false when the
// result would exceed limit words.
func expandBracesLimited(word string, limit int) ([]string, bool) {
	index := newBraceIndex(word)
	group, ok := index.groupFrom(0)
	if !ok {
		return []string{word}, true
	}
	// The top-level lists alone already multiply past the limit: say so
	// without building the words.
	product := len(group.alternatives)
	for from := group.close + 1; product <= limit; {
		next, ok := index.groupFrom(from)
		if !ok {
			break
		}
		product *= len(next.alternatives)
		from = next.close + 1
	}
	if product > limit {
		return nil, false
	}
	var out []string
	for _, alternative := range group.alternatives {
		expanded, complete := expandBracesLimited(word[:group.open]+alternative+word[group.close+1:], limit-len(out))
		out = append(out, expanded...)
		if !complete || len(out) > limit {
			return out, false
		}
	}
	return out, true
}

// maxBraceVariants bounds the per-alternative variants of an oversized
// brace expansion (one per alternative, nested lists included);
// maxBraceVariantBytes bounds rebuilding whole words for them, beyond which
// each alternative is judged in a braceWindow-byte window around its list.
const (
	maxBraceVariants     = 4096
	maxBraceVariantBytes = 1 << 20
	braceWindow          = 256
)

// braceAlternativeVariants puts each alternative of each top-level brace list
// into the word, the other lists replaced by their first alternative, and
// expands what the alternative itself holds.
func braceAlternativeVariants(word string, depth int) []string {
	if depth > 4 {
		return []string{word}
	}
	if out, complete := expandBracesLimited(word, maxBraceExpansions); complete {
		return out
	}
	var groups []braceGroup
	index := newBraceIndex(word)
	for from := 0; ; {
		group, ok := index.groupFrom(from)
		if !ok {
			break
		}
		groups = append(groups, group)
		from = group.close + 1
	}
	alternatives := 0
	for _, group := range groups {
		alternatives += len(group.alternatives)
	}
	var out []string
	if len(word)*alternatives > maxBraceVariantBytes {
		// Too large to rebuild the whole word per alternative: put each
		// alternative into a window of the word around its list (the
		// directory before it and the name after it are inside; the other
		// lists take their first alternative). Identical windows are judged
		// once.
		// The literal parts are folded first (./ and x/../ removed), so
		// padding cannot push the directory out of the window.
		var flat strings.Builder
		spans := make([][2]int, len(groups))
		last := 0
		for index, group := range groups {
			flat.WriteString(foldLiteralPath(word[last:group.open]))
			start := flat.Len()
			flat.WriteString(group.alternatives[0])
			spans[index], last = [2]int{start, flat.Len()}, group.close+1
		}
		flat.WriteString(foldLiteralPath(word[last:]))
		text := flat.String()
		seen := map[string]bool{}
		for index, group := range groups {
			before := text[max(0, spans[index][0]-braceWindow):spans[index][0]]
			after := text[spans[index][1]:min(len(text), spans[index][1]+braceWindow)]
			for _, alternative := range group.alternatives {
				for _, inner := range braceAlternativeVariants(alternative, depth+1) {
					if variant := before + inner + after; !seen[variant] {
						seen[variant] = true
						out = append(out, variant)
					}
				}
			}
		}
		return out
	}
	for chosen, group := range groups {
		for _, alternative := range group.alternatives {
			var variant strings.Builder
			last := 0
			for index, other := range groups {
				variant.WriteString(word[last:other.open])
				if index == chosen {
					variant.WriteString(alternative)
				} else {
					variant.WriteString(other.alternatives[0])
				}
				last = other.close + 1
			}
			variant.WriteString(word[last:])
			expanded := []string{variant.String()}
			if depth < 4 {
				if more, complete := expandBracesLimited(variant.String(), maxBraceExpansions); complete {
					expanded = more
				} else {
					expanded = braceAlternativeVariants(variant.String(), depth+1)
				}
			}
			for _, item := range expanded {
				if len(out) >= maxBraceVariants {
					return out
				}
				out = append(out, item)
			}
		}
	}
	return out
}

// shellWordPieces yields the word, its option value and the paths embedded in
// it (see shellWordCandidates).
func shellWordPieces(word string) []string {
	out := make([]string, 0, 4)
	add := func(value string) {
		value = strings.TrimLeft(strings.TrimSpace(value), "@<")
		if value != "" {
			out = append(out, value)
		}
	}
	add(word)
	if index := strings.Index(word, "="); index >= 0 {
		add(word[index+1:])
	}
	// $IFS / ${IFS} split words when the shell expands them (cat${IFS}.env).
	split := shellIFSReplacer.Replace(word)
	parts := []string{word}
	if strings.ContainsAny(split, shellWordSeparators) {
		parts = strings.FieldsFunc(split, func(r rune) bool {
			return strings.ContainsRune(shellWordSeparators, r)
		})
		for _, part := range parts {
			add(part)
		}
	}
	for _, part := range parts {
		if !strings.Contains(part, ":") {
			continue
		}
		for _, piece := range strings.Split(part, ":") {
			piece = strings.TrimLeft(strings.TrimSpace(piece), "@<")
			if strings.ContainsAny(piece, `/\`) || isSensitiveBareFileName(strings.ToLower(piece)) {
				add(piece)
			}
		}
	}
	return out
}

// credentialStoreReference reports a word naming a whole credential store
// directory, or a glob/variable/placeholder inside one ("~/.ssh/*",
// "~/.ssh/{}", "~/.ssh/$f"), which can expand to the keys it holds.
func credentialStoreReference(word string) (string, bool) {
	trimmed := strings.TrimSpace(word)
	if trimmed == "" || looksLikeURLArgument(trimmed) {
		return "", false
	}
	normalized := strings.ToLower(normalizeFilePath(trimmed))
	base := filepath.Base(normalized)
	if reason, ok := credentialStoreReasons[base]; ok {
		return reason, true
	}
	if isPublicKeyName(base) {
		return "", false
	}
	if strings.ContainsAny(base, "*?[{$%") {
		if reason, ok := credentialStoreReasons[filepath.Base(filepath.Dir(normalized))]; ok {
			return reason, true
		}
	}
	return "", false
}

// shellProgram returns the program name of a simple command and its
// arguments (empty when the command only assigns variables).
func shellProgram(words []string) (string, []string) {
	return shellProgramAt(words, commandStart(words))
}

func shellProgramAt(words []string, start int) (string, []string) {
	if start >= len(words) {
		return "", []string{}
	}
	return strings.ToLower(filepath.Base(words[start])), words[start+1:]
}

// standardProgramDirs are the system directories whose programs are taken as
// the well-known tools of their name.
var standardProgramDirs = flagSet("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
	"/opt/homebrew/bin", "/opt/homebrew/sbin", "/home/linuxbrew/.linuxbrew/bin", "/opt/local/bin", "/snap/bin")

// trustedProgramAt returns the program name of a simple command when its
// word is a bare name or a path in a standard bin directory, and "" for any
// other path (./jq, ~/bin/grep, /tmp/x/awk), which may be anything. Only a
// trusted name gets the program's argument roles, safe-consumer, use,
// metadata-only and key-use exemptions (复核员乙 L4); shellProgramAt (the
// base name) still drives the stricter checks (interpreters, tracing,
// written files).
func trustedProgramAt(words []string, start int) string {
	if start >= len(words) {
		return ""
	}
	word := words[start]
	if strings.Contains(word, "/") && !standardProgramDirs[path.Dir(path.Clean(word))] {
		return ""
	}
	return strings.ToLower(filepath.Base(word))
}

// shellKeywords open, continue or close a compound command and read no file,
// so the program after them is judged. "for" is not one of them: its word
// list is judged as written, so "for f in ~/.ssh/*" still names the store.
var shellKeywords = map[string]bool{
	"if": true, "then": true, "elif": true, "else": true, "fi": true,
	"do": true, "done": true, "while": true, "until": true,
	"!": true, "{": true, "}": true, "(": true,
}

// commandWrapper is a wrapper that runs its operand as the program, with the
// options it is known to take. Skipping stops at the first option that is not
// listed: that word is then taken as the program and every word after it is
// still judged as a read. xargs is not a wrapper here: its operands come from
// standard input.
type commandWrapper struct {
	flags, values string          // short options without / with a value
	long          map[string]bool // long option -> takes a value
	bareDash      bool            // env: "-" is -i
	numeric       bool            // nice: "-10" is an adjustment
	duration      bool            // timeout: a duration precedes the program
}

var commandWrappers = map[string]commandWrapper{
	"sudo": {flags: "EHnSkAP", values: "ugpCD", long: map[string]bool{
		"--user": true, "--group": true, "--preserve-env": false, "--non-interactive": false, "--set-home": false,
	}},
	"time": {flags: "p"},
	"env": {flags: "i", values: "u", bareDash: true, long: map[string]bool{
		"--ignore-environment": false, "--unset": true,
	}},
	"timeout": {flags: "v", values: "sk", duration: true, long: map[string]bool{
		"--foreground": false, "--preserve-status": false, "--verbose": false, "--signal": true, "--kill-after": true,
	}},
	"nice":    {values: "n", numeric: true, long: map[string]bool{"--adjustment": true}},
	"nohup":   {},
	"command": {flags: "pvV"},
	"builtin": {},
	"exec":    {flags: "cl", values: "a"},
}

// commandStart returns the index of the program word of a simple command:
// the first word after leading assignments, shell keywords and wrappers with
// their options, or len(words) when there is none.
func commandStart(words []string) int {
	index := 0
	wrapped := false
	for index < len(words) {
		word := words[index]
		if isShellAssignment(word) || (!wrapped && shellKeywords[word]) {
			index++
			continue
		}
		wrapper, ok := commandWrappers[strings.ToLower(filepath.Base(word))]
		if !ok {
			return index
		}
		wrapped = true
		next, ok := wrapper.skip(words, index+1)
		if !ok {
			return next
		}
		index = next
	}
	return index
}

// skip returns the index after the wrapper's options (and timeout's
// duration), or the index of the first word it does not recognize and false.
func (w commandWrapper) skip(words []string, index int) (int, bool) {
	for index < len(words) {
		word := words[index]
		switch {
		case word == "--":
			return w.afterOptions(words, index+1)
		case word == "-" && w.bareDash:
			index++
		case strings.HasPrefix(word, "--"):
			name, _, attached := strings.Cut(word, "=")
			takesValue, known := w.long[name]
			if !known || (takesValue && !attached && index+1 >= len(words)) {
				return index, false
			}
			index++
			if takesValue && !attached {
				index++
			}
		case strings.HasPrefix(word, "-") && len(word) > 1:
			if w.numeric && isDecimalDigits(word[1:]) {
				index++
				continue
			}
			next, ok := w.skipCluster(words, index)
			if !ok {
				return index, false
			}
			index = next
		default:
			return w.afterOptions(words, index)
		}
	}
	return index, true
}

func (w commandWrapper) skipCluster(words []string, index int) (int, bool) {
	word := words[index]
	for pos := 1; pos < len(word); pos++ {
		option := word[pos]
		if strings.IndexByte(w.flags, option) >= 0 {
			continue
		}
		if strings.IndexByte(w.values, option) < 0 {
			return index, false
		}
		if pos+1 < len(word) {
			return index + 1, true // the value is the rest of the cluster
		}
		if index+1 >= len(words) {
			return index, false
		}
		return index + 2, true
	}
	return index + 1, true
}

func (w commandWrapper) afterOptions(words []string, index int) (int, bool) {
	if w.duration {
		if index >= len(words) || !isShellNumber(words[index]) {
			return index, false
		}
		index++
	}
	return index, true
}

func isDecimalDigits(value string) bool {
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

func isShellAssignment(word string) bool {
	eq := strings.Index(word, "=")
	if eq <= 0 {
		return false
	}
	for i, r := range word[:eq] {
		if r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

// writtenDestinations marks argument positions that a program only writes.
func writtenDestinations(program string, args []string) map[int]bool {
	written := map[int]bool{}
	switch program {
	case "cp", "mv", "install", "ln":
		for _, arg := range args {
			if copyTargetDirectoryOption(program, arg) {
				// The destination is the option value; every operand is a source.
				return written
			}
		}
		for index := len(args) - 1; index >= 0; index-- {
			if !strings.HasPrefix(args[index], "-") {
				written[index] = true
				break
			}
		}
	case "tee":
		for index, arg := range args {
			if !strings.HasPrefix(arg, "-") {
				written[index] = true
			}
		}
	}
	return written
}

// copyValueOptions are the short options of cp, mv, ln and install (other
// than -t) whose value is the rest of the cluster or the next word.
var copyValueOptions = map[string]string{"cp": "S", "mv": "S", "ln": "S", "install": "gmoS"}

// copyTargetDirectoryOption reports -t, alone or inside a cluster before any
// option that takes a value (-rt, -vt, -Dt, -t/tmp/d), and every abbreviation
// of --target-directory that getopt accepts (--t, --target, --target-dir=x).
func copyTargetDirectoryOption(program, arg string) bool {
	if strings.HasPrefix(arg, "--") {
		name, _, _ := strings.Cut(arg, "=")
		return len(name) > len("--") && strings.HasPrefix("--target-directory", name)
	}
	if !strings.HasPrefix(arg, "-") {
		return false
	}
	for _, option := range arg[1:] {
		if option == 't' {
			return true
		}
		if strings.ContainsRune(copyValueOptions[program], option) {
			return false // the rest of the cluster is that option's value
		}
	}
	return false
}

// shellWrappers run their argument as the program.
var shellWrappers = map[string]bool{
	"sudo": true, "env": true, "command": true, "builtin": true, "exec": true, "nohup": true,
	"time": true, "nice": true, "timeout": true, "stdbuf": true, "xargs": true,
}

// gitCredentialDump finds "git [global options] credential fill" and a git
// credential helper's "get" action, both of which print stored secrets. The
// git program is looked for both after the exact wrapper parse
// (commandStart, which knows "sudo -u root") and after skipping every
// keyword, wrapper, option and number, so neither parse can hide it.
func gitCredentialDump(words []string) (string, bool) {
	if dump, ok := gitCredentialDumpAt(words, commandStart(words)); ok {
		return dump, true
	}
	index := 0
	for index < len(words) {
		word := words[index]
		base := strings.ToLower(filepath.Base(word))
		switch {
		case isShellAssignment(word), shellKeywords[word], shellWrappers[base], strings.HasPrefix(word, "-"), isShellNumber(word):
			index++
			continue
		}
		break
	}
	return gitCredentialDumpAt(words, index)
}

func gitCredentialDumpAt(words []string, index int) (string, bool) {
	if index >= len(words) {
		return "", false
	}
	program := strings.ToLower(filepath.Base(words[index]))
	rest := words[index+1:]
	if strings.HasPrefix(program, "git-credential-") {
		if firstShellOperand(rest) == "get" {
			return strings.Join(words[index:], " "), true
		}
		return "", false
	}
	if program != "git" {
		return "", false
	}
	for len(rest) > 0 {
		word := rest[0]
		if word == "-c" || word == "-C" || word == "--git-dir" || word == "--work-tree" || word == "--namespace" || word == "--exec-path" {
			if len(rest) < 2 {
				return "", false
			}
			rest = rest[2:]
			continue
		}
		if strings.HasPrefix(word, "-") {
			rest = rest[1:]
			continue
		}
		break
	}
	if len(rest) == 0 {
		return "", false
	}
	subcommand := strings.ToLower(rest[0])
	action := firstShellOperand(rest[1:])
	if (subcommand == "credential" && action == "fill") ||
		(strings.HasPrefix(subcommand, "credential-") && action == "get") {
		return strings.Join(words[index:], " "), true
	}
	return "", false
}

func firstShellOperand(words []string) string {
	for _, word := range words {
		if !strings.HasPrefix(word, "-") {
			return strings.ToLower(word)
		}
	}
	return ""
}

// isShellNumber matches a file descriptor or a duration such as "5" or "2.5s".
func isShellNumber(word string) bool {
	digits := 0
	for _, r := range strings.TrimRight(word, "smhd") {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r != '.':
			return false
		}
	}
	return digits > 0
}

// compoundOpeners start, and compoundClosers end, a compound command whose
// output is the output of every command between them.
var (
	compoundOpeners = map[string]bool{"{": true, "if": true, "while": true, "until": true, "for": true, "case": true, "select": true}
	compoundClosers = map[string]bool{"}": true, "fi": true, "done": true, "esac": true}
)

// closeCompoundCommands tracks the compound commands opened or closed by the
// keywords at the start of the last command of out. When a closer's output
// is piped or handed to a substitution ("{ ls ~/.ssh/id_rsa; } | xargs
// cat"), every command of the group is marked as piping out. open holds the
// index in out of each pending opener and is returned updated.
func closeCompoundCommands(out []shellSimpleCommand, open []int) []int {
	last := len(out) - 1
	for _, word := range out[last].Words {
		switch {
		case compoundOpeners[word]:
			open = append(open, last)
		case compoundClosers[word]:
			if len(open) == 0 {
				continue
			}
			first := open[len(open)-1]
			open = open[:len(open)-1]
			if out[last].PipesOut || out[last].Substitution {
				for index := first; index < last; index++ {
					out[index].PipesOut = true
				}
			}
		case shellKeywords[word]:
		default:
			return open
		}
	}
	return open
}

// splitShellSimpleCommands splits a command line into simple commands at
// ";", newline, "&", "&&", "||", "|", "|&" and subshell or substitution
// parentheses, honoring quotes ($'...' with its escapes, $"..."), backslash
// escapes and, as bash does, keeping $((...)), $[...], ((...)) and ${...}
// whole inside a word (a "<<" in them is no here-document). "\r" is an
// ordinary character, as in bash. Redirection targets are kept apart from
// words; fd duplications ("2>&1") are dropped. A "#" that starts a word begins
// a comment up to the end of the line. Here-document bodies (after the line
// that opens them, up to the delimiter line) and here-strings are kept on the
// command they feed instead of being parsed as commands; a body whose
// delimiter line never comes is kept and the rest of the text is parsed as
// commands too. Parsing is deliberately permissive: unknown syntax still
// yields words, so a protected path cannot hide behind it.
func splitShellSimpleCommands(command string) []shellSimpleCommand {
	return splitShellSimpleCommandsWork(command, nil)
}

// splitShellSimpleCommandsWork is splitShellSimpleCommands counting its
// work (the text, the lookahead scans) on work.
func splitShellSimpleCommandsWork(command string, work *shellWork) []shellSimpleCommand {
	work.add(len(command))
	if len(command) > maxDestructiveCommandBytes {
		command = command[:maxDestructiveCommandBytes]
	}
	var (
		out      []shellSimpleCommand
		current  shellSimpleCommand
		word     strings.Builder
		hasWord  bool
		quote    byte
		redirect string // "", "in", "out", "drop"
		// parens: one entry per open "(", true for a substitution whose
		// output the enclosing command consumes.
		parens   []bool
		backtick bool
		// compound: index in out of each open { / if / loop / case.
		compound []int
		pipeIn   bool
		// wordQuoted: the current word holds a quote or an escape (a quoted
		// here-document delimiter stops expansion in the body).
		wordQuoted   bool
		heredocStrip bool
		pending      []pendingHeredoc
	)
	captured := func() bool {
		if backtick {
			return true
		}
		for _, capture := range parens {
			if capture {
				return true
			}
		}
		return false
	}
	flushWord := func() {
		if !hasWord {
			return
		}
		value := word.String()
		quoted := wordQuoted
		word.Reset()
		hasWord, wordQuoted = false, false
		switch redirect {
		case "in":
			current.InputRedirects = append(current.InputRedirects, value)
		case "out":
			current.OutputRedirects = append(current.OutputRedirects, value)
		case "heredoc":
			pending = append(pending, pendingHeredoc{delim: value, stripTabs: heredocStrip, quoted: quoted, owner: len(out)})
		case "herestring":
			current.Heredocs = append(current.Heredocs, shellHeredoc{Body: value, Expands: true})
		case "dupout", "dupin":
			// >&N / <&N duplicate a descriptor; anything else (>&file, a
			// substitution) names a file or is only known after expansion.
			if !isDescriptorWord(value) {
				if redirect == "dupin" {
					current.InputRedirects = append(current.InputRedirects, value)
				} else {
					current.OutputRedirects = append(current.OutputRedirects, value)
				}
			}
		case "drop":
		default:
			current.Words = append(current.Words, value)
		}
		redirect = ""
	}
	flushCommand := func(pipesOut bool) {
		flushWord()
		redirect = ""
		if len(current.Words) > 0 || len(current.InputRedirects) > 0 || len(current.OutputRedirects) > 0 || len(current.Heredocs) > 0 {
			current.Captured = captured()
			current.PipesOut = pipesOut || current.Captured
			current.PipesIn = pipeIn
			pipeIn = false
			out = append(out, current)
			compound = closeCompoundCommands(out, compound)
		}
		if pipesOut {
			// The next command, group or subshell reads the pipe.
			pipeIn = true
		}
		current = shellSimpleCommand{}
	}
	markSubstitution := func() { current.Substitution = true }
	// consumeHeredocs reads the bodies of the pending here-documents from
	// pos (the start of the line after the one that opened them) and returns
	// the position after the last delimiter line.
	consumeHeredocs := func(pos int) int {
		for _, doc := range pending {
			bodyStart, body, found, closedParen := pos, "", false, false
			for pos < len(command) {
				line, next := command[pos:], len(command)
				if end := strings.IndexByte(line, '\n'); end >= 0 {
					line, next = line[:end], pos+end+1
				}
				check := line
				if doc.stripTabs {
					check = strings.TrimLeft(line, "\t")
				}
				if check == doc.delim {
					body, found, pos = command[bodyStart:pos], true, next
					break
				}
				if captured() && strings.HasPrefix(check, doc.delim+")") {
					// bash 5.3: inside $(...) "EOF)" ends the body and the ")"
					// closes the substitution.
					body, found, closedParen = command[bodyStart:pos], true, true
					pos += len(line) - len(check) + len(doc.delim)
					break
				}
				pos = next
			}
			if !found {
				body = command[bodyStart:]
			}
			heredoc := shellHeredoc{Body: body, Expands: !doc.quoted, Terminated: found, Delimiter: doc.delim, StripTabs: doc.stripTabs}
			if doc.owner < len(out) {
				out[doc.owner].Heredocs = append(out[doc.owner].Heredocs, heredoc)
			} else {
				out = append(out, shellSimpleCommand{Heredocs: []shellHeredoc{heredoc}})
			}
			if !found {
				// No delimiter line: the text is judged as the body and,
				// strictly, also parsed as commands.
				pending = pending[:0]
				return bodyStart
			}
			if closedParen {
				break
			}
		}
		pending = pending[:0]
		return pos
	}
	// A scan for the end of $(...), $((...)), ${...}, $[...] or `...` cannot
	// succeed past the last ")", "}", "]" or "`" of the text: those openers are
	// left as text without scanning (scanning from each of 20000 unclosed
	// "$(" cost the square of the length).
	lastParen, lastBrace := strings.LastIndexByte(command, ')'), strings.LastIndexByte(command, '}')
	lastBracket, lastTick := strings.LastIndexByte(command, ']'), strings.LastIndexByte(command, '`')
	closesAfter := func(open int, last int) bool { return (work == nil || !work.noLookahead) && open < last }
	// literal copies a $((...)) / $[...] / ${...} / ((...)) span into the word.
	literal := func(start, end int) int {
		text := command[start:end]
		if strings.Contains(text, "$(") || strings.Contains(text, "`") {
			markSubstitution()
		}
		word.WriteString(text)
		hasWord = true
		return end - 1
	}
	for i := 0; i < len(command); i++ {
		ch := command[i]
		if quote == 'A' {
			// $'...': backslash escapes are decoded as bash does.
			switch {
			case ch == '\'':
				quote = 0
			case ch == '\\' && i+1 < len(command):
				decoded, width := decodeANSICEscape(command[i+1:])
				word.WriteString(decoded)
				i += width
			default:
				word.WriteByte(ch)
			}
			continue
		}
		if quote == '\'' {
			if ch == '\'' {
				quote = 0
			} else {
				word.WriteByte(ch)
			}
			continue
		}
		if ch == '\\' && i+1 < len(command) {
			next := command[i+1]
			if quote == 0 && backtick && next == '`' {
				// \` inside `...` opens or closes a nested substitution.
				markSubstitution()
				current.SplitSubstitution = true
				flushCommand(false)
				i++
				continue
			}
			if quote == '"' && !strings.ContainsRune("\"\\$`\n", rune(next)) {
				word.WriteByte(ch)
				hasWord = true
				continue
			}
			i++
			if next != '\n' {
				word.WriteByte(next)
				hasWord, wordQuoted = true, true
			}
			continue
		}
		if quote == '"' {
			if ch == '"' {
				quote = 0
				continue
			}
			if ch == '$' && i+1 < len(command) && command[i+1] == '(' {
				// "$(...)" starts a new quoting context, as in bash: copy
				// the whole substitution (inner quotes, here-documents)
				// into the word.
				markSubstitution()
				if closesAfter(i+1, lastParen) {
					if end, ok := substitutionSpanEnd(command, i+1, work); ok {
						word.WriteString(command[i:end])
						i = end - 1
						continue
					}
				}
			}
			if ch == '`' {
				// "`...`": keep the substitution text as written (its \`
				// marks a nested substitution).
				markSubstitution()
				end := i + 1
				if !closesAfter(i, lastTick) || work.over() {
					end = len(command)
				}
				for end < len(command) && command[end] != '`' {
					if command[end] == '\\' {
						end++
					}
					end++
				}
				if end < len(command) {
					word.WriteString(command[i : end+1])
					i = end
					continue
				}
			}
			word.WriteByte(ch)
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
			hasWord, wordQuoted = true, true
		case ' ', '\t':
			flushWord()
		case '\n', ';':
			flushCommand(false)
			if ch == '\n' && len(pending) > 0 {
				i = consumeHeredocs(i+1) - 1
			}
		case '`':
			markSubstitution()
			current.SplitSubstitution = true
			flushCommand(false)
			backtick = !backtick
		case '$':
			if i+1 < len(command) {
				switch command[i+1] {
				case '\'':
					quote, hasWord, wordQuoted = 'A', true, true
					i++
					continue
				case '"':
					hasWord = true
					continue // $"..." is "..." translated
				case '(':
					if !closesAfter(i+1, lastParen) {
						break
					}
					if end, ok := shellArithmeticEnd(command, i+1, work); ok {
						i = literal(i, end)
						continue
					}
				case '[', '{':
					last := lastBracket
					if command[i+1] == '{' {
						last = lastBrace
					}
					if !closesAfter(i+1, last) {
						break
					}
					if end, ok := shellBracketEnd(command, i+1, work); ok {
						i = literal(i, end)
						continue
					}
				}
			}
			word.WriteByte(ch)
			hasWord = true
		case '(':
			if !hasWord && closesAfter(i, lastParen) {
				if end, ok := shellArithmeticEnd(command, i, work); ok {
					i = literal(i, end)
					continue
				}
			}
			substitution := strings.HasSuffix(word.String(), "$")
			if substitution {
				trimmed := strings.TrimSuffix(word.String(), "$")
				word.Reset()
				word.WriteString(trimmed)
				hasWord = trimmed != ""
				markSubstitution()
				current.SplitSubstitution = true
			}
			flushCommand(false)
			parens = append(parens, substitution)
		case ')':
			flushCommand(false)
			if len(parens) > 0 {
				parens = parens[:len(parens)-1]
			}
		case '|':
			if i+1 < len(command) && command[i+1] == '|' {
				i++
				flushCommand(false)
			} else {
				if i+1 < len(command) && command[i+1] == '&' {
					i++
				}
				flushCommand(true)
			}
		case '&':
			if i+1 < len(command) && command[i+1] == '>' {
				flushWord()
				i++
				if i+1 < len(command) && command[i+1] == '>' {
					i++
				}
				redirect = "out"
				continue
			}
			if i+1 < len(command) && command[i+1] == '&' {
				i++
			}
			flushCommand(false)
		case '<', '>':
			if hasWord && isShellNumber(word.String()) && !strings.ContainsAny(word.String(), ".smhd") {
				word.Reset()
				hasWord = false
			}
			if i+1 < len(command) && command[i+1] == '(' {
				// Process substitution <(...) / >(...): its own commands.
				markSubstitution()
				current.SplitSubstitution = true
				flushCommand(false)
				i++
				parens = append(parens, true)
				continue
			}
			flushWord()
			kind := "out"
			if ch == '<' {
				kind = "in"
			}
			// Consume the rest of the operator: >>, >|, >&, <<, <<-, <<<, <&, <>.
			less, dash := 1, false
			for i+1 < len(command) && strings.ContainsRune("<>|&-", rune(command[i+1])) {
				i++
				switch command[i] {
				case '&':
					kind = "dup"
				case '<':
					if ch == '<' {
						less++
						kind = "heredoc"
					}
				case '-':
					dash = dash || (kind == "heredoc" && less == 2)
				}
			}
			switch {
			case kind == "heredoc" && less >= 3:
				redirect = "herestring"
			case kind == "heredoc":
				if delim, quoted, next, ok := readHeredocDelimiter(command, i+1); ok && (delim != "" || quoted) {
					pending = append(pending, pendingHeredoc{delim: delim, stripTabs: dash, quoted: quoted, owner: len(out)})
					i = next - 1
				} else {
					// No word on this line, or an unclosed quote: the next
					// word is taken as the delimiter.
					redirect, heredocStrip = "heredoc", dash
				}
			case kind == "dup" && ch == '<':
				redirect = "dupin"
			case kind == "dup":
				redirect = "dupout"
			default:
				redirect = kind
			}
			if kind == "heredoc" || (ch == '<' && kind == "dup") {
				current.StdinFeed = true
			}
		case '#':
			if !hasWord {
				// A comment runs to the end of the line; the newline still
				// ends the command. Inside `...` it also ends at the closing
				// backquote: the shell cuts the substitution text out first.
				for i+1 < len(command) && command[i+1] != '\n' && !(backtick && command[i+1] == '`') {
					i++
				}
				continue
			}
			word.WriteByte(ch)
		default:
			word.WriteByte(ch)
			hasWord = true
		}
	}
	flushCommand(false)
	return out
}

// shellArithmeticEnd returns the index after the "))" that closes the "((" at
// open, as bash reads $((...)) and ((...)). When the parentheses do not close
// with "))" bash parses nested subshells instead, and so does the caller.
func shellArithmeticEnd(command string, open int, work *shellWork) (int, bool) {
	if work.over() {
		return 0, false
	}
	end, closed := shellArithmeticEndScan(command, open, work)
	work.scanned(command, open, end, closed)
	return end, closed
}

func shellArithmeticEndScan(command string, open int, work *shellWork) (int, bool) {
	if open+1 >= len(command) || command[open] != '(' || command[open+1] != '(' {
		return 0, false
	}
	depth := 0
	for j := open; j < len(command); j++ {
		switch c := command[j]; c {
		case '\\':
			j++
		case '\'', '"':
			end := strings.IndexByte(command[j+1:], c)
			if end < 0 {
				return 0, false
			}
			j += end + 1
		case '(':
			depth++
		case ')':
			depth--
			if depth == 1 {
				if j+1 < len(command) && command[j+1] == ')' {
					return j + 2, true
				}
				return 0, false
			}
		}
	}
	return 0, false
}

// shellBracketEnd returns the index after the bracket that closes the "[" or
// "{" at open ($[...], ${...}), skipping quotes. As in bash, only a nested
// "${" opens another level inside ${...} (a plain "{" does not: ${x:-{}
// ends at the first "}"), and a $(...) inside is skipped whole.
func shellBracketEnd(command string, open int, work *shellWork) (int, bool) {
	if work.over() {
		return 0, false
	}
	end, closed := shellBracketEndScan(command, open, work)
	work.scanned(command, open, end, closed)
	return end, closed
}

func shellBracketEndScan(command string, open int, work *shellWork) (int, bool) {
	opening := command[open]
	closing := byte(']')
	if opening == '{' {
		closing = '}'
	}
	depth := 0
	for j := open; j < len(command); j++ {
		switch c := command[j]; {
		case c == '\\':
			j++
		case c == '\'' || c == '"':
			end := strings.IndexByte(command[j+1:], c)
			if end < 0 {
				return 0, false
			}
			j += end + 1
		case c == '$' && j+1 < len(command) && command[j+1] == '(' && opening == '{':
			end, ok := shellParenEndScan(command, j+1, work)
			if !ok {
				return 0, false
			}
			j = end - 1
		case c == opening && (opening == '[' || j == open || command[j-1] == '$'):
			depth++
		case c == closing:
			depth--
			if depth == 0 {
				return j + 1, true
			}
		}
	}
	return 0, false
}

// shellParenEnd returns the index after the ")" that closes the "(" at open,
// skipping quotes and nested parentheses.
func shellParenEnd(command string, open int, work *shellWork) (int, bool) {
	if work.over() {
		return 0, false
	}
	end, closed := shellParenEndScan(command, open, work)
	work.scanned(command, open, end, closed)
	return end, closed
}

func shellParenEndScan(command string, open int, work *shellWork) (int, bool) {
	depth := 0
	for j := open; j < len(command); j++ {
		switch c := command[j]; c {
		case '\\':
			j++
		case '\'', '"':
			end := strings.IndexByte(command[j+1:], c)
			if end < 0 {
				return 0, false
			}
			j += end + 1
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return j + 1, true
			}
		}
	}
	return 0, false
}

// decodeANSICEscape decodes the escape after a backslash inside $'...' and
// returns the text and how many bytes after the backslash it used.
func decodeANSICEscape(s string) (string, int) {
	if s == "" {
		return "\\", 0
	}
	hexDigits := func(from, max int) (int, int) {
		value, n := 0, 0
		for n < max && from+n < len(s) {
			digit := strings.IndexByte("0123456789abcdef", s[from+n]|0x20)
			if digit < 0 {
				break
			}
			value, n = value*16+digit, n+1
		}
		return value, n
	}
	switch c := s[0]; c {
	case 'n':
		return "\n", 1
	case 't':
		return "\t", 1
	case 'r':
		return "\r", 1
	case 'a':
		return "\a", 1
	case 'b':
		return "\b", 1
	case 'f':
		return "\f", 1
	case 'v':
		return "\v", 1
	case 'e', 'E':
		return "\x1b", 1
	case '\\', '\'', '"', '?':
		return string(c), 1
	case 'x':
		value, n := hexDigits(1, 2)
		if n == 0 {
			return "\\x", 1
		}
		return string([]byte{byte(value)}), 1 + n
	case 'u', 'U':
		max := 4
		if c == 'U' {
			max = 8
		}
		value, n := hexDigits(1, max)
		if n == 0 {
			return "\\" + string(c), 1
		}
		return string(rune(value)), 1 + n
	case 'c':
		// \cX is control-X; before the closing quote (or the end) bash keeps
		// "\c" as it is: $'\c' is the two characters \ and c.
		if len(s) > 1 && s[1] != '\'' {
			return string([]byte{s[1] & 0x1f}), 2
		}
		return "\\c", 1
	}
	if s[0] >= '0' && s[0] <= '7' {
		value, n := 0, 0
		for n < 3 && n < len(s) && s[n] >= '0' && s[n] <= '7' {
			value, n = value*8+int(s[n]-'0'), n+1
		}
		return string([]byte{byte(value)}), n
	}
	return "\\" + string(s[0]), 1
}

// isDescriptorWord: a file descriptor number, "N-" (move) or "-" (close).
func isDescriptorWord(value string) bool {
	trimmed := strings.TrimSuffix(value, "-")
	return trimmed == "" || isDecimalDigits(trimmed)
}

// shellKeywordAt reports the reserved word at text[j:] ending at a blank, an
// operator character or the end.
func shellKeywordAt(text string, j int, word string) bool {
	end := j + len(word)
	return strings.HasPrefix(text[j:], word) && (end == len(text) || strings.IndexByte(" \t\n;|&()<>", text[end]) >= 0)
}

// readHeredocDelimiter reads the delimiter word of a here-document that
// starts at k (after "<<" or "<<-"), as the shell does: blanks before it are
// skipped, the word ends at a blank or an operator character, and quotes
// ('...', "...", $'...' with its escapes, $"...") and backslashes are removed.
// quoted reports any quoting (the body is then not expanded); next is the
// index after the word. ok is false only for an unclosed quote. Both the
// splitter and substitutionSpanEnd read delimiters with it.
func readHeredocDelimiter(command string, k int) (delim string, quoted bool, next int, ok bool) {
	for k < len(command) && (command[k] == ' ' || command[k] == '\t') {
		k++
	}
	var b strings.Builder
	for k < len(command) {
		c := command[k]
		switch {
		case strings.IndexByte(" \t\n;|&()<>", c) >= 0:
			return b.String(), quoted, k, true
		case c == '\'':
			end := strings.IndexByte(command[k+1:], '\'')
			if end < 0 {
				return "", false, k, false
			}
			b.WriteString(command[k+1 : k+1+end])
			quoted, k = true, k+end+2
		case c == '$' && k+1 < len(command) && command[k+1] == '\'':
			j := k + 2
			for j < len(command) && command[j] != '\'' {
				if command[j] == '\\' && j+1 < len(command) {
					decoded, width := decodeANSICEscape(command[j+1:])
					b.WriteString(decoded)
					j += width + 1
					continue
				}
				b.WriteByte(command[j])
				j++
			}
			if j >= len(command) {
				return "", false, k, false
			}
			quoted, k = true, j+1
		case c == '"' || (c == '$' && k+1 < len(command) && command[k+1] == '"'):
			j := k + 1
			if c == '$' {
				j++
			}
			for j < len(command) && command[j] != '"' {
				if command[j] == '\\' && j+1 < len(command) && strings.IndexByte("\"\\$`\n", command[j+1]) >= 0 {
					if command[j+1] != '\n' {
						b.WriteByte(command[j+1])
					}
					j += 2
					continue
				}
				b.WriteByte(command[j])
				j++
			}
			if j >= len(command) {
				return "", false, k, false
			}
			quoted, k = true, j+1
		case c == '\\' && k+1 < len(command):
			if command[k+1] != '\n' {
				b.WriteByte(command[k+1])
				quoted = true
			}
			k += 2
		default:
			b.WriteByte(c)
			k++
		}
	}
	return b.String(), quoted, k, true
}

// substitutionSpanEnd returns the index after the ")" that closes the "$(" whose
// "(" is at open, reading the inside as bash does: quotes, nested
// parentheses, backquotes, comments and here-document bodies (whose quotes
// and parentheses are text). It returns false when the text ends first.
func substitutionSpanEnd(command string, open int, work *shellWork) (int, bool) {
	if work.over() {
		return 0, false
	}
	end, closed := substitutionSpanEndScan(command, open, work)
	work.scanned(command, open, end, closed)
	return end, closed
}

func substitutionSpanEndScan(command string, open int, work *shellWork) (int, bool) {
	type delimiter struct {
		word  string
		strip bool
	}
	var pending []delimiter
	depth := 0
	wordStart := true
	// cases: the depth of each open case statement; inPattern: a pattern of
	// the innermost one is being read, whose ")" (and optional "(") does not
	// nest ("$(case x in x) cat f;; esac)").
	var cases []int
	awaitIn, inPattern := false, false
	inCase := func() bool { return len(cases) > 0 && cases[len(cases)-1] == depth }
	for j := open; j < len(command); j++ {
		c := command[j]
		atWordStart := wordStart
		wordStart = strings.IndexByte(" \t\n;|&(", c) >= 0
		if atWordStart && c >= 'a' && c <= 'z' {
			switch {
			case shellKeywordAt(command, j, "case"):
				cases, awaitIn = append(cases, depth), true
				j += len("case") - 1
				continue
			case awaitIn && shellKeywordAt(command, j, "in"):
				awaitIn, inPattern = false, true
				j += len("in") - 1
				continue
			case inCase() && shellKeywordAt(command, j, "esac"):
				cases, inPattern = cases[:len(cases)-1], false
				j += len("esac") - 1
				continue
			}
		}
		switch c {
		case '\\':
			j++
		case '$':
			if j+1 < len(command) && command[j+1] == '\'' {
				// $'...': a backslash escapes the next character (\' included).
				k := j + 2
				for k < len(command) && command[k] != '\'' {
					if command[k] == '\\' {
						k++
					}
					k++
				}
				if k >= len(command) {
					return 0, false
				}
				j = k
			}
		case ';':
			if inCase() && j+1 < len(command) && (command[j+1] == ';' || command[j+1] == '&') {
				inPattern = true
				j++
				if j+1 < len(command) && command[j+1] == '&' {
					j++
				}
			}
		case '\'', '`':
			end := strings.IndexByte(command[j+1:], c)
			if end < 0 {
				return 0, false
			}
			j += end + 1
		case '"':
			for j++; j < len(command) && command[j] != '"'; j++ {
				if command[j] == '\\' {
					j++
				} else if command[j] == '$' && j+1 < len(command) && command[j+1] == '(' {
					end, ok := substitutionSpanEndScan(command, j+1, work)
					if !ok {
						return 0, false
					}
					j = end - 1
				}
			}
			if j >= len(command) {
				return 0, false
			}
		case '#':
			if atWordStart {
				for j+1 < len(command) && command[j+1] != '\n' {
					j++
				}
			}
		case '(':
			if inPattern && inCase() {
				continue // the optional "(" before a case pattern
			}
			depth++
		case ')':
			if inPattern && inCase() {
				inPattern = false // the end of a case pattern
				continue
			}
			depth--
			if depth == 0 {
				return j + 1, true
			}
		case '<':
			if j+2 < len(command) && command[j+1] == '<' && command[j+2] != '<' {
				k := j + 2
				strip := k < len(command) && command[k] == '-'
				if strip {
					k++
				}
				delim, _, next, ok := readHeredocDelimiter(command, k)
				if !ok {
					return 0, false
				}
				pending = append(pending, delimiter{word: delim, strip: strip})
				j = next - 1
			}
		case '\n':
			closed := false
			for _, doc := range pending {
				found := false
				for j+1 < len(command) {
					lineStart := j + 1
					lineEnd := strings.IndexByte(command[lineStart:], '\n')
					line := command[lineStart:]
					next := len(command)
					if lineEnd >= 0 {
						line, next = line[:lineEnd], lineStart+lineEnd
					}
					check := line
					if doc.strip {
						check = strings.TrimLeft(line, "\t")
					}
					if check == doc.word {
						j, found = next, true
						break
					}
					if strings.HasPrefix(check, doc.word+")") {
						// bash 5.3: "EOF)" ends the body; the ")" is read next.
						j = lineStart + len(line) - len(check) + len(doc.word) - 1
						found, closed = true, true
						break
					}
					j = next
					if lineEnd < 0 {
						break
					}
				}
				if !found {
					return 0, false
				}
				if closed {
					break
				}
			}
			pending = pending[:0]
			wordStart = !closed
		}
	}
	return 0, false
}
