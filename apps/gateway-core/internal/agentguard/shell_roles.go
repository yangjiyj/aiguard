package agentguard

import (
	"regexp"
	"strings"
)

// 按程序理解参数角色（设计第 6 节）。每个处理函数只认它列出的选项；遇到不认识的选项、
// 缺值或解析不了的写法返回 false，整条命令回到 2.9.21 的整词判定。

// shellNested is a command that runs elsewhere and is judged by its own parse:
// a command line (ssh remote command, sh -c string) or a command vector
// (kubectl exec -- cmd ...). at is the argument holding it.
type shellNested struct {
	at   int
	text string
	argv []string
}

// shellCommandRoles is what a program handler knows about its arguments:
// the role of each position (absent = read), where an attached option value
// starts inside its word, and the nested commands.
type shellCommandRoles struct {
	roles   map[int]shellArgRole
	offsets map[int]int
	nested  []shellNested
	// printed: positions whose text the program prints as it is (an awk,
	// jq, yq or sed program, a template or format string, jq --arg values,
	// a replacement, a pattern printed by -o). When the output lands in a
	// regular file they are judged as reads.
	printed map[int]bool
}

func (roles *shellCommandRoles) markPrinted(positions ...int) {
	if roles.printed == nil {
		roles.printed = map[int]bool{}
	}
	for _, at := range positions {
		roles.printed[at] = true
	}
}

func newShellCommandRoles() shellCommandRoles {
	return shellCommandRoles{roles: map[int]shellArgRole{}, offsets: map[int]int{}}
}

type shellRoleHandler func(args []string) (shellCommandRoles, bool)

var shellRoleHandlers = map[string]shellRoleHandler{
	"pip": fetchURLRoles("pip"), "pip3": fetchURLRoles("pip3"), "npm": fetchURLRoles("npm"),
	"pnpm": fetchURLRoles("pnpm"), "yarn": fetchURLRoles("yarn"), "go": fetchURLRoles("go"),
	"helm": fetchURLRoles("helm"), "docker": dockerRoles,
	"echo": echoRoles, "printf": printfRoles,
	"sed": sedRoles,
	"awk": awkRoles, "gawk": awkRoles, "mawk": awkRoles, "nawk": awkRoles,
	"jq": jqRoles, "yq": yqRoles,
	"grep": grepRoles, "egrep": grepRoles, "fgrep": grepRoles, "rg": rgRoles,
	"curl": curlRoles, "wget": wgetRoles,
	"git":     gitRoles,
	"kubectl": kubectlRoles, "oc": kubectlRoles,
	"ssh": sshRemoteRoles,
	"sh":  shellCommandStringRoles, "bash": shellCommandStringRoles, "zsh": shellCommandStringRoles,
	"dash": shellCommandStringRoles, "ksh": shellCommandStringRoles, "mksh": shellCommandStringRoles, "ash": shellCommandStringRoles,
}

// optionTable describes the options of a program with GNU-style parsing.
type optionTable struct {
	shortFlags    string                  // short options without a value
	shortOptional string                  // short options whose value can only be attached (sed -i.bak)
	shortValues   map[byte]shellArgRole   // short options with a value, and its role
	longFlags     map[string]bool         // long options without a value ("--color=auto" accepted)
	longValues    map[string]shellArgRole // long options with a value, and its role
	// optionalValues: the role of a value attached to a shortOptional option
	// ("-d" in gawk -dFILE) or to a long flag ("--dump-variables" in
	// --dump-variables=FILE); without an entry the attached value is ignored.
	optionalValues map[string]shellArgRole
	digits         bool // -NUM is an option (grep -5)
}

// optionWalk is the result of walking options: roles of option words and
// values, operand positions in order, and the positions of each option's values.
type optionWalk struct {
	shellCommandRoles
	operands []int
	seen     map[string]bool
	values   map[string][]int
}

// walkOptions parses args with getopt rules. Options may follow operands
// unless stopAtOperand (POSIX awk); "--" ends options. It returns false on an
// unknown option or a missing value.
func walkOptions(table optionTable, args []string, stopAtOperand bool) (optionWalk, bool) {
	walk := optionWalk{shellCommandRoles: newShellCommandRoles(), seen: map[string]bool{}, values: map[string][]int{}}
	value := func(name string, at, offset int, role shellArgRole) {
		walk.seen[name] = true
		walk.roles[at] = role
		if offset > 0 {
			walk.offsets[at] = offset
		}
		walk.values[name] = append(walk.values[name], at)
	}
	for index := 0; index < len(args); index++ {
		word := args[index]
		switch {
		case word == "--":
			walk.roles[index] = shellArgSkip
			for rest := index + 1; rest < len(args); rest++ {
				walk.operands = append(walk.operands, rest)
			}
			return walk, true
		case strings.HasPrefix(word, "--"):
			name, _, attached := strings.Cut(word, "=")
			if role, ok := table.longValues[name]; ok {
				if attached {
					value(name, index, len(name)+1, role)
					continue
				}
				if index+1 >= len(args) {
					return walk, false
				}
				walk.roles[index] = shellArgSkip
				index++
				value(name, index, 0, role)
				continue
			}
			if !table.longFlags[name] {
				return walk, false
			}
			walk.seen[name] = true
			walk.roles[index] = shellArgSkip
			if role, ok := table.optionalValues[name]; ok && attached {
				value(name, index, len(name)+1, role)
			}
		case len(word) > 1 && word[0] == '-':
			walk.roles[index] = shellArgSkip
			if table.digits && isDecimalDigits(word[1:]) {
				continue
			}
			for pos := 1; pos < len(word); pos++ {
				option := word[pos]
				name := "-" + string(option)
				if strings.IndexByte(table.shortFlags, option) >= 0 {
					walk.seen[name] = true
					continue
				}
				if strings.IndexByte(table.shortOptional, option) >= 0 {
					walk.seen[name] = true
					if role, ok := table.optionalValues[name]; ok && pos+1 < len(word) {
						value(name, index, pos+1, role)
					}
					break
				}
				role, ok := table.shortValues[option]
				if !ok {
					return walk, false
				}
				if pos+1 < len(word) {
					value(name, index, pos+1, role)
					break
				}
				if index+1 >= len(args) {
					return walk, false
				}
				index++
				value(name, index, 0, role)
				break
			}
		default:
			walk.operands = append(walk.operands, index)
			if stopAtOperand {
				for rest := index + 1; rest < len(args); rest++ {
					walk.operands = append(walk.operands, rest)
				}
				return walk, true
			}
		}
	}
	return walk, true
}

func (walk optionWalk) valuesOf(names ...string) []int {
	var out []int
	for _, name := range names {
		out = append(out, walk.values[name]...)
	}
	return out
}

func (walk optionWalk) seenAny(names ...string) bool {
	for _, name := range names {
		if walk.seen[name] {
			return true
		}
	}
	return false
}

func flagSet(names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, name := range names {
		out[name] = true
	}
	return out
}

// echo and printf print their arguments; no argument is opened. printf -v
// assigns a variable that a later word may read, so it is not handled.
func echoRoles(args []string) (shellCommandRoles, bool) {
	roles := newShellCommandRoles()
	for index := range args {
		roles.roles[index] = shellArgSkip
		roles.markPrinted(index)
	}
	return roles, true
}

func printfRoles(args []string) (shellCommandRoles, bool) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-v") {
			return shellCommandRoles{}, false
		}
	}
	return echoRoles(args)
}

var sedOptions = optionTable{
	shortFlags:    "nErsuzb",
	shortOptional: "i",
	shortValues:   map[byte]shellArgRole{'e': shellArgSkip, 'f': shellArgRead, 'l': shellArgSkip},
	longFlags: flagSet("--quiet", "--silent", "--regexp-extended", "--separate", "--unbuffered", "--null-data",
		"--zero-terminated", "--posix", "--debug", "--sandbox", "--follow-symlinks", "--binary", "--help", "--version", "--in-place"),
	longValues: map[string]shellArgRole{"--expression": shellArgSkip, "--file": shellArgRead, "--line-length": shellArgSkip},
}

// sed: the script is not a file unless it reads, writes or runs one (r, R,
// w, W, e, s///e, s///w); the other operands are files read.
func sedRoles(args []string) (shellCommandRoles, bool) {
	walk, ok := walkOptions(sedOptions, args, false)
	if !ok {
		return shellCommandRoles{}, false
	}
	scripts := walk.valuesOf("-e", "--expression")
	operands := walk.operands
	if len(scripts) == 0 && !walk.seenAny("-f", "--file") && len(operands) > 0 {
		scripts, operands = operands[:1], operands[1:]
	}
	for _, at := range scripts {
		walk.roles[at] = shellArgRead
		if sedScriptSafe(args[at][walk.offsets[at]:]) {
			walk.roles[at] = shellArgSkip
		}
		walk.markPrinted(at)
	}
	for _, at := range operands {
		walk.roles[at] = shellArgRead
	}
	return walk.shellCommandRoles, true
}

// sedScriptSafe parses a sed script and accepts it only when no command
// reads, writes or runs a file: r, R, w, W, e, v, the e and w flags of s, and
// anything it cannot parse are rejected.
func sedScriptSafe(script string) bool {
	i, n := 0, len(script)
	blanks := func() {
		for i < n && (script[i] == ' ' || script[i] == '\t') {
			i++
		}
	}
	digits := func() {
		for i < n && script[i] >= '0' && script[i] <= '9' {
			i++
		}
	}
	// delimited reads up to the unescaped delimiter (i is after the opening one).
	delimited := func(delim byte) bool {
		for i < n {
			c := script[i]
			switch {
			case c == '\\':
				i += 2
			case c == delim:
				i++
				return true
			case c == '\n':
				return false
			default:
				i++
			}
		}
		return false
	}
	address := func() bool {
		switch {
		case i < n && script[i] >= '0' && script[i] <= '9':
			digits()
			if i < n && script[i] == '~' {
				i++
				digits()
			}
		case i < n && script[i] == '$':
			i++
		case i < n && script[i] == '/':
			i++
			if !delimited('/') {
				return false
			}
			for i < n && (script[i] == 'I' || script[i] == 'M') {
				i++
			}
		case i+1 < n && script[i] == '\\':
			delim := script[i+1]
			i += 2
			if !delimited(delim) {
				return false
			}
			for i < n && (script[i] == 'I' || script[i] == 'M') {
				i++
			}
		}
		return true
	}
	toLineEnd := func() {
		for i < n && script[i] != '\n' {
			if script[i] == '\\' {
				i++
			}
			i++
		}
	}
	for {
		for i < n && strings.IndexByte(" \t\n;", script[i]) >= 0 {
			i++
		}
		if i >= n {
			return true
		}
		if !address() {
			return false
		}
		blanks()
		if i < n && script[i] == ',' {
			i++
			blanks()
			if i < n && (script[i] == '+' || script[i] == '~') {
				i++
				digits()
			} else if !address() {
				return false
			}
		}
		blanks()
		for i < n && script[i] == '!' {
			i++
			blanks()
		}
		if i >= n {
			return false
		}
		command := script[i]
		i++
		switch command {
		case '{', '}', '=', 'd', 'D', 'g', 'G', 'h', 'H', 'n', 'N', 'p', 'P', 'x', 'z', 'F':
		case 'l', 'L', 'q', 'Q':
			blanks()
			digits()
		case 'b', 't', 'T', ':':
			for i < n && script[i] != ';' && script[i] != '\n' {
				i++
			}
		case '#', 'a', 'i', 'c':
			toLineEnd()
		case 's', 'y':
			if i >= n || script[i] == '\\' || script[i] == '\n' {
				return false
			}
			delim := script[i]
			i++
			if !delimited(delim) || !delimited(delim) {
				return false
			}
			for command == 's' && i < n {
				flag := script[i]
				if strings.IndexByte("gpiImM0123456789", flag) < 0 {
					break
				}
				i++
			}
		default:
			return false
		}
		blanks()
		if i < n && strings.IndexByte(";\n}#", script[i]) < 0 {
			return false
		}
	}
}

var awkOptions = optionTable{
	shortFlags:    "bcCghMnNOPrsStV",
	shortOptional: "dDLop",
	shortValues: map[byte]shellArgRole{
		'F': shellArgSkip, 'v': shellArgRead, 'f': shellArgRead, 'E': shellArgRead,
		'e': shellArgSkip, 'i': shellArgRead, 'l': shellArgSkip,
	},
	longFlags: flagSet("--posix", "--traditional", "--sandbox", "--re-interval", "--characters-as-bytes", "--bignum",
		"--non-decimal-data", "--optimize", "--no-optimize", "--use-lc-numeric", "--csv", "--lint", "--dump-variables",
		"--profile", "--pretty-print", "--debug", "--gen-pot", "--help", "--version", "--copyright"),
	longValues: map[string]shellArgRole{
		"--field-separator": shellArgSkip, "--assign": shellArgRead, "--file": shellArgRead, "--exec": shellArgRead,
		"--source": shellArgSkip, "--include": shellArgRead, "--load": shellArgSkip,
	},
	// gawk -d/-o/-p[FILE]、--dump-variables/--pretty-print/--profile[=FILE] 写文件；
	// -D/--debug[=FILE] 从文件读调试命令。
	optionalValues: map[string]shellArgRole{
		"-d": shellArgWrite, "-o": shellArgWrite, "-p": shellArgWrite, "-D": shellArgRead,
		"--dump-variables": shellArgWrite, "--pretty-print": shellArgWrite, "--profile": shellArgWrite,
		"--debug": shellArgRead,
	},
}

// awkUnsafeProgram: getline and system read files or run commands, "|" pipes
// to or from a command, ARGV/ARGC rewrite the input files, @include/@load
// read further files, and print > "file" / print > $0 writes one.
var awkUnsafeProgram = regexp.MustCompile(`getline|system|\||ARGV|ARGC|@|>\s*>?\s*"|(print|printf)\b[^;}\n]*>`)

// awk: the program text is not a file unless it opens one; -v values and
// the operands (files or var=value assignments) are judged as reads.
func awkRoles(args []string) (shellCommandRoles, bool) {
	walk, ok := walkOptions(awkOptions, args, true)
	if !ok {
		return shellCommandRoles{}, false
	}
	if walk.seenAny("-l", "--load") {
		// 扩展库（filefuncs 的 stat、readfile 的 readfile ……）能直接打开文件，程序文本不再
		// 只是数据：整条退回整词判定。
		return shellCommandRoles{}, false
	}
	programs := walk.valuesOf("-e", "--source")
	operands := walk.operands
	if len(programs) == 0 && !walk.seenAny("-f", "--file", "-E", "--exec") && len(operands) > 0 {
		programs, operands = operands[:1], operands[1:]
	}
	for _, at := range programs {
		walk.roles[at] = shellArgRead
		if !awkUnsafeProgram.MatchString(args[at][walk.offsets[at]:]) {
			walk.roles[at] = shellArgSkip
		}
		walk.markPrinted(at)
	}
	for _, at := range operands {
		walk.roles[at] = shellArgRead
	}
	return walk.shellCommandRoles, true
}

var jqLongFlags = flagSet("--null-input", "--raw-input", "--slurp", "--compact-output", "--tab", "--color-output",
	"--monochrome-output", "--ascii-output", "--unbuffered", "--sort-keys", "--raw-output", "--raw-output0",
	"--join-output", "--exit-status", "--seq", "--stream", "--stream-errors", "--help", "--version",
	"--build-configuration", "--nul-output")

// jq: the filter is not a file unless it imports modules; --arg/--argjson
// values are strings, --rawfile/--slurpfile/-f/-L files are read, and the
// other operands are input files (or $ARGS strings after --args).
func jqRoles(args []string) (shellCommandRoles, bool) {
	roles := newShellCommandRoles()
	var operands []int
	fromFile, positional := false, false
	need := func(index, count int) bool { return index+count < len(args) }
	for index := 0; index < len(args); index++ {
		word := args[index]
		switch {
		case word == "--":
			roles.roles[index] = shellArgSkip
			for rest := index + 1; rest < len(args); rest++ {
				operands = append(operands, rest)
			}
			index = len(args)
		case word == "--arg" || word == "--argjson":
			if !need(index, 2) {
				return shellCommandRoles{}, false
			}
			roles.roles[index], roles.roles[index+1], roles.roles[index+2] = shellArgSkip, shellArgSkip, shellArgSkip
			roles.markPrinted(index + 2)
			index += 2
		case word == "--rawfile" || word == "--slurpfile":
			if !need(index, 2) {
				return shellCommandRoles{}, false
			}
			roles.roles[index], roles.roles[index+1], roles.roles[index+2] = shellArgSkip, shellArgSkip, shellArgRead
			index += 2
		case word == "-f" || word == "--from-file" || word == "-L" || word == "--library-path":
			if !need(index, 1) {
				return shellCommandRoles{}, false
			}
			fromFile = fromFile || word == "-f" || word == "--from-file"
			roles.roles[index], roles.roles[index+1] = shellArgSkip, shellArgRead
			index++
		case word == "--indent":
			if !need(index, 1) {
				return shellCommandRoles{}, false
			}
			roles.roles[index], roles.roles[index+1] = shellArgSkip, shellArgSkip
			index++
		case word == "--args" || word == "--jsonargs":
			positional = true
			roles.roles[index] = shellArgSkip
		case jqLongFlags[word]:
			roles.roles[index] = shellArgSkip
		case strings.HasPrefix(word, "-L") && len(word) > 2:
			roles.roles[index], roles.offsets[index] = shellArgRead, 2
		case len(word) > 1 && word[0] == '-':
			if strings.Trim(word[1:], "nrjacCMSesRhV0") != "" || strings.HasPrefix(word, "--") {
				return shellCommandRoles{}, false
			}
			roles.roles[index] = shellArgSkip
		default:
			operands = append(operands, index)
		}
	}
	if !fromFile && len(operands) > 0 {
		filter := operands[0]
		roles.roles[filter] = shellArgSkip
		if jqUnsafeFilter.MatchString(args[filter]) {
			roles.roles[filter] = shellArgRead
		}
		roles.markPrinted(filter)
		operands = operands[1:]
	}
	for _, at := range operands {
		if positional {
			roles.roles[at] = shellArgSkip
			roles.markPrinted(at)
		} else {
			roles.roles[at] = shellArgRead
		}
	}
	return roles, true
}

var yqOptions = optionTable{
	shortFlags: "inCMPNr0vVhyYjce",
	shortValues: map[byte]shellArgRole{
		'o': shellArgSkip, 'p': shellArgSkip, 'I': shellArgSkip,
	},
	longFlags: flagSet("--inplace", "--null-input", "--exit-status", "--colors", "--no-colors", "--prettyPrint",
		"--no-doc", "--unwrapScalar", "--nul-output", "--verbose", "--version", "--help", "--yaml-output",
		"--yaml-roundtrip", "--tojson", "--compact-output", "--header-preprocess"),
	longValues: map[string]shellArgRole{
		"--output-format": shellArgSkip, "--input-format": shellArgSkip, "--indent": shellArgSkip,
		"--front-matter": shellArgSkip, "--expression": shellArgSkip, "--from-file": shellArgRead,
		"--split-exp": shellArgSkip, "--xml-attribute-prefix": shellArgSkip, "--xml-content-name": shellArgSkip,
	},
}

// yq: the expression is not a file unless it loads one (load, load_str ...);
// the other operands are input files. "-s" means a split expression in one
// yq and slurp in the other, so it is not handled.
func yqRoles(args []string) (shellCommandRoles, bool) {
	start := 0
	if len(args) > 0 {
		switch args[0] {
		case "eval", "e", "eval-all", "ea":
			start = 1
		}
	}
	for _, arg := range args[start:] {
		if arg == "-s" || (len(arg) > 1 && arg[0] == '-' && arg[1] != '-' && strings.Contains(arg, "=") && !strings.HasPrefix(arg, "-r=")) {
			return shellCommandRoles{}, false
		}
	}
	cleaned := make([]string, len(args)-start)
	for index, arg := range args[start:] {
		cleaned[index] = arg
		if arg == "-r=false" || arg == "-r=true" {
			cleaned[index] = "-r"
		}
	}
	walk, ok := walkOptions(yqOptions, cleaned, false)
	if !ok {
		return shellCommandRoles{}, false
	}
	roles := newShellCommandRoles()
	if start == 1 {
		roles.roles[0] = shellArgSkip
	}
	for at, role := range walk.roles {
		roles.roles[at+start] = role
	}
	for at, offset := range walk.offsets {
		roles.offsets[at+start] = offset
	}
	expressions := walk.valuesOf("--expression")
	operands := walk.operands
	if len(expressions) == 0 && !walk.seen["--from-file"] && len(operands) > 0 {
		expressions, operands = operands[:1], operands[1:]
	}
	for _, at := range expressions {
		roles.roles[at+start] = shellArgSkip
		if jqUnsafeFilter.MatchString(args[at+start]) {
			roles.roles[at+start] = shellArgRead
		}
		roles.markPrinted(at + start)
	}
	for _, at := range operands {
		roles.roles[at+start] = shellArgRead
	}
	return roles, true
}

var grepOptions = optionTable{
	shortFlags: "EFGPiywvcLloqsbHhnTZzaIrRUuxV",
	shortValues: map[byte]shellArgRole{
		'e': shellArgSkip, 'f': shellArgRead, 'm': shellArgSkip, 'A': shellArgSkip, 'B': shellArgSkip,
		'C': shellArgSkip, 'd': shellArgSkip, 'D': shellArgSkip,
	},
	digits: true,
	longFlags: flagSet("--extended-regexp", "--fixed-strings", "--basic-regexp", "--perl-regexp", "--ignore-case",
		"--no-ignore-case", "--word-regexp", "--line-regexp", "--null-data", "--no-messages", "--invert-match",
		"--version", "--help", "--count", "--color", "--colour", "--files-without-match", "--files-with-matches",
		"--only-matching", "--quiet", "--silent", "--byte-offset", "--with-filename", "--no-filename",
		"--line-number", "--line-buffered", "--initial-tab", "--unix-byte-offsets", "--null", "--text",
		"--recursive", "--dereference-recursive", "--binary", "--no-group-separator"),
	longValues: map[string]shellArgRole{
		"--regexp": shellArgSkip, "--file": shellArgRead, "--max-count": shellArgSkip, "--after-context": shellArgSkip,
		"--before-context": shellArgSkip, "--context": shellArgSkip, "--label": shellArgSkip, "--binary-files": shellArgSkip,
		"--devices": shellArgSkip, "--directories": shellArgSkip, "--exclude-from": shellArgRead,
		"--group-separator": shellArgSkip,
		// 选文件的通配：按文件目标判定（--include=.env 读的就是 .env）。
		"--include": shellArgRead, "--exclude": shellArgRead, "--exclude-dir": shellArgRead,
	},
}

// grep: patterns are not files; -f files, the --include/--exclude globs and
// the operands after the pattern are read.
func grepRoles(args []string) (shellCommandRoles, bool) {
	return searchRoles(grepOptions, args, false)
}

var rgOptions = optionTable{
	shortFlags: "0abcFHhIiLlNnoPpqSsUuVvwxz",
	shortValues: map[byte]shellArgRole{
		'A': shellArgSkip, 'B': shellArgSkip, 'C': shellArgSkip, 'd': shellArgSkip, 'E': shellArgSkip,
		'e': shellArgSkip, 'f': shellArgRead, 'g': shellArgRead, 'j': shellArgSkip, 'M': shellArgSkip,
		'm': shellArgSkip, 'r': shellArgSkip, 't': shellArgSkip, 'T': shellArgSkip,
	},
	longFlags: flagSet("--text", "--byte-offset", "--count", "--count-matches", "--fixed-strings", "--with-filename",
		"--no-filename", "--ignore-case", "--follow", "--files-with-matches", "--files-without-match",
		"--no-line-number", "--line-number", "--only-matching", "--pretty", "--pcre2", "--quiet", "--case-sensitive",
		"--smart-case", "--multiline", "--multiline-dotall", "--unrestricted", "--invert-match", "--version",
		"--word-regexp", "--line-regexp", "--search-zip", "--null", "--null-data", "--hidden", "--no-hidden",
		"--no-ignore", "--no-ignore-vcs", "--no-ignore-dot", "--no-ignore-global", "--no-ignore-parent",
		"--no-ignore-exclude", "--no-ignore-files", "--no-ignore-messages", "--files", "--type-list", "--json",
		"--no-json", "--vimgrep", "--column", "--no-column", "--heading", "--no-heading", "--trim", "--no-trim",
		"--stats", "--no-messages", "--no-config", "--binary", "--no-binary", "--crlf", "--no-crlf",
		"--one-file-system", "--passthru", "--sort-files", "--line-buffered", "--block-buffered", "--mmap",
		"--no-mmap", "--debug", "--trace", "--help", "--max-columns-preview", "--no-unicode", "--unicode",
		"--auto-hybrid-regex", "--no-pcre2-unicode", "--glob-case-insensitive", "--no-require-git",
		"--stop-on-nonmatch", "--include-zero", "--no-include-zero", "--color", "--colour", "--invert-match"),
	longValues: map[string]shellArgRole{
		"--regexp": shellArgSkip, "--file": shellArgRead, "--after-context": shellArgSkip, "--before-context": shellArgSkip,
		"--context": shellArgSkip, "--max-depth": shellArgSkip, "--encoding": shellArgSkip,
		"--glob": shellArgRead, "--iglob": shellArgRead, "--threads": shellArgSkip, "--max-columns": shellArgSkip, "--max-count": shellArgSkip,
		"--replace": shellArgSkip, "--type": shellArgSkip, "--type-not": shellArgSkip, "--type-add": shellArgSkip,
		"--type-clear": shellArgSkip, "--colors": shellArgSkip, "--context-separator": shellArgSkip,
		"--field-context-separator": shellArgSkip, "--field-match-separator": shellArgSkip,
		"--path-separator": shellArgSkip, "--sort": shellArgSkip, "--sortr": shellArgSkip, "--ignore-file": shellArgRead,
		"--pre": shellArgRead, "--pre-glob": shellArgSkip, "--max-filesize": shellArgSkip, "--dfa-size-limit": shellArgSkip,
		"--regex-size-limit": shellArgSkip, "--engine": shellArgSkip, "--hostname-bin": shellArgRead,
		"--hyperlink-format": shellArgSkip, "--generate": shellArgSkip,
	},
}

// rg: like grep (-g/--glob/--iglob globs are read); with --files or
// --type-list there is no pattern.
func rgRoles(args []string) (shellCommandRoles, bool) {
	return searchRoles(rgOptions, args, true)
}

func searchRoles(table optionTable, args []string, ripgrep bool) (shellCommandRoles, bool) {
	walk, ok := walkOptions(table, args, false)
	if !ok {
		return shellCommandRoles{}, false
	}
	operands := walk.operands
	noPattern := ripgrep && walk.seenAny("--files", "--type-list")
	onlyMatching := walk.seenAny("-o", "--only-matching")
	if !noPattern && !walk.seenAny("-e", "--regexp", "-f", "--file") && len(operands) > 0 {
		walk.roles[operands[0]] = shellArgSkip
		if onlyMatching {
			walk.markPrinted(operands[0])
		}
		operands = operands[1:]
	}
	if onlyMatching {
		walk.markPrinted(walk.valuesOf("-e", "--regexp")...)
	}
	if ripgrep {
		walk.markPrinted(walk.valuesOf("-r", "--replace")...)
	}
	for _, at := range operands {
		walk.roles[at] = shellArgRead
	}
	return walk.shellCommandRoles, true
}

// curl option value kinds.
const (
	curlData      = "data"      // -d: inline unless @file
	curlEncode    = "urlencode" // --data-urlencode: name@file / @file read
	curlForm      = "form"      // -F: name=@file / name=<file read
	curlAtFile    = "at"        // -H, -w: @file read
	curlCookie    = "cookie"    // -b: a file unless it holds "="
	curlFileRead  = "read"
	curlFileWrite = "write"
	curlText      = "skip"
	curlURL       = "url"
)

var curlShortOptions = map[byte]string{
	'd': curlData, 'F': curlForm, 'H': curlAtFile, 'T': curlFileRead, 'o': curlFileWrite, 'X': curlText,
	'u': curlText, 'A': curlText, 'e': curlText, 'x': curlText, 'm': curlText, 'w': curlAtFile, 'b': curlCookie,
	'c': curlFileWrite, 'K': curlFileRead, 'E': curlFileRead, 'C': curlText, 'r': curlText, 'U': curlText,
	'Y': curlText, 'y': curlText, 'z': curlText, 't': curlText, 'Q': curlText, 'D': curlFileWrite, 'P': curlText,
}

const curlShortFlags = "sSLkviIfGNOJRnlgq0123456BjMpZa#V:"

var curlLongOptions = map[string]string{
	"--data": curlData, "--data-ascii": curlData, "--data-binary": curlData, "--json": curlData,
	"--data-raw": curlText, "--form-string": curlText, "--data-urlencode": curlEncode, "--url-query": curlEncode,
	"--variable": curlEncode, "--form": curlForm, "--header": curlAtFile, "--proxy-header": curlAtFile,
	"--write-out": curlAtFile, "--cookie": curlCookie,
	"--upload-file": curlFileRead, "--config": curlFileRead, "--cert": curlFileRead, "--key": curlFileRead,
	"--cacert": curlFileRead, "--capath": curlFileRead, "--unix-socket": curlFileRead,
	"--abstract-unix-socket": curlFileRead, "--netrc-file": curlFileRead, "--proxy-cacert": curlFileRead,
	"--proxy-cert": curlFileRead, "--proxy-key": curlFileRead, "--crlfile": curlFileRead, "--hsts": curlFileRead,
	"--alt-svc": curlFileRead, "--etag-compare": curlFileRead,
	"--output": curlFileWrite, "--cookie-jar": curlFileWrite, "--dump-header": curlFileWrite, "--trace": curlFileWrite,
	"--trace-ascii": curlFileWrite, "--stderr": curlFileWrite, "--etag-save": curlFileWrite, "--libcurl": curlFileWrite,
	"--url":  curlURL,
	"--user": curlText, "--request": curlText, "--user-agent": curlText, "--referer": curlText, "--proxy": curlText,
	"--max-time": curlText, "--connect-timeout": curlText, "--retry": curlText, "--retry-delay": curlText,
	"--retry-max-time": curlText, "--resolve": curlText, "--connect-to": curlText, "--limit-rate": curlText,
	"--max-filesize": curlText, "--interface": curlText, "--dns-servers": curlText, "--oauth2-bearer": curlText,
	"--aws-sigv4": curlText, "--proxy-user": curlText, "--noproxy": curlText, "--ciphers": curlText,
	"--tls-max": curlText, "--cert-type": curlText, "--key-type": curlText, "--pass": curlText,
	"--output-dir": curlText, "--range": curlText, "--continue-at": curlText, "--max-redirs": curlText,
	"--expect100-timeout": curlText, "--keepalive-time": curlText, "--mail-from": curlText, "--mail-rcpt": curlText,
	"--request-target": curlText, "--socks5": curlText, "--socks5-hostname": curlText, "--preproxy": curlText,
	"--time-cond": curlText, "--quote": curlText, "--ftp-port": curlText, "--telnet-option": curlText,
	"--local-port": curlText, "--happy-eyeballs-timeout-ms": curlText, "--rate": curlText, "--parallel-max": curlText,
	"--speed-limit": curlText, "--speed-time": curlText, "--proto": curlText, "--proto-redir": curlText,
	"--http2-prior-knowledge": "", "--compressed": "", "--insecure": "", "--location": "", "--silent": "",
	"--show-error": "", "--fail": "", "--fail-with-body": "", "--include": "", "--head": "", "--verbose": "",
	"--http1.0": "", "--http1.1": "", "--http2": "", "--http3": "", "--get": "", "--globoff": "",
	"--remote-name": "", "--remote-name-all": "", "--remote-header-name": "", "--netrc": "", "--netrc-optional": "",
	"--progress-bar": "", "--raw": "", "--tcp-nodelay": "", "--path-as-is": "", "--ssl": "", "--ssl-reqd": "",
	"--tlsv1": "", "--tlsv1.0": "", "--tlsv1.1": "", "--tlsv1.2": "", "--tlsv1.3": "", "--ipv4": "", "--ipv6": "",
	"--create-dirs": "", "--location-trusted": "", "--retry-all-errors": "", "--retry-connrefused": "",
	"--parallel": "", "--next": "", "--anyauth": "", "--basic": "", "--digest": "", "--ntlm": "", "--negotiate": "",
	"--disable": "", "--append": "", "--crlf": "", "--list-only": "", "--styled-output": "", "--suppress-connect-headers": "",
	"--write-out-json": "", "--help": "", "--version": "", "--manual": "", "--trace-time": "", "--junk-session-cookies": "",
	"--post301": "", "--post302": "", "--post303": "", "--ftp-pasv": "", "--ftp-create-dirs": "", "--remove-on-error": "",
}

// curlValueRole returns the role of an option value and where the file name
// starts inside it.
func curlValueRole(kind, value string) (shellArgRole, int) {
	switch kind {
	case curlData, curlAtFile:
		if strings.HasPrefix(value, "@") && value != "@-" {
			return shellArgRead, 1
		}
		return shellArgSkip, 0
	case curlEncode:
		at, eq := strings.IndexByte(value, '@'), strings.IndexByte(value, '=')
		if at >= 0 && (eq < 0 || at < eq) {
			return shellArgRead, at + 1
		}
		return shellArgSkip, 0
	case curlForm:
		for _, marker := range []string{"=@", "=<"} {
			if at := strings.Index(value, marker); at >= 0 {
				return shellArgRead, at + 2
			}
		}
		return shellArgSkip, 0
	case curlCookie:
		if strings.Contains(value, "=") {
			return shellArgSkip, 0
		}
		return shellArgRead, 0
	case curlFileRead:
		return shellArgRead, 0
	case curlFileWrite:
		return shellArgWrite, 0
	case curlURL:
		return curlOperandRole(value), 0
	}
	return shellArgSkip, 0
}

// curlOperandRole: an operand is a URL; only file:// opens a local file.
func curlOperandRole(value string) shellArgRole {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "file:") {
		return shellArgRead
	}
	return shellArgSkip
}

// curl: URLs, inline data and headers are not files; @file data, uploads,
// form files, configs, certificates and sockets are read.
func curlRoles(args []string) (shellCommandRoles, bool) {
	roles := newShellCommandRoles()
	set := func(at int, kind, value string, offset int) {
		role, inner := curlValueRole(kind, value)
		roles.roles[at] = role
		if role != shellArgSkip && offset+inner > 0 {
			roles.offsets[at] = offset + inner
		}
	}
	for index := 0; index < len(args); index++ {
		word := args[index]
		switch {
		case word == "--":
			for rest := index + 1; rest < len(args); rest++ {
				roles.roles[rest] = curlOperandRole(args[rest])
			}
			return roles, true
		case strings.HasPrefix(word, "--"):
			name, attached, hasValue := strings.Cut(word, "=")
			kind, known := curlLongOptions[name]
			if !known && !strings.HasPrefix(name, "--no-") {
				return shellCommandRoles{}, false
			}
			roles.roles[index] = shellArgSkip
			if kind == "" {
				continue
			}
			if hasValue {
				set(index, kind, attached, len(name)+1)
				continue
			}
			if index+1 >= len(args) {
				return shellCommandRoles{}, false
			}
			index++
			set(index, kind, args[index], 0)
		case len(word) > 1 && word[0] == '-':
			roles.roles[index] = shellArgSkip
			for pos := 1; pos < len(word); pos++ {
				option := word[pos]
				if strings.IndexByte(curlShortFlags, option) >= 0 {
					continue
				}
				kind, ok := curlShortOptions[option]
				if !ok {
					return shellCommandRoles{}, false
				}
				if pos+1 < len(word) {
					set(index, kind, word[pos+1:], pos+1)
				} else if index+1 < len(args) {
					index++
					set(index, kind, args[index], 0)
				} else {
					return shellCommandRoles{}, false
				}
				break
			}
		default:
			roles.roles[index] = curlOperandRole(word)
		}
	}
	return roles, true
}

var wgetOptions = optionTable{
	shortFlags: "qvcrNkpmSbxEKFHL46hV",
	shortValues: map[byte]shellArgRole{
		'O': shellArgWrite, 'o': shellArgWrite, 'a': shellArgWrite, 'i': shellArgRead, 'P': shellArgSkip,
		't': shellArgSkip, 'T': shellArgSkip, 'w': shellArgSkip, 'Q': shellArgSkip, 'U': shellArgSkip,
		'e': shellArgRead, 'B': shellArgSkip, 'l': shellArgSkip, 'A': shellArgSkip, 'R': shellArgSkip,
		'D': shellArgSkip, 'X': shellArgSkip, 'I': shellArgSkip, 'n': shellArgSkip,
	},
	longFlags: flagSet("--quiet", "--verbose", "--no-verbose", "--continue", "--recursive", "--mirror", "--spider",
		"--no-check-certificate", "--server-response", "--background", "--force-directories", "--no-directories",
		"--no-host-directories", "--no-parent", "--span-hosts", "--timestamping", "--page-requisites",
		"--convert-links", "--content-disposition", "--trust-server-names", "--inet4-only", "--inet6-only",
		"--no-clobber", "--show-progress", "--progress", "--no-cache", "--no-cookies", "--keep-session-cookies",
		"--ignore-length", "--auth-no-challenge", "--https-only", "--adjust-extension", "--backup-converted",
		"--relative", "--follow-ftp", "--delete-after", "--no-proxy", "--help", "--version", "--debug",
		"--retry-connrefused", "--no-dns-cache", "--no-hsts", "--compression"),
	longValues: map[string]shellArgRole{
		"--post-file": shellArgRead, "--body-file": shellArgRead, "--input-file": shellArgRead,
		"--load-cookies": shellArgRead, "--certificate": shellArgRead, "--private-key": shellArgRead,
		"--ca-certificate": shellArgRead, "--config": shellArgRead, "--execute": shellArgRead,
		"--output-document": shellArgWrite, "--output-file": shellArgWrite, "--append-output": shellArgWrite,
		"--save-cookies": shellArgWrite,
		"--post-data":    shellArgSkip, "--body-data": shellArgSkip, "--header": shellArgSkip, "--user": shellArgSkip,
		"--password": shellArgSkip, "--http-user": shellArgSkip, "--http-password": shellArgSkip,
		"--method": shellArgSkip, "--user-agent": shellArgSkip, "--timeout": shellArgSkip, "--tries": shellArgSkip,
		"--directory-prefix": shellArgSkip, "--referer": shellArgSkip, "--level": shellArgSkip,
		"--accept": shellArgSkip, "--reject": shellArgSkip, "--domains": shellArgSkip, "--wait": shellArgSkip,
		"--limit-rate": shellArgSkip, "--quota": shellArgSkip, "--connect-timeout": shellArgSkip,
		"--read-timeout": shellArgSkip, "--dns-timeout": shellArgSkip, "--waitretry": shellArgSkip,
	},
}

// wget: operands are URLs (wget has no file://); --post-file, -i and the like
// are read.
func wgetRoles(args []string) (shellCommandRoles, bool) {
	walk, ok := walkOptions(wgetOptions, args, false)
	if !ok {
		return shellCommandRoles{}, false
	}
	for _, at := range walk.operands {
		walk.roles[at] = shellArgSkip
	}
	return walk.shellCommandRoles, true
}

// sh -c / bash -c: the command string is parsed again (nested); words after
// it are $0, $1 ... and judged as reads. Without -c the script file is read.
func shellCommandStringRoles(args []string) (shellCommandRoles, bool) {
	roles := newShellCommandRoles()
	commandMode := false
	index := 0
options:
	for ; index < len(args); index++ {
		word := args[index]
		switch {
		case word == "--" || word == "-":
			roles.roles[index] = shellArgSkip
			index++
			break options
		case word == "--rcfile" || word == "--init-file":
			if index+1 >= len(args) {
				return shellCommandRoles{}, false
			}
			roles.roles[index], roles.roles[index+1] = shellArgSkip, shellArgRead
			index++
		case strings.HasPrefix(word, "--"):
			switch word {
			case "--norc", "--noprofile", "--login", "--posix", "--restricted", "--verbose", "--noediting",
				"--debugger", "--dump-strings", "--dump-po-strings", "--help", "--version", "--pretty-print":
				roles.roles[index] = shellArgSkip
			default:
				return shellCommandRoles{}, false
			}
		case len(word) > 1 && (word[0] == '-' || word[0] == '+'):
			roles.roles[index] = shellArgSkip
			takesValue := false
			for _, option := range word[1:] {
				switch {
				case option == 'c':
					commandMode = true
				case option == 'o' || option == 'O':
					takesValue = true
				case strings.ContainsRune("abefhiklmnprstuvxBCEHPT", option):
				default:
					return shellCommandRoles{}, false
				}
			}
			if takesValue {
				if index+1 >= len(args) {
					return shellCommandRoles{}, false
				}
				index++
				roles.roles[index] = shellArgSkip
			}
		default:
			break options
		}
	}
	if commandMode && index < len(args) {
		roles.roles[index] = shellArgSkip
		roles.nested = append(roles.nested, shellNested{at: index, text: args[index]})
	}
	return roles, true
}

// sshLocateOptions are ssh's options for finding the destination and the
// remote command; -F/-I are allowed here (their values are judged as reads).
var sshLocateOptions = func() shortOptionTable {
	table := sshTransportOptions["ssh"]
	table.denied = ""
	return table
}()

// ssh: the remote command (every word after the destination and the options
// ssh parses after it) is parsed again as the remote shell does: the words
// joined with spaces. Option values are judged as reads (-E as a write); the
// key that -i names is handled by sshKeyUseArguments.
func sshRemoteRoles(args []string) (shellCommandRoles, bool) {
	roles := newShellCommandRoles()
	visit := func(offset int) func(option byte, value string, at int) bool {
		return func(option byte, _ string, at int) bool {
			if at >= 0 && option == 'E' {
				roles.roles[offset+at] = shellArgWrite
			}
			return true
		}
	}
	destination, ok := walkShortOptions(sshLocateOptions, args, visit(0))
	if !ok {
		return shellCommandRoles{}, false
	}
	if destination >= len(args) {
		return roles, true
	}
	rest := destination + 1
	next, ok := walkShortOptions(sshLocateOptions, args[rest:], visit(rest))
	if !ok {
		return shellCommandRoles{}, false
	}
	remote := rest + next
	if remote >= len(args) {
		return roles, true
	}
	for at := remote; at < len(args); at++ {
		roles.roles[at] = shellArgSkip
	}
	roles.nested = append(roles.nested, shellNested{at: remote, text: strings.Join(args[remote:], " ")})
	for at := remote + 1; at < len(args); at++ {
		roles.nested = append(roles.nested, shellNested{at: at, text: ""})
	}
	return roles, true
}
