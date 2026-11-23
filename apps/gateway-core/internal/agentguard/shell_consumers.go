package agentguard

// 安全数据消费者（复审第五轮）：管道下游、heredoc 读入方只有在这张“程序 + 选项”白名单里才算
// 只把输入当数据。程序前带环境变量赋值或包装（LESSOPEN=… less、env X=… less、nice …）、出现
// 列表外的选项（gawk -l、sort --compress-program、jq --rawfile …）、脚本不安全，都不算。
// less、more 不在表里：输出不是终端时等同 cat，还会照同一行更早 export 的 LESSOPEN 执行命令。

// consumerSpec is a safe consumer: the options it may take, whether it may
// name files of its own, and a check of its script.
type consumerSpec struct {
	options       optionTable
	stopAtOperand bool // options end at the first operand (awk)
	noOperands    bool // only "-" (standard input) may be an operand
	check         func(args []string, walk optionWalk) bool
}

// shortSkipValues marks the short options in names as taking a value that is
// not a file.
func shortSkipValues(names string) map[byte]shellArgRole {
	out := map[byte]shellArgRole{}
	for index := 0; index < len(names); index++ {
		out[names[index]] = shellArgSkip
	}
	return out
}

// longSkipValues marks the long options in names as taking a value that is
// not a file.
func longSkipValues(names ...string) map[string]shellArgRole {
	out := map[string]shellArgRole{}
	for _, name := range names {
		out[name] = shellArgSkip
	}
	return out
}

var (
	grepConsumer = consumerSpec{options: optionTable{
		shortFlags: "ivncowxEFGPhHqslLa", shortValues: shortSkipValues("mABCe"), digits: true,
		longFlags: flagSet("--color", "--colour", "--ignore-case", "--invert-match", "--line-number", "--count",
			"--only-matching", "--word-regexp", "--line-regexp", "--extended-regexp", "--fixed-strings",
			"--basic-regexp", "--perl-regexp", "--no-filename", "--with-filename", "--quiet", "--silent",
			"--files-with-matches", "--files-without-match", "--text", "--line-buffered", "--null"),
		longValues: longSkipValues("--max-count", "--after-context", "--before-context", "--context", "--regexp"),
	}}
	awkConsumer = consumerSpec{options: optionTable{shortValues: shortSkipValues("Fv"),
		longValues: longSkipValues("--field-separator", "--assign")}, stopAtOperand: true,
		check: func(args []string, _ optionWalk) bool {
			for _, arg := range args {
				if awkUnsafeProgram.MatchString(arg) {
					return false
				}
			}
			return true
		}}
	jqConsumer = consumerSpec{options: optionTable{
		shortFlags: "rcejsSnaMC",
		longFlags: flagSet("--raw-output", "--compact-output", "--exit-status", "--join-output", "--slurp",
			"--sort-keys", "--null-input", "--ascii-output", "--monochrome-output", "--color-output", "--tab"),
		longValues: longSkipValues("--indent"),
	}, check: safeExpressions}
	yqConsumer = consumerSpec{options: optionTable{
		shortFlags: "rePnCMN", shortValues: shortSkipValues("oI"),
		longFlags: flagSet("--exit-status", "--prettyPrint", "--null-input", "--colors", "--no-colors",
			"--no-doc", "--unwrapScalar"),
		longValues: longSkipValues("--output-format", "--indent"),
	}, check: safeExpressions}
)

// safeExpressions: no jq/yq argument loads files or names its inputs.
func safeExpressions(args []string, _ optionWalk) bool {
	for _, arg := range args {
		if jqUnsafeFilter.MatchString(arg) {
			return false
		}
	}
	return true
}

var safeConsumers = map[string]consumerSpec{
	"grep": grepConsumer, "egrep": grepConsumer, "fgrep": grepConsumer,
	"rg": {options: optionTable{
		shortFlags: "ivncowxFsSlqNH", shortValues: shortSkipValues("mABCe"),
		longFlags: flagSet("--color", "--no-heading", "--heading", "--line-number", "--no-line-number", "--count",
			"--only-matching", "--word-regexp", "--line-regexp", "--fixed-strings", "--ignore-case", "--smart-case",
			"--case-sensitive", "--invert-match", "--quiet", "--files-with-matches", "--no-filename", "--with-filename"),
		longValues: longSkipValues("--max-count", "--after-context", "--before-context", "--context", "--regexp"),
	}},
	"head": {options: optionTable{shortFlags: "qv", shortValues: shortSkipValues("nc"), digits: true,
		longFlags: flagSet("--quiet", "--silent", "--verbose"), longValues: longSkipValues("--lines", "--bytes")}},
	"tail": {options: optionTable{shortFlags: "qvfF", shortValues: shortSkipValues("nc"), digits: true,
		longFlags: flagSet("--quiet", "--silent", "--verbose", "--follow"), longValues: longSkipValues("--lines", "--bytes")}},
	"wc": {options: optionTable{shortFlags: "lwcmL",
		longFlags: flagSet("--lines", "--words", "--bytes", "--chars", "--max-line-length")}},
	"sort": {options: optionTable{shortFlags: "rnuhVfbs", shortValues: shortSkipValues("ktS"),
		longFlags: flagSet("--reverse", "--numeric-sort", "--unique", "--human-numeric-sort", "--version-sort",
			"--ignore-case", "--ignore-leading-blanks", "--stable"),
		longValues: longSkipValues("--key", "--field-separator", "--buffer-size")}, noOperands: true},
	"uniq": {options: optionTable{shortFlags: "cdui", shortValues: shortSkipValues("fsw"),
		longFlags:  flagSet("--count", "--repeated", "--unique", "--ignore-case"),
		longValues: longSkipValues("--skip-fields", "--skip-chars", "--check-chars")}, noOperands: true},
	"cut": {options: optionTable{shortFlags: "s", shortValues: shortSkipValues("dfcb"),
		longFlags:  flagSet("--only-delimited", "--complement"),
		longValues: longSkipValues("--delimiter", "--fields", "--characters", "--bytes", "--output-delimiter")}},
	"tr":     {options: optionTable{shortFlags: "dscC"}},
	"column": {options: optionTable{shortFlags: "tx", shortValues: shortSkipValues("sc")}},
	"nl":     {options: optionTable{shortValues: shortSkipValues("bnwsv")}},
	"fold":   {options: optionTable{shortFlags: "bs", shortValues: shortSkipValues("w")}},
	"cat":    {options: optionTable{shortFlags: "nAbeEsTtv"}, noOperands: true},
	"tee":    {options: optionTable{shortFlags: "ai"}},
	"base64": {options: optionTable{shortFlags: "di", shortValues: shortSkipValues("w"),
		longFlags: flagSet("--decode", "--ignore-garbage"), longValues: longSkipValues("--wrap")}},
	"xxd": {options: optionTable{shortFlags: "pu", shortValues: shortSkipValues("cgls")}},
	"od":  {options: optionTable{shortFlags: "bcdoxv", shortValues: shortSkipValues("AtwNj")}},
	"jq":  jqConsumer,
	"yq":  yqConsumer,
	"awk": awkConsumer, "gawk": awkConsumer, "mawk": awkConsumer,
	"sed": {options: optionTable{shortFlags: "nEr", shortValues: shortSkipValues("e"),
		longFlags: flagSet("--quiet", "--silent", "--regexp-extended"), longValues: longSkipValues("--expression")},
		check: func(args []string, walk optionWalk) bool {
			scripts := walk.valuesOf("-e", "--expression")
			if len(scripts) == 0 && len(walk.operands) > 0 {
				scripts = walk.operands[:1]
			}
			for _, at := range scripts {
				if !sedScriptSafe(args[at][walk.offsets[at]:]) {
					return false
				}
			}
			return true
		}},
	"diff": {options: optionTable{shortFlags: "uqiwbBNyc", shortValues: shortSkipValues("U")}},
	"comm": {options: optionTable{shortFlags: "123"}, noOperands: true},
}

// isSafeConsumer reports a command that only reads its input as data: a
// safe consumer run directly (no assignment, wrapper or variable before it)
// with listed options only and a safe script.
func isSafeConsumer(simple shellSimpleCommand) bool {
	words := simple.Words
	start := commandStart(words)
	for _, word := range words[:start] {
		if !shellKeywords[word] {
			return false
		}
	}
	program, args := trustedProgramAt(words, start), words[min(start+1, len(words)):]
	spec, ok := safeConsumers[program]
	if !ok {
		return false
	}
	walk, ok := walkOptions(spec.options, args, spec.stopAtOperand)
	if !ok {
		return false
	}
	if spec.noOperands {
		for _, at := range walk.operands {
			if args[at] != "-" {
				return false
			}
		}
	}
	return spec.check == nil || spec.check(args, walk)
}
