package agentguard

import (
	"encoding/base64"
	"path"
	"strings"
	"unicode/utf16"
)

// 本文件是命令行层面的补漏：sudo、env 包装拆解，数据库命令行、云存储删除、rsync --delete，
// 写敏感路径的 tee、cp、install、sed -i 和 PowerShell Set-Content，以及 PowerShell 嵌套脚本。
// 级别只影响告警分级，处置由策略决定。

const maxCommandWrappers = 8

func commandBaseName(word string) string {
	return strings.TrimSuffix(strings.ToLower(path.Base(strings.ReplaceAll(word, `\`, "/"))), ".exe")
}

// destructiveCommandWords 去掉前面的 sudo、env（连同它们的选项、选项值和 NAME=值），返回真正执行的命令及参数；
// 包装后面没有命令（sudo -l、单独的 env）时返回 nil，不是包装命令时原样返回。
func destructiveCommandWords(words []string) []string {
	for range maxCommandWrappers {
		if len(words) == 0 {
			return nil
		}
		switch commandBaseName(words[0]) {
		case "sudo":
			words = unwrapSudo(words[1:])
		case "env":
			words = unwrapEnv(words[1:])
		default:
			return words
		}
	}
	return words
}

var sudoValueLongOptions = map[string]bool{
	"--user": true, "--group": true, "--host": true, "--prompt": true, "--role": true, "--type": true,
	"--close-from": true, "--chdir": true, "--other-user": true, "--command-timeout": true, "--chroot": true,
}

// unwrapSudo：sudo [选项] [NAME=值] 命令。-u、-g、-h、-p、-r、-t、-C、-D、-U、-T、-R 带值。
func unwrapSudo(args []string) []string {
	for index := 0; index < len(args); index++ {
		word := args[index]
		switch {
		case word == "--":
			return skipEnvAssignments(args[index+1:], true)
		case strings.HasPrefix(word, "--"):
			if name, _, hasValue := strings.Cut(word, "="); !hasValue && sudoValueLongOptions[name] {
				index++
			}
		case strings.HasPrefix(word, "-") && len(word) > 1:
			if shortClusterTakesNext(word, "ughprtCDUTR") {
				index++
			}
		case envAssignmentWord(word, true):
		default:
			return args[index:]
		}
	}
	return nil
}

// unwrapEnv：env [选项] [NAME=值] 命令。-u、-C、-P、-a 带值；-S 的值按空白拆开，放回原处继续解析。
func unwrapEnv(args []string) []string {
	args = append([]string(nil), args...)
	for index, expansions := 0, 0; index < len(args); index++ {
		word := args[index]
		split, hasSplit := "", false
		switch {
		case word == "--":
			return skipEnvAssignments(args[index+1:], false)
		case word == "-":
		case strings.HasPrefix(word, "--"):
			name, value, hasValue := strings.Cut(word, "=")
			switch name {
			case "--split-string":
				split, hasSplit = value, true
				if !hasValue && index+1 < len(args) {
					index++
					split = args[index]
				}
			case "--unset", "--chdir", "--argv0":
				if !hasValue {
					index++
				}
			}
		case strings.HasPrefix(word, "-") && len(word) > 1:
			for position := 1; position < len(word); position++ {
				letter := word[position]
				if letter == 'S' {
					split, hasSplit = word[position+1:], true
					if split == "" && index+1 < len(args) {
						index++
						split = args[index]
					}
					break
				}
				if strings.IndexByte("uCPa", letter) >= 0 {
					if position == len(word)-1 {
						index++
					}
					break
				}
			}
		case envAssignmentWord(word, false):
		default:
			return args[index:]
		}
		if hasSplit {
			expansions++
			if expansions > maxCommandWrappers {
				return nil
			}
			rest := append(strings.Fields(split), args[min(index+1, len(args)):]...)
			args, index = rest, -1
		}
	}
	return nil
}

// shortClusterTakesNext 判断短选项簇里第一个带值字母是否在簇尾（值是下一个词）。
func shortClusterTakesNext(word, valueLetters string) bool {
	for position := 1; position < len(word); position++ {
		if strings.IndexByte(valueLetters, word[position]) >= 0 {
			return position == len(word)-1
		}
	}
	return false
}

func envAssignmentWord(word string, strict bool) bool {
	name, _, ok := strings.Cut(word, "=")
	if !ok || name == "" {
		return false
	}
	if !strict {
		return true
	}
	for index, r := range name {
		if r != '_' && !(r < 128 && isASCIILetter(byte(r))) && (index == 0 || r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func skipEnvAssignments(words []string, strict bool) []string {
	for len(words) > 0 && envAssignmentWord(words[0], strict) {
		words = words[1:]
	}
	if len(words) == 0 {
		return nil
	}
	return words
}

// nestedScript 是命令里嵌套执行的脚本：sh -c、docker exec … sh -c、powershell -Command / -EncodedCommand。
type nestedScript struct {
	Script string
	// Lexical 表示脚本是 PowerShell，用词法兜底解析。
	Lexical bool
	// Encoded 表示脚本来自 -EncodedCommand：证据用外层这条命令，渲染时再解码。
	Encoded bool
}

func nestedShellScript(words []string) (nestedScript, bool) {
	words = destructiveCommandWords(words)
	if script, ok := literalShellScript(words); ok {
		return nestedScript{Script: script}, true
	}
	if nested, ok := powershellNestedScript(words); ok {
		return nested, true
	}
	if script, ok := literalDockerExecShellScript(words); ok {
		return nestedScript{Script: script}, true
	}
	return nestedScript{}, false
}

// powershellNestedScript 取 powershell/pwsh 的 -Command（其后所有词）或 -EncodedCommand（base64 的 UTF-16LE）脚本。
// 参数名可缩写（-c、-com、-e、-ec、-enc），也可写成 /enc、--command；遇到 -File 或位置参数就不是内联脚本。
func powershellNestedScript(words []string) (nestedScript, bool) {
	if len(words) < 3 {
		return nestedScript{}, false
	}
	switch commandBaseName(words[0]) {
	case "powershell", "pwsh":
	default:
		return nestedScript{}, false
	}
	for index := 1; index < len(words); index++ {
		word := words[index]
		if len(word) < 2 || word[0] != '-' && word[0] != '/' {
			return nestedScript{}, false
		}
		name, inline, hasInline := strings.Cut(strings.ToLower(strings.TrimLeft(word, "-/")), ":")
		switch {
		case name == "c" || powershellParameterIs(name, "command", 3):
			if index+1 >= len(words) || words[index+1] == "-" {
				return nestedScript{}, false
			}
			return nestedScript{Script: strings.Join(words[index+1:], " "), Lexical: true}, true
		case name == "e" || name == "ec" || powershellParameterIs(name, "encodedcommand", 2):
			value := inline
			if !hasInline {
				if index+1 >= len(words) {
					return nestedScript{}, false
				}
				value = words[index+1]
			}
			script, ok := decodePowerShellEncodedCommand(value)
			if !ok {
				return nestedScript{}, false
			}
			return nestedScript{Script: script, Lexical: true, Encoded: true}, true
		case name == "f" || powershellParameterIs(name, "file", 2):
			return nestedScript{}, false
		case hasInline:
		case name == "ep" || powershellParameterIs(name, "executionpolicy", 2) ||
			powershellParameterIs(name, "windowstyle", 1) || powershellParameterIs(name, "version", 1) ||
			name == "of" || powershellParameterIs(name, "outputformat", 1) ||
			name == "if" || powershellParameterIs(name, "inputformat", 2) ||
			name == "wd" || powershellParameterIs(name, "workingdirectory", 2) ||
			powershellParameterIs(name, "configurationname", 3) || powershellParameterIs(name, "psconsolefile", 3) ||
			powershellParameterIs(name, "settingsfile", 3) || powershellParameterIs(name, "custompipename", 3):
			index++
		}
	}
	return nestedScript{}, false
}

func powershellParameterIs(name, full string, minimum int) bool {
	return len(name) >= minimum && strings.HasPrefix(full, name)
}

func decodePowerShellEncodedCommand(value string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) < 2 || len(raw)%2 != 0 {
		return "", false
	}
	units := make([]uint16, 0, len(raw)/2)
	for index := 0; index+1 < len(raw); index += 2 {
		units = append(units, uint16(raw[index])|uint16(raw[index+1])<<8)
	}
	return string(utf16.Decode(units)), true
}

// cliOptionTable 描述一个命令的选项写法，用来把选项值和位置参数分开，避免把选项值当成目标。
type cliOptionTable struct {
	valueShort   string          // 带值的短选项字母：簇里剩下的部分或下一个词是值
	attachedOnly string          // 只取连写值的短选项字母（mysql -p口令）
	valueLong    map[string]bool // 带值的长选项：没有 = 时下一个词是值
	longDefault  bool            // 未列出的长选项也带值（rclone、az 的惯例）
	booleanLong  map[string]bool // longDefault 为真时仍不带值的长选项
}

type cliScanResult struct {
	operands []string
	options  map[string][]string // 选项名 → 值；短选项按字母拆成 -x，长选项小写、去掉 =值
}

func (table cliOptionTable) scan(args []string) cliScanResult {
	result := cliScanResult{options: map[string][]string{}}
	record := func(name, value string) { result.options[name] = append(result.options[name], value) }
	for index := 0; index < len(args); index++ {
		word := args[index]
		switch {
		case word == "--":
			result.operands = append(result.operands, args[index+1:]...)
			return result
		case strings.HasPrefix(word, "--"):
			name, value, hasValue := strings.Cut(word, "=")
			name = strings.ToLower(name)
			takesValue := table.valueLong[name] || table.longDefault && !table.booleanLong[name]
			if !hasValue && takesValue && index+1 < len(args) {
				index++
				value = args[index]
			}
			record(name, value)
		case strings.HasPrefix(word, "-") && len(word) > 1:
			for position := 1; position < len(word); position++ {
				letter := word[position]
				name, rest := "-"+string(letter), word[position+1:]
				if strings.IndexByte(table.attachedOnly, letter) >= 0 {
					record(name, rest)
					break
				}
				if strings.IndexByte(table.valueShort, letter) >= 0 {
					if rest == "" && index+1 < len(args) {
						index++
						rest = args[index]
					}
					record(name, rest)
					break
				}
				record(name, "")
			}
		default:
			result.operands = append(result.operands, word)
		}
	}
	return result
}

func (result cliScanResult) has(names ...string) bool {
	for _, name := range names {
		if _, ok := result.options[name]; ok {
			return true
		}
	}
	return false
}

func (result cliScanResult) values(names ...string) []string {
	var values []string
	for _, name := range names {
		for _, value := range result.options[name] {
			if value != "" {
				values = append(values, value)
			}
		}
	}
	return values
}

func longOptions(names ...string) map[string]bool {
	table := make(map[string]bool, len(names))
	for _, name := range names {
		table[name] = true
	}
	return table
}

var (
	mysqlCommandOptions = cliOptionTable{valueShort: "eDhPSuO", attachedOnly: "p", valueLong: longOptions(
		"--execute", "--database", "--host", "--port", "--socket", "--user", "--default-character-set", "--init-command",
		"--login-path", "--defaults-extra-file", "--delimiter", "--connect-timeout", "--max-allowed-packet",
		"--net-buffer-length", "--plugin-dir", "--protocol", "--bind-address", "--character-sets-dir", "--default-auth",
		"--server-public-key-path", "--ssl-ca", "--ssl-cert", "--ssl-key", "--ssl-mode", "--ssl-cipher", "--tls-version",
		"--tee", "--prompt")}
	psqlCommandOptions = cliOptionTable{valueShort: "cdfhpUvoLPTFR", valueLong: longOptions(
		"--command", "--dbname", "--file", "--host", "--port", "--username", "--set", "--variable", "--output",
		"--log-file", "--pset", "--table-attr", "--field-separator", "--record-separator")}
	dropdbCommandOptions     = cliOptionTable{valueShort: "hpU", valueLong: longOptions("--host", "--port", "--username", "--maintenance-db")}
	mysqladminCommandOptions = cliOptionTable{valueShort: "uhPScOi", attachedOnly: "p", valueLong: longOptions(
		"--user", "--host", "--port", "--socket", "--count", "--sleep", "--login-path", "--defaults-extra-file",
		"--connect-timeout", "--shutdown-timeout", "--protocol", "--bind-address", "--default-character-set")}
	redisCommandOptions = cliOptionTable{valueShort: "hpsaurindDX", valueLong: longOptions(
		"--user", "--pass", "--sni", "--cacert", "--cacertdir", "--tls-ciphers", "--tls-ciphersuites", "--cert", "--key",
		"--show-pushes", "--lru-test", "--rdb", "--functions-rdb", "--pipe-timeout", "--memkeys-samples", "--pattern",
		"--count", "--quoted-pattern", "--intrinsic-latency", "--eval", "--cluster")}
	awsCommandOptions = cliOptionTable{valueLong: longOptions(
		"--profile", "--region", "--endpoint-url", "--output", "--query", "--ca-bundle", "--cli-read-timeout",
		"--cli-connect-timeout", "--color", "--cli-binary-format", "--exclude", "--include", "--request-payer",
		"--expected-bucket-owner", "--page-size")}
	azCommandOptions = cliOptionTable{valueShort: "ncsfpgqtod", longDefault: true, booleanLong: longOptions(
		"--yes", "--debug", "--verbose", "--only-show-errors", "--dryrun", "--fail-not-exist", "--if-exists",
		"--recursive", "--help")}
	ossutilCommandOptions = cliOptionTable{valueShort: "ikectjL", valueLong: longOptions(
		"--access-key-id", "--access-key-secret", "--endpoint", "--config-file", "--sts-token", "--jobs", "--parallel",
		"--loglevel", "--include", "--exclude", "--encoding-type", "--version-id", "--payer", "--proxy-host",
		"--proxy-user", "--proxy-pwd", "--mode", "--ecs-role-name", "--token-timeout", "--ram-role-arn",
		"--role-session-name", "--read-timeout", "--connect-timeout", "--sts-region", "--retry-times", "--language")}
	rcloneCommandOptions = cliOptionTable{longDefault: true, booleanLong: longOptions(
		"--dry-run", "--interactive", "--progress", "--verbose", "--quiet", "--checksum", "--update", "--ignore-times",
		"--fast-list", "--no-traverse", "--rmdirs", "--copy-links", "--links", "--one-file-system", "--metadata",
		"--ignore-errors", "--no-check-certificate", "--no-update-modtime", "--use-json-log", "--stats-one-line",
		"--ask-password", "--auto-confirm", "--human-readable", "--immutable", "--no-check-dest", "--size-only",
		"--ignore-existing", "--ignore-size", "--leave-root", "--track-renames", "--create-empty-src-dirs",
		"--delete-excluded", "--use-server-modtime", "--help")}
	s3cmdCommandOptions = cliOptionTable{valueShort: "cm", valueLong: longOptions(
		"--config", "--access_key", "--secret_key", "--access_token", "--region", "--host", "--host-bucket", "--exclude",
		"--include", "--rexclude", "--rinclude", "--exclude-from", "--include-from", "--rexclude-from", "--rinclude-from",
		"--mime-type", "--encoding", "--add-header", "--storage-class", "--bucket-location", "--cache-file", "--ca-certs")}
	rsyncCommandOptions = cliOptionTable{valueShort: "efBTM", valueLong: longOptions(
		"--rsh", "--rsync-path", "--exclude", "--include", "--exclude-from", "--include-from", "--files-from", "--filter",
		"--password-file", "--port", "--log-file", "--chmod", "--chown", "--block-size", "--bwlimit", "--timeout",
		"--contimeout", "--compare-dest", "--copy-dest", "--link-dest", "--temp-dir", "--partial-dir", "--backup-dir",
		"--suffix", "--max-size", "--min-size", "--max-delete", "--modify-window", "--out-format", "--log-file-format",
		"--skip-compress", "--usermap", "--groupmap", "--iconv", "--info", "--debug", "--sockopts", "--address",
		"--protocol", "--outbuf", "--checksum-choice", "--compress-choice", "--compress-level", "--stop-at",
		"--stop-after", "--remote-option")}
	cpCommandOptions      = cliOptionTable{valueShort: "St", valueLong: longOptions("--target-directory", "--suffix")}
	installCommandOptions = cliOptionTable{valueShort: "mogSt", valueLong: longOptions(
		"--mode", "--owner", "--group", "--suffix", "--target-directory", "--strip-program")}
	teeCommandOptions = cliOptionTable{}
)

// 删除整个容器、共享、账户、文件系统、目录等的 az storage 资源按严重处理；单个 blob、文件按高危。
var azCriticalStorageResources = map[string]bool{
	"container": true, "share": true, "account": true, "fs": true, "filesystem": true, "queue": true, "table": true, "directory": true,
}

// analyzeDestructiveToolCommand 识别 analyzeDestructiveCommandAction 之外的破坏性命令行。
func analyzeDestructiveToolCommand(segment destructiveCommandSegment) (destructiveCommandFinding, bool) {
	words := destructiveCommandWords(segment.Words)
	if len(words) == 0 {
		return destructiveCommandFinding{}, false
	}
	args := words[1:]
	command := commandBaseName(words[0])
	switch {
	case command == "mysql" || command == "mariadb":
		scan := mysqlCommandOptions.scan(args)
		return sqlCommandLineFinding(scan.values("-e", "--execute"), destructiveSQLMySQL)
	case command == "psql":
		scan := psqlCommandOptions.scan(args)
		return sqlCommandLineFinding(scan.values("-c", "--command"), destructiveSQLPostgres)
	case command == "dropdb":
		if scan := dropdbCommandOptions.scan(args); len(scan.operands) > 0 {
			return destructiveCommandFinding{Analysis: classification("database_destroy"), Targets: scan.operands[:1], Command: true}, true
		}
	case command == "mysqladmin":
		operands := mysqladminCommandOptions.scan(args).operands
		for index := 0; index+1 < len(operands); index++ {
			if strings.EqualFold(operands[index], "drop") {
				return destructiveCommandFinding{Analysis: classification("database_destroy"), Targets: operands[index+1 : index+2],
					Shown: operands[index : index+1], Command: true}, true
			}
		}
	case command == "redis-cli":
		operands := redisCommandOptions.scan(args).operands
		if len(operands) > 0 && (strings.EqualFold(operands[0], "flushall") || strings.EqualFold(operands[0], "flushdb")) {
			return destructiveCommandFinding{Analysis: classification("database_destroy"), Shown: operands[:1], Command: true}, true
		}
	case command == "aws":
		scan := awsCommandOptions.scan(args)
		operands := scan.operands
		if len(operands) >= 2 && strings.EqualFold(operands[0], "s3") && strings.EqualFold(operands[1], "rm") &&
			scan.has("--recursive") && !scan.has("--dryrun") {
			return cloudStorageFinding(true, prefixedWords(operands[2:], "s3://"), nil), true
		}
	case command == "az":
		return azStorageDeleteFinding(args)
	case strings.HasPrefix(command, "ossutil"):
		scan := ossutilCommandOptions.scan(args)
		if len(scan.operands) > 0 && strings.EqualFold(scan.operands[0], "rm") {
			recursive := scan.has("-r", "--recursive", "-b", "--bucket", "-a", "--all-type")
			return cloudStorageFinding(recursive, prefixedWords(scan.operands[1:], "oss://"), nil), true
		}
	case command == "rclone":
		scan := rcloneCommandOptions.scan(args)
		if len(scan.operands) >= 2 && strings.EqualFold(scan.operands[0], "purge") && !scan.has("--dry-run", "-n") {
			return cloudStorageFinding(true, scan.operands[1:2], nil), true
		}
	case command == "s3cmd":
		scan := s3cmdCommandOptions.scan(args)
		if len(scan.operands) > 0 && (strings.EqualFold(scan.operands[0], "del") || strings.EqualFold(scan.operands[0], "rm")) &&
			!scan.has("--dry-run", "-n") {
			return cloudStorageFinding(scan.has("-r", "--recursive"), prefixedWords(scan.operands[1:], "s3://"), nil), true
		}
	case command == "rsync":
		return rsyncDeleteFinding(args)
	case command == "tee":
		return sensitiveWriteFinding(segment, teeCommandOptions.scan(args).operands, true)
	case command == "cp" || command == "install":
		table := cpCommandOptions
		if command == "install" {
			table = installCommandOptions
		}
		scan := table.scan(args)
		if command == "install" && scan.has("-d", "--directory") {
			return destructiveCommandFinding{}, false
		}
		destination := scan.values("-t", "--target-directory")
		if len(destination) == 0 && len(scan.operands) >= 2 && !lastCallWordDynamic(segment) {
			destination = scan.operands[len(scan.operands)-1:]
		}
		return sensitiveWriteFinding(segment, destination, true)
	case command == "sed":
		return sensitiveWriteFinding(segment, sedInPlaceTargets(args), true)
	case command == "set-content":
		return sensitiveWriteFinding(segment, powershellFileTargets(args), false)
	}
	return destructiveCommandFinding{}, false
}

// sqlCommandLineFinding 分析 mysql -e、psql -c 里的 SQL；触发的语句另起证据段，按 SQL 骨架显示。
func sqlCommandLineFinding(statements []string, dialect destructiveSQLDialect) (destructiveCommandFinding, bool) {
	var best DestructiveAnalysis
	var extra []EvidenceSegment
	for _, statement := range statements {
		analysis := analyzeDestructiveSQL(statement, "command", dialect)
		if analysis.Category == "" {
			continue
		}
		extra = append(extra, analysis.EvidenceSegments...)
		if best.Category == "" || analysis.HighConfidence && !best.HighConfidence ||
			analysis.HighConfidence == best.HighConfidence && preferDestructiveFinding(analysis, best) {
			best = analysis
		}
	}
	if best.Category == "" {
		return destructiveCommandFinding{}, false
	}
	best.Evidence, best.EvidenceSegments, best.TargetSummary, best.ParseRejected = nil, nil, "", false
	return destructiveCommandFinding{Analysis: best, Extra: extra, Command: true}, true
}

func cloudStorageFinding(bulk bool, targets, shown []string) destructiveCommandFinding {
	analysis := classification("cloud_resource_destroy")
	if !bulk {
		analysis.RiskLevel = "high"
	}
	return destructiveCommandFinding{Analysis: analysis, Targets: targets, Shown: shown, Command: true}
}

func prefixedWords(words []string, prefix string) []string {
	var result []string
	for _, word := range words {
		if len(word) > len(prefix) && strings.EqualFold(word[:len(prefix)], prefix) {
			result = append(result, word)
		}
	}
	return result
}

// azStorageDeleteFinding：az storage <资源…> delete | delete-batch。命令链是 az 后面连续的非选项词。
func azStorageDeleteFinding(args []string) (destructiveCommandFinding, bool) {
	chain := 0
	for chain < len(args) && !strings.HasPrefix(args[chain], "-") {
		chain++
	}
	if chain < 2 || !strings.EqualFold(args[0], "storage") {
		return destructiveCommandFinding{}, false
	}
	for index := 1; index < chain; index++ {
		verb := strings.ToLower(args[index])
		if verb != "delete" && verb != "delete-batch" {
			continue
		}
		scan := azCommandOptions.scan(args[chain:])
		if scan.has("--dryrun") {
			return destructiveCommandFinding{}, false
		}
		bulk := verb == "delete-batch" || azCriticalStorageResources[strings.ToLower(args[index-1])]
		targets := scan.values("--name", "-n", "--container-name", "-c", "--share-name", "--source", "-s", "--file-system", "-f",
			"--path", "-p", "--queue-name", "-q", "--table-name", "-t", "--directory-name")
		return cloudStorageFinding(bulk, targets, args[index:index+1]), true
	}
	return destructiveCommandFinding{}, false
}

// rsyncDeleteFinding：rsync --delete*（含 --del）删除目标目录里源端没有的文件，目标是最后一个位置参数。
func rsyncDeleteFinding(args []string) (destructiveCommandFinding, bool) {
	scan := rsyncCommandOptions.scan(args)
	deletes := false
	for name := range scan.options {
		deletes = deletes || name == "--del" || strings.HasPrefix(name, "--delete")
	}
	if !deletes || scan.has("-n", "--dry-run") || len(scan.operands) < 2 {
		return destructiveCommandFinding{}, false
	}
	return destructiveCommandFinding{Analysis: classification("filesystem_delete"), Targets: scan.operands[len(scan.operands)-1:], Command: true}, true
}

// sensitiveWriteFinding 按重定向同一张敏感表给写入目标定级。sensitiveOnly 为真时（tee、cp、install、sed -i）
// 只报敏感目标，普通文件不报；Set-Content 与覆盖重定向一样，普通文件按中危。
func sensitiveWriteFinding(segment destructiveCommandSegment, targets []string, sensitiveOnly bool) (destructiveCommandFinding, bool) {
	kept := make([]string, 0, len(targets))
	risk, subcategory := "", ""
	for _, target := range targets {
		targetRisk, targetSubcategory, keep := writeTargetRiskWithBases(target, sensitiveOnly, segment.BaseDirs)
		if !keep {
			continue
		}
		kept = append(kept, target)
		if destructiveRiskRank(targetRisk) > destructiveRiskRank(risk) {
			risk, subcategory = targetRisk, targetSubcategory
		}
	}
	if len(kept) == 0 {
		return destructiveCommandFinding{}, false
	}
	if subcategory == "" {
		subcategory = "filesystem_overwrite"
	}
	analysis := classification(subcategory)
	analysis.RiskLevel = risk
	return destructiveCommandFinding{Analysis: analysis, Targets: kept, Command: true}, true
}

// sedInPlaceTargets：只有 -i/--in-place 才写文件。-i 后面连写的是备份后缀（-ie 的 e 是后缀）；
// 没有 -e/-f 时第一个位置参数是脚本，其余是文件。
func sedInPlaceTargets(args []string) []string {
	inPlace, hasScript := false, false
	var operands []string
	for index := 0; index < len(args); index++ {
		word := args[index]
		switch {
		case word == "--":
			operands = append(operands, args[index+1:]...)
			index = len(args)
		case strings.HasPrefix(word, "--"):
			name, _, hasValue := strings.Cut(word, "=")
			switch name {
			case "--in-place":
				inPlace = true
			case "--expression", "--file":
				hasScript = true
				if !hasValue {
					index++
				}
			case "--line-length":
				if !hasValue {
					index++
				}
			}
		case strings.HasPrefix(word, "-") && len(word) > 1:
			for position := 1; position < len(word); position++ {
				letter := word[position]
				if letter == 'i' {
					inPlace = true
					break
				}
				if letter == 'e' || letter == 'f' || letter == 'l' {
					hasScript = hasScript || letter != 'l'
					if position == len(word)-1 {
						index++
					}
					break
				}
			}
		default:
			operands = append(operands, word)
		}
	}
	if !inPlace {
		return nil
	}
	if !hasScript && len(operands) > 0 {
		operands = operands[1:]
	}
	return operands
}

// lastCallWordDynamic 判断命令的最后一个参数是否含变量等动态内容（解析时已从 Words 里去掉）。
func lastCallWordDynamic(segment destructiveCommandSegment) bool {
	for index := len(segment.Evidence) - 1; index >= 0; index-- {
		if word := segment.Evidence[index]; word.Kind == EvidenceArg {
			return word.Dynamic
		}
	}
	return false
}

// powershellGroupEnd：从 index 开始的 (…)、$(…)、@(…) 子表达式，返回括号配平的那个词的位置。
func powershellGroupEnd(words []string, index int) (int, bool) {
	if index >= len(words) {
		return 0, false
	}
	first := words[index]
	if !strings.HasPrefix(first, "(") && !strings.HasPrefix(first, "$(") && !strings.HasPrefix(first, "@(") {
		return 0, false
	}
	depth := 0
	for position := index; position < len(words); position++ {
		depth += strings.Count(words[position], "(") - strings.Count(words[position], ")")
		if depth <= 0 {
			return position, true
		}
	}
	return len(words) - 1, true
}
