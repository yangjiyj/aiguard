package agentguard

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	maxAppendTargetCombinations = 16
	maxCDTargets                = 16
)

// posixAssignments 记录同一脚本里每个变量的所有赋值来源和字面 cd 目标。
// 没有出现的变量视为外部环境变量；all 表示脚本里有 eval、source、trap 等运行时写变量的手段，
// 或收集遍历超出语法节点预算。parent 指向外层脚本，嵌套 shell 沿链查找，不整表复制。
type posixAssignments struct {
	literals map[string][]string
	dynamic  map[string]bool
	cmdWords []*syntax.Word // 收集阶段的动态命令词，赋值收集完成后再判断
	cdWords  []*syntax.Word // 收集阶段的 cd/pushd 参数，nil 表示不带参数
	cds      []string       // 解析后的 cd 目标，去重且最多 maxCDTargets 个
	cdOver   bool
	all      bool
	parent   *posixAssignments
}

func newPOSIXAssignments() *posixAssignments {
	return &posixAssignments{literals: map[string][]string{}, dynamic: map[string]bool{}}
}

func (a *posixAssignments) addLiteral(name, value string) {
	a.literals[name] = append(a.literals[name], value)
}

func (a *posixAssignments) markDynamic(name string) {
	if name != "" {
		a.dynamic[name] = true
	}
}

// unknown 表示脚本里存在无法静态看到的赋值来源。
func (a *posixAssignments) unknown() bool {
	for current := a; current != nil; current = current.parent {
		if current.all {
			return true
		}
	}
	return false
}

// lookup 沿外层链汇总变量的字面赋值，dynamic 为 true 表示存在运行时取值的来源。
func (a *posixAssignments) lookup(name string) (values []string, dynamic bool) {
	for current := a; current != nil; current = current.parent {
		values = append(values, current.literals[name]...)
		dynamic = dynamic || current.dynamic[name]
	}
	return values, dynamic
}

// cdTargets 返回脚本（含外层）里能解析出的 cd/pushd 目标，不计顺序和子 shell。
func (a *posixAssignments) cdTargets() []string {
	var result []string
	for current := a; current != nil; current = current.parent {
		result = append(result, current.cds...)
	}
	return result
}

// cdOverflow 表示 cd 目标多到无法逐个拼接，相对目标必须兜底。
func (a *posixAssignments) cdOverflow() bool {
	for current := a; current != nil; current = current.parent {
		if current.cdOver {
			return true
		}
	}
	return false
}

// resolveCDs 在赋值收集完成后解析 cd 参数：字面参数直接取；简单参数展开复用 appendTargetCandidates 代入；
// 不带参数的 cd 回到家目录，同脚本赋值过 HOME 时一并代入；其余动态参数不拼接。
func (a *posixAssignments) resolveCDs() {
	add := func(value string) {
		value = normalizeTildeDir(value)
		for _, existing := range a.cds {
			if existing == value {
				return
			}
		}
		if len(a.cds) >= maxCDTargets {
			a.cdOver = true
			return
		}
		a.cds = append(a.cds, value)
	}
	addWithHome := func(value string) {
		add(value)
		expanded, _ := expandHomeTargets([]string{value}, a)
		for _, item := range expanded {
			add(item)
		}
	}
	for _, word := range a.cdWords {
		switch {
		case word == nil:
			addWithHome("~")
		default:
			if value, ok := literalAssignValue(word); ok {
				addWithHome(value)
			} else if name, defaultValue, hasDefault, ok := singleParamWord(word); ok && hasDefault {
				// cd "${X:-/etc}"：X 的字面赋值和默认值都可能是目标。
				values, dynamic := a.lookup(name)
				if !dynamic {
					for _, value := range append(values, defaultValue) {
						addWithHome(value)
					}
				}
			} else if simplePOSIXParamWord(word) {
				if candidates, _, ok := appendTargetCandidates(word, a); ok {
					for _, candidate := range candidates {
						if !strings.Contains(candidate, "$") {
							add(candidate)
						}
					}
				}
			}
		}
	}
	a.cdWords = nil
}

// posixEnvLoader 按需收集赋值：只有出现需要变量代入或工作目录的重定向目标时才遍历脚本。
type posixEnvLoader struct {
	file   *syntax.File
	parent *posixEnvLoader
	env    *posixAssignments
}

func (l *posixEnvLoader) get() *posixAssignments {
	if l == nil {
		return nil
	}
	if l.env == nil {
		l.env = collectPOSIXAssignments(l.file)
		l.env.parent = l.parent.get()
		l.env.resolveCommandWords()
		l.env.resolveCDs()
	}
	return l.env
}

// collectPOSIXAssignments 用 syntax.Walk 收集脚本里所有变量赋值，不区分先后和作用域，
// 遍历同样受 maxDestructiveSyntaxNodes 约束，超出视为存在未知赋值。
func collectPOSIXAssignments(file *syntax.File) *posixAssignments {
	result := newPOSIXAssignments()
	visited := 0
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil || result.all {
			return false
		}
		visited++
		if visited > maxDestructiveSyntaxNodes {
			result.all = true
			return false
		}
		switch node := node.(type) {
		case *syntax.Assign:
			collectPOSIXAssign(result, node)
		case *syntax.DeclClause:
			for _, arg := range node.Args {
				if arg.Naked && arg.Name == nil && arg.Value != nil {
					collectDeclareOption(result, arg.Value)
				}
			}
		case *syntax.ForClause:
			if loop, ok := node.Loop.(*syntax.WordIter); ok && loop.Name != nil {
				result.markDynamic(loop.Name.Value)
			}
		case *syntax.BinaryArithm:
			if arithmeticAssignment(node.Op) {
				markArithmeticTarget(result, node.X)
			}
		case *syntax.UnaryArithm:
			if node.Op == syntax.Inc || node.Op == syntax.Dec {
				markArithmeticTarget(result, node.X)
			}
		case *syntax.ParamExp:
			if node.Param != nil && node.Exp != nil && (node.Exp.Op == syntax.AssignUnset || node.Exp.Op == syntax.AssignUnsetOrNull) {
				result.markDynamic(node.Param.Value)
			}
		case *syntax.CallExpr:
			collectPOSIXCallAssignments(result, node)
		}
		return true
	})
	return result
}

// collectDeclareOption 处理 declare/export 等内建参数里不带变量名的词：
// 纯字面且以 - 开头的是选项（-n 名称引用可别名到任意变量）；带引号或非字面的词
// 可能拼出 NAME=VALUE，无法静态判断。
func collectDeclareOption(result *posixAssignments, word *syntax.Word) {
	for _, part := range word.Parts {
		if _, ok := part.(*syntax.Lit); !ok {
			result.all = true
			return
		}
	}
	value, ok := literalAssignValue(word)
	switch {
	case !ok:
		result.all = true
	case strings.HasPrefix(value, "-"):
		if strings.Contains(value, "n") {
			result.all = true
		}
	default:
		result.all = true
	}
}

func collectPOSIXAssign(result *posixAssignments, assign *syntax.Assign) {
	if assign.Name == nil {
		return
	}
	name := assign.Name.Value
	if assign.Naked {
		return
	}
	if assign.Append || assign.Index != nil || assign.Array != nil {
		result.markDynamic(name)
		return
	}
	if assign.Value == nil {
		result.addLiteral(name, "")
		return
	}
	value, ok := literalAssignValue(assign.Value)
	if !ok {
		result.markDynamic(name)
		return
	}
	result.addLiteral(name, value)
}

// literalAssignValue 取纯字面赋值：Lit、单引号和双引号内的纯字面，可含 ~。
func literalAssignValue(word *syntax.Word) (string, bool) {
	var builder strings.Builder
	var visit func(parts []syntax.WordPart, quoted bool) bool
	visit = func(parts []syntax.WordPart, quoted bool) bool {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				builder.WriteString(unescapePOSIXLiteral(part.Value, quoted))
			case *syntax.SglQuoted:
				if part.Dollar {
					return false
				}
				builder.WriteString(part.Value)
			case *syntax.DblQuoted:
				if part.Dollar || !visit(part.Parts, true) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	if !visit(word.Parts, false) {
		return "", false
	}
	return builder.String(), true
}

func arithmeticAssignment(op syntax.BinAritOperator) bool {
	switch op {
	case syntax.Assgn, syntax.AddAssgn, syntax.SubAssgn, syntax.MulAssgn, syntax.QuoAssgn, syntax.RemAssgn,
		syntax.AndAssgn, syntax.OrAssgn, syntax.XorAssgn, syntax.ShlAssgn, syntax.ShrAssgn:
		return true
	default:
		return false
	}
}

func markArithmeticTarget(result *posixAssignments, expr syntax.ArithmExpr) {
	word, ok := expr.(*syntax.Word)
	if !ok {
		result.all = true
		return
	}
	for _, part := range word.Parts {
		if lit, ok := part.(*syntax.Lit); ok {
			result.markDynamic(lit.Value)
		}
	}
}

// stripBuiltinPrefix 去掉 builtin、command（及其选项）前缀，返回真正的命令名和参数。
// literal 为 false 表示命令词不是纯字面（、$'eval'、eval），无法知道执行的是什么。
func stripBuiltinPrefix(args []*syntax.Word) (name string, rest []*syntax.Word, literal bool) {
	for len(args) > 0 {
		word, ok := literalAssignValue(args[0])
		if !ok {
			return "", nil, false
		}
		if word != "builtin" && word != "command" {
			return word, args[1:], true
		}
		args = args[1:]
		for len(args) > 0 {
			option, ok := literalAssignValue(args[0])
			if !ok || !strings.HasPrefix(option, "-") {
				break
			}
			args = args[1:]
		}
	}
	return "", nil, true
}

// collectPOSIXCallAssignments 处理运行时写变量的内建：read、mapfile、readarray、getopts、printf -v，
// 无法静态看到赋值的 eval、source、.、trap、alias，经 builtin/command 前缀调用的 declare 族，
// 以及 cd/pushd 目标。命令词不是纯字面时无法判断执行的是什么，一律按未知赋值处理。
func collectPOSIXCallAssignments(result *posixAssignments, call *syntax.CallExpr) {
	if len(call.Args) == 0 {
		return
	}
	command, args, literal := stripBuiltinPrefix(call.Args)
	if !literal {
		// 命令词含字面 / 时展开后一定是外部程序路径，不可能是 eval、read、cd 这类内建。
		// 其余动态命令词要等赋值收集完成后再判断它可能是什么。
		if _, firstLiteral := literalAssignValue(call.Args[0]); firstLiteral {
			result.all = true // builtin/command 前缀后跟动态词
		} else if !dynamicCommandWordIsPath(call.Args[0]) {
			result.cmdWords = append(result.cmdWords, call.Args[0])
		}
		return
	}
	switch command {
	case "eval", "source", ".", "trap", "alias", "declare", "typeset", "export", "local", "readonly":
		result.all = true
	case "read":
		result.markDynamic("REPLY")
		markReadArguments(result, args, "ptdnNui", "a")
	case "mapfile", "readarray":
		result.markDynamic("MAPFILE")
		if mapfileHasCallback(args) {
			result.all = true // -C 回调是一段运行时执行的脚本，可以改任意变量
		}
		markReadArguments(result, args, "dnOsuCc", "")
	case "getopts":
		markIdentifierArguments(result, args)
	case "printf":
		markPrintfVariable(result, args)
	case "cd", "pushd":
		collectCDTarget(result, args)
	}
}

// mapfileHasCallback 判断 mapfile/readarray 是否带 -C 回调（含 -tC 这类连写）。
func mapfileHasCallback(args []*syntax.Word) bool {
	for _, word := range args {
		value, literal := literalAssignValue(word)
		if literal && strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "--") && strings.Contains(value, "C") {
			return true
		}
	}
	return false
}

// collectCDTarget 记录 cd/pushd 的第一个非选项参数；cd - 和 popd 不拼接。
func collectCDTarget(result *posixAssignments, args []*syntax.Word) {
	for _, word := range args {
		if value, ok := literalAssignValue(word); ok {
			if value == "-" {
				return
			}
			if strings.HasPrefix(value, "-") {
				continue
			}
		}
		result.cdWords = append(result.cdWords, word)
		return
	}
	result.cdWords = append(result.cdWords, nil) // 不带参数的 cd 回到家目录
}

// markPrintfVariable 只关心 printf -v NAME 和连写的 -vNAME；变量名不是字面时无法判断写入哪个变量。
func markPrintfVariable(result *posixAssignments, args []*syntax.Word) {
	if len(args) == 0 {
		return
	}
	first, ok := literalAssignValue(args[0])
	if !ok {
		// 首参以不带 - 的字面量开头（"start $(date)\n"）时不可能是选项；整个首参是展开或以 - 开头才无法判断。
		if leading, found := leadingLiteralText(args[0]); found && leading != "" && !strings.HasPrefix(leading, "-") {
			return
		}
		result.all = true
		return
	}
	switch {
	case first == "-v":
		if len(args) < 2 {
			return
		}
		name, ok := literalAssignValue(args[1])
		if !ok || !validShellName(strings.SplitN(name, "[", 2)[0]) {
			result.all = true
			return
		}
		result.markDynamic(strings.SplitN(name, "[", 2)[0])
	case strings.HasPrefix(first, "-v") && len(first) > 2:
		name := strings.SplitN(first[2:], "[", 2)[0]
		if !validShellName(name) {
			result.all = true
			return
		}
		result.markDynamic(name)
	}
}

// markIdentifierArguments 把参数里的变量名标为动态；出现非字面参数时无法判断写入哪个变量。
func markIdentifierArguments(result *posixAssignments, words []*syntax.Word) {
	for _, word := range words {
		value, ok := literalAssignValue(word)
		if !ok {
			result.all = true
			return
		}
		if validShellName(value) {
			result.markDynamic(value)
		}
	}
}

func validShellName(value string) bool {
	if value == "" {
		return false
	}
	for index, r := range value {
		switch {
		case r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
		case r >= '0' && r <= '9' && index > 0:
		default:
			return false
		}
	}
	return true
}

// shellAutoAssignedVariables 是 shell 自己运行时赋值的变量，内容不可静态预知。
var shellAutoAssignedVariables = map[string]struct{}{
	"BASH_REMATCH": {}, "OPTARG": {}, "OPTIND": {}, "REPLY": {}, "MAPFILE": {}, "COPROC": {},
	"BASH_ARGV": {}, "BASH_ARGC": {}, "BASH_SOURCE": {}, "FUNCNAME": {}, "BASH_COMMAND": {}, "DIRSTACK": {},
	// 非交互 shell 启动时会 source 这两个变量指向的文件。
	"BASH_ENV": {}, "ENV": {},
}

// appendTargetCandidates 判断动态目标能否静态定级。
// ok 为 false 表示必须维持原兜底；否则返回把已赋值变量代入后的候选路径（外部变量保留为 $NAME，
// $PWD、$OLDPWD 按相对路径 . 处理，由调用方与 cd 目标和工作目录拼接）。
func appendTargetCandidates(word *syntax.Word, env *posixAssignments) (candidates []string, external, ok bool) {
	candidates = []string{""}
	if env.unknown() {
		return nil, false, false
	}
	expand := func(options []string) bool {
		next := make([]string, 0, len(candidates)*len(options))
		for _, prefix := range candidates {
			for _, option := range options {
				next = append(next, prefix+option)
			}
		}
		if len(next) > maxAppendTargetCombinations {
			return false
		}
		candidates = next
		return true
	}
	literalOption := func(text string) bool {
		// 未代入的外部变量之后再出现 .. 段，可能逃出目录，无法静态判断。
		if external && strings.Contains(text, "..") {
			return false
		}
		return expand([]string{text})
	}
	var visit func(parts []syntax.WordPart, first, quoted bool) bool
	visit = func(parts []syntax.WordPart, first, quoted bool) bool {
		for index, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				text := unescapePOSIXLiteral(part.Value, quoted)
				if first && index == 0 {
					text = normalizeTildeDir(text)
				}
				if first && index == 0 && (text == "~" || strings.HasPrefix(text, "~/")) {
					// ~/ 等价于 $HOME/：同脚本里赋值过 HOME 时一起代入。
					values, dynamic := env.lookup("HOME")
					if dynamic {
						return false
					}
					if len(values) > 0 {
						if !expand(values) {
							return false
						}
						text = text[1:]
					}
				}
				if !literalOption(text) {
					return false
				}
			case *syntax.SglQuoted:
				if !literalOption(part.Value) {
					return false
				}
			case *syntax.DblQuoted:
				if !visit(part.Parts, false, true) {
					return false
				}
			case *syntax.ParamExp:
				name := part.Param.Value
				values, dynamic := env.lookup(name)
				if dynamic {
					return false
				}
				if len(values) > 0 {
					for _, value := range values {
						// 不加引号的展开结果还会做通配符展开，值里的 * ? [ 可能匹配到任意文件。
						if !quoted && strings.ContainsAny(value, "*?[") {
							return false
						}
					}
					if !expand(values) {
						return false
					}
					continue
				}
				if name == "PWD" || name == "OLDPWD" {
					if !expand([]string{"."}) {
						return false
					}
					continue
				}
				if _, auto := shellAutoAssignedVariables[name]; auto {
					return false
				}
				external = true
				if !expand([]string{"$" + name}) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	if !visit(word.Parts, true, false) {
		return nil, false, false
	}
	return candidates, external, true
}

// expandHomeTargets 在同脚本赋值过 HOME 时，把静态目标里的 ~/ 一并按 HOME 的值展开。
// dynamic 为 true 表示 HOME 来自运行时取值，目标无法静态判断。
func expandHomeTargets(targets []string, env *posixAssignments) (expanded []string, dynamic bool) {
	expanded = targets
	for _, target := range targets {
		if target != "~" && !strings.HasPrefix(target, "~/") {
			continue
		}
		// 有 eval、source 时仍按家目录判定，除非同脚本对 HOME 有动态赋值。
		values, isDynamic := env.lookup("HOME")
		if isDynamic {
			return targets, true
		}
		for _, value := range values {
			expanded = append(expanded, strings.TrimRight(value, "/")+target[1:])
		}
	}
	return expanded, false
}

// positionalOrSpecialParam 判断参数名是否是位置参数或可能指向任意路径的特殊参数。
// $$、$?、$!、$#、$- 不可能指向敏感路径，仍按简单展开处理；$0 与 $_ 按位置参数处理。
func positionalOrSpecialParam(name string) bool {
	switch name {
	case "@", "*", "_":
		return true
	case "$", "?", "!", "#", "-":
		return false
	}
	return name != "" && name[0] >= '0' && name[0] <= '9'
}

// dynamicCommandWordIsPath 判断动态命令词是否含字面 /（"$VENV/bin/python"、"$ROOT"/run.sh），
// 此时它必定是路径，而内建命令名不含 /。
func dynamicCommandWordIsPath(word *syntax.Word) bool {
	var visit func(parts []syntax.WordPart) bool
	visit = func(parts []syntax.WordPart) bool {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				if strings.Contains(part.Value, "/") {
					return true
				}
			case *syntax.SglQuoted:
				if !part.Dollar && strings.Contains(part.Value, "/") {
					return true
				}
			case *syntax.DblQuoted:
				if !part.Dollar && visit(part.Parts) {
					return true
				}
			}
		}
		return false
	}
	return visit(word.Parts)
}

// leadingLiteralText 取词开头的字面文本；开头是变量或命令替换时 found 为 false。
func leadingLiteralText(word *syntax.Word) (text string, found bool) {
	if len(word.Parts) == 0 {
		return "", false
	}
	switch part := word.Parts[0].(type) {
	case *syntax.Lit:
		return unescapePOSIXLiteral(part.Value, false), true
	case *syntax.SglQuoted:
		if part.Dollar {
			return "", false
		}
		return part.Value, true
	case *syntax.DblQuoted:
		if part.Dollar || len(part.Parts) == 0 {
			return "", false
		}
		if lit, ok := part.Parts[0].(*syntax.Lit); ok {
			return unescapePOSIXLiteral(lit.Value, true), true
		}
	}
	return "", false
}

// markReadArguments 处理 read、mapfile 的参数：带值选项（read -p 提示、-t 超时等）后面的参数不是变量名；
// arrayOptions 后面的参数是数组名，算赋值目标；其余非选项参数是变量名，非字面时无法判断。
func markReadArguments(result *posixAssignments, words []*syntax.Word, valueOptions, arrayOptions string) {
	skipNext, arrayNext := false, false
	for _, word := range words {
		value, literal := literalAssignValue(word)
		switch {
		case skipNext:
			skipNext = false
			continue
		case arrayNext:
			arrayNext = false
			if !literal {
				result.all = true
				return
			}
			if validShellName(value) {
				result.markDynamic(value)
			}
			continue
		case literal && strings.HasPrefix(value, "-") && value != "-" && value != "--":
			flags := value[1:]
			for index := 0; index < len(flags); index++ {
				isValue := strings.IndexByte(valueOptions, flags[index]) >= 0
				isArray := strings.IndexByte(arrayOptions, flags[index]) >= 0
				if !isValue && !isArray {
					continue
				}
				if index == len(flags)-1 {
					skipNext, arrayNext = isValue, isArray
				} else if isArray {
					result.markDynamic(flags[index+1:]) // -aARR 连写
				}
				break
			}
			continue
		case !literal:
			result.all = true
			return
		}
		if validShellName(value) {
			result.markDynamic(value)
		}
	}
}

// mutatingBuiltins 是会改变量、目录、别名或 shell 选项的内建；作为命令词时无法静态跟踪其效果。
var mutatingBuiltins = map[string]struct{}{
	"eval": {}, "source": {}, ".": {}, "read": {}, "mapfile": {}, "readarray": {}, "printf": {},
	"declare": {}, "typeset": {}, "local": {}, "export": {}, "readonly": {}, "cd": {}, "pushd": {}, "popd": {},
	"alias": {}, "builtin": {}, "command": {}, "trap": {}, "getopts": {}, "set": {}, "unset": {}, "shopt": {}, "let": {},
}

// singleParamWord 识别整个词就是一个简单参数展开（可在双引号内），允许 ${X:-字面} 形式的默认值。
func singleParamWord(word *syntax.Word) (name, defaultValue string, hasDefault, ok bool) {
	parts := unquotedSingleParts(word)
	if len(parts) != 1 {
		return "", "", false, false
	}
	param, isParam := parts[0].(*syntax.ParamExp)
	if !isParam || param.Param == nil || param.Excl || param.Length || param.Width || param.Index != nil ||
		param.Slice != nil || param.Repl != nil || param.Names != 0 {
		return "", "", false, false
	}
	if param.Exp == nil {
		return param.Param.Value, "", false, true
	}
	if param.Exp.Op != syntax.DefaultUnset && param.Exp.Op != syntax.DefaultUnsetOrNull {
		return "", "", false, false
	}
	value, literal := "", true
	if param.Exp.Word != nil {
		value, literal = literalAssignValue(param.Exp.Word)
	}
	if !literal {
		return "", "", false, false
	}
	return param.Param.Value, value, true, true
}

// unquotedSingleParts 返回词的各部分；整个词是一对双引号时取其内部各部分。
func unquotedSingleParts(word *syntax.Word) []syntax.WordPart {
	parts := word.Parts
	if len(parts) == 1 {
		if quoted, isQuoted := parts[0].(*syntax.DblQuoted); isQuoted && !quoted.Dollar {
			return quoted.Parts
		}
	}
	return parts
}

// dynamicCommandWordSafe 判断动态命令词是否不会改 shell 状态：
// 简单变量展开（含字面默认值）的所有可能取值都不是会改状态的内建，外部变量信任外部环境；
// $(which X)、$(command -v X) 只是在查程序路径。
func (a *posixAssignments) dynamicCommandWordSafe(word *syntax.Word) bool {
	if name, defaultValue, hasDefault, ok := singleParamWord(word); ok {
		if positionalOrSpecialParam(name) {
			return false
		}
		values, dynamic := a.lookup(name)
		if dynamic {
			return false
		}
		if hasDefault {
			values = append(values, defaultValue)
		}
		for _, value := range values {
			if fields := strings.Fields(value); len(fields) > 0 {
				if _, mutating := mutatingBuiltins[fields[0]]; mutating {
					return false
				}
			}
		}
		return true
	}
	parts := unquotedSingleParts(word)
	if len(parts) != 1 {
		return false
	}
	subst, isSubst := parts[0].(*syntax.CmdSubst)
	if !isSubst || len(subst.Stmts) != 1 {
		return false
	}
	call, isCall := subst.Stmts[0].Cmd.(*syntax.CallExpr)
	if !isCall || len(call.Args) < 2 {
		return false
	}
	command, ok := literalAssignValue(call.Args[0])
	if !ok {
		return false
	}
	switch command {
	case "which":
	case "command":
		if option, ok := literalAssignValue(call.Args[1]); !ok || (option != "-v" && option != "-V") {
			return false
		}
	default:
		return false
	}
	for _, arg := range call.Args[1:] {
		if _, ok := literalAssignValue(arg); !ok {
			return false
		}
	}
	return true
}

// resolveCommandWords 在赋值收集完成后判断动态命令词，任何一个不安全就视为存在未知赋值。
func (a *posixAssignments) resolveCommandWords() {
	for _, word := range a.cmdWords {
		if !a.dynamicCommandWordSafe(word) {
			a.all = true
			break
		}
	}
	a.cmdWords = nil
}
