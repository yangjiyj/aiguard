package agentguard

import (
	"fmt"
	"math/rand"
	"path"
	"regexp"
	"strings"
	"testing"
)

// 代码质量审查（严重项的局部修正）：花括号、for 循环变量名、写入集合原来逐个起点重扫或逐条比对，
// 病态输入上是平方级。改成一遍建索引后，结果必须与改前逐一相同：这里保留改前的写法逐条对照。

func oldBraceGroupFrom(word string, from int) (braceGroup, bool) {
	for i := from; i < len(word); i++ {
		if word[i] != '{' || (i > 0 && word[i-1] == '$') {
			continue
		}
		depth, start := 0, i+1
		var parts []string
		for j := i; j < len(word); j++ {
			switch word[j] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					if len(parts) > 0 {
						return braceGroup{open: i, close: j, alternatives: append(parts, word[start:j])}, true
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
	return braceGroup{}, false
}

func TestBraceIndexMatchesScanFromEachBrace2922(t *testing.T) {
	random := rand.New(rand.NewSource(2922))
	alphabet := "{},a$b"
	for round := 0; round < 50000; round++ {
		var b strings.Builder
		for n := random.Intn(24); n > 0; n-- {
			b.WriteByte(alphabet[random.Intn(len(alphabet))])
		}
		word := b.String()
		lazy := newBraceIndex(word)
		built := newBraceIndex(word)
		built.build()
		for from := 0; from <= len(word); from++ {
			want, wantOK := oldBraceGroupFrom(word, from)
			for _, index := range []*braceIndex{lazy, built} {
				got, gotOK := index.groupFrom(from)
				if gotOK != wantOK || fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("%q from %d (built %v): got %v %v, want %v %v", word, from, index.built, got, gotOK, want, wantOK)
				}
			}
		}
	}
}

func oldLoopVariableUntouched(raw, name string) bool {
	assignment := regexp.MustCompile(`(^|[^A-Za-z0-9_$])` + regexp.QuoteMeta(name) + `(\[[^\]]*\])?\+?=`)
	if assignment.MatchString(raw) {
		return false
	}
	braced := "${" + name
	for rest := raw; ; {
		at := strings.Index(rest, braced)
		if at < 0 {
			return true
		}
		rest = rest[at+len(braced):]
		if !strings.HasPrefix(rest, "}") {
			return false
		}
	}
}

func TestLoopNameUsesMatchRegexPerHeader2922(t *testing.T) {
	random := rand.New(rand.NewSource(2922))
	pieces := []string{"f", "fx", "g", "_a", "1f", "$", "${", "}", "=", "+=", "[", "]", " ", ";", "x", "{", "$f", "f=", "${f}", "${fx}", "${f:-a}"}
	names := []string{"f", "fx", "g", "_a", "a"}
	for round := 0; round < 20000; round++ {
		var b strings.Builder
		for n := random.Intn(10); n > 0; n-- {
			b.WriteString(pieces[random.Intn(len(pieces))])
		}
		raw := b.String()
		uses := scanLoopNameUses(raw)
		for _, name := range names {
			if got, want := uses.untouched(name), oldLoopVariableUntouched(raw, name); got != want {
				t.Fatalf("%q name %q: got %v, want %v", raw, name, got, want)
			}
		}
	}
}

func oldSameWrittenFile(target, name string) bool {
	written, loaded := shellPathKey(target), shellPathKey(name)
	if written == loaded {
		return true
	}
	base := path.Base(loaded)
	if base == "." || base == "/" || base == ".." || path.Base(written) != base {
		return false
	}
	return pathForm(written) != pathForm(loaded) || strings.HasPrefix(written, "..") || strings.HasPrefix(loaded, "..")
}

func oldLoadsWritten(targets []string, cd, workspace bool, name string) bool {
	key := shellPathKey(name)
	unknownName := strings.ContainsAny(name, "$`")
	if workspace {
		return true
	}
	for _, target := range targets {
		if target == "" || target == "-" || ignoredOutputTarget(target) {
			continue
		}
		if cd || unknownName || strings.ContainsAny(target, "$`") || oldSameWrittenFile(target, name) {
			return true
		}
		if strings.ContainsAny(target, "*?[") {
			if matched, _ := path.Match(shellPathKey(target), key); matched {
				return true
			}
		}
	}
	return false
}

func TestShellWritesIndexMatchesLoop2922(t *testing.T) {
	random := rand.New(rand.NewSource(2922))
	vocabulary := []string{".env", "./.env", "/home/u/.env", "~/.env", "../.env", "a/.env", "a/../.env", "$F", "`x`",
		"*.env", ".e[n]v", "-", "", "/dev/null", "/dev/stdout", "x", "/x", "~/x", "../x", ".", "/", "..", "sub/x"}
	for round := 0; round < 20000; round++ {
		var targets []string
		for n := random.Intn(5); n > 0; n-- {
			targets = append(targets, vocabulary[random.Intn(len(vocabulary))])
		}
		cd := random.Intn(4) == 0
		var writes shellWrites
		writes.record(targets...)
		writes.cd = cd
		for _, name := range vocabulary {
			if got, want := writes.loads(name, nil), oldLoadsWritten(targets, cd, false, name); got != want {
				t.Fatalf("targets %q cd %v name %q: got %v, want %v", targets, cd, name, got, want)
			}
		}
	}
	// 写入超过上限：之后任何 source/. 都按加载了写过的文件处理。
	var writes shellWrites
	for i := 0; i <= maxShellWriteTargets; i++ {
		writes.record(fmt.Sprintf("o%d", i))
	}
	if !writes.workspace || !writes.loads("unrelated", nil) {
		t.Fatal("more than maxShellWriteTargets written files must count as writing the workspace")
	}
}

// 代码质量审查次要项：只写不读的文件工具（fileWriteToolNames）都在 builtinFreeTextArguments 里，
// 它们的正文参数（content、diff、edits 的新旧文字）不当路径判。
func TestFileWriteToolsHaveFreeTextArguments2922(t *testing.T) {
	for tool := range fileWriteToolNames {
		if len(builtinFreeTextArguments[tool]) == 0 {
			t.Errorf("%s writes files but lists no free-text argument", tool)
		}
	}
}

func oldExpandLoopWord(word string, loops []shellLoopBinding) []string {
	variants := []string{word}
	for _, binding := range loops {
		if !strings.Contains(word, "$"+binding.name) && !strings.Contains(word, "${"+binding.name+"}") {
			continue
		}
		next := make([]string, 0, min(len(variants)*len(binding.values), maxShellLoopVariants))
		for _, variant := range variants {
			for _, value := range binding.values {
				if len(next) < maxShellLoopVariants {
					next = append(next, substituteShellVariable(variant, binding.name, value))
				}
			}
		}
		variants = next
	}
	return variants
}

// 循环变量代入改为按深度优先只拼需要的前缀（32 个各 60 值的循环每个词原来要拼两千多个字符串），
// 结果与逐个循环展开的旧写法逐一相同。
func TestExpandLoopWordMatchesStepwise2922(t *testing.T) {
	random := rand.New(rand.NewSource(2922))
	names := []string{"f", "v", "v1", "v10", "x"}
	for round := 0; round < 20000; round++ {
		var loops []shellLoopBinding
		for n := random.Intn(5); n > 0; n-- {
			values := make([]string, random.Intn(4)+1)
			for i := range values {
				values[i] = fmt.Sprintf("k%d.pub", random.Intn(70))
			}
			if random.Intn(5) == 0 {
				values = make([]string, 70)
				for i := range values {
					values[i] = fmt.Sprintf("a%d.pub", i)
				}
			}
			loops = append(loops, shellLoopBinding{name: names[random.Intn(len(names))], values: values})
		}
		var b strings.Builder
		for n := random.Intn(5) + 1; n > 0; n-- {
			switch random.Intn(3) {
			case 0:
				b.WriteString("~/.ssh/")
			case 1:
				fmt.Fprintf(&b, "$%s", names[random.Intn(len(names))])
			default:
				fmt.Fprintf(&b, "${%s}", names[random.Intn(len(names))])
			}
		}
		word := b.String()
		if got, want := expandLoopWord(word, loops), oldExpandLoopWord(word, loops); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%q %+v: got %q, want %q", word, loops, got, want)
		}
	}
}
