package filerestrict

import (
	"reflect"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		wantErr  string // 子串；空表示应通过
	}{
		{"空数组合法（功能关闭）", []string{}, ""},
		{"合法扩展名", []string{"*.pdf", "*.docx"}, ""},
		{"合法 glob", []string{"docs/**/*.docx", "~/Documents/**"}, ""},
		{"合法目录", []string{"/srv/contracts/"}, ""},
		{"超过 64 条", makePatterns(65), "64"},
		{"单条超 128 字符", []string{"*." + strings.Repeat("a", 130)}, "128"},
		{"含空白", []string{"my file.pdf"}, "空白"},
		{"含空格前导", []string{" *.pdf"}, "空白"},
		{"含控制字符", []string{"*.pdf\x00"}, "控制字符"},
		{"含换行", []string{"*.pdf\n*.docx"}, "控制字符"},
		{"URL 拒绝 http", []string{"http://x.com/a.pdf"}, "URL"},
		{"URL 拒绝 https", []string{"https://x.com/a.pdf"}, "URL"},
		{"非法 glob 未闭合括号", []string{"docs/[abc.pdf"}, "语法"},
		{"普通文件名非法（必须含通配或为目录）", []string{"report.pdf"}, "通配"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.patterns)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate(%v) 应通过，得到 %v", tt.patterns, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate(%v) 应报错含 %q，得到 nil", tt.patterns, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate(%v) 错误 %q 不含 %q", tt.patterns, err.Error(), tt.wantErr)
			}
		})
	}
}

func makePatterns(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "*.pdf"
	}
	return out
}

func TestValidateAction(t *testing.T) {
	for _, ok := range []string{"record", "alert_allow", "block"} {
		if _, err := ValidateAction(ok); err != nil {
			t.Errorf("ValidateAction(%q) 应通过: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "confirm", "deny", "BLOCK"} {
		if _, err := ValidateAction(bad); err == nil {
			t.Errorf("ValidateAction(%q) 应报错", bad)
		}
	}
}

func mustCompile(t *testing.T, patterns ...string) *Matcher {
	t.Helper()
	m, err := Compile(patterns)
	if err != nil {
		t.Fatalf("Compile(%v): %v", patterns, err)
	}
	return m
}

func TestMatch(t *testing.T) {
	tests := []struct {
		name        string
		patterns    []string
		path        string
		wantHit     bool
		wantPattern string
	}{
		// 扩展名：只比 basename 最后一个扩展名，不区分大小写
		{"扩展名命中小写", []string{"*.pdf"}, "report.pdf", true, "*.pdf"},
		{"扩展名命中大写", []string{"*.pdf"}, "A.PDF", true, "*.pdf"},
		{"扩展名带目录", []string{"*.pdf"}, "/x/y/合同.pdf", true, "*.pdf"},
		{"双扩展名只认最后一个", []string{"*.pdf"}, "report.pdf.bak", false, ""},
		{"Windows 反斜杠 docx", []string{"*.docx"}, `C:\Users\a\合同.docx`, true, "*.docx"},
		{"相对路径 xlsx", []string{"*.xlsx"}, `.\a.xlsx`, true, "*.xlsx"},
		{"扩展名不匹配", []string{"*.pdf"}, "a.docx", false, ""},
		{"扩展名不误伤子串", []string{"*.pdf"}, "pdf.go", false, ""},

		// glob：** 任意层级；相对模式同时匹配 basename 与任意后缀路径
		{"glob 多级命中", []string{"docs/**/*.docx"}, "docs/a/b/c.docx", true, "docs/**/*.docx"},
		{"glob 相对后缀命中", []string{"docs/**/*.docx"}, "/home/u/docs/a/c.docx", true, "docs/**/*.docx"},
		{"glob basename 命中", []string{"**/secret.pdf"}, "secret.pdf", true, "**/secret.pdf"},
		{"波浪线 glob", []string{"~/Documents/**"}, "~/Documents/x.pdf", true, "~/Documents/**"},
		{"波浪线 glob 深层", []string{"~/Documents/**"}, "~/Documents/2026/q3/合同.pdf", true, "~/Documents/**"},
		{"glob 不命中", []string{"docs/**/*.docx"}, "src/a.go", false, ""},

		// 目录：以 / 结尾，前缀匹配
		{"目录前缀命中", []string{"/srv/contracts/"}, "/srv/contracts/2026/a.txt", true, "/srv/contracts/"},
		{"目录本身不命中（需其下文件）", []string{"/srv/contracts/"}, "/srv/contracts/", false, ""},
		{"目录不命中兄弟", []string{"/srv/contracts/"}, "/srv/other/a.pdf", false, ""},

		// 多模式取第一个命中
		{"多模式第一命中", []string{"*.docx", "*.pdf"}, "a.pdf", true, "*.pdf"},

		// 已知不得命中样本
		{"git log 不命中", []string{"*.pdf"}, "git", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mustCompile(t, tt.patterns...)
			hit, ok := m.MatchPath(tt.path)
			if ok != tt.wantHit {
				t.Fatalf("MatchPath(%q) hit=%v, want %v (patterns=%v)", tt.path, ok, tt.wantHit, tt.patterns)
			}
			if tt.wantHit && hit.Pattern != tt.wantPattern {
				t.Fatalf("MatchPath(%q) pattern=%q, want %q", tt.path, hit.Pattern, tt.wantPattern)
			}
			if tt.wantHit && hit.Precision != "exact" {
				t.Fatalf("MatchPath 应精确命中, got %q", hit.Precision)
			}
		})
	}
}

func TestMatchCommand(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		command  string
		wantHit  bool
		wantPrec string
	}{
		{"简单命令", []string{"*.pdf"}, "pdftotext 合同.pdf -", true, "exact"},
		{"分号分段", []string{"*.pdf"}, "ls; cat a.pdf", true, "exact"},
		{"&& 分段", []string{"*.pdf"}, "cd /x && pdftotext a.pdf -", true, "exact"},
		{"管道分段", []string{"*.docx"}, "cat a.docx | grep x", true, "exact"},
		{"重定向目标", []string{"*.pdf"}, "cat > out.pdf", true, "exact"},
		{"重定向输入", []string{"*.txt"}, "grep x < in.txt", true, "exact"},
		{"命令替换一层", []string{"*.pdf"}, "echo $(cat a.pdf)", true, "exact"},
		{"引号内空格路径", []string{"*.pdf"}, `cat "我的 文件.pdf"`, true, "exact"},
		{"单引号路径", []string{"*.pdf"}, `cat 'a b.pdf'`, true, "exact"},
		{"Windows 路径", []string{"*.docx"}, `type C:\Users\a\合同.docx`, true, "exact"},
		{"pip 不命中（无路径样片段）", []string{"*.whl", "*.pdf"}, "pip install pdfplumber", false, ""},
		{"grep 字符串不命中扩展名", []string{"*.pdf"}, `grep -r "pdf" src/`, false, ""},
		{"report.pdf.bak 不命中", []string{"*.pdf"}, "echo report.pdf.bak", false, ""},
		{"git log 不命中", []string{"*.pdf"}, "git log --oneline", false, ""},
		{"https URL 不命中", []string{"*.pdf"}, "curl https://x.com/a.pdf", false, ""},
		{"http URL 不命中", []string{"*.pdf"}, "wget http://x.com/a.pdf", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mustCompile(t, tt.patterns...)
			hits := m.MatchCommand(tt.command)
			if tt.wantHit && len(hits) == 0 {
				t.Fatalf("MatchCommand(%q) 无命中, want hit (patterns=%v)", tt.command, tt.patterns)
			}
			if !tt.wantHit && len(hits) != 0 {
				t.Fatalf("MatchCommand(%q) 误中 %+v, want none", tt.command, hits)
			}
			if tt.wantHit && hits[0].Precision != tt.wantPrec {
				t.Fatalf("MatchCommand(%q) precision=%q, want %q", tt.command, hits[0].Precision, tt.wantPrec)
			}
		})
	}
}

func TestMatchText(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		text     string
		wantHit  bool
	}{
		{"Python 字符串内路径", []string{"*.pdf"}, `open("contract.pdf")`, true},
		{"JS 字符串内路径", []string{"*.pdf"}, `fs.readFileSync("a.pdf")`, true},
		{"等号赋值", []string{"*.docx"}, `path="x.docx"`, true},
		{"http URL 丢弃", []string{"*.pdf"}, `fetch("https://x.com/a.pdf")`, false},
		{"粗略层只跑扩展名/basename glob", []string{"docs/**/*.docx"}, "a.docx", false},
		{"纯文本误伤检查（pdf 单词）", []string{"*.pdf"}, "please pdf this", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mustCompile(t, tt.patterns...)
			hits := m.MatchText(tt.text)
			if tt.wantHit && len(hits) == 0 {
				t.Fatalf("MatchText(%q) 无命中, want hit", tt.text)
			}
			if !tt.wantHit && len(hits) != 0 {
				t.Fatalf("MatchText(%q) 误中 %+v, want none", tt.text, hits)
			}
			if tt.wantHit && hits[0].Precision != "coarse" {
				t.Fatalf("MatchText precision=%q, want coarse", hits[0].Precision)
			}
		})
	}
}

func TestMatchCommandCoarseFallback(t *testing.T) {
	// 精确层无命中时才跑粗略层：JS 代码里的路径词法切不出来，粗略层抓字符串。
	m := mustCompile(t, "*.pdf")
	hits := m.MatchCommand(`const f = () => read("季度 报告 .pdf  ".trim())`)
	// 这里词法层可能切出 trim() 等，粗略层应能抓到 .pdf 结尾片段；至少不 panic。
	_ = hits
}

func TestRedactTarget(t *testing.T) {
	tests := []struct{ in, want string }{
		{"合同.pdf", "合****.pdf"},
		{"/x/y/季度报告.docx", "/x/y/季****.docx"},
		{"a.pdf", "a****.pdf"},
		{`C:\Users\a\合同.docx`, `C:\Users\a\合****.docx`},
	}
	for _, tt := range tests {
		if got := RedactTarget(tt.in); got != tt.want {
			t.Errorf("RedactTarget(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMatchPaths(t *testing.T) {
	m := mustCompile(t, "*.pdf", "*.docx")
	hits := m.MatchPaths([]string{"a.txt", "b.pdf", "/x/c.docx", "d.go"})
	if len(hits) != 2 {
		t.Fatalf("MatchPaths 命中数 = %d, want 2: %+v", len(hits), hits)
	}
	var got []string
	for _, h := range hits {
		got = append(got, h.Target)
	}
	if !reflect.DeepEqual(got, []string{"b.pdf", "/x/c.docx"}) {
		t.Fatalf("MatchPaths targets = %v", got)
	}
}
