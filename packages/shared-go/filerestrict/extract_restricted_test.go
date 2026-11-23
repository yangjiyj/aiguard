package filerestrict

import "testing"

// argv 元素含空格时拼接会加引号（proxy-server 与网关共用这条路径）。模式本身不含空白，
// 加引号前后，目录、glob、扩展名模式对这类元素都应命中，不能因为引号漏掉。
func TestRestrictedPatternsStillMatchQuotedArgvElements(t *testing.T) {
	for _, c := range []struct {
		pattern string
		argv    []any
	}{
		{"/srv/contracts/", []any{"cat", "/srv/contracts/My File.txt"}},
		{"~/Documents/**", []any{"cp", "~/Documents/Q3 Report.docx", "/tmp/x"}},
		{"*.pdf", []any{"pdftotext", "/data/My Report.pdf", "-"}},
		{"*.pdf", []any{"cat", "a.pdf b"}},
		{"*.pdf", []any{"bash", "-lc", "cat '/data/My Report.pdf'"}},
		{"*.docx", []any{"cmd", "/c", "type", `C:\Users\a\My Doc.docx`}},
	} {
		matcher, err := Compile([]string{c.pattern})
		if err != nil {
			t.Fatal(err)
		}
		commands, _ := ExtractCommandTexts(map[string]any{"command": c.argv})
		if len(commands) != 1 {
			t.Fatalf("%v: commands=%q", c.argv, commands)
		}
		if hits := matcher.MatchCommand(commands[0]); len(hits) == 0 {
			t.Errorf("%s must match %q", c.pattern, commands[0])
		}
	}
}
