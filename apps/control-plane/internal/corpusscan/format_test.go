package corpusscan

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func unitTexts(units []Unit) map[string]string {
	out := map[string]string{}
	for _, u := range units {
		out[u.Field] = u.Text
	}
	return out
}

func TestJSONLSelectsOnlyKnownTextFields(t *testing.T) {
	line := []byte(`{"id":7,"instruction":"写邮件","input":"手机 13812345678","output":"好的","meta":{"text":"不扫描"},"messages":[{"role":"user","content":"你好"},{"role":"assistant","content":[{"type":"text","text":"片段"},{"type":"image","url":"x"}]}],"system":"系统","chosen":"A","rejected":[{"role":"assistant","content":"B"}]}`)
	units, err := ParseLine(FormatJSONL, line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := unitTexts(units)
	want := map[string]string{
		"instruction":                 "写邮件",
		"input":                       "手机 13812345678",
		"output":                      "好的",
		"messages[0].content":         "你好",
		"messages[1].content[0].text": "片段",
		"system":                      "系统",
		"chosen":                      "A",
		"rejected[0].content":         "B",
	}
	if len(got) != len(want) {
		t.Fatalf("units = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("field %s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["meta.text"]; ok {
		t.Fatal("nested non-standard text field must not be scanned")
	}
}

func TestJSONLRewriteKeepsKeyOrderWhitespaceAndOtherFields(t *testing.T) {
	line := []byte(`{ "z":1,  "prompt" : "电话 13812345678 和 13812345678", "a":[1,2,{"b":null}], "completion":"无" }`)
	units, err := ParseLine(FormatJSONL, line)
	if err != nil {
		t.Fatal(err)
	}
	repl := make([][]Replacement, len(units))
	for i, u := range units {
		if u.Field == "prompt" {
			repl[i] = []Replacement{{Start: 3, End: 14, Text: "[手机号]"}, {Start: 17, End: 28, Text: "[手机号]"}}
		}
	}
	out := RewriteLine(line, units, repl)
	want := `{ "z":1,  "prompt" : "电话 [手机号] 和 [手机号]", "a":[1,2,{"b":null}], "completion":"无" }`
	if string(out) != want {
		t.Fatalf("rewrite =\n%s\nwant\n%s", out, want)
	}
}

func TestJSONLDecodesEscapesAndReencodesOnlyTheChangedString(t *testing.T) {
	line := []byte(`{"text":"张三 \"引号\" 13812345678\n下一行","input":"不动"}`)
	units, err := ParseLine(FormatJSONL, line)
	if err != nil {
		t.Fatal(err)
	}
	texts := unitTexts(units)
	if texts["text"] != "张三 \"引号\" 13812345678\n下一行" {
		t.Fatalf("decoded = %q", texts["text"])
	}
	repl := make([][]Replacement, len(units))
	for i, u := range units {
		if u.Field == "text" {
			repl[i] = []Replacement{{Start: 8, End: 19, Text: "[手机号]"}}
		}
	}
	out := string(RewriteLine(line, units, repl))
	want := `{"text":"张三 \"引号\" [手机号]\n下一行","input":"不动"}`
	if out != want {
		t.Fatalf("rewrite = %s\nwant %s", out, want)
	}
}

func TestJSONLRejectsInvalidLines(t *testing.T) {
	for _, line := range []string{
		`{"text":"未闭合}`,
		`{"text":"a"} trailing`,
		`["not","object"]`,
		`{"text":"\ud800"}`,
		"{\"text\":\"raw\x01control\"}",
		`{"a":01}`,
		`{"a":tru}`,
		string([]byte{'{', '"', 't', '"', ':', '"', 0xff, '"', '}'}),
	} {
		if _, err := ParseLine(FormatJSONL, []byte(line)); !errors.Is(err, ErrUnparsable) {
			t.Errorf("line %q accepted: %v", line, err)
		}
	}
}

func TestJSONLAcceptsValidSurrogatePairsAndDeepNesting(t *testing.T) {
	units, err := ParseLine(FormatJSONL, []byte(`{"text":"😀 ok","x":[[[[{"y":[true,false,null,-1.5e3]}]]]]}`))
	if err != nil {
		t.Fatal(err)
	}
	if units[0].Text != "😀 ok" {
		t.Fatalf("surrogate pair decoded to %q", units[0].Text)
	}
	deep := strings.Repeat("[", 200) + strings.Repeat("]", 200)
	if _, err := ParseLine(FormatJSONL, []byte(`{"x":`+deep+`}`)); !errors.Is(err, ErrUnparsable) {
		t.Fatal("excessive nesting must be rejected")
	}
}

func TestCSVCellsQuotingAndRewrite(t *testing.T) {
	line := []byte(`张三,"13812345678","含,逗号 13812345678",,"引""号"`)
	units, err := ParseLine(FormatCSV, line)
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 4 {
		t.Fatalf("units = %+v (empty cell must be skipped)", units)
	}
	if units[2].Text != "含,逗号 13812345678" || units[3].Text != `引"号` {
		t.Fatalf("decoded cells = %q %q", units[2].Text, units[3].Text)
	}
	if units[3].Field != "col:5" {
		t.Fatalf("field = %q", units[3].Field)
	}
	repl := [][]Replacement{nil, {{Start: 0, End: 11, Text: "[手机号]"}}, {{Start: 5, End: 16, Text: "[手机号]"}}, nil}
	out := string(RewriteLine(line, units, repl))
	want := `张三,"[手机号]","含,逗号 [手机号]",,"引""号"`
	if out != want {
		t.Fatalf("rewrite = %s\nwant %s", out, want)
	}
}

func TestCSVUnquotedCellGetsQuotedWhenReplacementNeedsIt(t *testing.T) {
	line := []byte(`a,13812345678`)
	units, _ := ParseLine(FormatCSV, line)
	out := string(RewriteLine(line, units, [][]Replacement{nil, {{Start: 0, End: 11, Text: `[工号,"甲"]`}}}))
	if out != `a,"[工号,""甲""]"` {
		t.Fatalf("rewrite = %s", out)
	}
}

func TestCSVRejectsMalformedQuotes(t *testing.T) {
	for _, line := range []string{`a,"b`, `a,b"c`, `"a"b,c`} {
		if _, err := ParseLine(FormatCSV, []byte(line)); !errors.Is(err, ErrUnparsable) {
			t.Errorf("line %q accepted", line)
		}
	}
}

func TestApplyReplacementsUsesCharacterIndexes(t *testing.T) {
	text := "😀中文 13812345678 尾"
	got := ApplyReplacements(text, []Replacement{{Start: 4, End: 15, Text: "[手机号]"}})
	if got != "😀中文 [手机号] 尾" {
		t.Fatalf("got %q", got)
	}
	start, end, ok := CharSpanToBytes(text, 4, 15)
	if !ok || text[start:end] != "13812345678" {
		t.Fatalf("byte span = %d:%d ok=%v", start, end, ok)
	}
	if _, _, ok := CharSpanToBytes(text, 4, 99); ok {
		t.Fatal("out-of-range span accepted")
	}
}

func TestValidReplacementsRejectsOverlapsAndOutOfRange(t *testing.T) {
	if !ValidReplacements("abcdef", []Replacement{{0, 2, "x"}, {2, 4, "y"}}) {
		t.Fatal("adjacent spans rejected")
	}
	for _, spans := range [][]Replacement{
		{{0, 3, "x"}, {2, 4, "y"}},
		{{2, 4, "x"}, {0, 1, "y"}},
		{{0, 7, "x"}},
		{{3, 3, "x"}},
		{{-1, 2, "x"}},
	} {
		if ValidReplacements("abcdef", spans) {
			t.Errorf("spans %+v accepted", spans)
		}
	}
}

func TestMaskPreviewNeverReturnsTheValue(t *testing.T) {
	for _, value := range []string{"13812345678", "11010519491231002X", "张三", "a"} {
		preview := MaskPreview(value)
		if preview == value || (len([]rune(value)) > 4 && strings.Contains(preview, string([]rune(value)[1:4]))) {
			t.Errorf("preview %q leaks %q", preview, value)
		}
	}
	if MaskPreview("13812345678") != "1****8" {
		t.Fatalf("preview = %q", MaskPreview("13812345678"))
	}
}

func TestFormatsAndLimits(t *testing.T) {
	cases := map[string]string{"a.JSONL": FormatJSONL, "b.csv": FormatCSV, "c.txt": FormatTXT, "d.docx": FormatDOCX, "e.pdf": FormatPDF, "f.xlsx": FormatXLSX, "g.json": "", "h": ""}
	for name, want := range cases {
		if got := FormatFromFileName(name); got != want {
			t.Errorf("%s -> %q, want %q", name, got, want)
		}
	}
	if MaxFileBytes(FormatJSONL) != 2<<30 || MaxFileBytes(FormatPDF) != 100<<20 {
		t.Fatal("unexpected limits")
	}
}

func TestTXTLineIsOneUnit(t *testing.T) {
	units, err := ParseLine(FormatTXT, []byte("整行 13812345678"))
	if err != nil || len(units) != 1 || units[0].Text != "整行 13812345678" {
		t.Fatalf("units = %+v err=%v", units, err)
	}
	if _, err := ParseLine(FormatTXT, []byte{0xff, 0xfe}); !errors.Is(err, ErrUnparsable) {
		t.Fatal("invalid UTF-8 accepted")
	}
	out := RewriteLine([]byte("整行 13812345678"), units, [][]Replacement{{{Start: 3, End: 14, Text: "[手机号]"}}})
	if !bytes.Equal(out, []byte("整行 [手机号]")) {
		t.Fatalf("rewrite = %s", out)
	}
}

func TestJSONLAcceptsLeadingUTF8BOM(t *testing.T) {
	line := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"text":"电话 13812345678"}`)...)
	units, err := ParseLine(FormatJSONL, line)
	if err != nil || len(units) != 1 || units[0].Text != "电话 13812345678" {
		t.Fatalf("units = %+v err=%v", units, err)
	}
	out := RewriteLine(line, units, [][]Replacement{{{Start: 3, End: 14, Text: "[手机号]"}}})
	if !bytes.Equal(out, append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"text":"电话 [手机号]"}`)...)) {
		t.Fatalf("rewrite = %q", out)
	}
}
