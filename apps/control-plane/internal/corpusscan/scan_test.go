package corpusscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// fakeEngine 模拟 /internal/corpus/scan：手机号、身份证号按字符下标返回，并生成替换后的文本。
type fakeEngine struct {
	calls      int
	maxItems   int
	incomplete map[string]bool
	corrupt    bool
}

var fakePatterns = []struct {
	re          *regexp.Regexp
	kind, label string
}{
	// 身份证号在前：真实引擎会把重叠命中合并成更长的那条。
	{regexp.MustCompile(`\d{17}[\dX]`), "id_card_cn", "身份证号"},
	{regexp.MustCompile(`1[3-9]\d{9}`), "phone_cn", "手机号"},
}

func (f *fakeEngine) Scan(_ context.Context, items []EngineItem) (EngineBatch, error) {
	f.calls++
	if len(items) > f.maxItems {
		f.maxItems = len(items)
	}
	out := EngineBatch{RulePackVersion: "rp-1"}
	for _, item := range items {
		result := EngineResult{ID: item.ID, Findings: []EngineFinding{}, Incomplete: f.incomplete[item.Text]}
		var replacements []Replacement
		for _, p := range fakePatterns {
			for _, loc := range p.re.FindAllStringIndex(item.Text, -1) {
				start := utf8.RuneCountInString(item.Text[:loc[0]])
				end := start + utf8.RuneCountInString(item.Text[loc[0]:loc[1]])
				if overlaps(replacements, start, end) {
					continue
				}
				result.Findings = append(result.Findings, EngineFinding{Type: p.kind, Label: p.label, Start: start, End: end, Severity: "high"})
				replacements = append(replacements, Replacement{Start: start, End: end, Text: "[" + p.label + "]"})
			}
		}
		sortFindings(result.Findings)
		sortReplacements(replacements)
		result.MaskedText = ApplyReplacements(item.Text, replacements)
		if f.corrupt && len(result.Findings) > 0 {
			result.Findings[0].End += 3
		}
		out.Items = append(out.Items, result)
	}
	return out, nil
}

func overlaps(rs []Replacement, start, end int) bool {
	for _, r := range rs {
		if start < r.End && r.Start < end {
			return true
		}
	}
	return false
}

func sortFindings(fs []EngineFinding) {
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && fs[j].Start < fs[j-1].Start; j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

func sortReplacements(rs []Replacement) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rs[j].Start < rs[j-1].Start; j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
}

func run(t *testing.T, format, input string, engine *fakeEngine, maxBatch int) (string, Report) {
	t.Helper()
	var out bytes.Buffer
	report, err := Run(context.Background(), strings.NewReader(input), &out, Options{Format: format, Engine: engine, MaxBatch: maxBatch})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return out.String(), report
}

func TestRunJSONLReplacesEveryOccurrenceAndKeepsOtherLines(t *testing.T) {
	input := strings.Join([]string{
		`{"id":1,"instruction":"给 13812345678 打电话","output":"好的，13812345678 已记录"}`,
		`{"id":2,"text":"无敏感内容"}`,
		`坏行 {`,
		``,
		`{"id":3,"messages":[{"role":"user","content":"证件 11010519491231002X 和 13812345678"}]}`,
	}, "\n") + "\n"
	engine := &fakeEngine{}
	out, report := run(t, FormatJSONL, input, engine, 0)
	want := strings.Join([]string{
		`{"id":1,"instruction":"给 [手机号] 打电话","output":"好的，[手机号] 已记录"}`,
		`{"id":2,"text":"无敏感内容"}`,
		`坏行 {`,
		``,
		`{"id":3,"messages":[{"role":"user","content":"证件 [身份证号] 和 [手机号]"}]}`,
	}, "\n") + "\n"
	if out != want {
		t.Fatalf("masked copy =\n%s\nwant\n%s", out, want)
	}
	if report.TotalRecords != 4 || report.ScannedRecords != 3 || report.HitRecords != 2 || report.UnscannedRecords != 1 {
		t.Fatalf("counts = %+v", report.Progress)
	}
	if len(report.Unscanned) != 1 || report.Unscanned[0].Line != 3 || report.Unscanned[0].Reason != ReasonUnparsable {
		t.Fatalf("unscanned = %+v", report.Unscanned)
	}
	if report.ProcessedBytes != int64(len(input)) {
		t.Fatalf("processed bytes = %d, want %d", report.ProcessedBytes, len(input))
	}
	if report.RulePackVersion != "rp-1" {
		t.Fatalf("rule pack = %q", report.RulePackVersion)
	}
	stats := map[string]TypeStat{}
	for _, s := range report.Stats {
		stats[s.Type] = s
	}
	if stats["phone_cn"].Hits != 3 || stats["phone_cn"].Records != 2 || stats["id_card_cn"].Hits != 1 {
		t.Fatalf("stats = %+v", report.Stats)
	}
}

func TestRunReportNeverContainsOriginalValues(t *testing.T) {
	input := `{"text":"手机 13812345678 证件 11010519491231002X"}` + "\n"
	_, report := run(t, FormatJSONL, input, &fakeEngine{}, 0)
	data, err := MarshalReport(report, map[string]any{"job_id": "j1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"13812345678", "11010519491231002X"} {
		if bytes.Contains(data, []byte(raw)) {
			t.Fatalf("report leaks %s: %s", raw, data)
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil || decoded["job_id"] != "j1" {
		t.Fatalf("report = %s err=%v", data, err)
	}
	if len(report.Samples) != 2 || report.Samples[0].Preview != "1****8" || report.Samples[0].Field != "text" || report.Samples[0].Line != 1 {
		t.Fatalf("samples = %+v", report.Samples)
	}
}

func TestRunKeepsOrderAcrossBatchesAndPreservesCRLF(t *testing.T) {
	var lines []string
	for i := 0; i < 25; i++ {
		lines = append(lines, "第"+strings.Repeat("x", i)+"行 13812345678")
	}
	input := strings.Join(lines, "\r\n") + "\r\n"
	engine := &fakeEngine{}
	out, report := run(t, FormatTXT, input, engine, 4)
	if engine.calls < 7 || engine.maxItems > 4 {
		t.Fatalf("calls=%d max=%d", engine.calls, engine.maxItems)
	}
	want := strings.ReplaceAll(input, "13812345678", "[手机号]")
	if out != want {
		t.Fatalf("output order or line endings changed")
	}
	if report.HitRecords != 25 {
		t.Fatalf("hits = %d", report.HitRecords)
	}
}

func TestRunCSVSkipsHeaderAndRewritesCells(t *testing.T) {
	input := "姓名,电话,备注\n张三,13812345678,\"含,逗号 11010519491231002X\"\n李四,\"坏\n"
	out, report := run(t, FormatCSV, input, &fakeEngine{}, 0)
	want := "姓名,电话,备注\n张三,[手机号],\"含,逗号 [身份证号]\"\n李四,\"坏\n"
	if out != want {
		t.Fatalf("csv copy =\n%s\nwant\n%s", out, want)
	}
	if report.TotalRecords != 2 || report.ScannedRecords != 1 || report.UnscannedRecords != 1 {
		t.Fatalf("counts = %+v", report.Progress)
	}
	if report.Samples[0].Field != "col:2" {
		t.Fatalf("field = %q", report.Samples[0].Field)
	}
}

func TestRunCopiesOverlongLinesVerbatimAndMarksThemUnscanned(t *testing.T) {
	long := strings.Repeat("长", MaxLineBytes/3+10) + "13812345678"
	input := "前 13812345678\n" + long + "\n后 13812345678"
	out, report := run(t, FormatTXT, input, &fakeEngine{}, 0)
	want := "前 [手机号]\n" + long + "\n后 [手机号]"
	if out != want {
		t.Fatalf("overlong line not copied verbatim (len out=%d want=%d)", len(out), len(want))
	}
	if report.TotalRecords != 3 || report.UnscannedRecords != 1 || report.Unscanned[0].Line != 2 || report.Unscanned[0].Reason != ReasonTooLong {
		t.Fatalf("report = %+v unscanned=%+v", report.Progress, report.Unscanned)
	}
	if report.ProcessedBytes != int64(len(input)) {
		t.Fatalf("processed = %d want %d", report.ProcessedBytes, len(input))
	}
}

func TestRunMarksIncompleteItems(t *testing.T) {
	text := "规则超时 13812345678"
	_, report := run(t, FormatTXT, text+"\n", &fakeEngine{incomplete: map[string]bool{text: true}}, 0)
	if report.IncompleteRecords != 1 || report.HitRecords != 1 {
		t.Fatalf("report = %+v", report.Progress)
	}
}

func TestRunFailsWhenEngineOffsetsDisagree(t *testing.T) {
	var out bytes.Buffer
	_, err := Run(context.Background(), strings.NewReader("电话 13812345678\n"), &out, Options{Format: FormatTXT, Engine: &fakeEngine{corrupt: true}})
	if !errors.Is(err, ErrEngineMismatch) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(out.String(), "[") {
		t.Fatal("mismatched result must not be written")
	}
}

func TestRunStopsWhenProgressCallbackFails(t *testing.T) {
	stop := errors.New("canceled")
	var out bytes.Buffer
	calls := 0
	_, err := Run(context.Background(), strings.NewReader(strings.Repeat("13812345678\n", 10)), &out, Options{
		Format: FormatTXT, Engine: &fakeEngine{}, MaxBatch: 2,
		OnBatch: func(Progress) error { calls++; return stop },
	})
	if !errors.Is(err, stop) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestSplitDocumentTextDropsBlankParagraphsAndSplitsLongOnes(t *testing.T) {
	text := "第一段\r\n\r\n  \n第二段\n" + strings.Repeat("汉", maxParagraphBytes/3+5)
	lines := strings.Split(strings.TrimSuffix(SplitDocumentText(text), "\n"), "\n")
	if lines[0] != "第一段" || lines[1] != "第二段" || len(lines) != 4 {
		t.Fatalf("lines = %d %q %q", len(lines), lines[0], lines[1])
	}
	for _, line := range lines {
		if !utf8.ValidString(line) || len(line) > maxParagraphBytes {
			t.Fatalf("bad split line of %d bytes", len(line))
		}
	}
}
