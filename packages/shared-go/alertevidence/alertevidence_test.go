package alertevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// engineContext 复刻引擎 hit_display.evidence_context_for：命中点前后各 500 字，截断处加“…”。
func engineContext(content []rune, start, end int) string {
	from, to := start-500, end+500
	prefix, suffix := "…", "…"
	if from <= 0 {
		from, prefix = 0, ""
	}
	if to >= len(content) {
		to, suffix = len(content), ""
	}
	return prefix + string(content[from:to]) + suffix
}

func locationOf(start, end int) string {
	return "content[" + strconv.Itoa(start) + ":" + strconv.Itoa(end) + "]"
}

// 引擎全部命中类型：语义类、运行类（raw_evidence 是整段送检内容）不存原文，其余按字面命中存原文。
func TestStoresRawCoversEveryEngineFindingType(t *testing.T) {
	for _, tc := range []struct {
		typ, kind string
		want      bool
	}{
		{"secret", "literal", true}, {"pii", "literal", true}, {"data_leak", "literal", true},
		{"code_config", "literal", true}, {"content_safety", "literal", true}, {"content_safety", "contextual", true},
		{"custom", "", true}, {"catalog_policy", "literal", true}, {"prompt_injection", "literal", true},
		{"prompt_stego", "literal", true}, {"file", "literal", true}, {"agent", "literal", true},
		{"agent_guard", "literal", true}, {"request_context", "contextual", true},
		{"semantic_attack", "semantic", false}, {"semantic_telemetry", "runtime", false},
		{"llm_judge", "runtime", false}, {"engine_runtime", "runtime", false},
	} {
		if got := StoresRaw(tc.typ, "x", tc.kind); got != tc.want {
			t.Errorf("type=%s kind=%s: StoresRaw=%v, want %v", tc.typ, tc.kind, got, tc.want)
		}
	}
	for _, tc := range []struct{ typ, category, kind string }{
		{"custom", "semantic_jailbreak", "literal"}, {"custom", "x", "runtime"}, {"custom", "x", "observation"}, {"custom", "x", "telemetry"},
	} {
		if StoresRaw(tc.typ, tc.category, tc.kind) {
			t.Errorf("%+v 不应存原文", tc)
		}
	}
}

func TestTruncateCapsRawAt4096Characters(t *testing.T) {
	long := strings.Repeat("密", 5000)
	got, truncated := Truncate(long)
	if !truncated || utf8.RuneCountInString(got) != RawMaxRunes || !strings.HasPrefix(long, got) {
		t.Fatalf("超长原文应截到 %d 字并标记: truncated=%v len=%d", RawMaxRunes, truncated, utf8.RuneCountInString(got))
	}
	if got, truncated := Truncate("AKIAIOSFODNN7EXAMPLE"); truncated || got != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("短原文不应改动: %q %v", got, truncated)
	}
}

func TestExtractKeepsPlainTextAroundTheHit(t *testing.T) {
	before, after := strings.Repeat("前", 700), strings.Repeat("后", 700)
	hit := "password=Sh0rt9 token=ghp_0123456789abcdef0123456789abcdef0123"
	content := []rune(before + hit + after)
	start := utf8.RuneCountInString(before)
	end := start + utf8.RuneCountInString(hit)
	gotHit, window := Extract(hit, engineContext(content, start, end), locationOf(start, end))
	want := "…" + strings.Repeat("前", ContextRunes) + hit + strings.Repeat("后", ContextRunes) + "…"
	if gotHit != hit || window != want {
		t.Fatalf("前后文以命中为中心各留 %d 字且不打码:\n hit=%q\n got=%q\nwant=%q", ContextRunes, gotHit, window, want)
	}
}

// 位置能解析且在范围内就按位置取，不要求引擎给的命中文字与原文相同：关键字规则命中的是归一化后的词
// （全角转半角、大小写折叠、去零宽字符），客户要看的是内容里的实际原文。
func TestExtractUsesPositionWhenEngineTextDiffers(t *testing.T) {
	for _, tc := range []struct{ name, original, normalized string }{
		{"全角", "ＡＰＩ＿ＫＥＹ＝ｓｋ１２３", "API_KEY=sk123"},
		{"大小写", "PassWord=Hunter2", "password=hunter2"},
		{"零宽", "pass​word=Hunter2", "password=Hunter2"},
	} {
		before, after := strings.Repeat("甲", 50), strings.Repeat("乙", 50)
		content := []rune(before + tc.original + after)
		start := utf8.RuneCountInString(before)
		end := start + utf8.RuneCountInString(tc.original)
		hit, window := Extract(tc.normalized, engineContext(content, start, end), locationOf(start, end))
		if hit != tc.original {
			t.Fatalf("%s: 原文应取内容里的实际片段 %q，得到 %q", tc.name, tc.original, hit)
		}
		if window != before+tc.original+after {
			t.Fatalf("%s: 前后文应以位置为准: %q", tc.name, window)
		}
	}
}

// 引擎前后文在命中起点超过 500 时开头带“…”：起点 500 不带、501 带，偏移差一位。
func TestExtractPositionBoundaryAt500And501(t *testing.T) {
	for _, start := range []int{500, 501} {
		before := strings.Repeat("前", start)
		hit := "ＳＥＣＲＥＴ"
		content := []rune(before + hit + strings.Repeat("后", 600))
		end := start + utf8.RuneCountInString(hit)
		ctx := engineContext(content, start, end)
		if strings.HasPrefix(ctx, "…") != (start > 500) {
			t.Fatalf("start=%d: 引擎前后文前缀不符合预期", start)
		}
		gotHit, window := Extract("secret", ctx, locationOf(start, end))
		if gotHit != hit {
			t.Fatalf("start=%d: 原文切片错位: %q", start, gotHit)
		}
		want := "…" + strings.Repeat("前", ContextRunes) + hit + strings.Repeat("后", ContextRunes) + "…"
		if window != want {
			t.Fatalf("start=%d: 前后文错位: %q", start, window)
		}
	}
}

func TestExtractHitAtStartOfLongContent(t *testing.T) {
	hit := "ＡＫＩＡ密钥"
	content := []rune(hit + strings.Repeat("正文", 1500))
	end := utf8.RuneCountInString(hit)
	gotHit, window := Extract("akia密钥", engineContext(content, 0, end), locationOf(0, end))
	if gotHit != hit || !strings.HasPrefix(window, hit) || strings.HasPrefix(window, "…") || !strings.HasSuffix(window, "…") {
		t.Fatalf("命中在开头时从头保留、结尾截断: hit=%q window=%q", gotHit, window)
	}
	if utf8.RuneCountInString(window) != end+ContextRunes+1 {
		t.Fatalf("窗口长度: %d", utf8.RuneCountInString(window))
	}
}

func TestExtractWithoutPositionSearchesThenKeepsTheMiddle(t *testing.T) {
	ctx := strings.Repeat("z", 300) + " api_key=sk-test-123456 " + strings.Repeat("y", 300)
	hit, window := Extract("api_key=sk-test-123456", ctx, "input")
	if hit != "api_key=sk-test-123456" || !strings.Contains(window, " api_key=sk-test-123456 ") ||
		utf8.RuneCountInString(window) != 2*ContextRunes+len("api_key=sk-test-123456")+2 {
		t.Fatalf("没有位置时按原文查找: %q %d", hit, utf8.RuneCountInString(window))
	}
	middle := strings.Repeat("a", 500) + "MID" + strings.Repeat("b", 500)
	if _, window := Extract("not-in-context", middle, ""); !strings.Contains(window, "MID") ||
		utf8.RuneCountInString(window) > 2*ContextRunes+len("not-in-context")+2 {
		t.Fatalf("查不到时取中段: %q", window)
	}
}

// 位置超出前后文范围（不是引擎窗口格式）时不能用位置，退回查找。
func TestExtractFallsBackWhenPositionOutOfRange(t *testing.T) {
	ctx := "short context with token=abc123 inside"
	hit, window := Extract("token=abc123", ctx, "content[900:912]")
	if hit != "token=abc123" || window != ctx {
		t.Fatalf("位置超出范围时退回查找: %q %q", hit, window)
	}
	hit, _ = Extract("token=abc123", ctx, "content[5:5]")
	if hit != "token=abc123" {
		t.Fatalf("空区间不能当位置用: %q", hit)
	}
}

func TestExtractCapsVeryLongHit(t *testing.T) {
	hit := strings.Repeat("长", RawMaxRunes+1000)
	content := []rune("头" + hit + "尾")
	_, window := Extract(hit, engineContext(content, 1, 1+len([]rune(hit))), locationOf(1, 1+len([]rune(hit))))
	if n := utf8.RuneCountInString(window); n > RawMaxRunes+2*ContextRunes+2 || !strings.HasPrefix(window, "头长") || !strings.HasSuffix(window, "…") {
		t.Fatalf("超长命中的前后文封顶并标记截断: %d", n)
	}
}

func TestStoredTextDropsNULForPostgresJSONB(t *testing.T) {
	if got := Stored("a\x00b"); got != "ab" {
		t.Fatalf("NUL 字符会让 jsonb 写入失败，必须去掉: %q", got)
	}
	if _, window := Extract("x\x00y", "pre x\x00y post", ""); strings.Contains(window, "\x00") || !strings.Contains(window, "pre xy post") {
		t.Fatalf("前后文同样去掉 NUL: %q", window)
	}
}

func TestIdentityUsesFirstNonEmptyLegacyBasis(t *testing.T) {
	sum := sha256.Sum256([]byte("ey****J9（36 位）"))
	if got := Identity("", "ey****J9（36 位）", "other"); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("证据身份取第一个非空的旧口径字段: %q", got)
	}
	if got := Identity("", ""); got != "" {
		t.Fatalf("旧口径没有证据身份时为空: %q", got)
	}
}

func rawFinding(i, size int) map[string]any {
	return map[string]any{
		"type": "pii", "rule_id": "pii_phone", IdentityKey: "",
		FieldRawEvidence:      strings.Repeat("r", size/2),
		FieldEvidenceContext:  strings.Repeat("c", size-size/2),
		"raw_evidence_sha256": strconv.Itoa(i),
	}
}

// 每个事件的原文（命中片段加前后文）按命中顺序累计，超过 256KB 的命中不存原文、标 raw_evidence_omitted。
func TestLimitEventRawKeepsEarlierHitsWithinBudget(t *testing.T) {
	findings := []map[string]any{}
	for i := 0; i < 300; i++ {
		findings = append(findings, rawFinding(i, 1024))
	}
	semantic := map[string]any{"type": "semantic_attack", FieldEvidenceContext: strings.Repeat("s", 4096)}
	findings = append(findings, semantic)
	LimitEventRaw(findings)
	total, kept := 0, 0
	for i, f := range findings[:300] {
		raw, hasRaw := f[FieldRawEvidence].(string)
		ctx, _ := f[FieldEvidenceContext].(string)
		total += len(raw) + len(ctx)
		if hasRaw {
			kept++
			if f[FieldRawEvidenceOmitted] != nil {
				t.Fatalf("finding %d 保留原文却标了省略", i)
			}
		} else if f[FieldRawEvidenceOmitted] != true || f[FieldEvidenceContext] != nil || f["raw_evidence_sha256"] != strconv.Itoa(i) {
			t.Fatalf("finding %d 超出总量：不存原文和前后文、标省略、哈希保留: %#v", i, f)
		}
	}
	if total > MaxEventRawBytes || kept != MaxEventRawBytes/1024 {
		t.Fatalf("总量 %d 字节、保留 %d 条，应不超过 %d 字节、保留前 %d 条", total, kept, MaxEventRawBytes, MaxEventRawBytes/1024)
	}
	for i := 0; i < kept; i++ {
		if _, ok := findings[i][FieldRawEvidence]; !ok {
			t.Fatalf("按命中顺序累计：前 %d 条应保留，第 %d 条丢了", kept, i)
		}
	}
	if semantic[FieldEvidenceContext] == nil || semantic[FieldRawEvidenceOmitted] != nil {
		t.Fatal("语义类的打码前后文不是原文，不计入也不剔除")
	}
}

// 剔除名单与写入字段是同一组常量：写入侧用到的每个原文字段都会被剔除，哈希、证据身份、标记保留。
func TestStripRawRemovesEveryRawFieldAtAnyDepth(t *testing.T) {
	finding := map[string]any{
		FieldRawEvidence: "SECRET-RAW", FieldEvidenceContext: "ctx SECRET-RAW ctx", FieldRawEvidenceTruncated: true,
		FieldRawEvidenceOmitted: true, IdentityKey: "abc", "raw_evidence_sha256": "h1", "evidence_context_sha256": "h2",
		"redacted_evidence": "SE****AW",
	}
	summary := map[string]any{
		"findings": []any{finding}, "raw_findings": []map[string]any{finding}, "primary_finding": finding,
		"matched": map[string]any{"findings": []any{finding}},
	}
	stripped := StripRaw(summary)
	encoded, _ := json.Marshal(stripped)
	if strings.Contains(string(encoded), "SECRET-RAW") {
		t.Fatalf("剔除后仍有原文: %s", encoded)
	}
	for _, key := range RawFields {
		if strings.Contains(string(encoded), `"`+key+`"`) {
			t.Fatalf("剔除后仍有字段 %s: %s", key, encoded)
		}
	}
	for _, keep := range []string{"raw_evidence_sha256", "evidence_context_sha256", IdentityKey, FieldRawEvidenceOmitted, "redacted_evidence"} {
		if !strings.Contains(string(encoded), `"`+keep+`"`) {
			t.Fatalf("不该剔除 %s: %s", keep, encoded)
		}
	}
	if finding[FieldRawEvidence] != "SECRET-RAW" {
		t.Fatal("剔除返回副本，不改原对象")
	}
	if len(RawFields) != 3 {
		t.Fatalf("剔除名单变了要同步改读取侧和外发口径: %v", RawFields)
	}
}

// 主命中不再整条复制原文：引用 findings 里的位置，原文只存一份。
func TestPrimaryReferenceDropsRawAndPointsAtFinding(t *testing.T) {
	item := map[string]any{"rule_id": "r1", FieldRawEvidence: "RAW", FieldEvidenceContext: "CTX", "raw_evidence_sha256": "h"}
	ref := PrimaryReference(item, 7)
	if ref[FieldRawEvidence] != nil || ref[FieldEvidenceContext] != nil || ref["rule_id"] != "r1" || ref["raw_evidence_sha256"] != "h" || ref[FieldFindingsIndex] != 7 {
		t.Fatalf("主命中引用: %#v", ref)
	}
	if item[FieldRawEvidence] != "RAW" {
		t.Fatal("不改原命中")
	}
}

// 位置与前后文不是同一段内容时（流式输出分段检测把位置改成了整段输出的偏移），按位置截出的文字与引擎
// 命中词对不上：先在前后文里查找命中词，找到就用找到的位置；查不到才信位置（归一化关键字）。
func TestExtractPrefersEngineTextWhenPositionPointsElsewhere(t *testing.T) {
	key := "sk-proj-AbCdEf0123456789AbCdEf0123456789"
	segment := []rune(strings.Repeat("前", 100) + key + strings.Repeat("后", 800))
	ctx := engineContext(segment, 100, 100+len(key))
	shifted := locationOf(31744+100, 31744+100+len(key)) // 第二段起点 32768-1024=31744
	hit, window := Extract(key, ctx, shifted)
	want := strings.Repeat("前", 100) + key + strings.Repeat("后", ContextRunes) + "…"
	if hit != key || window != want {
		t.Fatalf("位置错位时应按命中词定位:\n hit=%q\n got=%q\nwant=%q", hit, window, want)
	}
}

// 主命中和阻断依据的那条先占预算，其余命中再按顺序：它们排在后面、总量超限时也保留原文。
func TestLimitEventRawReservesPrimaryAndBlockingFirst(t *testing.T) {
	findings := []map[string]any{}
	for i := 0; i < 300; i++ {
		findings = append(findings, rawFinding(i, 1024))
	}
	LimitEventRaw(findings, 299, 150, 299, -1, 1000)
	for _, index := range []int{299, 150} {
		if findings[index][FieldRawEvidence] == nil || findings[index][FieldRawEvidenceOmitted] != nil {
			t.Fatalf("预留的第 %d 条应保留原文: %#v", index, findings[index])
		}
	}
	total, kept := 0, 0
	for _, f := range findings {
		raw, ok := f[FieldRawEvidence].(string)
		ctx, _ := f[FieldEvidenceContext].(string)
		total += len(raw) + len(ctx)
		if ok {
			kept++
		}
	}
	if total > MaxEventRawBytes || kept != MaxEventRawBytes/1024 || findings[0][FieldRawEvidence] == nil || findings[255][FieldRawEvidence] != nil {
		t.Fatalf("预留后其余按顺序填满: total=%d kept=%d", total, kept)
	}
}

// 没有可用位置、按命中词查找时，同词多次出现定位到第一处。
func TestExtractSearchFallbackUsesFirstOccurrence(t *testing.T) {
	ctx := "第一处 token=abc123 中间" + strings.Repeat("间", 300) + "第二处 token=abc123 结尾"
	_, window := Extract("token=abc123", ctx, "")
	if !strings.Contains(window, "第一处 token=abc123") || strings.Contains(window, "第二处") {
		t.Fatalf("应定位到第一处: %q", window)
	}
}
