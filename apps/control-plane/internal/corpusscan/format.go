// Package corpusscan 实现训练语料扫描的解析与改写（规格第 5.2、5.4 节）。
//
// 解析器把 jsonl / csv / txt 逐行拆成「扫描单位」，每个单位带它在本行里的字节区间；
// 引擎按字符下标返回命中后，改写器在原字段上替换，其他字节原样保留：
//   - jsonl 用 token 级改写，只替换已知文本字段的字符串字面量，键顺序、空白、其余字段不变；
//   - csv 只替换单元格内容，重新加引号时保持 RFC 4180；
//   - txt 每行一个单位。
//
// 无法解析的行（坏 JSON、坏引号、非 UTF-8、超过单行上限）记为「未扫描」，原样写入副本。
package corpusscan

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// 单行上限：超过的行不读入内存，记为未扫描并原样复制（规格 5.4）。
const MaxLineBytes = 1 << 20

// 支持的格式。
const (
	FormatJSONL = "jsonl"
	FormatCSV   = "csv"
	FormatTXT   = "txt"
	FormatDOCX  = "docx"
	FormatPDF   = "pdf"
	FormatXLSX  = "xlsx"
)

// 单个文件上限：jsonl/csv/txt 2 GB；文档类沿用文件 DLP 的 100 MB。
const (
	MaxTextFileBytes     int64 = 2 << 30
	MaxDocumentFileBytes int64 = 100 << 20
)

// FormatFromFileName 按扩展名识别格式；不支持时返回空串。
func FormatFromFileName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, format := range []string{FormatJSONL, FormatCSV, FormatTXT, FormatDOCX, FormatPDF, FormatXLSX} {
		if strings.HasSuffix(lower, "."+format) {
			return format
		}
	}
	return ""
}

// MaxFileBytes 返回该格式允许的最大字节数。
func MaxFileBytes(format string) int64 {
	switch format {
	case FormatDOCX, FormatPDF, FormatXLSX:
		return MaxDocumentFileBytes
	case FormatJSONL, FormatCSV, FormatTXT:
		return MaxTextFileBytes
	}
	return 0
}

// IsDocument 表示该格式需要先由引擎提取文本，副本输出为 .txt。
func IsDocument(format string) bool {
	return format == FormatDOCX || format == FormatPDF || format == FormatXLSX
}

// Unit 是一行里的一个扫描单位。Start/End 是该单位在行内的字节区间（替换时覆盖这段字节）；
// Text 是解码后的文本（jsonl 字符串字面量解码后的值、csv 去掉引号后的单元格）。
type Unit struct {
	Field string
	Start int
	End   int
	Text  string
	kind  unitKind
	// quoted 表示 csv 单元格原本带引号；改写后保持同样的写法。
	quoted bool
}

type unitKind int

const (
	kindRaw unitKind = iota
	kindJSONString
	kindCSVCell
)

// Replacement 是引擎返回的一处替换：Start/End 是 Unit.Text 里的字符（Unicode 码点）下标。
type Replacement struct {
	Start int
	End   int
	Text  string
}

// ErrUnparsable 表示该行无法按格式解析。
var ErrUnparsable = errors.New("corpus line is not parsable")

// ParseLine 把一行（不含行尾换行符）拆成扫描单位。
func ParseLine(format string, line []byte) ([]Unit, error) {
	if !utf8.Valid(line) {
		return nil, ErrUnparsable
	}
	switch format {
	case FormatJSONL:
		return parseJSONLLine(line)
	case FormatCSV:
		return parseCSVLine(line)
	default:
		return []Unit{{Field: "line", Start: 0, End: len(line), Text: string(line), kind: kindRaw}}, nil
	}
}

// RewriteLine 按单位的替换结果改写一行。units 与 replacements 一一对应；没有替换的单位传 nil。
func RewriteLine(line []byte, units []Unit, replacements [][]Replacement) []byte {
	type edit struct {
		start, end int
		value      []byte
	}
	var edits []edit
	for index, unit := range units {
		if index >= len(replacements) || len(replacements[index]) == 0 {
			continue
		}
		masked := ApplyReplacements(unit.Text, replacements[index])
		if masked == unit.Text {
			continue
		}
		var encoded []byte
		switch unit.kind {
		case kindJSONString:
			encoded = encodeJSONString(masked)
		case kindCSVCell:
			encoded = encodeCSVCell(masked, unit.quoted)
		default:
			encoded = []byte(masked)
		}
		edits = append(edits, edit{unit.Start, unit.End, encoded})
	}
	if len(edits) == 0 {
		return line
	}
	out := make([]byte, 0, len(line))
	cursor := 0
	for _, e := range edits {
		out = append(out, line[cursor:e.start]...)
		out = append(out, e.value...)
		cursor = e.end
	}
	return append(out, line[cursor:]...)
}

// ApplyReplacements 在文本上应用按字符下标给出的替换。下标越界、重叠或倒序的项被忽略。
func ApplyReplacements(text string, replacements []Replacement) string {
	if len(replacements) == 0 {
		return text
	}
	offsets := runeByteOffsets(text)
	runes := len(offsets) - 1
	var b strings.Builder
	cursor := 0
	lastEnd := 0
	for _, r := range replacements {
		if r.Start < lastEnd || r.Start < 0 || r.End <= r.Start || r.End > runes {
			continue
		}
		start, end := offsets[r.Start], offsets[r.End]
		b.WriteString(text[cursor:start])
		b.WriteString(r.Text)
		cursor = end
		lastEnd = r.End
	}
	b.WriteString(text[cursor:])
	return b.String()
}

// CharSpanToBytes 把字符下标换算成 UTF-8 字节偏移；越界时返回 ok=false。
func CharSpanToBytes(text string, start, end int) (int, int, bool) {
	offsets := runeByteOffsets(text)
	if start < 0 || end < start || end >= len(offsets) {
		return 0, 0, false
	}
	return offsets[start], offsets[end], true
}

// runeByteOffsets 返回每个码点的起始字节偏移，末尾追加 len(text)。
// Python 的 str 下标按码点计数，非法 UTF-8 已在 ParseLine 拒绝，所以两边一致。
func runeByteOffsets(text string) []int {
	offsets := make([]int, 0, len(text)+1)
	for index := range text {
		offsets = append(offsets, index)
	}
	return append(offsets, len(text))
}

// MaskPreview 生成命中样例里的打码片段：保留首尾各一个字符，中间用星号，不暴露原值。
func MaskPreview(value string) string {
	runes := []rune(value)
	switch {
	case len(runes) == 0:
		return ""
	case len(runes) <= 2:
		return strings.Repeat("*", len(runes))
	case len(runes) <= 6:
		return string(runes[0]) + strings.Repeat("*", len(runes)-2) + string(runes[len(runes)-1])
	default:
		return string(runes[0]) + strings.Repeat("*", 4) + string(runes[len(runes)-1])
	}
}
