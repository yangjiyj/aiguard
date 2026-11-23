package corpusscan

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// 批次上限与引擎接口一致（规格 5.3）：每批最多 256 条、文本合计不超过 4 MB。
const (
	MaxBatchItems = 256
	MaxBatchBytes = 4 << 20
	// 单个扫描单位超过一批的上限时无法送检，记为未扫描。
	MaxUnitBytes = MaxBatchBytes
	// 报告里最多保留的命中样例与未扫描行号。
	MaxSamples         = 200
	MaxUnscannedListed = 1000
	// 等待检测结果期间最多暂存的行字节数；超过就先把当前批次送检，避免坏行堆积占满内存。
	maxBufferedBytes = 8 << 20
	// 文档按段落切分；单段超过上限时在字符边界上再切。
	maxParagraphBytes = 64 << 10
)

// ErrEngineMismatch 表示引擎返回的结果和送检文本对不上；任务失败，不写出可能错位的副本。
var ErrEngineMismatch = errors.New("corpus engine result does not match the submitted text")

// EngineItem 是送给引擎的一条文本。
type EngineItem struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// EngineFinding 是引擎返回的一处命中（字符下标），不含原值。
type EngineFinding struct {
	Type     string `json:"type"`
	Label    string `json:"label"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Severity string `json:"severity"`
}

// EngineResult 是一条文本的检测结果。
type EngineResult struct {
	ID         string          `json:"id"`
	Findings   []EngineFinding `json:"findings"`
	MaskedText string          `json:"masked_text"`
	Incomplete bool            `json:"incomplete"`
}

// EngineBatch 是一批的检测结果。
type EngineBatch struct {
	Items           []EngineResult `json:"items"`
	RulePackVersion string         `json:"rule_pack_version"`
}

// Engine 抽象 security-engine 的 /internal/corpus/scan，便于测试替换。
type Engine interface {
	Scan(ctx context.Context, items []EngineItem) (EngineBatch, error)
}

// Sample 是报告里的一条命中样例：只有类型、位置和打码片段。
type Sample struct {
	Line    int64  `json:"line"`
	Field   string `json:"field"`
	Type    string `json:"type"`
	Label   string `json:"label"`
	Start   int    `json:"start"`
	End     int    `json:"end"`
	Preview string `json:"preview"`
}

// TypeStat 是按类型的统计：命中次数和含该类型的条数。
type TypeStat struct {
	Type    string `json:"type"`
	Label   string `json:"label"`
	Hits    int64  `json:"hits"`
	Records int64  `json:"records"`
}

// UnscannedLine 是一条未扫描记录。
type UnscannedLine struct {
	Line   int64  `json:"line"`
	Reason string `json:"reason"`
}

// Progress 是扫描进度。
type Progress struct {
	ProcessedBytes    int64 `json:"processed_bytes"`
	TotalRecords      int64 `json:"total_records"`
	ScannedRecords    int64 `json:"scanned_records"`
	HitRecords        int64 `json:"hit_records"`
	UnscannedRecords  int64 `json:"unscanned_records"`
	IncompleteRecords int64 `json:"incomplete_records"`
}

// Report 是扫描结果汇总。
type Report struct {
	Progress
	Stats              []TypeStat      `json:"stats"`
	Samples            []Sample        `json:"samples"`
	Unscanned          []UnscannedLine `json:"unscanned"`
	UnscannedTruncated bool            `json:"unscanned_truncated"`
	RulePackVersion    string          `json:"rule_pack_version"`
}

// Options 控制一次扫描。
type Options struct {
	Format string
	Engine Engine
	// OnBatch 在每个批次写出后回调；返回错误会中止扫描（取消、租约丢失）。
	OnBatch func(Progress) error
	// MaxBatch 覆盖每批条数（测试用），0 表示 MaxBatchItems。
	MaxBatch int
}

// 未扫描原因。
const (
	ReasonUnparsable = "unparsable"
	ReasonTooLong    = "line_too_long"
	ReasonUnitTooBig = "field_too_large"
)

type pendingLine struct {
	number       int64
	raw          []byte
	newline      []byte
	units        []Unit
	results      []*EngineResult
	replacements [][]Replacement
	pending      int
}

type scanner struct {
	opts       Options
	out        *bufio.Writer
	report     Report
	stats      map[string]*TypeStat
	lines      []*pendingLine
	buffered   int
	batch      []EngineItem
	batchRefs  []unitRef
	batchBytes int
}

type unitRef struct {
	line *pendingLine
	unit int
}

// Run 扫描 src，按原格式把脱敏副本写到 dst，返回报告。
// 同一时刻只有一个批次请求在途；行按原顺序写出，未扫描的行原样保留。
func Run(ctx context.Context, src io.Reader, dst io.Writer, opts Options) (Report, error) {
	if opts.Engine == nil {
		return Report{}, errors.New("corpus engine is required")
	}
	if opts.MaxBatch <= 0 || opts.MaxBatch > MaxBatchItems {
		opts.MaxBatch = MaxBatchItems
	}
	s := &scanner{opts: opts, out: bufio.NewWriterSize(dst, 256<<10), stats: map[string]*TypeStat{}}
	s.report.Stats = []TypeStat{}
	s.report.Samples = []Sample{}
	s.report.Unscanned = []UnscannedLine{}
	reader := bufio.NewReaderSize(src, 256<<10)
	var number int64
	for {
		if err := ctx.Err(); err != nil {
			return s.report, err
		}
		line, tooLong, more, readErr := nextLine(reader)
		if readErr != nil && readErr != io.EOF {
			return s.report, readErr
		}
		if len(line) == 0 && readErr == io.EOF {
			break
		}
		number++
		if tooLong {
			if err := s.copyTooLong(ctx, reader, number, line, more); err != nil {
				return s.report, err
			}
		} else if err := s.addLine(ctx, number, line); err != nil {
			return s.report, err
		}
		if readErr == io.EOF {
			break
		}
	}
	if err := s.flushBatch(ctx); err != nil {
		return s.report, err
	}
	if err := s.writeReady(); err != nil {
		return s.report, err
	}
	if err := s.out.Flush(); err != nil {
		return s.report, err
	}
	s.finishStats()
	return s.report, nil
}

// nextLine 读一行（含行尾换行符）。超过 MaxLineBytes 时返回 tooLong；more 表示这一行还有没读完的部分。
func nextLine(r *bufio.Reader) (line []byte, tooLong, more bool, err error) {
	for {
		chunk, e := r.ReadSlice('\n')
		line = append(line, chunk...)
		if e == bufio.ErrBufferFull {
			if len(line) > MaxLineBytes+2 {
				return line, true, true, nil
			}
			continue
		}
		body, _ := splitNewline(line)
		return line, len(body) > MaxLineBytes, false, e
	}
}

func splitNewline(line []byte) ([]byte, []byte) {
	if n := len(line); n > 0 && line[n-1] == '\n' {
		if n > 1 && line[n-2] == '\r' {
			return line[:n-2], line[n-2:]
		}
		return line[:n-1], line[n-1:]
	}
	return line, nil
}

// copyTooLong 把超长行原样写进副本。先把排队的批次送检、写出之前的行，保证顺序不变。
func (s *scanner) copyTooLong(ctx context.Context, r *bufio.Reader, number int64, prefix []byte, more bool) error {
	if err := s.flushBatch(ctx); err != nil {
		return err
	}
	if err := s.writeReady(); err != nil {
		return err
	}
	if _, err := s.out.Write(prefix); err != nil {
		return err
	}
	s.report.ProcessedBytes += int64(len(prefix))
	for more {
		chunk, e := r.ReadSlice('\n')
		if _, err := s.out.Write(chunk); err != nil {
			return err
		}
		s.report.ProcessedBytes += int64(len(chunk))
		if e != bufio.ErrBufferFull {
			if e != nil && e != io.EOF {
				return e
			}
			more = false
		}
	}
	s.report.TotalRecords++
	s.markUnscanned(number, ReasonTooLong)
	return nil
}

func (s *scanner) addLine(ctx context.Context, number int64, data []byte) error {
	s.report.ProcessedBytes += int64(len(data))
	raw, newline := splitNewline(data)
	line := &pendingLine{number: number, raw: append([]byte(nil), raw...), newline: append([]byte(nil), newline...)}
	s.lines = append(s.lines, line)
	s.buffered += len(data)
	// 空行和 csv 表头不是记录：不计数、不扫描，原样保留。
	if len(raw) == 0 || (s.opts.Format == FormatCSV && number == 1) {
		return s.afterAppend(ctx)
	}
	s.report.TotalRecords++
	units, err := ParseLine(s.opts.Format, line.raw)
	if err != nil {
		s.markUnscanned(number, ReasonUnparsable)
		return s.afterAppend(ctx)
	}
	for _, unit := range units {
		if len(unit.Text) > MaxUnitBytes {
			s.markUnscanned(number, ReasonUnitTooBig)
			return s.afterAppend(ctx)
		}
	}
	if len(units) == 0 {
		s.report.ScannedRecords++
		return s.afterAppend(ctx)
	}
	line.units = units
	line.results = make([]*EngineResult, len(units))
	line.pending = len(units)
	for index, unit := range units {
		if len(s.batch) >= s.opts.MaxBatch || s.batchBytes+len(unit.Text) > MaxBatchBytes {
			if err := s.flushBatch(ctx); err != nil {
				return err
			}
		}
		s.batch = append(s.batch, EngineItem{ID: strconv.Itoa(len(s.batch)), Text: unit.Text})
		s.batchRefs = append(s.batchRefs, unitRef{line: line, unit: index})
		s.batchBytes += len(unit.Text)
	}
	return s.afterAppend(ctx)
}

func (s *scanner) afterAppend(ctx context.Context) error {
	if s.buffered > maxBufferedBytes {
		if err := s.flushBatch(ctx); err != nil {
			return err
		}
	}
	return s.writeReady()
}

func (s *scanner) markUnscanned(number int64, reason string) {
	s.report.UnscannedRecords++
	if len(s.report.Unscanned) < MaxUnscannedListed {
		s.report.Unscanned = append(s.report.Unscanned, UnscannedLine{Line: number, Reason: reason})
	} else {
		s.report.UnscannedTruncated = true
	}
}

func (s *scanner) flushBatch(ctx context.Context) error {
	if len(s.batch) == 0 {
		return nil
	}
	batch, err := s.opts.Engine.Scan(ctx, s.batch)
	if err != nil {
		return err
	}
	if len(batch.Items) != len(s.batch) {
		return fmt.Errorf("%w: %d results for %d items", ErrEngineMismatch, len(batch.Items), len(s.batch))
	}
	if batch.RulePackVersion != "" {
		s.report.RulePackVersion = batch.RulePackVersion
	}
	for index := range batch.Items {
		result := batch.Items[index]
		if result.ID != s.batch[index].ID {
			return fmt.Errorf("%w: results out of order", ErrEngineMismatch)
		}
		ref := s.batchRefs[index]
		ref.line.results[ref.unit] = &result
		ref.line.pending--
		if ref.line.pending == 0 {
			if err := s.completeLine(ref.line); err != nil {
				return err
			}
		}
	}
	s.batch = s.batch[:0]
	s.batchRefs = s.batchRefs[:0]
	s.batchBytes = 0
	if err := s.writeReady(); err != nil {
		return err
	}
	if s.opts.OnBatch != nil {
		return s.opts.OnBatch(s.report.Progress)
	}
	return nil
}

// completeLine 在一行所有单位都拿到结果后，按字符下标算出替换，并与引擎的替换结果核对。
func (s *scanner) completeLine(line *pendingLine) error {
	line.replacements = make([][]Replacement, len(line.units))
	for index, result := range line.results {
		unit := line.units[index]
		replacements := make([]Replacement, 0, len(result.Findings))
		for _, finding := range result.Findings {
			replacements = append(replacements, Replacement{Start: finding.Start, End: finding.End, Text: "[" + finding.Label + "]"})
		}
		if !ValidReplacements(unit.Text, replacements) || ApplyReplacements(unit.Text, replacements) != result.MaskedText {
			return fmt.Errorf("%w: line %d", ErrEngineMismatch, line.number)
		}
		line.replacements[index] = replacements
	}
	s.report.ScannedRecords++
	hit, incomplete := false, false
	seenTypes := map[string]bool{}
	for index, result := range line.results {
		incomplete = incomplete || result.Incomplete
		unit := line.units[index]
		for _, finding := range result.Findings {
			hit = true
			stat := s.stats[finding.Type]
			if stat == nil {
				stat = &TypeStat{Type: finding.Type, Label: finding.Label}
				s.stats[finding.Type] = stat
			}
			stat.Hits++
			if !seenTypes[finding.Type] {
				seenTypes[finding.Type] = true
				stat.Records++
			}
			if len(s.report.Samples) < MaxSamples {
				startByte, endByte, _ := CharSpanToBytes(unit.Text, finding.Start, finding.End)
				s.report.Samples = append(s.report.Samples, Sample{
					Line: line.number, Field: unit.Field, Type: finding.Type, Label: finding.Label,
					Start: finding.Start, End: finding.End, Preview: MaskPreview(unit.Text[startByte:endByte]),
				})
			}
		}
	}
	if hit {
		s.report.HitRecords++
	}
	if incomplete {
		s.report.IncompleteRecords++
	}
	return nil
}

// writeReady 按行号顺序写出已完成的行；遇到第一条还在等结果的行就停。
func (s *scanner) writeReady() error {
	written := 0
	for _, line := range s.lines {
		if line.pending > 0 {
			break
		}
		output := line.raw
		if line.replacements != nil {
			output = RewriteLine(line.raw, line.units, line.replacements)
		}
		if _, err := s.out.Write(output); err != nil {
			return err
		}
		if _, err := s.out.Write(line.newline); err != nil {
			return err
		}
		s.buffered -= len(line.raw) + len(line.newline)
		written++
	}
	s.lines = s.lines[written:]
	return nil
}

func (s *scanner) finishStats() {
	stats := make([]TypeStat, 0, len(s.stats))
	for _, stat := range s.stats {
		stats = append(stats, *stat)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Hits != stats[j].Hits {
			return stats[i].Hits > stats[j].Hits
		}
		return stats[i].Type < stats[j].Type
	})
	s.report.Stats = stats
}

// SplitDocumentText 把引擎提取出的文档文本按段落切成行，供 txt 格式扫描。
// 空段落丢弃；超长段落在字符边界上再切，避免单条超出批次上限。
func SplitDocumentText(text string) string {
	var b strings.Builder
	for _, paragraph := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		paragraph = strings.TrimRight(paragraph, " \t\r")
		if strings.TrimSpace(paragraph) == "" {
			continue
		}
		for len(paragraph) > maxParagraphBytes {
			cut := maxParagraphBytes
			for cut > 0 && !utf8.RuneStart(paragraph[cut]) {
				cut--
			}
			b.WriteString(paragraph[:cut])
			b.WriteByte('\n')
			paragraph = paragraph[cut:]
		}
		b.WriteString(paragraph)
		b.WriteByte('\n')
	}
	return b.String()
}

// MarshalReport 生成报告文件（JSON）；meta 里放任务编号、文件名等元数据。
func MarshalReport(report Report, meta map[string]any) ([]byte, error) {
	document := map[string]any{
		"total_records":       report.TotalRecords,
		"scanned_records":     report.ScannedRecords,
		"hit_records":         report.HitRecords,
		"unscanned_records":   report.UnscannedRecords,
		"incomplete_records":  report.IncompleteRecords,
		"processed_bytes":     report.ProcessedBytes,
		"stats":               report.Stats,
		"samples":             report.Samples,
		"unscanned":           report.Unscanned,
		"unscanned_truncated": report.UnscannedTruncated,
		"rule_pack_version":   report.RulePackVersion,
	}
	for key, value := range meta {
		document[key] = value
	}
	return json.MarshalIndent(document, "", "  ")
}
