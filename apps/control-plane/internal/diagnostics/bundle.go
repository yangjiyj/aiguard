package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/buildinfo"
)

// BundleSession 是导出诊断包所需的一次会话的全部数据。
type BundleSession struct {
	ID, TenantID, UserID  string
	Input                 Input
	Report                *Report
	Steps                 []Step
	Messages              json.RawMessage
	Host                  *HostSnapshot
	CreatedAt, FinishedAt time.Time
	Version               string // 网关版本；为空时读 buildinfo，取不到为 "unknown"
}

// BundleBuilder 供会话层调用，测试中可替换。
var BundleBuilder func(ctx context.Context, s BundleSession) ([]byte, error) = BuildBundle

// t15MaxBundleBytes 是诊断包大小上限（变量仅为便于测试）。
var t15MaxBundleBytes = 20 << 20

// t15RedactValue 递归脱敏解码后的 JSON 值：字符串走 Redact，敏感键的字符串值整体打码。
// 返回是否发生了修改。
func t15RedactValue(v any) (any, bool) {
	changed := false
	switch x := v.(type) {
	case string:
		r := Redact(x)
		return r, r != x
	case []any:
		for i := range x {
			nv, c := t15RedactValue(x[i])
			x[i], changed = nv, changed || c
		}
		return x, changed
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok && sensitiveKey(k) {
				if s != redacted {
					x[k], changed = redacted, true
				}
				continue
			}
			nv, c := t15RedactValue(e)
			x[k], changed = nv, changed || c
		}
		return x, changed
	}
	return v, false
}

// t15JSON 先把任意值转成通用 JSON 结构脱敏，再序列化（避免对已转义文本做正则）。
func t15JSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var g any
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, err
	}
	g, _ = t15RedactValue(g)
	return json.Marshal(g)
}

type t15StepLine struct {
	Tool            string          `json:"tool"`
	Args            json.RawMessage `json:"args,omitempty"`
	Summary         string          `json:"summary"`
	Error           string          `json:"error,omitempty"`
	Output          any             `json:"output,omitempty"`
	OutputTruncated bool            `json:"output_truncated,omitempty"`
}

// t15StepsJSONL 生成 steps.jsonl；outLimit<0 表示不截断，否则 output 超过 outLimit 字节即截断。
func t15StepsJSONL(steps []Step, outLimit int) ([]byte, bool, error) {
	var buf bytes.Buffer
	truncated := false
	for _, st := range steps {
		l := t15StepLine{Tool: st.Tool, Summary: st.Summary, Error: st.Err}
		if len(st.Args) > 0 && json.Valid(st.Args) {
			l.Args = st.Args
		}
		if len(st.Output) > 0 {
			if outLimit >= 0 && len(st.Output) > outLimit {
				s := strings.ToValidUTF8(string(st.Output[:outLimit]), "")
				l.Output, l.OutputTruncated = s, true
				truncated = true
			} else {
				var g any
				if json.Unmarshal(st.Output, &g) == nil {
					l.Output = g
				} else {
					l.Output = string(st.Output)
				}
			}
		}
		b, err := t15JSON(l)
		if err != nil {
			return nil, false, err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), truncated, nil
}

func t15Hash12(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}

func t15MessageTurns(m json.RawMessage) int {
	var arr []json.RawMessage
	if len(m) == 0 || json.Unmarshal(m, &arr) != nil {
		return 0
	}
	return len(arr)
}

// t15InputView 只保留请求编号或输入类型，不保留原文。
func t15InputView(in Input) map[string]any {
	ids := reqIDRe.FindAllString(in.Text+" "+in.Ref, -1)
	seen := map[string]bool{}
	uniq := []string{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			uniq = append(uniq, id)
		}
	}
	return map[string]any{"kind": in.Kind, "request_ids": uniq, "window_hours": in.WindowH}
}

func t15LevelCN(l Level) string {
	switch l {
	case LevelConfirmed:
		return "确定"
	case LevelSuspected:
		return "疑似"
	}
	return "无法判断"
}

func t15SevCN(s Severity) string {
	switch s {
	case SevError:
		return "错误"
	case SevWarn:
		return "警告"
	}
	return "正常"
}

func t15ReportMD(s BundleSession, version string) string {
	r := s.Report
	var b strings.Builder
	b.WriteString("# 诊断报告\n\n")
	fmt.Fprintf(&b, "- 会话：%s\n- 网关版本：%s\n- 档位：%s\n", s.ID, version, r.Tier)
	if !s.CreatedAt.IsZero() {
		fmt.Fprintf(&b, "- 会话时间：%s ~ %s\n", s.CreatedAt.Format(time.RFC3339), s.FinishedAt.Format(time.RFC3339))
	}
	iv := t15InputView(s.Input)
	fmt.Fprintf(&b, "- 输入类型：%v\n", iv["kind"])
	if ids := iv["request_ids"].([]string); len(ids) > 0 {
		fmt.Fprintf(&b, "- 请求编号：%s\n", strings.Join(ids, "、"))
	}
	b.WriteString("\n## 结论\n\n")
	if len(r.Findings) == 0 {
		fmt.Fprintf(&b, "未发现异常（正常项 %d 个）。\n\n", r.OKCount)
	}
	for i, f := range r.Findings {
		fmt.Fprintf(&b, "### %d. %s\n\n- 级别：%s\n- 严重程度：%s\n- 检查项：%s\n\n", i+1, f.Title, t15LevelCN(f.Level), t15SevCN(f.Severity), f.CheckID)
		if f.Impact != "" {
			fmt.Fprintf(&b, "**影响**\n\n%s\n\n", f.Impact)
		}
		if len(f.Advice) > 0 {
			b.WriteString("**建议**\n\n")
			for _, a := range f.Advice {
				if a.Link != "" {
					fmt.Fprintf(&b, "- %s（%s）\n", a.Text, a.Link)
				} else {
					fmt.Fprintf(&b, "- %s\n", a.Text)
				}
			}
			b.WriteString("\n")
		}
		if len(f.Excluded) > 0 {
			b.WriteString("**已排除**\n\n")
			for _, e := range f.Excluded {
				fmt.Fprintf(&b, "- %s\n", e)
			}
			b.WriteString("\n")
		}
		if len(f.Evidence) > 0 {
			b.WriteString("**证据**\n\n")
			for _, e := range f.Evidence {
				fmt.Fprintf(&b, "- [%s] %s：%s\n", e.Kind, e.Ref, e.Summary)
				if e.Raw != "" {
					fmt.Fprintf(&b, "  ```\n  %s\n  ```\n", strings.ReplaceAll(e.Raw, "\n", "\n  "))
				}
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("## 排查过程\n\n")
	steps := s.Steps
	if len(steps) == 0 {
		steps = r.Steps
	}
	for i, st := range steps {
		fmt.Fprintf(&b, "%d. `%s`：%s", i+1, st.Tool, st.Summary)
		if st.Err != "" {
			fmt.Fprintf(&b, "（失败：%s）", st.Err)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n## 档位与降级原因\n\n")
	fmt.Fprintf(&b, "- 档位：%s\n", r.Tier)
	if r.Degraded != "" {
		fmt.Fprintf(&b, "- 降级原因：%s\n", r.Degraded)
	} else {
		b.WriteString("- 降级原因：无\n")
	}
	return b.String()
}

type t15File struct {
	name string
	data []byte
}

// t15Assemble 生成 zip 字节。
func t15Assemble(s BundleSession, version string, outLimit int) ([]byte, bool, error) {
	steps, truncated, err := t15StepsJSONL(s.Steps, outLimit)
	if err != nil {
		return nil, false, err
	}
	reportJSON, err := t15JSON(struct {
		Report
		Input map[string]any `json:"input"`
	}{*s.Report, t15InputView(s.Input)})
	if err != nil {
		return nil, false, err
	}
	meta := map[string]any{
		"version":       version,
		"generated_at":  time.Now().UTC().Format(time.RFC3339),
		"created_at":    s.CreatedAt.UTC().Format(time.RFC3339),
		"finished_at":   s.FinishedAt.UTC().Format(time.RFC3339),
		"tenant_hash":   t15Hash12(s.TenantID),
		"message_turns": t15MessageTurns(s.Messages),
		"truncated":     truncated,
	}
	if truncated {
		meta["truncated_note"] = fmt.Sprintf("诊断包超过大小上限，steps.jsonl 中的 output 已截断至每条 %d 字节", outLimit)
	}
	metaJSON, err := t15JSON(meta)
	if err != nil {
		return nil, false, err
	}
	files := []t15File{
		{"report.json", reportJSON},
		{"report.md", []byte(Redact(t15ReportMD(s, version)))},
		{"steps.jsonl", steps},
	}
	if s.Host != nil {
		hj, err := t15JSON(s.Host)
		if err != nil {
			return nil, false, err
		}
		files = append(files, t15File{"host_snapshot.json", hj})
	}
	files = append(files, t15File{"meta.json", metaJSON})

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: s.FinishedAt})
		if err != nil {
			return nil, false, err
		}
		if _, err := w.Write(f.data); err != nil {
			return nil, false, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, false, err
	}
	return buf.Bytes(), truncated, nil
}

// t15VerifyClean 解压后逐文件再脱敏一遍，内容有变化说明有遗漏。
func t15VerifyClean(b []byte) error {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}
		dirty := false
		switch {
		case strings.HasSuffix(f.Name, ".json"):
			var g any
			if err := json.Unmarshal(data, &g); err != nil {
				return fmt.Errorf("诊断包 %s 不是合法 JSON: %w", f.Name, err)
			}
			_, dirty = t15RedactValue(g)
		case strings.HasSuffix(f.Name, ".jsonl"):
			for _, line := range bytes.Split(data, []byte("\n")) {
				if len(bytes.TrimSpace(line)) == 0 {
					continue
				}
				var g any
				if err := json.Unmarshal(line, &g); err != nil {
					return fmt.Errorf("诊断包 %s 含非法 JSON 行: %w", f.Name, err)
				}
				if _, c := t15RedactValue(g); c {
					dirty = true
				}
			}
		default:
			dirty = Redact(string(data)) != string(data)
		}
		if dirty {
			return fmt.Errorf("诊断包文件 %s 二次脱敏后内容仍有变化，已中止导出", f.Name)
		}
	}
	return nil
}

// BuildBundle 生成诊断包 zip。不含对话正文，所有文件均已脱敏。
func BuildBundle(ctx context.Context, s BundleSession) ([]byte, error) {
	if s.Report == nil {
		return nil, fmt.Errorf("会话没有诊断报告，无法导出")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	version := s.Version
	if version == "" {
		version = buildinfo.Current().Version
	}
	if version == "" {
		version = "unknown"
	}
	b, _, err := t15Assemble(s, version, -1)
	if err != nil {
		return nil, err
	}
	// 超限：逐步缩小每条 output 的上限直到装得下。
	for limit := 64 << 10; len(b) > t15MaxBundleBytes; limit /= 2 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if b, _, err = t15Assemble(s, version, limit); err != nil {
			return nil, err
		}
		if limit == 0 {
			if len(b) > t15MaxBundleBytes {
				return nil, fmt.Errorf("诊断包即使截断全部工具输出仍超过 %d 字节上限", t15MaxBundleBytes)
			}
			break
		}
	}
	if err := t15VerifyClean(b); err != nil {
		return nil, err
	}
	return b, nil
}
