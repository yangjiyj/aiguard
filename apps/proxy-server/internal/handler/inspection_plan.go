package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// 未识别（unknown）来源文本的送检窗口上限：前 15 窗送审 + 1 条截断除证。
// 2026-09 生产事故：一段 1.8MB 的 unknown 载荷连续滑行成 ~505 个裁判分片/请求，
// 每回合重发，直接灌爆补检队列；unknown 来源没有类型化上下文，收敛窗口数不损失
// 可定位的检测语义（注入类载荷集中于头部），其余部分显式留证而非静默吞掉。
const maxUnknownSourceWindowParts = 16

// Every code point is inspected; overlap preserves local evidence crossing a boundary.
func inspectionTextParts(text string) []string {
	runes := []rune(text)
	if len(runes) == 0 {
		return nil
	}
	parts := make([]string, 0, (len(runes)+3583)/3584)
	for start := 0; start < len(runes); start += 3584 {
		end := start + 4096
		if end > len(runes) {
			end = len(runes)
		}
		parts = append(parts, string(runes[start:end]))
		if end == len(runes) {
			break
		}
	}
	return parts
}

func truncateUnknownSourceWindows(original string, windows []string) []string {
	kept := append([]string(nil), windows[:maxUnknownSourceWindowParts-1]...)
	kept = append(kept, fmt.Sprintf("[检测范围说明] 未识别内容共 %d 个滑窗（%d 字符），已收敛为前 %d 窗送审，其余未送审。",
		len(windows), len([]rune(original)), maxUnknownSourceWindowParts-1))
	return kept
}

func copyInspectionPayload(payload map[string]interface{}) map[string]interface{} {
	p := make(map[string]interface{}, len(payload))
	for k, v := range payload {
		p[k] = v
	}
	c := map[string]interface{}{}
	if original, ok := payload["context"].(map[string]interface{}); ok {
		for k, v := range original {
			c[k] = v
		}
	}
	delete(c, "attachments")
	p["context"] = c
	return p
}

func buildInspectionPlan(payload map[string]interface{}, extracted ExtractedContent) ([]map[string]interface{}, error) {
	var tasks []map[string]interface{}
	messages := extracted.Messages
	if len(messages) == 0 {
		text, _ := payload["content"].(string)
		if !extracted.InspectionScopeKnown {
			messages = []ConvMessage{{Content: text, Source: "unknown"}}
		}
	}
	for _, m := range messages {
		if m.Source == "unknown" {
			m.Content = inspectionUnknownText(m.Content, extracted.Attachments)
		}
		if strings.TrimSpace(m.Content) == "" {
			continue
		}
		windows := inspectionTextParts(m.Content)
		if m.Source == "unknown" && len(windows) > maxUnknownSourceWindowParts {
			windows = truncateUnknownSourceWindows(m.Content, windows)
		}
		for index, text := range windows {
			p := copyInspectionPayload(payload)
			p["content"] = text
			p["content_source"] = m.Source
			inspectionMessageContext(p["context"].(map[string]interface{}), m, extracted)
			p["context"].(map[string]interface{})["inspection_content_offset"] = index * 3584
			p["inspection_source_part"] = index
			tasks = append(tasks, p)
		}
	}
	// Binary content never enters text windows. Identical attachment occurrences are
	// inspected once per request with all security-relevant metadata in the identity.
	seen := map[string]bool{}
	for _, att := range extracted.Attachments {
		raw, _ := json.Marshal([]interface{}{att.SHA256, att.FileName, att.ContentType, att.ReferenceID, att.DownloadURL, att.ContentSource, att.MessageIndex, att.SourcePath})
		key := string(raw)
		if att.SHA256 == "" {
			raw, _ = json.Marshal(att)
			key = string(raw)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		p := copyInspectionPayload(payload)
		p["content"] = ""
		p["content_source"] = attachmentInspectionMessage(att).Source
		inspectionAttachmentContext(p["context"].(map[string]interface{}), att, extracted)
		p["inspection_attachment"] = att
		tasks = append(tasks, p)
	}
	if len(tasks) == 0 && !extracted.InspectionScopeKnown {
		p := copyInspectionPayload(payload)
		p["content"] = ""
		tasks = append(tasks, p)
	}
	if len(tasks) > 32768 {
		return nil, fmt.Errorf("inspection_part_limit")
	}
	return tasks, nil
}

// Some protocol parsers preserve unrecognized image blocks as JSON text as well
// as attachments. Remove binary only when identical bytes exist in the separate
// inspection plan; keep all surrounding fields and unknown shapes for scanning.
func inspectionUnknownText(text string, attachments []ExtractedAttachment) string {
	known := map[[32]byte]bool{}
	for _, a := range attachments {
		if a.DataBase64 != "" {
			known[sha256.Sum256([]byte(a.DataBase64))] = true
		}
	}
	if len(known) == 0 {
		return text
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	var out bytes.Buffer
	for {
		var item interface{}
		err := decoder.Decode(&item)
		if err == io.EOF {
			break
		}
		if err != nil {
			return text
		}
		var scrub func(interface{}) interface{}
		scrub = func(v interface{}) interface{} {
			switch x := v.(type) {
			case map[string]interface{}:
				for k, value := range x {
					x[k] = scrub(value)
				}
			case []interface{}:
				for i, value := range x {
					x[i] = scrub(value)
				}
			case string:
				encoded := x
				if strings.HasPrefix(x, "data:") {
					if n := strings.IndexByte(x, ','); n >= 0 {
						encoded = x[n+1:]
					}
				}
				if known[sha256.Sum256([]byte(encoded))] {
					return "[attachment inspected separately]"
				}
			}
			return v
		}
		b, err := json.Marshal(scrub(item))
		if err != nil {
			return text
		}
		out.Write(b)
		out.WriteByte('\n')
	}
	return out.String()
}
