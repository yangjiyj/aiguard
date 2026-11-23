package handler

import (
	"encoding/json"
	"strings"
)

// maskMessageTextContent 把引擎对 messageText 的脱敏结果写回 Message.Content，
// 只改写 text 块，图片、文件等其它块原样保留（2.9.11 实测 N03/N10/N12/N13）。
//
//   - content 是 JSON 字符串或无法识别的形状：整条替换为脱敏文本（原行为）；
//   - 只有一个非空 text 块：直接替换该块；
//   - 多个 text 块：messageText 用 "\n" 拼接，脱敏只替换行内片段，按各块行数切回；
//     行数对不上（命中跨块或替换改了换行）时把脱敏文本整体放进第一个 text 块、
//     清掉其它 text 块，宁可改结构也不能让原文出站；
//   - 与送检文本对不上（兜底）：只保留已知的图片/音频/文件块，input_text、output_text
//     等未送检的文本块与无法识别的块一律丢弃，不能原样出站。
func maskMessageTextContent(content json.RawMessage, original, masked string) json.RawMessage {
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(content, &blocks); err != nil {
		return jsonQuote(masked)
	}
	textIndexes := make([]int, 0, len(blocks))
	texts := make([]string, 0, len(blocks))
	for index, block := range blocks {
		var text string
		if blockTypeOf(block) != "text" || json.Unmarshal(block["text"], &text) != nil || text == "" {
			continue
		}
		textIndexes = append(textIndexes, index)
		texts = append(texts, text)
	}
	if len(textIndexes) == 0 || strings.Join(texts, "\n") != original {
		// 与送检文本对不上，无法定位文本块：脱敏文本放最前，只保留已知的媒体块。
		kept := []map[string]json.RawMessage{{"type": jsonQuote("text"), "text": jsonQuote(masked)}}
		for _, block := range blocks {
			if fallbackKeepsBlock(block) {
				kept = append(kept, block)
			}
		}
		return marshalBlocks(kept, masked)
	}

	maskedTexts := splitMaskedByBlocks(texts, masked)
	out := make([]map[string]json.RawMessage, 0, len(blocks))
	for index, block := range blocks {
		position := textBlockPosition(textIndexes, index)
		if position < 0 {
			out = append(out, block)
			continue
		}
		if maskedTexts == nil {
			if position > 0 {
				continue
			}
			block["text"] = jsonQuote(masked)
		} else {
			block["text"] = jsonQuote(maskedTexts[position])
		}
		out = append(out, block)
	}
	return marshalBlocks(out, masked)
}

// splitMaskedByBlocks 按原各块行数把脱敏文本切回；对不上返回 nil。
func splitMaskedByBlocks(texts []string, masked string) []string {
	if len(texts) == 1 {
		return []string{masked}
	}
	lines := strings.Split(masked, "\n")
	total := 0
	for _, text := range texts {
		total += strings.Count(text, "\n") + 1
	}
	if total != len(lines) {
		return nil
	}
	out := make([]string, 0, len(texts))
	cursor := 0
	for _, text := range texts {
		count := strings.Count(text, "\n") + 1
		out = append(out, strings.Join(lines[cursor:cursor+count], "\n"))
		cursor += count
	}
	return out
}

func marshalBlocks(blocks []map[string]json.RawMessage, masked string) json.RawMessage {
	encoded, err := json.Marshal(blocks)
	if err != nil {
		return jsonQuote(masked)
	}
	return encoded
}

func textBlockPosition(values []int, target int) int {
	for position, value := range values {
		if value == target {
			return position
		}
	}
	return -1
}

// fallbackMediaBlockTypes 是兜底时允许原样保留的块类型：图片、音频、文件，不含文本。
var fallbackMediaBlockTypes = map[string]bool{
	"image_url": true, "image": true, "input_image": true,
	"input_audio": true, "audio": true,
	"file": true, "input_file": true,
}

// fallbackKeepsBlock：只保留已知媒体块，且块里不能直接带 text 字段。
func fallbackKeepsBlock(block map[string]json.RawMessage) bool {
	if !fallbackMediaBlockTypes[blockTypeOf(block)] {
		return false
	}
	_, hasText := block["text"]
	return !hasText
}

func blockTypeOf(block map[string]json.RawMessage) string {
	var blockType string
	_ = json.Unmarshal(block["type"], &blockType)
	return blockType
}

// attachmentMaskUnavailable 报告引擎是否指出附件正文里有无法改写的脱敏命中。
func attachmentMaskUnavailable(findings []SecurityFinding) bool {
	for _, finding := range findings {
		if !strings.EqualFold(strings.TrimSpace(finding.Action), "mask") {
			continue
		}
		if finding.ContentSource == "file_attachment" || finding.AttachmentIndex != nil {
			return true
		}
		if unavailable, _ := finding.Triage["mask_unavailable"].(bool); unavailable {
			return true
		}
	}
	return false
}
