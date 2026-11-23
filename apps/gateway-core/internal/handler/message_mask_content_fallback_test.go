package handler

import (
	"encoding/json"
	"strings"
	"testing"
)

// 兜底分支（送检文本与 text 块对不上）不能把未识别的文本块原样带出站：
// input_text、output_text 或任何带 text 字段的未知块里可能就是原文。
func TestMaskMessageTextContentFallbackDropsUnknownTextBlocks(t *testing.T) {
	image := `{"type":"image_url","image_url":{"url":"` + pngDataURL + `"}}`
	for name, content := range map[string]string{
		"input_text":  `[{"type":"input_text","text":"手机13800138000"},` + image + `]`,
		"output_text": `[{"type":"text","text":"另一段"},{"type":"output_text","text":"手机13800138000"},` + image + `]`,
		"未知带文本块":      `[{"type":"custom_note","text":"手机13800138000"},` + image + `]`,
		"未知嵌套文本块":     `[{"type":"rich","content":[{"text":"手机13800138000"}]},` + image + `]`,
		"无 type 的文本块": `[{"text":"手机13800138000"},` + image + `]`,
	} {
		t.Run(name, func(t *testing.T) {
			got := maskMessageTextContent(json.RawMessage(content), "手机13800138000", "手机<MASKED>")
			if strings.Contains(string(got), "13800138000") {
				t.Fatalf("兜底不应让原文出站: %s", got)
			}
			blocks := decodeBlocks(t, got)
			images, texts := 0, []string{}
			for _, block := range blocks {
				switch block["type"] {
				case "image_url":
					images++
				case "text":
					texts = append(texts, block["text"].(string))
				}
			}
			if images != 1 || len(texts) != 1 || texts[0] != "手机<MASKED>" {
				t.Fatalf("应保留图片、只留一个脱敏文本块: texts=%q images=%d content=%s", texts, images, got)
			}
		})
	}
}
