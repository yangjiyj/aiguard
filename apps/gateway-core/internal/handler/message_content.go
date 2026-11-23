package handler

import (
	"encoding/json"
	"strings"
)

// messageText 从 Message.Content(可能是 JSON 字符串或 OpenAI 多模态数组)里抽出纯文本。
//   - content 为 JSON 字符串 "..."                       -> 返回该字符串值
//   - content 为数组 [{type:"text",text},{type:"image_url",...}]
//     -> 拼接所有 type=="text" 块的 text(用 \n 连接), 忽略图片等非文本块
//   - null / 空 / 无法识别的形状                         -> 返回 ""(安全退化)
//
// 分支逻辑与 messages.go 的 anthropicContentToText 保持一致(只取文本, 丢非文本块)。
func messageText(content json.RawMessage) string {
	if len(content) == 0 {
		return ""
	}
	// 最常见: 纯文本请求, content 就是一个 JSON 字符串。
	var s string
	if err := json.Unmarshal(content, &s); err == nil {
		return s
	}
	// 多模态: content 是块数组, 只取 text 块的 text 字段。
	var blocks []map[string]interface{}
	if err := json.Unmarshal(content, &blocks); err == nil {
		parts := make([]string, 0, len(blocks))
		for _, b := range blocks {
			if t, _ := b["type"].(string); t != "text" {
				continue
			}
			if txt, ok := b["text"].(string); ok && txt != "" {
				parts = append(parts, txt)
			}
		}
		return strings.Join(parts, "\n")
	}
	// 其它形状(数字/布尔/对象/字符串数组等) -> 安全退化为空串。
	return ""
}

// jsonQuote 把普通字符串包成一个合法的 JSON 字符串字面量("...")的 RawMessage,
// 供构造 Message.Content(json.RawMessage) 的写入点使用; 行为等价于原先直接写 string。
func jsonQuote(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
