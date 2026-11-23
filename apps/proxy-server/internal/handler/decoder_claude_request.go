package handler

import (
	"encoding/json"
	"mime"
	"net/http"
	"strings"
)

// decodeClaudeWebRequest 解析 claude.ai 网页版「发送侧」请求，供正向代理内容抽取/留存使用。
//
// 当前覆盖 JSON 的 completion 请求（POST .../chat_conversations/{id}/completion）：
//   - prompt          用户发送的文字
//   - attachments[]   文档附件：claude.ai 在请求体里直接给出 extracted_content（已提取文本），
//     DLP 可直接读，无需网关再解析文件
//   - files[]         图片附件的 file_uuid（图片字节在 wiggle/upload-file 上传请求里，
//     此处仅留引用，字节抽取留待后续增量）
//
// multipart 的 wiggle/upload-file（图片/文件原始字节）非 JSON，这里直接放过返回 false，
// 由后续增量处理；保持「识别得到才命中、不误吞」。
func decodeClaudeWebRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		// multipart 上传(wiggle/upload-file)由现有通用上传管道处理(字节留存/外置化)，这里不拦截。
		return ExtractedContent{}, false
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ExtractedContent{}, false
	}

	var parts []string
	var attachments []ExtractedAttachment
	matched := false

	// 用户发送的文字
	if p, ok := payload["prompt"].(string); ok && strings.TrimSpace(p) != "" {
		parts = append(parts, p)
		matched = true
	}

	// 文档附件：extracted_content 是 claude.ai 已提取的文档文本，并入正文供内容/数据外泄检测；
	// 留存侧给截断预览，避免超长文本灌入。
	if raw, ok := payload["attachments"].([]interface{}); ok {
		for _, item := range raw {
			am, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			att := ExtractedAttachment{Source: "claude_web_attachment"}
			if v, ok := am["file_name"].(string); ok {
				att.FileName = v
			}
			if v, ok := am["file_type"].(string); ok {
				att.ContentType = v
			}
			if v, ok := am["file_size"].(float64); ok {
				att.Size = int64(v)
			}
			if v, ok := am["extracted_content"].(string); ok && strings.TrimSpace(v) != "" {
				parts = append(parts, v)
				att.TextPreview = preview(v, 200)
			}
			attachments = append(attachments, att)
			matched = true
		}
	}

	// 图片附件：files 是 file_uuid 字符串数组，字节在 wiggle/upload-file 上传请求里。
	if raw, ok := payload["files"].([]interface{}); ok {
		for _, item := range raw {
			if uuid, ok := item.(string); ok && strings.TrimSpace(uuid) != "" {
				attachments = append(attachments, ExtractedAttachment{
					Source:      "claude_web_file",
					ReferenceID: uuid,
					ContentType: "reference/file-id",
				})
				matched = true
			}
		}
	}

	if !matched {
		return ExtractedContent{}, false
	}
	return buildExtracted(parts, attachments, "json"), true
}
