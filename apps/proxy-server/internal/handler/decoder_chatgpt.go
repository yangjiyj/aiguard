package handler

import (
	"net/http"
	"strings"
)

func decodeChatGPTWebRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	if ref := chatGPTEstuaryReferenceID(req); ref != "" {
		return ExtractedContent{Attachments: []ExtractedAttachment{{
			Source:      "estuary_content_reference",
			FieldName:   "estuary_content_id",
			ReferenceID: ref,
			ContentType: "reference/file-id",
		}}}, true
	}
	// 取文件字节请求(estuary)之外，解析会话发送请求正文(文字 + 图片/文件引用)。
	// multipart 文件上传由现有通用上传管道处理(字节留存/外置化/OCR)，这里不拦截。
	return decodeChatGPTConversationRequest(body, contentType)
}

func decodeChatGPTWebResponse(body []byte, contentType string) (ExtractedContent, bool) {
	if !isEventStream(contentType, body) {
		return ExtractedContent{}, false
	}
	events := parseSSEDataEvents(body)
	if c, ok := reassembleChatGPTWebPatchStream(events); ok {
		return c, true
	}
	if c, ok := reassembleOpenAIDeltaStream(events); ok {
		return c, true
	}
	if c, ok := reassembleOpenAIResponsesStream(events); ok {
		return c, true
	}
	return ExtractedContent{}, false
}

// chatGPTEstuaryReferenceID 解析 ChatGPT 网页版取文件请求里的 file-id。该端点是其图片/文件字节
// 经正向代理的唯一可见副本：GET /backend-api/estuary/content?id=file_xxx，file-id 在 query 上。
func chatGPTEstuaryReferenceID(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	if !strings.Contains(strings.ToLower(req.URL.Path), "/estuary/content") {
		return ""
	}
	return strings.TrimSpace(req.URL.Query().Get("id"))
}

func reassembleChatGPTWebPatchStream(events []sseEvent) (ExtractedContent, bool) {
	matched := false
	var answer strings.Builder
	for _, ev := range events {
		m, ok := ev.decoded.(map[string]interface{})
		if !ok {
			continue
		}
		path, ok := m["p"].(string)
		if !ok || !strings.HasPrefix(path, "/message/content/parts") {
			continue
		}
		value, ok := m["v"].(string)
		if !ok {
			continue
		}
		matched = true
		answer.WriteString(value)
	}
	if !matched || strings.TrimSpace(answer.String()) == "" {
		return ExtractedContent{}, false
	}
	return buildReassembledExtracted(answer.String(), "", collectStreamAttachments(events)), true
}
