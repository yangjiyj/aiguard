package handler

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"strings"
)

func decodeWorkBuddyInvokeRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	if !isWorkBuddyInvokeRequest(req) {
		return ExtractedContent{}, false
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- extractor needs arbitrary JSON text traversal; encoding/json does not instantiate arbitrary types.
	var decoded interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return ExtractedContent{}, false
	}
	var parts []string
	var attachments []ExtractedAttachment
	collectWorkBuddyInvokeJSONText(decoded, "", &parts, &attachments)
	return buildExtracted(parts, attachments, "json"), true
}

func isWorkBuddyInvokeRequest(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	host := normalizeHost(req.URL.Host)
	if host == "" {
		host = normalizeHost(req.Host)
	}
	if host != "ride-3-live-webapp.azurewebsites.net" {
		return false
	}
	path := strings.ToLower(req.URL.Path)
	return strings.Contains(path, "/api/invoke") || strings.Contains(path, "/api/stream")
}

func collectWorkBuddyInvokeJSONText(value interface{}, path string, parts *[]string, attachments *[]ExtractedAttachment) {
	switch v := value.(type) {
	case map[string]interface{}:
		objectAttachments := attachmentsFromJSONFileObject(path, v)
		objectAttachments = append(objectAttachments, attachmentsFromJSONImageObject(path, v)...)
		if len(objectAttachments) == 0 {
			objectAttachments = append(objectAttachments, attachmentsFromJSONFileIDObject(path, v)...)
		}
		*attachments = append(*attachments, objectAttachments...)
		for key, child := range v {
			nextPath := key
			if path != "" {
				nextPath = path + "." + key
			}
			collectWorkBuddyInvokeJSONText(child, nextPath, parts, attachments)
		}
	case []interface{}:
		for _, item := range v {
			collectWorkBuddyInvokeJSONText(item, path, parts, attachments)
		}
	case string:
		appendWorkBuddyInvokeJSONString(path, v, parts, attachments)
	}
}

func appendWorkBuddyInvokeJSONString(path, value string, parts *[]string, attachments *[]ExtractedAttachment) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}
	if attachment, ok := attachmentFromDataURL(path, trimmed); ok {
		*attachments = append(*attachments, attachment)
		*parts = append(*parts, fmt.Sprintf("[embedded:%s type=%s size=%d sha256=%s]", path, attachment.ContentType, attachment.Size, attachment.SHA256))
		return
	}
	if attachment, ok := attachmentFromImageURL(path, trimmed); ok {
		*attachments = append(*attachments, attachment)
		return
	}
	if shouldDiscardRetainedFileURLText(path, trimmed) || isFileTypeProtocolValue(trimmed) || looksLikeSignedDownloadShortLink(trimmed) {
		return
	}
	if looksLikeRetainedFileReference(path, trimmed) {
		*parts = append(*parts, fmt.Sprintf("[%s] %s", path, trimmed))
		*attachments = append(*attachments, attachmentsFromFileReference(path, trimmed)...)
		return
	}
	if shouldSkipJSONText(path, trimmed) {
		return
	}
	if !isWorkBuddyPromptJSONPath(path) && !looksLikeHumanText(trimmed) {
		return
	}
	if len(trimmed) > maxTextFragmentBytes {
		trimmed = trimmed[:maxTextFragmentBytes] + "...[truncated]"
	}
	*parts = append(*parts, trimmed)
}

// decodeWorkBuddyInvokeAttachmentsRequest 是 CodeBuddy/WorkBuddy /api/invoke 的请求侧解码器:
// /api/invoke 是 RPC 管理/遥测调用(InsightsManager 遥测、工作区元数据、文件 op),从不是对话——
// 对话走 /api/stream。其文本(管理参数/HTTP头/元数据)全是噪音,故**只抽附件、丢全部文本**。
//
// 认领策略(关键):只要 host 是 ride-3 的 /api/invoke 合法 JSON 请求,就**始终 matched=true**(认领),
// 无附件 → 返回空内容(无文本无附件),有图 → 只留附件。绝不在无附件时返回 false——否则
// extractRequestContentWithDecoder(content_extractor.go) 会回退到 decodeRequestWithSniffedWebDecoder,
// 其 sniff 链含老贪婪 workbuddy_web(=decodeWorkBuddyInvokeRequest),把请求体里的 HTTP 头
// (User-Agent/Accept-Encoding 等)重新当 prompt 抽出,噪音卷土重来(实测双斜杠 //api/invoke 即此患)。
// 空内容(无文本无附件)在 audit.buildAccessContentLogPayload 里 requestText/responseText 空 + metadata 空
// → 返回 ok=false → 不产 content 行 → 噪音消失。隔离:不复用/不改 decodeWorkBuddyInvokeRequest。
// host 不匹配 / 非 JSON / Unmarshal 失败仍返回 false(让真不匹配的流量正常走回退)。
func decodeWorkBuddyInvokeAttachmentsRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	if !isWorkBuddyInvokeRequest(req) {
		return ExtractedContent{}, false
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- extractor needs arbitrary JSON traversal
	var decoded interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return ExtractedContent{}, false
	}
	var discardText []string
	var attachments []ExtractedAttachment
	collectWorkBuddyInvokeJSONText(decoded, "", &discardText, &attachments)
	// 始终认领(matched=true):只留附件、丢全部文本。无附件=空内容(短路回退,不写库)。
	return buildExtracted(nil, attachments, "json"), true
}

// decodeWorkBuddyInvokeAttachmentsResponse 是 /api/invoke 响应侧解码器:同理只抽附件丢文本。
// CodeBuddy 用户图就在这里(响应 JSON 的 Messages.Attachments → json_image_url)。
// 同样**始终认领**(JSON 校验通过即 matched=true):遥测响应("Invocation logged")/元数据响应无附件
// → 空内容 → 不写噪音行;但绝不返 false,否则回退 extractResponseContentWithDecoder 的 sniff +
// extractHTTPContent 会贪婪抽 JSON 文本,噪音复发。非 JSON / Unmarshal 失败仍返回 false。
func decodeWorkBuddyInvokeAttachmentsResponse(body []byte, contentType string) (ExtractedContent, bool) {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- extractor needs arbitrary JSON traversal
	var decoded interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return ExtractedContent{}, false
	}
	var discardText []string
	var attachments []ExtractedAttachment
	collectWorkBuddyInvokeJSONText(decoded, "", &discardText, &attachments)
	// 始终认领:只留附件、丢全部文本。无附件=空内容(短路回退,不写库)。
	return buildExtracted(nil, attachments, "json"), true
}

func isWorkBuddyPromptJSONPath(path string) bool {
	lowerPath := strings.ToLower(path)
	segments := strings.Split(lowerPath, ".")
	last := ""
	if len(segments) > 0 {
		last = segments[len(segments)-1]
	}
	switch last {
	case "content", "description", "input", "instructions", "message", "prompt", "query", "question", "text", "title", "user_input", "userinput", "usermessage", "value":
		return true
	default:
		return strings.Contains(lowerPath, "user.input") || strings.Contains(lowerPath, "user.message")
	}
}
