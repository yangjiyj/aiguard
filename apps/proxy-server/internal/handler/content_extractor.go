package handler

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionturn"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const maxTextFragmentBytes = 256 * 1024
const maxAttachmentContextBytes = 2 * 1024 * 1024

var dataURLPattern = regexp.MustCompile(`^data:([^;,]+)(;base64)?,(.*)$`)
var fileReferenceIDPattern = regexp.MustCompile(`(?i)\b(?:file|upload|attachment)[-_][a-z0-9][a-z0-9._-]{5,}\b`)
var standaloneUUIDValuePattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var protocolLongNumberPattern = regexp.MustCompile(`^\d{8,}$`)

type ExtractedAttachment struct {
	MessageIndex        *int   `json:"message_index,omitempty"`
	MessageRole         string `json:"message_role,omitempty"`
	ContentSource       string `json:"content_source,omitempty"`
	SourcePath          string `json:"source_path,omitempty"`
	InspectionIsHistory bool   `json:"inspection_is_history"`
	IsLatestUser        bool   `json:"is_latest_user"`
	Source              string `json:"source"`
	FieldName           string `json:"field_name,omitempty"`
	FileName            string `json:"file_name,omitempty"`
	ReferenceID         string `json:"reference_id,omitempty"`
	ContentType         string `json:"content_type,omitempty"`
	Size                int64  `json:"size"`
	SHA256              string `json:"sha256"`
	TextPreview         string `json:"text_preview,omitempty"`
	DataBase64          string `json:"data_base64,omitempty"`
	DownloadURL         string `json:"download_url,omitempty"`
}

// ConvMessage 是结构化消息统一产物的字面别名（设计 1a），实现在 shared-go/aimsg。
type ConvMessage = aimsg.ConvMessage

// ToolInvocation 是本轮一次工具调用的机器可读参数（工具名 + 原始参数文本）。
// 供正向代理的受限文件模式评估使用；仅additive，不影响 Text/SecurityText/VisibleText。
type ToolInvocation struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type ExtractedContent struct {
	SemanticTaskContexts           map[string]proxySemanticTask `json:"-"`
	SemanticAttachmentTaskContexts map[string]proxySemanticTask `json:"-"`
	UserTask                       string                       `json:"-"`
	InspectionScopeKnown           bool                         `json:"-"`
	NonDialogue                    bool                         `json:"-"`
	JudgmentContext                []map[string]any             `json:"-"`
	InspectionPolicyFingerprint    string                       `json:"-"`
	TurnRequest                    *retentionturn.Request       `json:"-"`
	TurnResponse                   *retentionturn.Response      `json:"-"`
	Text                           string                       `json:"text"`
	VisibleText                    string                       `json:"-"`
	VisibleTextKnown               bool                         `json:"-"`
	// SecurityText is the source-aware projection sent to the security engine.
	// Text remains the complete extracted/audit representation for compatibility;
	// structured decoders set SecurityTextKnown so system prompts and tool
	// definitions cannot create customer DLP false positives.
	SecurityText      string                `json:"-"`
	SecurityTextKnown bool                  `json:"-"`
	ContentType       string                `json:"content_type"`
	Attachments       []ExtractedAttachment `json:"attachments,omitempty"`
	ConversationID    string                `json:"conversation_id,omitempty"`
	SectionID         string                `json:"section_id,omitempty"`
	Model             string                `json:"model,omitempty"`
	// Messages 是结构化消息数组（additive，设计 1a 双形态）：仅 anthropic_messages /
	// openai_compatible 等结构化解码器填充，带 source 喂检测；平铺 Text 继续由消息拼接生成，
	// 旧消费方（留证写路径 buildAccessContentLogPayload、CheckInput/CheckOutput content）零改动。
	Messages []ConvMessage `json:"messages,omitempty"`
	// ToolInvocations 是本轮工具调用的结构化参数列表（受限文件模式评估用）。
	// 与 Text/SecurityText/VisibleText 完全解耦，仅additive。
	ToolInvocations []ToolInvocation `json:"tool_invocations,omitempty"`
	// ToolCalls 是本轮工具的机器可读索引（工具名/种类/阶段/脱敏预览），落
	// access_content_logs.tool_call_metadata_json。与 TurnRequest/TurnResponse 的 tools 不同：
	// 那边只有 id/name/kind 的关联指纹，这里带人类可读的预览，供告警详情直接展示。
	ToolCalls []retainedToolCall `json:"-"`
}

func extractRequestContent(req *http.Request, body []byte) ExtractedContent {
	return extractRequestContentWithDecoder(req, body, "")
}

func extractRequestContentWithDecoder(req *http.Request, body []byte, decoderName string) ExtractedContent {
	content := extractRequestContentDecoded(req, body, decoderName)
	decoded := body
	if req != nil {
		decoded = decodeContentEncoding(body, req.Header.Get("Content-Encoding"))
	}
	content.TurnRequest = retentionturn.BuildRequest(content.Messages, decoded, "")
	// 工具调用索引必须从解码后的原始 JSON 抽（Messages 里只剩渲染过的文本，id 已丢失）。
	content.ToolCalls = retainedRequestToolCalls(decoded)
	return content
}
func extractRequestContentDecoded(req *http.Request, body []byte, decoderName string) ExtractedContent {
	contentType := ""
	encoding := ""
	if req != nil {
		contentType = req.Header.Get("Content-Type")
		encoding = req.Header.Get("Content-Encoding")
	}
	// 与响应侧对称：VSCode 系客户端（CodeBuddy gzip 的 chat/completions、GitHub Copilot br 的
	// Responses）会压缩请求体。响应侧在 proxy.go 已用 decodeContentEncoding 解压后才抽取，请求侧
	// 过去缺这一步——压缩字节命中 extractHTTPContent 的 isCompressedPayload 早退守卫（gzip）或被
	// safeText 过滤成空（br 无魔数）→ 用户提问抓不到。这里按请求自带的 Content-Encoding 头先解压。
	// 仅改函数内局部 body（切片按值传参），不影响 proxy.go 用于转发/raw 留存的原始 requestBody。
	body = decodeContentEncoding(body, encoding)
	if decoder, ok := getWebDecoder(decoderName); ok {
		if content, matched := decoder.DecodeRequest(req, body, contentType); matched {
			return content
		}
	}
	if content, ok := decodeRequestWithSniffedWebDecoder(req, body, contentType); ok {
		return content
	}
	return extractHTTPContent(body, contentType, "request")
}

func extractResponseContent(body []byte, contentType string) ExtractedContent {
	return extractResponseContentWithDecoder(body, contentType, "")
}

func extractResponseContentWithDecoder(body []byte, contentType, decoderName string) ExtractedContent {
	content := extractResponseContentDecoded(body, contentType, decoderName)
	text := content.Text
	if content.VisibleTextKnown {
		text = content.VisibleText
	}
	content.TurnResponse = retentionturn.BuildResponse(body, text)
	// 响应侧工具调用从 Text 里捞（VisibleText 只含 text 块）；id 与 TurnResponse.Tools 顺序配对。
	content.ToolCalls = retainedResponseToolCalls(content.Text, content.TurnResponse.Tools)
	return content
}
func extractResponseContentDecoded(body []byte, contentType, decoderName string) ExtractedContent {
	if decoder, ok := getWebDecoder(decoderName); ok {
		if content, matched := decoder.DecodeResponse(body, contentType); matched {
			return content
		}
		if isEventStream(contentType, body) {
			return fallbackSSEContent(parseSSEDataEvents(body))
		}
	}
	if content, ok := decodeResponseWithSniffedWebDecoder(body, contentType); ok {
		return content
	}
	if isEventStream(contentType, body) {
		return fallbackSSEContent(parseSSEDataEvents(body))
	}
	return extractHTTPContent(body, contentType, "response")
}

func extractHTTPContent(body []byte, contentType, source string) ExtractedContent {
	mediaType, params, _ := mime.ParseMediaType(contentType)
	mediaType = strings.ToLower(mediaType)

	if isCompressedPayload(body) {
		contentKind := "binary"
		if mediaType != "" {
			contentKind = mediaType
		}
		return ExtractedContent{ContentType: contentKind}
	}

	if strings.HasPrefix(mediaType, "multipart/") && params["boundary"] != "" {
		return extractMultipartContent(body, params["boundary"], mediaType)
	}

	if isConnectJSONContent(mediaType) {
		if extracted, ok := extractConnectJSONContent(body, mediaType); ok {
			return extracted
		}
	}

	if isFormURLEncodedContent(mediaType) {
		if extracted, ok := extractFormURLEncodedContent(body, mediaType); ok {
			return extracted
		}
	}

	if isJSONContent(mediaType, body) {
		// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- extractor needs arbitrary JSON text traversal; encoding/json does not instantiate arbitrary types.
		var decoded interface{}
		if err := json.Unmarshal(body, &decoded); err == nil {
			var parts []string
			var attachments []ExtractedAttachment
			collectJSONText(decoded, "", &parts, &attachments)
			return buildExtracted(parts, attachments, "json")
		}
	}

	contentKind := "text"
	if mediaType != "" {
		contentKind = mediaType
	}
	if isTemporaryRedirectHTML(mediaType, body) {
		return ExtractedContent{ContentType: contentKind}
	}
	// 请求侧原始 PDF/Office/压缩包/图片等二进制没有 JSON 或 multipart
	// 外壳，仍必须作为附件交给文件内容 DLP；此前只有响应侧保留这类字节，
	// 导致直接 POST 文件请求只记录媒体类型而完全没有可扫描字节。
	if source == "request" && len(body) > 0 && !isTextualContent(contentType, "", body) {
		attachment := attachmentFromBytes("request_body", "", "", mediaType, body)
		return ExtractedContent{ContentType: contentKind, Attachments: []ExtractedAttachment{attachment}}
	}
	// 响应体是可保留的二进制时（图片，或 PDF/Office/压缩包等文件），整段作为「模型回复的文件/
	// 图片」附件落库。此前仅 image/* 走这条路径，ChatGPT 等网页大模型经 estuary 回传的非图片文件
	// （PDF、docx 等）因此在访问留存里彻底丢失。用 mediaType 判定，与 attachmentFromBytes 内部的
	// shouldRetainAttachmentBytes 取同一口径，避免出现「有附件却没 DataBase64」；文件名按媒体类型
	// 取人类可读名，避免把 PDF 误标成图片。是否真填 DataBase64（含 2MB 上限）仍统一由它决定。
	if source == "response" && shouldRetainAttachmentBytes(mediaType, "", body) {
		attachment := attachmentFromBytes("response_body", "response_body", responseFileNameForMediaType(mediaType), mediaType, body)
		return ExtractedContent{ContentType: contentKind, Attachments: []ExtractedAttachment{attachment}}
	}
	if !isTextualContent(contentType, "", body) {
		return ExtractedContent{ContentType: contentKind}
	}
	return ExtractedContent{Text: safeText(body), ContentType: contentKind}
}

func extractMultipartContent(body []byte, boundary, mediaType string) ExtractedContent {
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var parts []string
	var attachments []ExtractedAttachment

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			parts = append(parts, fmt.Sprintf("[multipart_error] %s", err.Error()))
			break
		}
		partBody, _ := io.ReadAll(part)
		fieldName := part.FormName()
		fileName := part.FileName()
		partContentType := part.Header.Get("Content-Type")
		if partContentType == "" || strings.EqualFold(strings.TrimSpace(partContentType), "application/octet-stream") {
			partContentType = inferContentType(fileName, partBody)
		}

		if fileName == "" {
			value := strings.TrimSpace(safeText(partBody))
			if value != "" {
				parts = append(parts, fmt.Sprintf("[field:%s] %s", fieldName, value))
			}
			continue
		}

		attachment := attachmentFromBytes("multipart", fieldName, fileName, partContentType, partBody)
		if isTextualContent(partContentType, fileName, partBody) {
			text := safeText(partBody)
			attachment.TextPreview = preview(text, 200)
			parts = append(parts, fmt.Sprintf("[file:%s type=%s size=%d sha256=%s]\n%s", fileName, partContentType, len(partBody), attachment.SHA256, text))
		} else {
			parts = append(parts, fmt.Sprintf("[file:%s type=%s size=%d sha256=%s]", fileName, partContentType, len(partBody), attachment.SHA256))
		}
		attachments = append(attachments, attachment)
	}
	applyMultipartReferenceIDs(parts, attachments)

	return buildExtracted(parts, attachments, mediaType)
}

func applyMultipartReferenceIDs(parts []string, attachments []ExtractedAttachment) {
	if len(attachments) == 0 {
		return
	}
	ref := multipartReferenceID(parts)
	if ref == "" {
		return
	}
	for i := range attachments {
		if attachments[i].ReferenceID == "" {
			attachments[i].ReferenceID = ref
		}
	}
}

func multipartReferenceID(parts []string) string {
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || !strings.HasPrefix(part, "[field:") {
			continue
		}
		end := strings.Index(part, "]")
		if end <= len("[field:") {
			continue
		}
		field := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(part[:end], "[field:")))
		if field != "file_id" && field != "fileid" && field != "reference_id" && field != "upload_id" && field != "attachment_id" && field != "id" {
			continue
		}
		value := strings.TrimSpace(part[end+1:])
		if value != "" {
			return value
		}
	}
	return ""
}

func extractSSEContent(body []byte) ExtractedContent {
	return extractSSEContentWithDecoder(body, "")
}

func extractSSEContentWithDecoder(body []byte, decoderName string) ExtractedContent {
	if decoder, ok := getWebDecoder(decoderName); ok {
		if c, matched := decoder.DecodeResponse(body, "text/event-stream"); matched {
			return c
		}
		return fallbackSSEContent(parseSSEDataEvents(body))
	}
	if c, ok := decodeResponseWithSniffedWebDecoder(body, "text/event-stream"); ok {
		return c
	}
	return fallbackSSEContent(parseSSEDataEvents(body))
}

func fallbackSSEContent(events []sseEvent) ExtractedContent {
	var parts []string
	var attachments []ExtractedAttachment
	for _, ev := range events {
		if ev.parsed {
			collectJSONText(ev.decoded, "", &parts, &attachments)
			continue
		}
		parts = append(parts, ev.raw)
	}
	return buildExtracted(parts, attachments, "text/event-stream")
}

// reassembleOpenAIResponsesStream 处理 OpenAI Responses API 的流式 SSE。
// GitHub Copilot / VS Code Copilot Chat 经正向代理(:3128)后即走此格式。
func reassembleOpenAIResponsesStream(events []sseEvent) (ExtractedContent, bool) {
	matched := false
	var toolInvocations []ToolInvocation
	itemsByID := make(map[string]*openAIResponsesStreamItem)
	itemsByIndex := make(map[string]*openAIResponsesStreamItem)
	unkeyedItems := make(map[string]*openAIResponsesStreamItem)
	itemOrder := make([]*openAIResponsesStreamItem, 0)
	// 身份绑定一致性：同一 item_id 只允许绑定一个 output_index，反之亦然。
	// 服务端乱序或复用身份时 fail-closed，防止内容跨 item 串线（CONFLICT_* 用例）。
	idToIndex := make(map[string]string)
	indexToID := make(map[string]string)
	conflicted := func(itemID, outputIndex string) *openAIResponsesStreamItem {
		if itemID != "" {
			if projection, ok := itemsByID[itemID]; ok {
				return projection
			}
		}
		if outputIndex != "" {
			if projection, ok := itemsByIndex[outputIndex]; ok {
				return projection
			}
		}
		projection := &openAIResponsesStreamItem{}
		itemOrder = append(itemOrder, projection)
		return projection
	}
	itemFor := func(event, item map[string]interface{}, completedIndex int, fallback string, authoritative bool) *openAIResponsesStreamItem {
		itemID, outputIndex := openAIResponsesItemIdentity(event, item, completedIndex)
		if itemID != "" && outputIndex != "" {
			if prev, ok := idToIndex[itemID]; ok && prev != outputIndex {
				projection := conflicted(itemID, outputIndex)
				projection.failClosed = true
				return projection
			}
			if prev, ok := indexToID[outputIndex]; ok && prev != itemID {
				projection := conflicted(itemID, outputIndex)
				projection.failClosed = true
				return projection
			}
			idToIndex[itemID] = outputIndex
			indexToID[outputIndex] = itemID
		}
		var projection *openAIResponsesStreamItem
		if itemID != "" {
			projection = itemsByID[itemID]
		}
		if projection == nil && outputIndex != "" {
			projection = itemsByIndex[outputIndex]
		}
		if projection == nil && itemID == "" && outputIndex == "" {
			projection = unkeyedItems[fallback]
		}
		if projection == nil {
			projection = &openAIResponsesStreamItem{}
			itemOrder = append(itemOrder, projection)
		}
		if itemID != "" {
			itemsByID[itemID] = projection
		}
		if outputIndex != "" {
			itemsByIndex[outputIndex] = projection
		}
		if itemID == "" && outputIndex == "" {
			unkeyedItems[fallback] = projection
		}
		// 只有 output_item.added / output_item.done / response.completed 三类权威
		// item 事件才算"已声明"。delta 类事件身份可能完全虚构（msg_unbound 用例），
		// 必须等权威声明确认后才允许投影缓冲的增量。
		if authoritative {
			projection.declared = true
		}
		return projection
	}
	var attachments []ExtractedAttachment
	for _, ev := range events {
		m, ok := ev.decoded.(map[string]interface{})
		if !ok {
			continue
		}
		typ, ok := m["type"].(string)
		if !ok || !strings.HasPrefix(typ, "response.") {
			continue
		}
		// A parsed response.* event is sufficient protocol confirmation. Unknown
		// future events must be ignored here instead of falling through to generic
		// JSON traversal, which can expose tool definitions and internal metadata.
		matched = true
		switch typ {
		case "response.output_text.delta", "response.refusal.delta":
			if s, ok := m["delta"].(string); ok {
				itemFor(m, nil, -1, "answer", false).answerLane(openAIResponsesLaneKey(m, "content_index")).delta.WriteString(s)
			}
		case "response.function_call_arguments.delta":
			if s, ok := m["delta"].(string); ok {
				itemFor(m, nil, -1, "tool:function", false).toolDelta.WriteString(s)
			}
		case "response.custom_tool_call_input.delta":
			if s, ok := m["delta"].(string); ok {
				itemFor(m, nil, -1, "tool:custom", false).toolDelta.WriteString(s)
			}
		case "response.code_interpreter_call_code.delta":
			if s, ok := m["delta"].(string); ok {
				itemFor(m, nil, -1, "tool:code_interpreter", false).toolDelta.WriteString(s)
			}
		case "response.mcp_call_arguments.delta":
			if s, ok := m["delta"].(string); ok {
				itemFor(m, nil, -1, "tool:mcp", false).toolDelta.WriteString(s)
			}
		case "response.reasoning_summary_text.delta", "response.reasoning_text.delta":
			if s, ok := m["delta"].(string); ok {
				itemFor(m, nil, -1, "reasoning", false).reasoningLane(openAIResponsesLaneKey(m, "summary_index")).delta.WriteString(s)
			}
		case "response.output_text.done":
			lane := itemFor(m, nil, -1, "answer", false).answerLane(openAIResponsesLaneKey(m, "content_index"))
			if appendOpenAIResponsesSnapshotText(m["text"], &lane.snapshots) {
				lane.snapshotKnown = true
			}
		case "response.refusal.done":
			lane := itemFor(m, nil, -1, "answer", false).answerLane(openAIResponsesLaneKey(m, "content_index"))
			if appendOpenAIResponsesSnapshotText(m["refusal"], &lane.snapshots) || appendOpenAIResponsesSnapshotText(m["text"], &lane.snapshots) {
				lane.snapshotKnown = true
			}
		case "response.reasoning_summary_text.done", "response.reasoning_text.done":
			lane := itemFor(m, nil, -1, "reasoning", false).reasoningLane(openAIResponsesLaneKey(m, "summary_index"))
			if appendOpenAIResponsesSnapshotText(m["text"], &lane.snapshots) {
				lane.snapshotKnown = true
			}
		case "response.function_call_arguments.done":
			projection := itemFor(m, nil, -1, "tool:function", false)
			if appendOpenAIResponsesToolPayload(m["arguments"], &projection.toolSnapshots) {
				projection.toolSnapshotKnown = true
			}
		case "response.custom_tool_call_input.done":
			projection := itemFor(m, nil, -1, "tool:custom", false)
			if appendOpenAIResponsesToolPayload(m["input"], &projection.toolSnapshots) {
				projection.toolSnapshotKnown = true
			}
		case "response.code_interpreter_call_code.done":
			projection := itemFor(m, nil, -1, "tool:code_interpreter", false)
			if appendOpenAIResponsesToolPayload(m["code"], &projection.toolSnapshots) {
				projection.toolSnapshotKnown = true
			}
		case "response.mcp_call_arguments.done":
			projection := itemFor(m, nil, -1, "tool:mcp", false)
			if appendOpenAIResponsesToolPayload(m["arguments"], &projection.toolSnapshots) {
				projection.toolSnapshotKnown = true
			}
		case "response.output_item.added":
			if item, ok := m["item"].(map[string]interface{}); ok {
				projection := itemFor(m, item, -1, "output_item", true)
				if !projection.failClosed && openAIResponsesItemAllowsAttachments(item) {
					collectOpenAIResponsesAttachments(item, "output", &attachments)
				}
				if inv, ok := toolInvocationFromResponsesItem(item); ok {
					toolInvocations = append(toolInvocations, inv)
				}
			}
		case "response.output_item.done":
			// A tool-only Responses stream may have no text or tool deltas. The
			// completed item is authoritative; response.created is not, because its
			// tools field contains request-side definitions and internal prompts.
			if item, ok := m["item"].(map[string]interface{}); ok {
				projection := itemFor(m, item, -1, "output_item", true)
				if !projection.failClosed {
					if collectOpenAIResponsesOutputItem(item, projection) {
						collectOpenAIResponsesAttachments(item, "output", &attachments)
					}
					if inv, ok := toolInvocationFromResponsesItem(item); ok {
						toolInvocations = append(toolInvocations, inv)
					}
				}
			}
		case "response.content_part.added", "response.content_part.done":
			// 附件只允许挂在已声明的 item 身份下；身份从未被权威事件确认的
			// content_part 一律丢弃（msg_unbound 附件用例）。
			if part, ok := m["part"].(map[string]interface{}); ok {
				if openAIResponsesIdentityDeclared(itemsByID, itemsByIndex, m) {
					collectOpenAIResponsesAttachments(part, "output.content", &attachments)
				}
			}
		case "response.completed":
			// Some implementations only expose finished output in the final response
			// snapshot. Collect known message/reasoning/tool fields and dedupe them
			// against output_item.done below.
			if response, ok := m["response"].(map[string]interface{}); ok {
				if output, ok := response["output"].([]interface{}); ok {
					for index, rawItem := range output {
						item, ok := rawItem.(map[string]interface{})
						if !ok {
							continue
						}
						projection := itemFor(nil, item, index, "completed", true)
						if !projection.failClosed {
							if collectOpenAIResponsesOutputItem(item, projection) {
								collectOpenAIResponsesAttachments(item, "output", &attachments)
							}
							if inv, ok := toolInvocationFromResponsesItem(item); ok {
								toolInvocations = append(toolInvocations, inv)
							}
						}
					}
				}
			}
		default:
			// response.created / *.added / future events are protocol-only here.
		}
	}
	if !matched {
		return ExtractedContent{}, false
	}
	var answers, reasonings, toolPayloads []string
	for _, item := range itemOrder {
		// fail-closed 与从未被权威事件声明的 item 一律不投影。
		if item.failClosed || !item.declared {
			continue
		}
		answer := ""
		if item.answerSnapshotKnown {
			answer = mergeOpenAIResponsesSnapshots(item.answerSnapshots)
		} else {
			// 无 item 级权威快照时按 content_index lane 结算：有快照的 lane 用快照，
			// 其余 lane 保留增量（LANE_* 用例）。
			answer = openAIResponsesProjectLanes(item.answerLanes)
		}
		if strings.TrimSpace(answer) != "" {
			answers = append(answers, answer)
		}
		reasoning := ""
		if item.reasoningSnapshotKnown {
			reasoning = mergeOpenAIResponsesSnapshots(item.reasoningSnapshots)
		} else {
			reasoning = openAIResponsesProjectLanes(item.reasoningLanes)
		}
		if strings.TrimSpace(reasoning) != "" {
			reasonings = append(reasonings, reasoning)
		}
		if item.toolSnapshotKnown {
			if snapshot := mergeOpenAIResponsesSnapshots(item.toolSnapshots); snapshot != "" {
				toolPayloads = append(toolPayloads, snapshot)
			}
		} else if delta := strings.TrimSpace(item.toolDelta.String()); delta != "" {
			toolPayloads = append(toolPayloads, delta)
		}
	}
	answerText := strings.Join(uniqueStrings(answers), "\n")
	reasoningText := strings.Join(uniqueStrings(reasonings), "\n")
	toolText := strings.Join(uniqueStrings(toolPayloads), "\n[tool] ")
	extracted := buildReassembledExtractedWithTool(answerText, reasoningText, toolText, attachments)
	extracted.ToolInvocations = dedupeToolInvocations(toolInvocations)
	return extracted, true
}

// toolInvocationFromResponsesItem 从 Responses 输出项抽 ToolInvocation（name + 该 item 的
// tool payload 字段文本）。与 collectOpenAIResponsesToolItem 的 field 映射一致，但不写
// projection，只独立收集，绝不影响 Text/SecurityText/VisibleText。
func toolInvocationFromResponsesItem(item map[string]interface{}) (ToolInvocation, bool) {
	itemType, _ := item["type"].(string)
	field := ""
	switch strings.ToLower(strings.TrimSpace(itemType)) {
	case "function_call", "mcp_call":
		field = "arguments"
	case "custom_tool_call":
		field = "input"
	case "code_interpreter_call":
		field = "code"
	case "local_shell_call", "shell_call", "computer_call":
		field = "action"
	default:
		return ToolInvocation{}, false
	}
	raw, _ := item[field].(string)
	if strings.TrimSpace(raw) == "" {
		return ToolInvocation{}, false
	}
	name, _ := item["name"].(string)
	return ToolInvocation{Name: name, Arguments: raw}, true
}

// dedupeToolInvocations 按 (name, arguments) 去重（added/done/completed 可能重复收集同一调用）。
func dedupeToolInvocations(in []ToolInvocation) []ToolInvocation {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]ToolInvocation, 0, len(in))
	for _, inv := range in {
		key := inv.Name + "\x00" + inv.Arguments
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, inv)
	}
	return out
}

type openAIResponsesStreamItem struct {
	toolDelta                                          strings.Builder
	answerSnapshots, reasoningSnapshots, toolSnapshots []string
	answerSnapshotKnown, reasoningSnapshotKnown        bool
	toolSnapshotKnown, failClosed, declared            bool
	// answer/reasoning 的增量按 content_index / summary_index 分 lane 缓冲，
	// 快照只覆盖自己所在 lane，不再整体作废其他 lane 的增量。
	answerLanes, reasoningLanes map[string]*openAIResponsesStreamLane
}

type openAIResponsesStreamLane struct {
	delta         strings.Builder
	snapshots     []string
	snapshotKnown bool
}

func (item *openAIResponsesStreamItem) answerLane(key string) *openAIResponsesStreamLane {
	if item.answerLanes == nil {
		item.answerLanes = make(map[string]*openAIResponsesStreamLane)
	}
	lane, ok := item.answerLanes[key]
	if !ok {
		lane = &openAIResponsesStreamLane{}
		item.answerLanes[key] = lane
	}
	return lane
}

func (item *openAIResponsesStreamItem) reasoningLane(key string) *openAIResponsesStreamLane {
	if item.reasoningLanes == nil {
		item.reasoningLanes = make(map[string]*openAIResponsesStreamLane)
	}
	lane, ok := item.reasoningLanes[key]
	if !ok {
		lane = &openAIResponsesStreamLane{}
		item.reasoningLanes[key] = lane
	}
	return lane
}

func openAIResponsesLaneKey(event map[string]interface{}, field string) string {
	if raw, ok := event[field]; ok && raw != nil {
		return fmt.Sprint(raw)
	}
	return "0"
}

// openAIResponsesProjectLanes 按 lane 序号升序结算：有快照的 lane 输出快照，
// 否则输出该 lane 累积的增量。快照为空串（空/畸形 done）时不覆盖增量。
func openAIResponsesProjectLanes(lanes map[string]*openAIResponsesStreamLane) string {
	if len(lanes) == 0 {
		return ""
	}
	keys := make([]string, 0, len(lanes))
	for key := range lanes {
		keys = append(keys, key)
	}
	numeric := true
	for _, key := range keys {
		if _, err := strconv.Atoi(key); err != nil {
			numeric = false
			break
		}
	}
	if numeric {
		sort.Slice(keys, func(i, j int) bool {
			left, _ := strconv.Atoi(keys[i])
			right, _ := strconv.Atoi(keys[j])
			return left < right
		})
	} else {
		sort.Strings(keys)
	}
	var parts []string
	for _, key := range keys {
		lane := lanes[key]
		if lane.snapshotKnown {
			if snapshot := mergeOpenAIResponsesSnapshots(lane.snapshots); snapshot != "" {
				parts = append(parts, snapshot)
				continue
			}
		}
		if delta := strings.TrimSpace(lane.delta.String()); delta != "" {
			parts = append(parts, delta)
		}
	}
	return strings.Join(parts, "\n")
}

// openAIResponsesIdentityDeclared 判断事件携带的 item 身份是否已被权威事件
// （output_item.added / output_item.done / response.completed）声明过。
func openAIResponsesIdentityDeclared(itemsByID, itemsByIndex map[string]*openAIResponsesStreamItem, event map[string]interface{}) bool {
	if itemID, ok := event["item_id"].(string); ok && itemID != "" {
		if projection, exists := itemsByID[itemID]; exists && projection.declared {
			return true
		}
	}
	if raw, ok := event["output_index"]; ok && raw != nil {
		if projection, exists := itemsByIndex[fmt.Sprint(raw)]; exists && projection.declared {
			return true
		}
	}
	return false
}

func openAIResponsesItemIdentity(event, item map[string]interface{}, completedIndex int) (string, string) {
	itemID := ""
	outputIndex := ""
	if event != nil {
		if value, ok := event["item_id"].(string); ok {
			itemID = strings.TrimSpace(value)
		}
		if value, ok := event["output_index"]; ok && value != nil {
			outputIndex = fmt.Sprint(value)
		}
	}
	if itemID == "" && item != nil {
		if value, ok := item["id"].(string); ok {
			itemID = strings.TrimSpace(value)
		}
	}
	if outputIndex == "" && completedIndex >= 0 {
		outputIndex = fmt.Sprint(completedIndex)
	}
	return itemID, outputIndex
}

func collectOpenAIResponsesOutputItem(item map[string]interface{}, projection *openAIResponsesStreamItem) bool {
	itemType, _ := item["type"].(string)
	switch strings.ToLower(strings.TrimSpace(itemType)) {
	case "message":
		role, _ := item["role"].(string)
		if !strings.EqualFold(strings.TrimSpace(role), "assistant") {
			projection.failClosed = true
			return false
		}
		// 只有真实收集到文本片段才算"有权威快照"；content 缺失/畸形/空（malformed
		// 用例）不得作废此前收到的有效增量。
		if collectOpenAIResponsesMessageContent(item["content"], &projection.answerSnapshots) {
			projection.answerSnapshotKnown = true
		}
		return true
	case "reasoning":
		if collectOpenAIResponsesReasoningContent(item["summary"], &projection.reasoningSnapshots) ||
			collectOpenAIResponsesReasoningContent(item["content"], &projection.reasoningSnapshots) {
			projection.reasoningSnapshotKnown = true
		}
		return false
	case "image_generation_call":
		return true
	default:
		if collectOpenAIResponsesToolItem(item, projection) {
			return false
		}
		projection.failClosed = true
		return false
	}
}

func collectOpenAIResponsesMessageContent(value interface{}, answers *[]string) bool {
	content, ok := value.([]interface{})
	if !ok {
		return false
	}
	found := false
	for _, value := range content {
		part, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		partType, _ := part["type"].(string)
		switch strings.ToLower(strings.TrimSpace(partType)) {
		case "output_text":
			found = appendOpenAIResponsesSnapshotText(part["text"], answers) || found
		case "refusal":
			if _, ok := part["refusal"].(string); ok {
				found = appendOpenAIResponsesSnapshotText(part["refusal"], answers) || found
			} else {
				found = appendOpenAIResponsesSnapshotText(part["text"], answers) || found
			}
		}
	}
	return found
}

func collectOpenAIResponsesReasoningContent(value interface{}, reasonings *[]string) bool {
	content, ok := value.([]interface{})
	if !ok {
		return false
	}
	found := false
	for _, value := range content {
		part, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		partType, _ := part["type"].(string)
		switch strings.ToLower(strings.TrimSpace(partType)) {
		case "summary_text", "reasoning_text":
			found = appendOpenAIResponsesSnapshotText(part["text"], reasonings) || found
		}
	}
	return found
}

func appendOpenAIResponsesSnapshotText(value interface{}, snapshots *[]string) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	text = strings.TrimSpace(safeText([]byte(text)))
	if text == "" {
		return false
	}
	*snapshots = append(*snapshots, text)
	return true
}

func collectOpenAIResponsesToolItem(item map[string]interface{}, projection *openAIResponsesStreamItem) bool {
	itemType, _ := item["type"].(string)
	field := ""
	switch strings.ToLower(strings.TrimSpace(itemType)) {
	case "function_call", "mcp_call":
		field = "arguments"
	case "custom_tool_call":
		field = "input"
	case "computer_call", "web_search_call", "local_shell_call", "shell_call":
		field = "action"
	case "file_search_call":
		field = "queries"
	case "code_interpreter_call":
		field = "code"
	default:
		return false
	}
	projection.toolSnapshotKnown = appendOpenAIResponsesToolPayload(item[field], &projection.toolSnapshots) || projection.toolSnapshotKnown
	return true
}

func openAIResponsesItemAllowsAttachments(item map[string]interface{}) bool {
	itemType, _ := item["type"].(string)
	switch strings.ToLower(strings.TrimSpace(itemType)) {
	case "message":
		role, _ := item["role"].(string)
		return strings.EqualFold(strings.TrimSpace(role), "assistant")
	case "image_generation_call":
		return true
	default:
		return false
	}
}

func collectOpenAIResponsesAttachments(value interface{}, path string, attachments *[]ExtractedAttachment) {
	// image_generation_call 的 result 是裸 base64 图片字节（非 data: URL），
	// 通用 JSON 遍历抓不到，必须显式转附件；字节本身不得成为可见文本。
	if item, ok := value.(map[string]interface{}); ok {
		if itemType, _ := item["type"].(string); strings.EqualFold(strings.TrimSpace(itemType), "image_generation_call") {
			if result, ok := item["result"].(string); ok && strings.TrimSpace(result) != "" {
				appendOpenAIResponsesImageGenAttachment(result, attachments)
				return
			}
		}
	}
	var discardedText []string
	collectJSONText(value, path, &discardedText, attachments)
}

func appendOpenAIResponsesImageGenAttachment(result string, attachments *[]ExtractedAttachment) {
	result = strings.TrimSpace(result)
	raw, err := base64.StdEncoding.DecodeString(result)
	if err != nil || len(raw) == 0 {
		return
	}
	sum := sha256.Sum256(raw)
	*attachments = append(*attachments, ExtractedAttachment{
		Source:      "json_data_url",
		FieldName:   "output.result",
		ContentType: "image/png",
		Size:        int64(len(raw)),
		SHA256:      hex.EncodeToString(sum[:]),
		DataBase64:  result,
	})
}

func mergeOpenAIResponsesSnapshots(values []string) string {
	merged := make([]string, 0, len(values))
	for _, candidate := range uniqueStrings(values) {
		handled := false
		for index, existing := range merged {
			switch {
			case strings.Contains(existing, candidate):
				handled = true
			case strings.Contains(candidate, existing):
				merged[index] = candidate
				handled = true
			}
			if handled {
				break
			}
		}
		if !handled {
			merged = append(merged, candidate)
		}
	}
	return strings.Join(merged, "\n")
}

func appendOpenAIResponsesToolPayload(value interface{}, payloads *[]string) bool {
	if value == nil {
		return false
	}
	var text string
	switch typed := value.(type) {
	case string:
		text = safeText([]byte(typed))
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return false
		}
		text = safeText(encoded)
	}
	text = strings.TrimSpace(text)
	if text == "" || text == "null" || text == "{}" || text == "[]" {
		return false
	}
	*payloads = append(*payloads, text)
	return true
}

type sseEvent struct {
	decoded interface{}
	parsed  bool
	raw     string
}

func parseSSEDataEvents(body []byte) []sseEvent {
	var events []sseEvent
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- SSE/Connect JSON frames need arbitrary JSON text traversal.
		var decoded interface{}
		parsed := true
		if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
			decoded = nil
			parsed = false
		}
		events = append(events, sseEvent{decoded: decoded, parsed: parsed, raw: payload})
	}
	return events
}

// reassembleOpenAIDeltaStream 处理 OpenAI 兼容的流式增量：choices[].delta.content 拼成回答，
// choices[].delta.reasoning_content 拼成思考，二者连续拼接且以 [reasoning] 标记分开。
func reassembleOpenAIDeltaStream(events []sseEvent) (ExtractedContent, bool) {
	matched := false
	var answer, reasoning, toolInput, messageText strings.Builder
	// delta.tool_calls 按 index 聚合 name+arguments（arguments 按 token 增量拼接）。
	type deltaToolCall struct {
		name string
		args strings.Builder
	}
	deltaTools := map[int]*deltaToolCall{}
	deltaToolOrder := []int{}
	for _, ev := range events {
		m, ok := ev.decoded.(map[string]interface{})
		if !ok {
			continue
		}
		choices, ok := m["choices"].([]interface{})
		if !ok {
			continue
		}
		for _, c := range choices {
			cm, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			if msg, ok := cm["message"].(map[string]interface{}); ok {
				// 部分网关在 delta 流式之外于末帧补发完整 message。message.content 里
				// delta 未携带的正文必须保留，否则相对 CANON 逐帧解析会漏检末帧正文。
				// 部分网关每帧都补发「截至当前的完整快照」，逐帧累加会把同一段正文的多个
				// 快照拼成乱序长串、放大下游检测误报；这里只保留最完整（最长）的一份。
				if str, ok := msg["content"].(string); ok && len(str) > messageText.Len() {
					messageText.Reset()
					messageText.WriteString(str)
				}
			}
			delta, ok := cm["delta"].(map[string]interface{})
			if !ok {
				continue
			}
			matched = true
			switch v := delta["content"].(type) {
			case string:
				answer.WriteString(v)
			case []interface{}:
				// 部分网关把 delta.content 以数组分段下发（[{type:text,text:...}]），取出每段 text 拼成回答。
				for _, part := range v {
					if pm, ok := part.(map[string]interface{}); ok {
						if txt, ok := pm["text"].(string); ok {
							answer.WriteString(txt)
						}
					}
				}
			}
			if str, ok := delta["reasoning_content"].(string); ok {
				reasoning.WriteString(str)
			}
			if str, ok := delta["refusal"].(string); ok {
				// delta.refusal 是模型拒答内容，属于回答的一部分，不能丢弃。
				answer.WriteString(str)
			}
			if tcs, ok := delta["tool_calls"].([]interface{}); ok {
				// 工具调用入参 function.arguments 常是自然语言、按 token 切分下发，
				// 与 CANON 逐帧解析一致地按顺序拼接，避免敏感正文漏检。
				for _, tc := range tcs {
					tcm, ok := tc.(map[string]interface{})
					if !ok {
						continue
					}
					idx := 0
					if f, ok := tcm["index"].(float64); ok {
						idx = int(f)
					}
					slot, ok := deltaTools[idx]
					if !ok {
						slot = &deltaToolCall{}
						deltaTools[idx] = slot
						deltaToolOrder = append(deltaToolOrder, idx)
					}
					fn, ok := tcm["function"].(map[string]interface{})
					if !ok {
						continue
					}
					if name, ok := fn["name"].(string); ok && name != "" {
						slot.name = name
					}
					if args, ok := fn["arguments"].(string); ok {
						toolInput.WriteString(args)
						slot.args.WriteString(args)
					}
				}
			}
		}
	}
	if matched {
		// 末帧补发的完整 message 与 delta 重组结果的关系有三种，分别处置以避免正文记两遍：
		//   1) message ⊆ answer：delta 已下发同一段正文 —— 不追加；
		//   2) message ⊇ answer：message 是 answer 的超集（含尾标点/空白规整化差异）——
		//      用更完整的 message 整体取代，而非叠加，避免同一敏感串出现两次放大下游检测误报；
		//   3) 二者互不包含：message 携带 delta 未下发的全新正文 —— 追加保留，避免漏检。
		if mt := strings.TrimSpace(messageText.String()); mt != "" {
			a := answer.String()
			switch {
			case strings.Contains(a, mt):
				// 子串/重复，丢弃。
			case strings.Contains(mt, a):
				answer.Reset()
				answer.WriteString(mt)
			default:
				answer.WriteString(mt)
			}
		}
	}
	att := collectStreamAttachments(events)
	if !matched || (answer.Len() == 0 && reasoning.Len() == 0 && toolInput.Len() == 0 && len(att) == 0) {
		// 匹配到 delta 结构但已知字段（content/reasoning_content）与附件都为空时，
		// 正文可能藏在 tool_calls.arguments 等未覆盖字段里。回退到逐帧 collectJSONText，
		// 与 CANON 始终逐帧解析的行为一致，避免吐空正文导致下游检测漏检。
		return ExtractedContent{}, false
	}
	extracted := buildReassembledExtractedWithTool(answer.String(), reasoning.String(), toolInput.String(), att)
	var invs []ToolInvocation
	for _, idx := range deltaToolOrder {
		slot := deltaTools[idx]
		if strings.TrimSpace(slot.args.String()) != "" {
			invs = append(invs, ToolInvocation{Name: slot.name, Arguments: slot.args.String()})
		}
	}
	extracted.ToolInvocations = invs
	return extracted, true
}

// 置于回答之前（与 appendJSONString 的标记保持一致），便于前端推理面板与正则检测复用。
func buildReassembledExtracted(answer, reasoning string, attachments []ExtractedAttachment) ExtractedContent {
	return buildReassembledExtractedWithTool(answer, reasoning, "", attachments)
}

func buildReassembledExtractedWithTool(answer, reasoning, toolInput string, attachments []ExtractedAttachment) ExtractedContent {
	var parts []string
	if r := strings.TrimSpace(reasoning); r != "" {
		// 思考可能跨多段（reasoning_content 内含换行）。前端按行解析 [reasoning]
		// 标记，因此逐行标记，避免第二段及之后漏进回答面板，与 CANON 逐帧标记一致。
		for _, line := range strings.Split(r, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				parts = append(parts, "[reasoning] "+line)
			}
		}
	}
	if a := strings.TrimSpace(answer); a != "" {
		parts = append(parts, a)
	}
	if tool := strings.TrimSpace(toolInput); tool != "" {
		parts = append(parts, "[tool] "+tool)
	}
	extracted := buildExtracted(parts, attachments, "text/event-stream")
	extracted.VisibleText = strings.TrimSpace(answer)
	extracted.VisibleTextKnown = true
	return extracted
}

// collectStreamAttachments 在重组路径上仍然扫描所有帧，收集模型返回的图片/文件附件，
// 确保流式重组不会丢失附件捕获能力。
func collectStreamAttachments(events []sseEvent) []ExtractedAttachment {
	var parts []string
	var attachments []ExtractedAttachment
	for _, ev := range events {
		if ev.parsed {
			collectJSONText(ev.decoded, "", &parts, &attachments)
		}
	}
	return attachments
}

func extractConnectJSONContent(body []byte, mediaType string) (ExtractedContent, bool) {
	var parts []string
	var attachments []ExtractedAttachment
	frames := 0

	for offset := 0; offset < len(body); {
		if len(body)-offset < 5 {
			return ExtractedContent{}, false
		}
		flags := body[offset]
		length := int(binary.BigEndian.Uint32(body[offset+1 : offset+5]))
		if length < 0 || length > len(body)-offset-5 {
			return ExtractedContent{}, false
		}
		payload := body[offset+5 : offset+5+length]
		offset += 5 + length
		frames++

		if length == 0 {
			continue
		}
		if flags&0x01 == 0x01 {
			parts = append(parts, fmt.Sprintf("[connect_frame compressed size=%d]", length))
			continue
		}

		payload = bytes.TrimSpace(payload)
		if len(payload) == 0 {
			continue
		}
		// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- Connect JSON frames need arbitrary JSON text traversal.
		var decoded interface{}
		if err := json.Unmarshal(payload, &decoded); err == nil {
			collectJSONText(decoded, "", &parts, &attachments)
			continue
		}
		parts = append(parts, safeText(payload))
	}

	if frames == 0 {
		return ExtractedContent{}, false
	}
	return buildExtracted(parts, attachments, mediaType), true
}

func isFormURLEncodedContent(mediaType string) bool {
	return strings.Contains(mediaType, "x-www-form-urlencoded")
}

func extractFormURLEncodedContent(body []byte, mediaType string) (ExtractedContent, bool) {
	values, err := url.ParseQuery(safeText(body))
	if err != nil {
		return ExtractedContent{}, false
	}
	var parts []string
	var attachments []ExtractedAttachment
	for key, fieldValues := range values {
		key = strings.TrimSpace(key)
		if key == "" || isProtocolFormField(key) {
			continue
		}
		for _, rawValue := range fieldValues {
			value := strings.TrimSpace(rawValue)
			if value == "" {
				continue
			}
			if key == "f.req" || isJSONContent("", []byte(value)) {
				// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- form fields may contain arbitrary JSON text that must be traversed for audit extraction; encoding/json does not instantiate arbitrary types.
				var decoded interface{}
				if err := json.Unmarshal([]byte(value), &decoded); err == nil {
					collectJSONText(decoded, key, &parts, &attachments)
					continue
				}
			}
			if attachment, ok := attachmentFromDataURL(key, value); ok {
				attachments = append(attachments, attachment)
				parts = append(parts, fmt.Sprintf("[embedded:%s type=%s size=%d sha256=%s]", key, attachment.ContentType, attachment.Size, attachment.SHA256))
				continue
			}
			if attachment, ok := attachmentFromImageURL(key, value); ok {
				attachments = append(attachments, attachment)
				continue
			}
			if classifyRetainedFileURL(key, value) {
				attachments = append(attachments, attachmentFromFileURL("form_file_url", key, value, "", "", 0, ""))
				continue
			}
			if looksLikeRetainedFileReference(key, value) {
				parts = append(parts, fmt.Sprintf("[%s] %s", key, value))
				attachments = append(attachments, attachmentsFromFileReference(key, value)...)
				continue
			}
			if shouldSkipJSONText(key, value) && !isSemanticFormField(key) {
				continue
			}
			if isSemanticFormField(key) || looksLikeHumanText(value) {
				parts = append(parts, value)
			}
		}
	}
	return buildExtracted(parts, attachments, mediaType), true
}

func isProtocolFormField(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "_reqid", "at", "bl", "hl", "rt", "source-path", "soc-app", "soc-platform", "soc-device", "rpcids", "f.sid":
		return true
	default:
		return false
	}
}

func isSemanticFormField(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "prompt", "query", "question", "message", "text", "content", "input":
		return true
	default:
		return false
	}
}

// isConversationAttachmentEchoPath 命中 Kimi 网页会话「已挂载文件」集合的 JSON 路径
// （chat.files 及其子路径）。该集合是用户上传文件在 /Chat 响应里的回显，模型新产出的
// 文件/图片走 message.refs.images、artifacts[] 等其它字段，不经此路径，故跳过它不会丢失
// 任何模型输出，只会消除把用户上传回显误判为「模型返回文件/图片」的幻影。
func isConversationAttachmentEchoPath(path string) bool {
	return path == "chat.files" || strings.HasPrefix(path, "chat.files.")
}

func collectJSONText(value interface{}, path string, parts *[]string, attachments *[]ExtractedAttachment) {
	// Kimi 网页 /Chat 响应体里的 chat.files 是「会话已挂载的文件集合」——用户上传文件的回显，
	// 不是模型新产出的文件。这些文件已在 /file/upload 请求侧带原始字节捕获（stage:request）。
	// 若在响应侧再抓一遍，会被 audit 统一打上 stage:response，错误地显示成「模型返回了文件/图片」。
	// 故整棵 chat.files 子树跳过：既不登记附件，也不让 signUrl/previewUrl 当文本泄露。
	// 模型真正产出的文件/图片走 message.refs.images、artifacts[] 等其它字段，不经此路径。
	if isConversationAttachmentEchoPath(path) {
		return
	}
	switch v := value.(type) {
	case map[string]interface{}:
		objectAttachments := attachmentsFromJSONFileObject(path, v)
		objectAttachments = append(objectAttachments, attachmentsFromJSONImageObject(path, v)...)
		objectAttachments = append(objectAttachments, attachmentsFromJSONTypedFileObject(path, v)...)
		// 没有下载 URL、但带 file-id+文件名的附件对象（ChatGPT/Claude/DeepSeek 网页上传都是这种）：
		// 直接登记人类可读文件名，避免下面字符串遍历把裸 file-id 当成"引用编码"展示。
		if len(objectAttachments) == 0 {
			objectAttachments = append(objectAttachments, attachmentsFromJSONFileIDObject(path, v)...)
		}
		*attachments = append(*attachments, objectAttachments...)
		coveredURLs := map[string]struct{}{}
		coveredRefs := map[string]struct{}{}
		for _, attachment := range objectAttachments {
			if attachment.DownloadURL != "" {
				coveredURLs[strings.TrimSpace(attachment.DownloadURL)] = struct{}{}
			}
			if attachment.ReferenceID != "" {
				coveredRefs[strings.TrimSpace(attachment.ReferenceID)] = struct{}{}
			}
		}
		if len(objectAttachments) > 0 {
			for key, raw := range v {
				value, ok := raw.(string)
				if !ok {
					continue
				}
				fieldName := key
				if path != "" {
					fieldName = path + "." + key
				}
				if classifyImageURL(fieldName, value) || classifyRetainedFileURL(fieldName, value) {
					coveredURLs[strings.TrimSpace(value)] = struct{}{}
				}
			}
		}
		for key, child := range v {
			if value, ok := child.(string); ok {
				trimmedChild := strings.TrimSpace(value)
				if _, covered := coveredURLs[trimmedChild]; covered {
					continue
				}
				if _, covered := coveredRefs[trimmedChild]; covered {
					continue
				}
			}
			// 外层已登记图片/文件附件时,其内嵌图片变体子对象(原图/缩略/预览)已由外层那条代表,
			// 不再递归单独登记,避免一张图冒出 wrapper+ori+thumb+preview 多条冗余留证。
			if len(objectAttachments) > 0 && isImageVariantKey(key) {
				if _, isObj := child.(map[string]interface{}); isObj {
					continue
				}
			}
			nextPath := key
			if path != "" {
				nextPath = path + "." + key
			}
			collectJSONText(child, nextPath, parts, attachments)
		}
	case []interface{}:
		for _, item := range v {
			collectJSONText(item, path, parts, attachments)
		}
	case string:
		appendJSONString(path, v, parts, attachments)
	}
}

func appendJSONString(path, value string, parts *[]string, attachments *[]ExtractedAttachment) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}
	if isReasoningJSONPath(path) {
		*parts = append(*parts, "[reasoning] "+trimmed)
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
	if shouldDiscardRetainedFileURLText(path, trimmed) || isFileTypeProtocolValue(trimmed) {
		return
	}
	// 相对下载短链（/file?file_id=<uuid>&state=<base64签名token> 等）是下载凭证、协议管线，
	// 与上面的绝对 http(s) 下载链同等处理：丢弃，绝不把超长签名编码与文件 ID 塞进给人看的留存内容。
	if looksLikeSignedDownloadShortLink(trimmed) {
		return
	}
	if isProtocolJSONPath(strings.ToLower(path)) && (strings.HasPrefix(strings.ToLower(trimmed), "http://") || strings.HasPrefix(strings.ToLower(trimmed), "https://")) {
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
	if !isSemanticJSONTextPath(path) && !looksLikeHumanText(trimmed) {
		return
	}
	if len(trimmed) > maxTextFragmentBytes {
		trimmed = trimmed[:maxTextFragmentBytes] + "...[truncated]"
	}
	*parts = append(*parts, trimmed)
}

func isCompressedPayload(body []byte) bool {
	if len(body) >= 3 && body[0] == 0x1f && body[1] == 0x8b && body[2] == 0x08 {
		return true
	}
	if len(body) >= 4 && body[0] == 0x28 && body[1] == 0xb5 && body[2] == 0x2f && body[3] == 0xfd {
		return true
	}
	return false
}

func isReasoningJSONPath(path string) bool {
	segments := strings.Split(strings.ToLower(path), ".")
	if len(segments) == 0 {
		return false
	}
	switch segments[len(segments)-1] {
	case "reasoning", "reasoning_content", "thinking", "thinking_content", "think", "thought", "chain_of_thought", "cot":
		return true
	default:
		return false
	}
}

func shouldSkipJSONText(path, value string) bool {
	lowerPath := strings.ToLower(path)
	lowerValue := strings.ToLower(strings.TrimSpace(value))
	if isProtocolJSONPath(lowerPath) {
		return true
	}
	if isSemanticJSONTextPath(path) {
		return false
	}
	return isProtocolJSONValue(lowerValue)
}

func isProtocolJSONPath(lowerPath string) bool {
	return isProtocolJSONPathForVendor("", lowerPath)
}

func isProtocolJSONPathForVendor(vendor, lowerPath string) bool {
	segments := strings.Split(lowerPath, ".")
	last := ""
	if len(segments) > 0 {
		last = segments[len(segments)-1]
	}
	if last == "" {
		return false
	}
	if hasProtocolJSONKey(vendor, last) {
		return true
	}
	return strings.HasSuffix(last, "_id") || strings.HasSuffix(last, "_ids") || strings.HasSuffix(last, "_url") || strings.HasSuffix(last, "url") || strings.HasSuffix(last, "uri") || strings.Contains(lowerPath, "metadata") || strings.Contains(lowerPath, "client_meta")
}

func isProtocolJSONValue(lowerValue string) bool {
	if lowerValue == "set" || lowerValue == "append" || lowerValue == "replace" || lowerValue == "done" || lowerValue == "default" || lowerValue == "assistant" || lowerValue == "user" || lowerValue == "system" || lowerValue == "未命名会话" {
		return true
	}
	if isFileTypeProtocolValue(lowerValue) {
		return true
	}
	if strings.HasPrefix(lowerValue, "scenario_") || strings.HasPrefix(lowerValue, "tool_type_") || strings.HasPrefix(lowerValue, "message_status_") || strings.HasPrefix(lowerValue, "local_") {
		return true
	}
	if strings.HasPrefix(lowerValue, "http://") || strings.HasPrefix(lowerValue, "https://") {
		return true
	}
	if standaloneUUIDValuePattern.MatchString(lowerValue) || protocolLongNumberPattern.MatchString(lowerValue) {
		return true
	}
	return strings.Contains(lowerValue, ".") && strings.Contains(lowerValue, "block") && strings.Contains(lowerValue, "content")
}

func isSemanticJSONTextPath(path string) bool {
	return isSemanticJSONTextPathForVendor("", path)
}

func isSemanticJSONTextPathForVendor(vendor, path string) bool {
	lowerPath := strings.ToLower(path)
	segments := strings.Split(lowerPath, ".")
	last := ""
	if len(segments) > 0 {
		last = segments[len(segments)-1]
	}
	if hasSemanticJSONKey(vendor, last) {
		return true
	}
	return strings.Contains(lowerPath, "text_block.text") || strings.Contains(lowerPath, "text_block.content")
}

func looksLikeHumanText(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	for _, r := range value {
		if r >= 0x4e00 && r <= 0x9fff {
			return true
		}
	}
	return strings.Contains(value, " ") && len(value) >= 16
}

func attachmentsFromJSONFileObject(path string, item map[string]interface{}) []ExtractedAttachment {
	if !hasFilePathContext(path) && !jsonObjectHasFileURLContext(item) {
		return nil
	}

	type urlCandidate struct {
		fieldName string
		value     string
		priority  int
	}
	var best urlCandidate
	for key, raw := range item {
		value, ok := raw.(string)
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" || !strings.HasPrefix(strings.ToLower(value), "http") {
			continue
		}
		fieldName := key
		if path != "" {
			fieldName = path + "." + key
		}
		if !classifyRetainedFileURL(fieldName, value) {
			continue
		}
		candidate := urlCandidate{fieldName: fieldName, value: value, priority: fileURLFieldPriority(key)}
		if best.value == "" || candidate.priority < best.priority {
			best = candidate
		}
	}
	if best.value == "" {
		return nil
	}
	fileName := fileNameFromDownloadURL(best.value)
	if fileName == "" {
		fileName = fileNameFromJSONObject(item)
	}
	contentType := contentTypeFromJSONObject(item)
	if contentType == "" {
		contentType = inferContentType(fileName, nil)
	}
	return []ExtractedAttachment{{
		Source:      "json_file_url",
		FieldName:   best.fieldName,
		FileName:    fileName,
		ReferenceID: referenceIDFromDownloadURL(best.value),
		ContentType: contentType,
		Size:        sizeFromJSONObject(item),
		SHA256:      sha256FromJSONObject(item),
		DownloadURL: best.value,
	}}
}

// attachmentsFromJSONFileIDObject 处理"没有下载 URL，但同一对象里同时带 file-id 和文件名"的附件对象。
// 这是 ChatGPT/Claude/DeepSeek 网页上传文件时最常见的形态，例如
// {"id":"file-AbC123","name":"季度财报.pdf","mime_type":"application/pdf","size":284512}。
// 只有当能给出人类可读文件名时才在此登记，纯裸 file-id（无文件名）留给跨请求 catalog 还原，
// 避免再向访问留存吐出"编码/ID"。
func attachmentsFromJSONFileIDObject(path string, item map[string]interface{}) []ExtractedAttachment {
	if !hasFilePathContext(path) && !jsonObjectLooksLikeFile(item) {
		return nil
	}
	fileName := fileNameFromJSONObject(item)
	if fileName == "" {
		return nil
	}
	contentType := contentTypeFromJSONObject(item)
	if contentType == "" {
		contentType = inferContentType(fileName, nil)
	}
	att := ExtractedAttachment{
		Source:      "json_file_object",
		FieldName:   path,
		FileName:    fileName,
		ReferenceID: referenceIDFromJSONObject(item),
		ContentType: contentType,
		Size:        sizeFromJSONObject(item),
		SHA256:      sha256FromJSONObject(item),
	}
	// biz_data.files 等结构的相对签名下载短链(signed_path,形如 /file?file_id=&state=<签名>)自带签名、
	// 可下载。留到 DownloadURL(仅附件元数据,不进给人看的文本——文本侧仍由字符串遍历丢弃)供留证旁路
	// 抓字节;抓完会清掉,签名 token 不落库。这是豆包/DeepSeek 网页版文件取字节的唯一可行路径。
	if sp := signedDownloadPathFromJSONObject(item); sp != "" {
		att.DownloadURL = sp
	}
	// 豆包等结构:image 对象内嵌 image_ori/image_thumb/image_preview 变体各带 url,而 image 自身只有
	// name/uri(非 http)→ 过去登记成空壳 json_file_object(无字节)+ 变体各自又冒一条 json_image_url。
	// 这里把原图 url 提到外层附件(优先 image_ori 原图);变体子对象在 collectJSONText 递归处被跳过,
	// 最终一张图=一条可下载的留证。
	if att.DownloadURL == "" {
		if u := bestImageVariantURLFromJSONObject(item); u != "" {
			att.DownloadURL = u
		}
	}
	return []ExtractedAttachment{att}
}

// imageVariantKeys 是图片对象里常见的"变体子对象"键(原图/缩略/预览),各自内嵌 url。
var imageVariantKeys = []string{
	"image_ori", "image_original", "image_raw", "original", "ori", "raw",
	"image_preview", "preview", "image_thumb", "thumb", "image_large", "large",
}

func isImageVariantKey(key string) bool {
	for _, k := range imageVariantKeys {
		if key == k {
			return true
		}
	}
	return false
}

// bestImageVariantURLFromJSONObject 从图片对象的内嵌变体里取最佳下载 url(优先原图,其次预览/缩略)。
func bestImageVariantURLFromJSONObject(item map[string]interface{}) string {
	for _, key := range imageVariantKeys {
		sub, ok := item[key].(map[string]interface{})
		if !ok {
			continue
		}
		if u, ok := sub["url"].(string); ok {
			u = strings.TrimSpace(u)
			if strings.HasPrefix(strings.ToLower(u), "http") {
				return u
			}
		}
	}
	return ""
}

// signedDownloadPathFromJSONObject 取文件对象里的相对签名下载短链(signed_path 等),
// 仅当确为签名短链(looksLikeSignedDownloadShortLink)时返回,避免误吞普通相对路径。
func signedDownloadPathFromJSONObject(item map[string]interface{}) string {
	for _, key := range []string{"signed_path", "signedPath", "download_path", "downloadPath", "download_url", "downloadUrl"} {
		value, ok := item[key].(string)
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") && looksLikeSignedDownloadShortLink(value) {
			return value
		}
	}
	return ""
}

// jsonObjectLooksLikeFile 在 JSON 路径本身没有文件语境（如附件被挂在非 file 命名的字段下）时，
// 用对象自身的特征判断它是不是一个文件对象，避免误吞 {"name":"张三"} 这类人名对象。
func jsonObjectLooksLikeFile(item map[string]interface{}) bool {
	if typeName, ok := item["type"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(typeName)) {
		case "file", "input_file", "document", "input_document", "attachment", "image", "input_image":
			return true
		}
	}
	for _, key := range []string{"file_name", "filename", "fileName"} {
		if value, ok := item[key].(string); ok && strings.TrimSpace(value) != "" {
			return true
		}
	}
	if referenceIDFromJSONObject(item) != "" && contentTypeFromJSONObject(item) != "" {
		return true
	}
	return false
}

// referenceIDFromJSONObject 从文件对象中取出稳定的文件标识，优先专用 file/attachment/document 等键，
// 通用 id/uuid 放最后兜底，并跳过 FILE_TYPE_ 这类协议枚举值。
func referenceIDFromJSONObject(item map[string]interface{}) string {
	for _, key := range []string{
		"file_id", "fileId", "file_uuid", "fileUuid",
		"attachment_id", "attachmentId",
		"document_id", "documentId",
		"asset_id", "assetId",
		"media_id", "mediaId",
		"resource_id", "resourceId",
		"id", "uuid",
	} {
		value, ok := item[key].(string)
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" || isFileTypeProtocolValue(value) {
			continue
		}
		return value
	}
	return ""
}

func attachmentsFromFileReference(path, value string) []ExtractedAttachment {
	lowerPath := strings.ToLower(path)
	if !strings.Contains(lowerPath, "file") && !strings.Contains(lowerPath, "attachment") && !strings.Contains(lowerPath, "upload") && !strings.Contains(lowerPath, "document") {
		return nil
	}
	ids := uniqueStrings(fileReferenceIDPattern.FindAllString(value, -1))
	if len(ids) == 0 {
		return nil
	}
	out := make([]ExtractedAttachment, 0, len(ids))
	for _, id := range ids {
		if isFileTypeProtocolValue(id) {
			continue
		}
		out = append(out, ExtractedAttachment{
			Source:      "json_file_reference",
			FieldName:   path,
			ReferenceID: id,
			ContentType: "reference/file-id",
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func uniqueStrings(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func attachmentFromDataURL(path, value string) (ExtractedAttachment, bool) {
	matches := dataURLPattern.FindStringSubmatch(value)
	if len(matches) != 4 || matches[2] != ";base64" {
		return ExtractedAttachment{}, false
	}
	decoded, err := base64.StdEncoding.DecodeString(matches[3])
	if err != nil {
		return ExtractedAttachment{}, false
	}
	return attachmentFromBytes("json_data_url", path, "", matches[1], decoded), true
}

// attachmentsFromJSONTypedFileObject handles file/image blocks in generic JSON
// envelopes when no provider-specific decoder is available. Known model APIs
// use their decoder; this fallback keeps arbitrary forward-proxy paths from
// silently treating inline file bytes as ordinary JSON strings.
func attachmentsFromJSONTypedFileObject(path string, item map[string]interface{}) []ExtractedAttachment {
	typeName, _ := item["type"].(string)
	switch strings.ToLower(strings.TrimSpace(typeName)) {
	case "file", "input_file", "document", "input_document", "attachment", "image", "input_image":
	default:
		return nil
	}

	fileName := fileNameFromJSONObject(item)
	contentType := contentTypeFromJSONObject(item)
	if contentType == "" {
		contentType = inferContentType(fileName, nil)
	}
	if source, ok := item["source"].(map[string]interface{}); ok {
		if media, ok := source["media_type"].(string); ok && strings.TrimSpace(media) != "" {
			contentType = strings.TrimSpace(media)
		}
		sourceType, _ := source["type"].(string)
		switch strings.ToLower(strings.TrimSpace(sourceType)) {
		case "base64":
			if raw, ok := source["data"].(string); ok {
				if attachment, ok := attachmentFromEncodedJSONFile(path, fileName, contentType, raw); ok {
					return []ExtractedAttachment{attachment}
				}
			}
		case "url":
			if raw, ok := source["url"].(string); ok && strings.TrimSpace(raw) != "" {
				if attachment, ok := attachmentFromDataURL(path, raw); ok {
					attachment.FileName = fileName
					return []ExtractedAttachment{attachment}
				}
				return []ExtractedAttachment{attachmentFromFileURL("json_file_url", path, raw, fileName, contentType, sizeFromJSONObject(item), sha256FromJSONObject(item))}
			}
		}
	}

	for _, key := range []string{"file_data", "data"} {
		raw, ok := item[key]
		if !ok {
			continue
		}
		if attachment, ok := attachmentFromJSONFileValue(path, fileName, contentType, raw); ok {
			return []ExtractedAttachment{attachment}
		}
	}
	return nil
}

func attachmentFromJSONFileValue(path, fileName, contentType string, raw interface{}) (ExtractedAttachment, bool) {
	switch value := raw.(type) {
	case string:
		return attachmentFromEncodedJSONFile(path, fileName, contentType, value)
	case map[string]interface{}:
		if nestedContentType := contentTypeFromJSONObject(value); nestedContentType != "" {
			contentType = nestedContentType
		}
		for _, key := range []string{"base64", "data"} {
			encoded, ok := value[key].(string)
			if !ok {
				continue
			}
			if attachment, ok := attachmentFromEncodedJSONFile(path, fileName, contentType, encoded); ok {
				return attachment, true
			}
		}
		if rawURL, ok := value["url"].(string); ok && strings.TrimSpace(rawURL) != "" {
			if attachment, ok := attachmentFromDataURL(path, rawURL); ok {
				attachment.FileName = fileName
				if attachment.ContentType == "" {
					attachment.ContentType = contentType
				}
				return attachment, true
			}
			return attachmentFromFileURL("json_file_url", path, rawURL, fileName, contentType, 0, ""), true
		}
	}
	return ExtractedAttachment{}, false
}

func attachmentFromEncodedJSONFile(path, fileName, contentType, raw string) (ExtractedAttachment, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ExtractedAttachment{}, false
	}
	if media, payload := parseDataURLForAttachment(raw); payload != "" {
		if contentType == "" {
			contentType = media
		}
		raw = payload
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(decoded) == 0 {
		return ExtractedAttachment{}, false
	}
	return attachmentFromBytes("json_file_data", path, fileName, contentType, decoded), true
}

func parseDataURLForAttachment(raw string) (string, string) {
	matches := dataURLPattern.FindStringSubmatch(raw)
	if len(matches) != 4 || matches[2] != ";base64" {
		return "", ""
	}
	if _, err := base64.StdEncoding.DecodeString(matches[3]); err != nil {
		return "", ""
	}
	return matches[1], matches[3]
}

func attachmentsFromJSONImageObject(path string, item map[string]interface{}) []ExtractedAttachment {
	if !hasImagePathContext(path) && !jsonObjectHasImageURLContext(item) {
		return nil
	}
	type urlCandidate struct {
		fieldName string
		value     string
		priority  int
	}
	var best urlCandidate
	for key, raw := range item {
		value, ok := raw.(string)
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		fieldName := key
		if path != "" {
			fieldName = path + "." + key
		}
		if !classifyImageURL(fieldName, value) {
			continue
		}
		candidate := urlCandidate{fieldName: fieldName, value: value, priority: imageURLFieldPriority(key)}
		if best.value == "" || candidate.priority < best.priority {
			best = candidate
		}
	}
	if best.value == "" {
		return nil
	}
	attachment, ok := attachmentFromImageURL(best.fieldName, best.value)
	if !ok {
		return nil
	}
	return []ExtractedAttachment{attachment}
}

func attachmentFromImageURL(path, value string) (ExtractedAttachment, bool) {
	if !classifyImageURL(path, value) {
		return ExtractedAttachment{}, false
	}
	fileName := fileNameFromDownloadURL(value)
	if fileName == "" {
		fileName = "model-image"
	}
	return ExtractedAttachment{
		Source:      "json_image_url",
		FieldName:   path,
		FileName:    fileName,
		ReferenceID: referenceIDFromDownloadURL(value),
		ContentType: contentTypeFromImageURL(value),
		DownloadURL: value,
	}, true
}

func attachmentFromFileURL(source, fieldName, rawURL, fileName, contentType string, size int64, sha256Value string) ExtractedAttachment {
	if fileName == "" {
		fileName = fileNameFromDownloadURL(rawURL)
	}
	if contentType == "" {
		contentType = inferContentType(fileName, nil)
	}
	return ExtractedAttachment{
		Source:      source,
		FieldName:   fieldName,
		FileName:    fileName,
		ReferenceID: referenceIDFromDownloadURL(rawURL),
		ContentType: contentType,
		Size:        size,
		SHA256:      sha256Value,
		DownloadURL: rawURL,
	}
}

func hasImagePathContext(path string) bool {
	lowerPath := strings.ToLower(path)
	return strings.Contains(lowerPath, "image") || strings.Contains(lowerPath, "images") || strings.Contains(lowerPath, "img") || strings.Contains(lowerPath, "picture") || strings.Contains(lowerPath, "photo") || strings.Contains(lowerPath, "generated") || strings.Contains(lowerPath, "output")
}

func jsonObjectHasImageURLContext(item map[string]interface{}) bool {
	for key, raw := range item {
		if value, ok := raw.(string); ok && classifyImageURL(key, value) {
			return true
		}
	}
	return false
}

// looksLikeSVGAssetURL 判断 value 是否为 .svg 矢量资源 URL（忽略查询串，按下载文件名后缀判定）。
// 在正向代理抓取的网页大模型对话里，.svg 链接几乎只会是网页 UI 的图标/装饰（例如 Gemini 用的
// fonts.gstatic.com/s/i/short-term/release/googlesymbols/.../24px.svg 这类 Material Symbols 图标），
// 多为 0 字节占位，并非模型真实产出的图片。据此在图片识别闸门处统一排除，避免污染「模型返回图片」。
func looksLikeSVGAssetURL(value string) bool {
	value = strings.TrimSpace(value)
	lowerValue := strings.ToLower(value)
	if !strings.HasPrefix(lowerValue, "http://") && !strings.HasPrefix(lowerValue, "https://") {
		return false
	}
	return strings.HasSuffix(strings.ToLower(fileNameFromDownloadURL(value)), ".svg")
}

func classifyImageURL(path, value string) bool {
	value = strings.TrimSpace(value)
	lowerValue := strings.ToLower(value)
	if !strings.HasPrefix(lowerValue, "http://") && !strings.HasPrefix(lowerValue, "https://") {
		return false
	}
	// .svg 资源（gstatic Material Symbols 等网页 UI 矢量图标）一律不作为模型图片附件，详见
	// looksLikeSVGAssetURL。必须早于下面 hasImagePathContext / 扩展名等任何放行分支拦截，否则当
	// svg 链接恰好处在含 image 的路径下时，会被 hasImagePathContext 直接放行成图片附件。
	if looksLikeSVGAssetURL(value) {
		return false
	}
	lowerPath := strings.ToLower(path)
	if (strings.Contains(lowerPath, "icon") || strings.Contains(lowerPath, "avatar")) && !strings.Contains(lowerPath, "generated") && !strings.Contains(lowerPath, "output") {
		return false
	}
	if strings.Contains(lowerPath, "source") && !fileExtensionLooksImage(fileNameFromDownloadURL(value)) {
		return false
	}
	if hasImagePathContext(lowerPath) || strings.Contains(lowerPath, "thumb") || strings.Contains(lowerPath, "origin") || strings.Contains(lowerPath, "original") || strings.Contains(lowerPath, "fullsize") {
		return true
	}
	return fileExtensionLooksImage(fileNameFromDownloadURL(value))
}

func imageURLFieldPriority(key string) int {
	lowerKey := strings.ToLower(key)
	switch {
	case strings.Contains(lowerKey, "origin") || strings.Contains(lowerKey, "original") || strings.Contains(lowerKey, "full"):
		return 1
	case lowerKey == "url" || strings.Contains(lowerKey, "imageurl") || strings.Contains(lowerKey, "image_url") || strings.Contains(lowerKey, "src"):
		return 2
	case strings.Contains(lowerKey, "preview"):
		return 3
	case strings.Contains(lowerKey, "thumb"):
		return 4
	default:
		return 5
	}
}

func contentTypeFromImageURL(rawURL string) string {
	switch strings.ToLower(filepath.Ext(fileNameFromDownloadURL(rawURL))) {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".bmp":
		return "image/bmp"
	case ".svg":
		return "image/svg+xml"
	default:
		return "image/*"
	}
}

func fileExtensionLooksImage(fileName string) bool {
	switch strings.ToLower(filepath.Ext(fileName)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg":
		return true
	default:
		return false
	}
}

func attachmentFromBytes(source, fieldName, fileName, contentType string, body []byte) ExtractedAttachment {
	return attachmentFromBytesWithPolicy(defaultAttachmentRetentionPolicy(), source, fieldName, fileName, contentType, body)
}

func attachmentFromBytesWithPolicy(policy AttachmentRetentionPolicy, source, fieldName, fileName, contentType string, body []byte) ExtractedAttachment {
	sum := sha256.Sum256(body)
	attachment := ExtractedAttachment{
		Source:      source,
		FieldName:   fieldName,
		FileName:    fileName,
		ContentType: contentType,
		Size:        int64(len(body)),
		SHA256:      hex.EncodeToString(sum[:]),
	}
	if policy.ShouldRetainBytes(contentType, fileName, body) {
		attachment.DataBase64 = base64.StdEncoding.EncodeToString(body)
	}
	return attachment
}

func shouldRetainAttachmentBytes(contentType, fileName string, body []byte) bool {
	if len(body) == 0 || len(body) > maxAttachmentContextBytes {
		return false
	}
	lower := strings.ToLower(contentType)
	if strings.HasPrefix(lower, "image/") {
		return true
	}
	return !isTextualContent(contentType, fileName, body)
}

func buildExtracted(parts []string, attachments []ExtractedAttachment, contentType string) ExtractedContent {
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}
	return ExtractedContent{
		Text:        strings.Join(cleaned, "\n"),
		ContentType: contentType,
		Attachments: uniqueAttachments(attachments),
	}
}

func isConnectJSONContent(mediaType string) bool {
	return strings.Contains(mediaType, "connect+json")
}

func isJSONContent(mediaType string, body []byte) bool {
	if strings.Contains(mediaType, "json") {
		return true
	}
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func isEventStream(contentType string, body []byte) bool {
	lower := strings.ToLower(contentType)
	return strings.Contains(lower, "text/event-stream") || bytes.HasPrefix(bytes.TrimSpace(body), []byte("data:"))
}

// decodeContentEncoding 按 HTTP Content-Encoding 头把响应体解压成原文，供安全抽取/检测使用。
// 正向代理仍把原始压缩字节回写给客户端，这里只对副本解压：网页大模型端几乎都用 br/gzip/zstd
// 压缩响应，不解压则正文是乱码、敏感数据漏检。未知编码或解压失败时原样返回，确保不 panic、不丢数据，
// 由上层 isCompressedPayload 兜底跳过。注意：解码必须在持有 Content-Encoding 头的调用方完成——
// extractResponseContent 仅凭裸字节不解压，从而保留「无头压缩体直接跳过」的安全护栏。
func decodeContentEncoding(body []byte, encoding string) []byte {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	if enc == "" || enc == "identity" || len(body) == 0 {
		return body
	}
	// Content-Encoding 可叠加多层（如 "br, gzip"），列出顺序是应用顺序，解码需逆序。
	// 实践中网页大模型几乎只用单层，这里按逆序逐层尝试，任一层失败即整体回退原始字节。
	layers := strings.Split(enc, ",")
	out := body
	for i := len(layers) - 1; i >= 0; i-- {
		decoded, ok := decodeOneEncoding(out, strings.TrimSpace(layers[i]))
		if !ok {
			return body
		}
		out = decoded
	}
	return out
}

func decodeOneEncoding(body []byte, layer string) ([]byte, bool) {
	switch layer {
	case "", "identity":
		return body, true
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		defer r.Close()
		out, err := io.ReadAll(io.LimitReader(r, maxAttachmentContextBytes))
		if err != nil {
			return nil, false
		}
		return out, true
	case "br":
		out, err := io.ReadAll(io.LimitReader(brotli.NewReader(bytes.NewReader(body)), maxAttachmentContextBytes))
		if err != nil {
			return nil, false
		}
		return out, true
	case "zstd":
		r, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		defer r.Close()
		out, err := io.ReadAll(io.LimitReader(r, maxAttachmentContextBytes))
		if err != nil {
			return nil, false
		}
		return out, true
	case "deflate":
		// HTTP deflate 规范是 zlib 包裹（RFC1950），但不少服务端直接发裸 DEFLATE，两者都试。
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			defer zr.Close()
			if out, err := io.ReadAll(io.LimitReader(zr, maxAttachmentContextBytes)); err == nil {
				return out, true
			}
		}
		fr := flate.NewReader(bytes.NewReader(body))
		defer fr.Close()
		out, err := io.ReadAll(io.LimitReader(fr, maxAttachmentContextBytes))
		if err != nil {
			return nil, false
		}
		return out, true
	default:
		return nil, false
	}
}

func isTemporaryRedirectHTML(mediaType string, body []byte) bool {
	if !strings.Contains(strings.ToLower(mediaType), "html") {
		return false
	}
	text := strings.ToLower(strings.TrimSpace(safeText(body)))
	return strings.Contains(text, "temporary redirect") && strings.Contains(text, "<a ")
}

func responseFileNameForMediaType(mediaType string) string {
	lower := strings.ToLower(strings.TrimSpace(mediaType))
	switch lower {
	case "image/png":
		return "model-response.png"
	case "image/jpeg", "image/jpg":
		return "model-response.jpg"
	case "image/gif":
		return "model-response.gif"
	case "image/webp":
		return "model-response.webp"
	case "application/pdf":
		return "model-response.pdf"
	case "application/msword":
		return "model-response.doc"
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return "model-response.docx"
	case "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return "model-response.xlsx"
	case "application/vnd.ms-powerpoint", "application/vnd.openxmlformats-officedocument.presentationml.presentation":
		return "model-response.pptx"
	case "application/zip":
		return "model-response.zip"
	}
	if strings.HasPrefix(lower, "image/") {
		return "model-response-image"
	}
	// 其余非图片二进制：尽量按媒体类型推一个扩展名，让访问留存里显示成「正式、给人看」的文件名，
	// 而非裸编码；推不出扩展名时退回通用的文件命名（仍不暴露任何 id/编码）。
	if exts, err := mime.ExtensionsByType(lower); err == nil && len(exts) > 0 {
		return "model-response" + exts[0]
	}
	return "model-response-file"
}

func isTextualContent(contentType, fileName string, body []byte) bool {
	lower := strings.ToLower(contentType)
	if strings.HasPrefix(lower, "image/") || strings.HasPrefix(lower, "audio/") || strings.HasPrefix(lower, "video/") || strings.Contains(lower, "pdf") || strings.Contains(lower, "zip") || strings.Contains(lower, "octet-stream") {
		return false
	}
	if bodyLooksBinary(body) {
		return false
	}
	switch strings.ToLower(filepath.Ext(fileName)) {
	case ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".zip", ".gz", ".tar", ".7z", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx":
		return false
	case ".txt", ".md", ".json", ".yaml", ".yml", ".xml", ".csv", ".tsv", ".log", ".env", ".ini", ".conf", ".go", ".py", ".js", ".ts", ".tsx", ".java", ".rs", ".sql", ".sh", ".html", ".htm", ".css":
		return true
	}
	if strings.HasPrefix(lower, "text/") || strings.Contains(lower, "json") || strings.Contains(lower, "xml") || strings.Contains(lower, "yaml") || strings.Contains(lower, "javascript") || strings.Contains(lower, "x-www-form-urlencoded") {
		return true
	}
	return true
}

func bodyLooksBinary(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	probe := body
	if len(probe) > 4096 {
		probe = probe[:4096]
	}
	if !utf8.Valid(probe) || bytes.Contains(probe, []byte{0x00}) {
		return true
	}
	controlBytes := 0
	for _, b := range probe {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			controlBytes++
		}
	}
	return controlBytes > 0
}

func inferContentType(fileName string, body []byte) string {
	if fileName != "" {
		switch strings.ToLower(filepath.Ext(fileName)) {
		case ".txt", ".md", ".log", ".env":
			return "text/plain"
		case ".json":
			return "application/json"
		case ".png":
			return "image/png"
		case ".jpg", ".jpeg":
			return "image/jpeg"
		case ".pdf":
			return "application/pdf"
		case ".doc":
			return "application/msword"
		case ".docx":
			return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
		case ".xls", ".xlsx", ".ppt", ".pptx":
			if detected := mime.TypeByExtension(strings.ToLower(filepath.Ext(fileName))); detected != "" {
				return detected
			}
		}
	}
	if len(body) > 0 {
		return http.DetectContentType(body)
	}
	return "application/octet-stream"
}

func safeText(body []byte) string {
	if len(body) > maxTextFragmentBytes {
		body = body[:maxTextFragmentBytes]
	}
	if !utf8.Valid(body) {
		return strings.ToValidUTF8(string(body), "\uFFFD")
	}
	return string(body)
}

func preview(text string, limit int) string {
	text = strings.TrimSpace(text)
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "..."
}

func looksLikeRetainedFileReference(path, value string) bool {
	lowerPath := strings.ToLower(path)
	lowerValue := strings.ToLower(value)
	if !(strings.Contains(lowerPath, "file") || strings.Contains(lowerPath, "attachment") || strings.Contains(lowerPath, "upload") || strings.Contains(lowerPath, "document") || strings.Contains(lowerPath, "ref")) {
		return false
	}
	return fileReferenceIDPattern.MatchString(value) || strings.HasPrefix(lowerValue, "http://") || strings.HasPrefix(lowerValue, "https://") || strings.HasPrefix(value, "/")
}

func hasFilePathContext(path string) bool {
	lowerPath := strings.ToLower(path)
	return strings.Contains(lowerPath, "file") || strings.Contains(lowerPath, "attachment") || strings.Contains(lowerPath, "upload") || strings.Contains(lowerPath, "document")
}

func jsonObjectHasFileURLContext(item map[string]interface{}) bool {
	for key, raw := range item {
		lowerKey := strings.ToLower(key)
		if hasFilePathContext(lowerKey) || strings.Contains(lowerKey, "download") || strings.Contains(lowerKey, "signurl") || strings.Contains(lowerKey, "previewurl") {
			return true
		}
		if value, ok := raw.(string); ok && classifyRetainedFileURL(key, value) {
			return true
		}
	}
	return false
}

func shouldDiscardRetainedFileURLText(path, value string) bool {
	return classifyRetainedFileURL(path, value)
}

func classifyRetainedFileURL(path, value string) bool {
	value = strings.TrimSpace(value)
	lowerValue := strings.ToLower(value)
	if !strings.HasPrefix(lowerValue, "http://") && !strings.HasPrefix(lowerValue, "https://") {
		return false
	}
	lowerPath := strings.ToLower(path)
	if strings.Contains(lowerPath, "image") || strings.Contains(lowerPath, "img") || strings.Contains(lowerPath, "icon") || strings.Contains(lowerPath, "avatar") {
		return false
	}
	if !(hasFilePathContext(lowerPath) || strings.Contains(lowerPath, "signurl") || strings.Contains(lowerPath, "downloadurl") || strings.Contains(lowerPath, "previewurl") || strings.Contains(lowerPath, "url")) {
		return false
	}
	fileName := fileNameFromDownloadURL(value)
	if fileName != "" && fileExtensionLooksDownloadable(fileName) {
		return true
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	lowerURLPath := strings.ToLower(parsed.EscapedPath())
	return strings.Contains(lowerURLPath, "/file") || strings.Contains(lowerURLPath, "sign-obj") || strings.Contains(lowerURLPath, "/blob/")
}

// looksLikeSignedDownloadShortLink 识别网页版大模型（deepseek/豆包等）返回的「带签名 token 的
// 相对下载短链」，形如 /file?file_id=<uuid>&state=<base64> 或 /…?sign=…&expire=…。这类是下载
// 凭证（协议管线）：既不该把超长 state/token 编码与文件 ID 原样塞进给人看的留存内容，也不是
// 用户或模型的语义文本。绝对 http(s) 下载链已在 shouldDiscardRetainedFileURLText 处丢弃，这里补齐相对
// 短链的同等处理。判定保持保守——必须是「/ 开头 + 含查询串 + 查询里出现签名/凭证/文件ID 参数」，
// 普通人类文本不会命中。
func looksLikeSignedDownloadShortLink(value string) bool {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, "/") {
		return false
	}
	q := strings.Index(trimmed, "?")
	if q < 0 {
		return false
	}
	lowerQuery := strings.ToLower(trimmed[q+1:])
	for _, token := range []string{"state=", "sign=", "signature=", "token=", "file_id=", "fileid=", "credential=", "x-amz-", "x-oss-", "expire="} {
		if strings.Contains(lowerQuery, token) {
			return true
		}
	}
	return false
}

func fileURLFieldPriority(key string) int {
	lowerKey := strings.ToLower(key)
	switch {
	case strings.Contains(lowerKey, "download") || strings.Contains(lowerKey, "sign") || lowerKey == "url":
		return 1
	case strings.Contains(lowerKey, "origin") || strings.Contains(lowerKey, "original") || strings.Contains(lowerKey, "full"):
		return 2
	case strings.Contains(lowerKey, "preview"):
		return 3
	case strings.Contains(lowerKey, "thumb"):
		return 4
	default:
		return 5
	}
}

func fileNameFromDownloadURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	for _, key := range []string{"filename", "fileName", "name"} {
		if value := strings.TrimSpace(parsed.Query().Get(key)); value != "" {
			return safeBaseName(value)
		}
	}
	path, err := url.PathUnescape(parsed.Path)
	if err != nil {
		path = parsed.Path
	}
	return safeBaseName(filepath.Base(path))
}

func fileNameFromJSONObject(item map[string]interface{}) string {
	for _, key := range []string{"file_name", "filename", "fileName", "name", "title"} {
		if value, ok := item[key].(string); ok {
			name := safeBaseName(value)
			if name != "" && !isFileTypeProtocolValue(name) {
				return name
			}
		}
	}
	return ""
}

func safeBaseName(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\x00", ""))
	if value == "" || value == "." || value == "/" {
		return ""
	}
	name := filepath.Base(value)
	if name == "." || name == string(filepath.Separator) {
		return ""
	}
	return name
}

func fileExtensionLooksDownloadable(fileName string) bool {
	switch strings.ToLower(filepath.Ext(fileName)) {
	case ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".md", ".csv", ".json", ".zip", ".rar", ".7z", ".tar", ".gz", ".png", ".jpg", ".jpeg", ".gif", ".webp":
		return true
	default:
		return false
	}
}

func referenceIDFromDownloadURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	path, err := url.PathUnescape(parsed.Path)
	if err != nil {
		path = parsed.Path
	}
	path = strings.Trim(path, "/")
	for _, marker := range []string{"kimi-fs/files/blob/", "files/blob/", "blob/"} {
		if idx := strings.Index(path, marker); idx >= 0 {
			return path[idx:]
		}
	}
	return path
}

func contentTypeFromJSONObject(item map[string]interface{}) string {
	for _, key := range []string{"content_type", "contentType", "mime_type", "mimeType", "mime"} {
		if value, ok := item[key].(string); ok && strings.Contains(value, "/") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sizeFromJSONObject(item map[string]interface{}) int64 {
	for _, key := range []string{"size", "file_size", "fileSize", "bytes"} {
		switch value := item[key].(type) {
		case float64:
			if value > 0 {
				return int64(value)
			}
		case int64:
			if value > 0 {
				return value
			}
		case json.Number:
			if parsed, err := value.Int64(); err == nil && parsed > 0 {
				return parsed
			}
		}
	}
	return 0
}

func sha256FromJSONObject(item map[string]interface{}) string {
	for _, key := range []string{"sha256", "sha_256", "hash"} {
		if value, ok := item[key].(string); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func isFileTypeProtocolValue(value string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(value)), "FILE_TYPE_")
}

func uniqueAttachments(items []ExtractedAttachment) []ExtractedAttachment {
	seen := map[string]ExtractedAttachment{}
	order := make([]string, 0, len(items))
	for _, item := range items {
		key := item.DownloadURL
		if key == "" {
			key = strings.Join([]string{item.Source, item.ReferenceID, item.FileName, item.FieldName, item.SHA256}, "|")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		if existing, ok := seen[key]; ok {
			if existing.FileName == "" {
				existing.FileName = item.FileName
			}
			if existing.ContentType == "" || existing.ContentType == "application/octet-stream" {
				existing.ContentType = item.ContentType
			}
			if existing.DownloadURL == "" {
				existing.DownloadURL = item.DownloadURL
			}
			seen[key] = existing
			continue
		}
		seen[key] = item
		order = append(order, key)
	}
	out := make([]ExtractedAttachment, 0, len(order))
	for _, key := range order {
		out = append(out, seen[key])
	}
	return out
}
