package handler

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

// userRequestRe 匹配 VS Code Copilot 注入的 <userRequest>...</userRequest> 标签（支持跨行）。
var userRequestRe = regexp.MustCompile(`(?s)<userRequest>(.*?)</userRequest>`)

// decodeVSCodeXWebRequest 解析 VS Code GitHub Copilot /responses 请求（OpenAI Responses API 格式）。
//
// 请求体结构：{"model":..., "input":[{"role":"user","content":[{"type":"input_text","text":"..."},{"type":"input_image","image_url":"https://..."}]}]}
//
// VS Code Copilot 会在 role=user 的 input_text 里注入大量上下文包（<environment_info>/<context>/<attachments> 等），
// 真实用户问题裹在 <userRequest>...</userRequest> 标签内。
// 图片附件以 {"type":"input_image","image_url":"https://..."} 形式给出（https 引用 URL，非 base64）。
//
// 优先路径（干净）：有 <userRequest> 或 input_image → 只抽 userRequest 内的文本 + input_image URL，其余上下文包丢弃。
// 兜底路径（防格式变更）：既无 <userRequest> 也无 input_image → 退回原行为，抽 role=user 所有 input_text。
func decodeVSCodeXWebRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	if !isVSCodeXResponsesRequest(req) {
		return ExtractedContent{}, false
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}

	// 使用宽松结构体：content[] 用 map 以支持不同 type 字段。
	var payload struct {
		Input []struct {
			Role    string                   `json:"role"`
			Content []map[string]interface{} `json:"content"`
		} `json:"input"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ExtractedContent{}, false
	}

	var parts []string
	var plainParts []string
	var attachments []ExtractedAttachment
	runtimeContextKey := ""

	// 第一遍扫描：收集 userRequest 文本 + input_image 附件。
	for _, input := range payload.Input {
		if strings.ToLower(strings.TrimSpace(input.Role)) != "user" {
			continue
		}
		for _, block := range input.Content {
			blockType, _ := block["type"].(string)
			switch blockType {
			case "input_text":
				text, _ := block["text"].(string)
				if runtimeContextKey == "" {
					runtimeContextKey = aimsg.RuntimeContextKey(text)
				}
				matches := userRequestRe.FindAllStringSubmatch(text, -1)
				if len(matches) == 0 {
					if visible := aimsg.NormalizeRetainedUserText(text); visible != "" {
						plainParts = append(plainParts, visible)
					}
				}
				for _, m := range matches {
					if inner := strings.TrimSpace(m[1]); inner != "" {
						parts = append(parts, inner)
					}
				}
			case "input_image":
				imageURL, _ := block["image_url"].(string)
				if imageURL = strings.TrimSpace(imageURL); imageURL != "" {
					if att, ok := attachmentFromImageURL("input_image.image_url", imageURL); ok {
						// 关联键归一:input_image 引用的是 https://github.com/github-copilot/chat/attachments/<id>,
						// 把 ReferenceID 归一成裸 <id>,与上传响应解码出的裸 id 一致(见 bareGitHubCopilotAttachmentID),
						// 使 resolveRetainedUploadMetadata 能跨请求把上传字节回填到这条对话引用上→对话留证内联显示图。
						if bareID := bareGitHubCopilotAttachmentID(imageURL); bareID != "" {
							att.ReferenceID = bareID
						}
						attachments = append(attachments, att)
					}
				}
			}
		}
	}

	// 干净路径：有 userRequest 文本或 input_image → 只返回这些。
	if len(parts) > 0 || len(attachments) > 0 {
		if len(parts) == 0 {
			parts = plainParts
		}
		content := buildExtracted(parts, attachments, "json")
		content.ConversationID = vscodeRuntimeConversationID(runtimeContextKey)
		populateVSCodeConversationMessages(&content, body)
		return content, true
	}

	// 兜底路径：格式变更/旧格式 → 退回原行为，抽 role=user 所有 input_text。
	for _, input := range payload.Input {
		if strings.ToLower(strings.TrimSpace(input.Role)) != "user" {
			continue
		}
		for _, block := range input.Content {
			blockType, _ := block["type"].(string)
			if blockType != "input_text" {
				continue
			}
			text, _ := block["text"].(string)
			if t := strings.TrimSpace(text); t != "" {
				parts = append(parts, t)
			}
		}
	}
	if len(parts) == 0 {
		return ExtractedContent{}, false
	}
	content := buildExtracted(parts, nil, "json")
	content.ConversationID = vscodeRuntimeConversationID(runtimeContextKey)
	populateVSCodeConversationMessages(&content, body)
	return content, true
}

func vscodeRuntimeConversationID(runtimeContextKey string) string {
	runtimeContextKey = strings.TrimSpace(runtimeContextKey)
	if runtimeContextKey == "" {
		return ""
	}
	return "vscode-runtime:" + runtimeContextKey
}

func isVSCodeXResponsesRequest(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	host := normalizeHost(req.URL.Host)
	if host == "" {
		host = normalizeHost(req.Host)
	}
	if !strings.HasSuffix(host, "githubcopilot.com") {
		return false
	}
	return strings.Contains(strings.ToLower(req.URL.Path), "/responses")
}

// decodeGitHubCopilotAttachmentUpload 抓取 VSCode Copilot 聊天图片上传的原始字节。
// VSCode 把用户图以 application/octet-stream 原始二进制 POST 到 uploads.github.com/copilot/chat/attachments
// (非 multipart、非 JSON,body 即图片字节);/responses 只引用其 https URL(取字节需 github 鉴权→留证破图)。
// 这里把上传 body 直接当图片附件落盘,使留证可显示真实图片。仅认图片(按字节魔数检测),非图片不留。
func decodeGitHubCopilotAttachmentUpload(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	if req == nil || req.URL == nil || len(body) == 0 {
		return ExtractedContent{}, false
	}
	host := normalizeHost(req.URL.Host)
	if host == "" {
		host = normalizeHost(req.Host)
	}
	if host != "uploads.github.com" {
		return ExtractedContent{}, false
	}
	if !strings.Contains(strings.ToLower(req.URL.Path), "/copilot/chat/attachments") {
		return ExtractedContent{}, false
	}
	// body 是原始上传字节(实测 octet-stream 的 PNG)。按字节真实类型检测,只留图片,避免误抓非图上传。
	detected := http.DetectContentType(body)
	if !strings.HasPrefix(detected, "image/") {
		return ExtractedContent{}, false
	}
	fileName := "copilot_upload" + imageExtFromContentType(detected) // .png/.jpg/...
	att := attachmentFromBytes("upload", "copilot/chat/attachments", fileName, detected, body)
	return buildExtracted(nil, []ExtractedAttachment{att}, "binary"), true
}

// imageExtFromContentType 由 image/* content-type 给文件扩展名;未知给 .img。
func imageExtFromContentType(ct string) string {
	switch ct {
	case "image/png":
		return ".png"
	case "image/jpeg":
		return ".jpg"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	case "image/bmp":
		return ".bmp"
	default:
		return ".img"
	}
}

// githubCopilotUploadRefSource 标识「上传响应解码器抽出的裸 attachment id」的内部传递标记附件。
// 它只在进程内从 respContent 传到 linkGitHubCopilotUploadReference,随后被剥离,绝不落库。
const githubCopilotUploadRefSource = "github_copilot_upload_ref"

// bareGitHubCopilotAttachmentID 从 GitHub Copilot 聊天附件 URL 取裸 attachment id(路径最后一段)。
// 上传响应的 url 字段与 /responses 的 input_image.image_url 是同一个
// https://github.com/github-copilot/chat/attachments/<id> URL;两侧都用本函数派生同一个裸 id,作为
// 留证跨请求关联(retainedUploadCatalog / resolveRetainedUploadMetadata)的关联键。非该形态
// (不含 /chat/attachments/)的 URL 返回空,避免把任意 URL 误当关联键。
func bareGitHubCopilotAttachmentID(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	path := parsed.Path
	if unescaped, err := url.PathUnescape(path); err == nil {
		path = unescaped
	}
	const marker = "/chat/attachments/"
	idx := strings.Index(strings.ToLower(path), marker)
	if idx < 0 {
		return ""
	}
	// 取 marker 之后的第一段即 attachment id;末尾斜杠/无 id 的畸形 URL 自然得空(不可误返回 attachments)。
	rest := strings.Trim(path[idx+len(marker):], "/")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return strings.TrimSpace(rest)
}

// decodeGitHubCopilotAttachmentUploadResponse 解 GitHub Copilot 图片上传的响应。
// 上传响应是个小 JSON(实测 {"url":"https://github.com/github-copilot/chat/attachments/<id>"}):上传的
// 图片字节在请求里(见 decodeGitHubCopilotAttachmentUpload),而 attachment id 由 GitHub 在响应里分配。
// 这里把响应 url 的裸 id 以一个无字节标记附件(Source=githubCopilotUploadRefSource)携带出去,供
// linkGitHubCopilotUploadReference 回贴到请求字节附件的 ReferenceID。标记仅作进程内传递、不落库
// (在 hydrateFileIDAttachments 里被剥离)。非该形态响应返回 false,退回原有行为(无害降级)。
func decodeGitHubCopilotAttachmentUploadResponse(body []byte, contentType string) (ExtractedContent, bool) {
	if len(body) == 0 {
		return ExtractedContent{}, false
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	var payload struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ExtractedContent{}, false
	}
	bareID := bareGitHubCopilotAttachmentID(payload.URL)
	if bareID == "" {
		return ExtractedContent{}, false
	}
	return ExtractedContent{
		ContentType: "json",
		Attachments: []ExtractedAttachment{{
			Source:      githubCopilotUploadRefSource,
			ReferenceID: bareID,
		}},
	}, true
}

// linkGitHubCopilotUploadReference 把上传响应解码出的裸 attachment id(以 githubCopilotUploadRefSource
// 标记附件携带在 respContent 里)回贴到请求字节附件(decodeGitHubCopilotAttachmentUpload 产出,
// Source=upload)的 ReferenceID,使上传字节能按裸 id 登记进 retainedUploadCatalog;随后 /responses 的
// input_image 引用(同一裸 id)就能跨请求回填字节、内联显示。无论是否配对成功都剥离标记附件,保证它
// 绝不落库污染留证。仅对 uploads.github.com 生效;其它流量原样返回。
//
// 该函数是纯进程内 metadata 关联(不抓网络),由 hydrateFileIDAttachments 在写库前调用。
func linkGitHubCopilotUploadReference(targetHost string, contents ...*ExtractedContent) {
	if normalizeHost(targetHost) != "uploads.github.com" {
		return
	}
	// 第一遍:取出标记里的裸 id,并把标记从所有 content 剥离(无论后续是否配对成功,标记都不得落库)。
	bareID := ""
	for _, c := range contents {
		if c == nil || len(c.Attachments) == 0 {
			continue
		}
		kept := c.Attachments[:0]
		for _, att := range c.Attachments {
			if att.Source == githubCopilotUploadRefSource {
				if bareID == "" {
					bareID = strings.TrimSpace(att.ReferenceID)
				}
				continue // 剥离标记,不保留
			}
			kept = append(kept, att)
		}
		c.Attachments = kept
	}
	if bareID == "" {
		return
	}
	// 第二遍:把裸 id 贴到请求字节附件(上传字节)的 ReferenceID(仅当其原本无 ReferenceID,不覆盖)。
	for _, c := range contents {
		if c == nil {
			continue
		}
		for i := range c.Attachments {
			att := &c.Attachments[i]
			if att.Source == "upload" && att.FieldName == "copilot/chat/attachments" && strings.TrimSpace(att.ReferenceID) == "" {
				att.ReferenceID = bareID
			}
		}
	}
}

// Preserve message boundaries and history for conversation and turn aggregation.
// Text and attachment extraction remain independent of these grouping hints.
func populateVSCodeConversationMessages(content *ExtractedContent, body []byte) {
	parsed, ok := aimsg.ParseOpenAIResponsesRequest(body)
	if !ok {
		return
	}
	for _, message := range parsed.Messages {
		if message.Source == aimsg.SourceUser {
			matches := userRequestRe.FindAllStringSubmatch(message.Content, -1)
			if len(matches) > 0 {
				var visible []string
				for _, match := range matches {
					visible = append(visible, strings.TrimSpace(match[1]))
				}
				message.Content = strings.Join(visible, "\n")
				message.ContentSHA256 = aimsg.ContentSHA256Hex(message.Content)
			}
		}
		content.Messages = append(content.Messages, message)
	}
}
