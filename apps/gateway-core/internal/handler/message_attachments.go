package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"os"
	"path"
	"strings"
)

// —— 文件内容 DLP 开关的环境后备（与 security-engine 同名 env，默认关）——
// 仅在控制平面动态配置不可用（toolRiskClient 缺失或缓存未加载）时由
// ChatCompletionsHandler.fileContentDLPEnabled 回落使用。运行态真源是控制平面
// system_settings.file_content_dlp_enabled 经签名动态配置缓存的投影。
func fileContentDLPEnvFallback() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("SECURITY_FILE_CONTENT_DLP_ENABLED")))
	switch v {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// attachmentsCtxKey 把 per-message 附件挂在 ctx 上传给 CheckInputDetailed，
// 不改 SecurityChecker 接口签名（与 skipSemanticCtxKey 同模式，对其它调用方零影响）。
type attachmentsCtxKey struct{}

func withAttachments(ctx context.Context, atts []map[string]interface{}) context.Context {
	if len(atts) == 0 {
		return ctx
	}
	return context.WithValue(ctx, attachmentsCtxKey{}, atts)
}

func attachmentsFromContext(ctx context.Context) []map[string]interface{} {
	v, _ := ctx.Value(attachmentsCtxKey{}).([]map[string]interface{})
	return v
}

func fileContentActionBlocksExternalSend(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "reply", "deny", "mask", "redact", "quarantine":
		return true
	default:
		return false
	}
}

// explicitFileTypePolicyBlocks 报告文件类型“禁止”命中是否仍要拦：只算动作仍是 block/quarantine、
// 又没被内容例外放开（没有 exception_id）的命中。引擎按例外把动作降成 audit/allow 后照常放行。
func explicitFileTypePolicyBlocks(findings []SecurityFinding) bool {
	for _, finding := range findings {
		if !isFileTypePolicyBlockedFinding(finding.Category, finding.RuleID) || strings.TrimSpace(finding.ExceptionID) != "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(finding.Action)) {
		case "block", "quarantine":
			return true
		}
	}
	return false
}

// isFileTypePolicyBlockedFinding 认文件类型“禁止”命中：类别，或规则编号（2.9.22 起带类型，
// 如 file-policy-blocked-type:exe；旧编号不带）。
func isFileTypePolicyBlockedFinding(category, ruleID string) bool {
	ruleID = strings.ToLower(strings.TrimSpace(ruleID))
	return strings.EqualFold(strings.TrimSpace(category), "file_policy_blocked_type") ||
		ruleID == "file-policy-blocked-type" || strings.HasPrefix(ruleID, "file-policy-blocked-type:")
}

// ctxWithAttachments 把 ctx 上由 withAttachments 挂载的 per-message 附件合并进
// 即将发给 security-engine 的 Context map。无附件时原样返回（不新增 key，零回归）。
func ctxWithAttachments(ctx context.Context, base map[string]interface{}) map[string]interface{} {
	atts := attachmentsFromContext(ctx)
	if len(atts) == 0 {
		return base
	}
	base["attachments"] = atts
	return base
}

// extractAttachments 从多模态 Message.Content 提取附件字节，供文件内容 DLP 送检。
//
// 支持的块形态（仅提取带 base64 字节的，http(s) URL 无字节不虚构）：
//   - OpenAI image_url: {"type":"image_url","image_url":{"url":"data:<mime>;base64,<data>"}}
//   - Anthropic image:  {"type":"image","source":{"type":"base64","media_type":"<mime>","data":"<data>"}}
//   - Anthropic/通用 input_image: {"type":"input_image","source":{...同上...}}
//
// 返回每个附件的 {content_type, data_base64, source}。无附件返回 nil。
// 纯文本 content（JSON 字符串或无 base64 块）返回 nil —— 与 messageText 的退化一致。
func extractAttachments(content json.RawMessage) []map[string]interface{} {
	if len(content) == 0 {
		return nil
	}
	var blocks []map[string]interface{}
	if err := json.Unmarshal(content, &blocks); err != nil {
		var single map[string]interface{}
		if json.Unmarshal(content, &single) != nil || single == nil {
			return nil
		}
		blocks = []map[string]interface{}{single}
	}
	out := make([]map[string]interface{}, 0, len(blocks))
	for _, b := range blocks {
		att := extractAttachmentFromBlock(b)
		if att != nil {
			out = append(out, att)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// extractRequestAttachments scans a JSON request envelope for file-bearing blocks.
// Reverse-proxy callers do not have a typed protocol request, so the walk keeps
// extraction additive and only returns blocks for which bytes or a reference are
// explicitly present.
func extractRequestAttachments(body []byte) []map[string]interface{} {
	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		return nil
	}

	var out []map[string]interface{}
	seen := map[string]struct{}{}
	var walk func(interface{})
	walk = func(value interface{}) {
		switch v := value.(type) {
		case map[string]interface{}:
			if attachment := extractAttachmentFromBlock(v); attachment != nil {
				if key, err := json.Marshal(attachment); err == nil {
					if _, exists := seen[string(key)]; !exists {
						seen[string(key)] = struct{}{}
						out = append(out, attachment)
					}
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []interface{}:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(root)
	if len(out) == 0 {
		return nil
	}
	return out
}

func extractRequestAttachmentsForProxy(body []byte, contentType, targetPath string) []map[string]interface{} {
	if attachments := extractRequestAttachments(body); len(attachments) > 0 {
		return attachments
	}
	if len(body) == 0 {
		return nil
	}

	mediaType := normalizedMediaType(contentType)
	if mediaType == "" {
		mediaType = mediaTypeFromProxyPath(targetPath)
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		return extractMultipartRequestAttachments(body, contentType)
	}
	pathMediaType := mediaTypeFromProxyPath(targetPath)
	if mediaType == "" ||
		strings.Contains(mediaType, "json") ||
		mediaType == "application/x-www-form-urlencoded" ||
		(strings.HasPrefix(mediaType, "text/") && pathMediaType == "") {
		return nil
	}

	attachment := map[string]interface{}{
		"source":       "reverse_proxy_request_body",
		"content_type": mediaType,
		"data_base64":  base64.StdEncoding.EncodeToString(body),
	}
	if filename := proxyFilenameFromPath(targetPath); filename != "" {
		attachment["file_name"] = filename
	}
	return []map[string]interface{}{attachment}
}

func extractMultipartRequestAttachments(body []byte, contentType string) []map[string]interface{} {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(strings.ToLower(mediaType), "multipart/") || params["boundary"] == "" {
		return nil
	}

	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	attachments := make([]map[string]interface{}, 0)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil
		}
		partBody, err := io.ReadAll(part)
		_ = part.Close()
		if err != nil {
			return nil
		}

		fileName := part.FileName()
		partContentType := normalizedMediaType(part.Header.Get("Content-Type"))
		// 无 filename 的 multipart 普通字段不是文件；没有类型的 file part
		// 仍按 octet-stream 交给引擎做类型检视，避免未知文件静默放行。
		if fileName == "" && partContentType == "" {
			continue
		}
		if partContentType == "" || partContentType == "application/octet-stream" {
			if inferred := mediaTypeFromProxyPath(fileName); inferred != "" {
				partContentType = inferred
			}
		}
		if partContentType == "" {
			partContentType = "application/octet-stream"
		}

		attachment := map[string]interface{}{
			"source":       "reverse_proxy_multipart",
			"content_type": partContentType,
			"data_base64":  base64.StdEncoding.EncodeToString(partBody),
		}
		if fieldName := part.FormName(); fieldName != "" {
			attachment["field_name"] = fieldName
		}
		if fileName != "" {
			attachment["file_name"] = fileName
		}
		attachments = append(attachments, attachment)
	}
	if len(attachments) == 0 {
		return nil
	}
	return attachments
}

func normalizedMediaType(contentType string) string {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err == nil {
		return strings.ToLower(strings.TrimSpace(mediaType))
	}
	return strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
}

func mediaTypeFromProxyPath(targetPath string) string {
	switch strings.ToLower(path.Ext(targetPath)) {
	case ".pdf":
		return "application/pdf"
	case ".docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case ".xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case ".pptx":
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	case ".zip":
		return "application/zip"
	case ".gz", ".gzip":
		return "application/gzip"
	case ".tar":
		return "application/x-tar"
	case ".7z":
		return "application/x-7z-compressed"
	case ".rar":
		return "application/vnd.rar"
	case ".txt":
		return "text/plain"
	case ".md":
		return "text/markdown"
	case ".csv":
		return "text/csv"
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".yaml", ".yml":
		return "application/x-yaml"
	default:
		return ""
	}
}

func proxyFilenameFromPath(targetPath string) string {
	name := path.Base(targetPath)
	if name == "." || name == "/" || name == "" {
		return ""
	}
	return name
}

func extractAttachmentFromBlock(b map[string]interface{}) map[string]interface{} {
	t, _ := b["type"].(string)
	// OpenAI image_url
	if t == "image_url" || t == "input_image_url" {
		iu, _ := b["image_url"].(map[string]interface{})
		if iu == nil {
			return nil
		}
		url, _ := iu["url"].(string)
		mime, data := parseDataURL(url)
		if data == "" {
			return nil
		}
		return map[string]interface{}{
			"content_type": mime,
			"data_base64":  data,
			"source":       "json_data_url",
		}
	}
	// Anthropic image / input_image：source.type=="base64"
	if t == "image" || t == "input_image" {
		src, _ := b["source"].(map[string]interface{})
		if src == nil {
			return nil
		}
		if st, _ := src["type"].(string); st != "base64" {
			return nil
		}
		media, _ := src["media_type"].(string)
		data, _ := src["data"].(string)
		if data == "" {
			return nil
		}
		if media == "" {
			media = "application/octet-stream"
		}
		return map[string]interface{}{
			"content_type": media,
			"data_base64":  data,
			"source":       "json_base64",
		}
	}
	// 文件块：input_file / file（OpenAI Responses/Anthropic 兼容）
	if t == "input_file" || t == "file" || t == "input_document" || t == "document" || t == "attachment" {
		return extractFileBlock(b)
	}
	// 兜底：块本身可能就是 file_data/data（无 type 声明），或嵌套在 file 对象中。
	if _, ok := b["file_data"]; ok {
		return extractFileBlock(b)
	}
	if nested, ok := b["file"].(map[string]interface{}); ok {
		merged := make(map[string]interface{}, len(nested)+len(b))
		for key, value := range nested {
			merged[key] = value
		}
		for key, value := range b {
			if key != "file" {
				merged[key] = value
			}
		}
		return extractFileBlock(merged)
	}
	return nil
}

// extractFileBlock 从文件块提取字节或引用。
// 支持的字段（按 OpenAI/Anthropic/通用兼容）：
//   - file_data / data：{"base64": "<b64>"} 或直接 "<b64>" 或 data URL
//   - data URL（file_data 为字符串时）
//   - file_id / reference_id / id：引用（无字节，交引擎查 registry）
//   - filename / name、mime_type / content_type
func extractFileBlock(b map[string]interface{}) map[string]interface{} {
	filename, _ := b["filename"].(string)
	if filename == "" {
		filename, _ = b["name"].(string)
	}
	if filename == "" {
		if fn, ok := b["file_name"].(string); ok {
			filename = fn
		}
	}
	if filename == "" {
		filename, _ = b["title"].(string)
	}
	mime := mimeFromBlock(b, filename)
	reference := refIDFromBlock(b)

	// 1) file_data / data
	if fd, ok := b["file_data"]; ok {
		if att := attFromFileData(fd, mime, filename); att != nil {
			return attachFileReference(att, reference)
		}
	}
	if d, ok := b["data"]; ok {
		if att := attFromFileData(d, mime, filename); att != nil {
			return attachFileReference(att, reference)
		}
	}

	// Anthropic document source：base64/text 可直接送检，file/url 保留为未验证引用。
	if source, ok := b["source"].(map[string]interface{}); ok {
		sourceType, _ := source["type"].(string)
		switch sourceType {
		case "base64":
			data, _ := source["data"].(string)
			if data != "" {
				media, _ := source["media_type"].(string)
				if media == "" {
					media = mime
				}
				return attachFileReference(finalizeFileAtt(media, filename, data), reference)
			}
		case "text":
			text, _ := source["data"].(string)
			if text == "" {
				text, _ = source["text"].(string)
			}
			if text != "" {
				return attachFileReference(finalizeFileAtt("text/plain", filename, base64.StdEncoding.EncodeToString([]byte(text))), reference)
			}
		case "url":
			if url, _ := source["url"].(string); url != "" {
				if m, payload := parseDataURL(url); payload != "" {
					return finalizeFileAtt(mimeOr(mime, m), filename, payload)
				}
				return referenceFileAtt(mime, filename, url, "anthropic_document_url")
			}
		case "file":
			if reference := referenceIDFromMap(source); reference != "" {
				return referenceFileAtt(mime, filename, reference, "anthropic_document_file")
			}
		}
	}

	if url := fileURLFromBlock(b); url != "" {
		if m, payload := parseDataURL(url); payload != "" {
			return attachFileReference(finalizeFileAtt(mimeOr(mime, m), filename, payload), reference)
		}
		return referenceFileAtt(mime, filename, url, "json_file_url")
	}

	// file_id / reference_id（无字节，交引擎两阶段协议）
	if reference != "" {
		return referenceFileAtt(mime, filename, reference, "json_file_reference")
	}
	// 部分客户端会先解析文件正文，只在可信 file/document/attachment 块中
	// 保留 filename/title。保留这份声明元数据，供文件策略按扩展名阻断；
	// 不虚构字节，也不把普通 text 块或正文中的 .pdf 当成附件证据。
	if filename != "" {
		return map[string]interface{}{
			"content_type": mime,
			"file_name":    filename,
			"source":       "json_file_metadata",
		}
	}
	return nil
}

func attachFileReference(att map[string]interface{}, reference string) map[string]interface{} {
	if att == nil || reference == "" {
		return att
	}
	att["reference_id"] = reference
	return att
}

func referenceFileAtt(mime, filename, reference, source string) map[string]interface{} {
	return map[string]interface{}{
		"content_type":          mime,
		"reference_id":          reference,
		"file_name":             filename,
		"source":                source,
		"object_id_unavailable": "reference_unverified",
	}
}

func mimeOr(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

func referenceIDFromMap(value map[string]interface{}) string {
	for _, key := range []string{"file_id", "reference_id", "id"} {
		if reference, ok := value[key].(string); ok && reference != "" {
			return reference
		}
	}
	return ""
}

func fileURLFromBlock(b map[string]interface{}) string {
	for _, key := range []string{"file_url", "download_url", "url"} {
		if url, ok := b[key].(string); ok && url != "" {
			return url
		}
	}
	if fd, ok := b["file_data"].(map[string]interface{}); ok {
		for _, key := range []string{"file_url", "download_url", "url"} {
			if url, ok := fd[key].(string); ok && url != "" {
				return url
			}
		}
	}
	return ""
}

// attFromFileData 从 file_data 字段（可能是 map{base64/data}、data URL 字符串、裸 base64）提取字节。
func attFromFileData(fd interface{}, mime, filename string) map[string]interface{} {
	switch v := fd.(type) {
	case map[string]interface{}:
		// {"base64": "..."} 或 {"data": "..."} 或 {"url": "data:...;base64,..."}
		if b64, ok := v["base64"].(string); ok && b64 != "" {
			return finalizeFileAtt(mime, filename, b64)
		}
		if d, ok := v["data"].(string); ok && d != "" {
			if m, payload := parseDataURL(d); payload != "" {
				if mime == "" {
					mime = m
				}
				return finalizeFileAtt(mime, filename, payload)
			}
			return finalizeFileAtt(mime, filename, d)
		}
		if u, ok := v["url"].(string); ok && u != "" {
			if m, payload := parseDataURL(u); payload != "" {
				if mime == "" {
					mime = m
				}
				return finalizeFileAtt(mime, filename, payload)
			}
		}
	case string:
		// data URL 或裸 base64
		if m, payload := parseDataURL(v); payload != "" {
			if mime == "" {
				mime = m
			}
			return finalizeFileAtt(mime, filename, payload)
		}
		// 仅当形似 base64 时才当裸 base64（避免把 http url 当 base64）
		if looksLikeBase64(v) {
			return finalizeFileAtt(mime, filename, v)
		}
	}
	return nil
}

func finalizeFileAtt(mime, filename, b64 string) map[string]interface{} {
	if b64 == "" {
		return nil
	}
	if mime == "" {
		mime = mimeFromExt(filename)
	}
	if mime == "" {
		mime = "application/octet-stream"
	}
	return map[string]interface{}{
		"content_type": mime,
		"data_base64":  b64,
		"file_name":    filename,
		"source":       "json_file_data",
	}
}

func mimeFromBlock(b map[string]interface{}, filename string) string {
	if m, ok := b["mime_type"].(string); ok && m != "" {
		return m
	}
	if m, ok := b["content_type"].(string); ok && m != "" {
		return m
	}
	if fd, ok := b["file_data"].(map[string]interface{}); ok {
		if m, ok := fd["mime_type"].(string); ok && m != "" {
			return m
		}
		if m, ok := fd["content_type"].(string); ok && m != "" {
			return m
		}
	}
	if source, ok := b["source"].(map[string]interface{}); ok {
		if m, ok := source["media_type"].(string); ok && m != "" {
			return m
		}
	}
	return mimeFromExt(filename)
}

func refIDFromBlock(b map[string]interface{}) string {
	if reference := referenceIDFromMap(b); reference != "" {
		return reference
	}
	if fd, ok := b["file_data"].(map[string]interface{}); ok {
		if reference := referenceIDFromMap(fd); reference != "" {
			return reference
		}
	}
	if source, ok := b["source"].(map[string]interface{}); ok {
		if reference := referenceIDFromMap(source); reference != "" {
			return reference
		}
	}
	return ""
}

func looksLikeBase64(s string) bool {
	if len(s) < 16 {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=') {
			return false
		}
	}
	return true
}

// mimeFromExt 从文件名扩展名推断常见 Office/文本 mime。
func mimeFromExt(filename string) string {
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".docx"):
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case strings.HasSuffix(lower, ".pptx"):
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	case strings.HasSuffix(lower, ".xlsx"):
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case strings.HasSuffix(lower, ".pdf"):
		return "application/pdf"
	case strings.HasSuffix(lower, ".txt"):
		return "text/plain"
	case strings.HasSuffix(lower, ".csv"):
		return "text/csv"
	case strings.HasSuffix(lower, ".json"):
		return "application/json"
	case strings.HasSuffix(lower, ".md"):
		return "text/markdown"
	case strings.HasSuffix(lower, ".xml"):
		return "application/xml"
	case strings.HasSuffix(lower, ".zip"):
		return "application/zip"
	case strings.HasSuffix(lower, ".tar"):
		return "application/x-tar"
	case strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".tgz"):
		return "application/gzip"
	case strings.HasSuffix(lower, ".rar"):
		return "application/vnd.rar"
	case strings.HasSuffix(lower, ".7z"):
		return "application/x-7z-compressed"
	}
	return ""
}

// parseDataURL 解析 "data:<mime>;base64,<payload>"，返回 mime 与 payload。
// 非 data URL 或无 base64 返回 ("", "")。
func parseDataURL(url string) (string, string) {
	if !strings.HasPrefix(url, "data:") {
		return "", ""
	}
	rest := url[len("data:"):]
	semi := strings.Index(rest, ";base64,")
	if semi < 0 {
		return "", ""
	}
	mime := rest[:semi]
	if mime == "" {
		mime = "application/octet-stream"
	}
	payload := rest[semi+len(";base64,"):]
	if payload == "" {
		return mime, ""
	}
	// 校验是合法 base64（不解码，只验字符集与填充），避免把普通字符串当附件
	if _, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload)); err != nil {
		return mime, ""
	}
	return mime, payload
}
