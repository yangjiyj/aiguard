package handler

import (
	"encoding/json"
	"mime"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func decodeDoubaoWebRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	if !isDoubaoWebCompletionRequest(req) {
		return ExtractedContent{}, false
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	var payload struct {
		Messages []struct {
			ContentBlock []struct {
				Content struct {
					TextBlock struct {
						Text string `json:"text"`
					} `json:"text_block"`
					// SP2:用户随提问上传的文件在 attachment_block.attachments[] 里。
					// 文件附件(type:3)带 file 子对象;图片附件(type:1)带 image 子对象——
					// 图片由响应侧 collectStreamAttachments 从 FULL_MSG_NOTIFY 回显捕获,
					// 这里只解 file,避免一张图被请求侧+响应侧重复登记。
					AttachmentBlock struct {
						Attachments []struct {
							Type       int    `json:"type"`
							Identifier string `json:"identifier"`
							File       *struct {
								URI  string      `json:"uri"`
								URL  string      `json:"url"`
								Name string      `json:"name"`
								Size interface{} `json:"size"` // JSON number 或字符串,统一在 doubaoFileSize 转 int64
							} `json:"file"`
						} `json:"attachments"`
					} `json:"attachment_block"`
				} `json:"content"`
			} `json:"content_block"`
		} `json:"messages"`
		ClientMeta struct {
			ConversationID string `json:"conversation_id"`
			SectionID      string `json:"section_id"`
		} `json:"client_meta"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ExtractedContent{}, false
	}
	var parts []string
	var fileAttachments []ExtractedAttachment
	for _, message := range payload.Messages {
		for _, block := range message.ContentBlock {
			if text := strings.TrimSpace(block.Content.TextBlock.Text); text != "" {
				parts = append(parts, text)
			}
			// SP2:只处理带 file 子对象的文件附件;带 image 的(File==nil)跳过,留给响应侧。
			for _, att := range block.Content.AttachmentBlock.Attachments {
				if att.File == nil {
					continue
				}
				name := strings.TrimSpace(att.File.Name)
				// 引用优先 TOS key(uri,稳定),退而用 identifier。
				ref := strings.TrimSpace(att.File.URI)
				if ref == "" {
					ref = strings.TrimSpace(att.Identifier)
				}
				if name == "" && ref == "" {
					// 既无文件名又无引用的空壳跳过,避免吐出无意义记录。
					continue
				}
				fileAttachments = append(fileAttachments, ExtractedAttachment{
					Source:      "json_file_object",
					FileName:    name,
					ReferenceID: ref,
					ContentType: doubaoFileContentType(name),
					Size:        doubaoFileSize(att.File.Size),
					// prepare_upload 仅给上传态 TOS 凭证(无下载权),file.url 为空、
					// uri 是无签名 TOS key →抓不到字节,DownloadURL 明确留空,不加任何 egress。
					DownloadURL: "",
				})
			}
		}
	}
	if len(parts) == 0 && len(fileAttachments) == 0 {
		return ExtractedContent{}, false
	}
	// turn 分组键请求侧兜底:豆包请求体 client_meta 带 conversation_id/section_id,
	// 响应侧若取到则优先(见 buildAccessContentLogPayload),这里只填请求侧已知值。
	// 不改 buildExtracted 签名,接出结果后再设字段/补附件(隔离写法)。
	c := buildExtracted(parts, nil, "json")
	c.Attachments = append(c.Attachments, fileAttachments...)
	c.ConversationID = payload.ClientMeta.ConversationID
	c.SectionID = payload.ClientMeta.SectionID
	return c, true
}

// doubaoFileSize 把豆包文件附件的 size 字段转 int64。JSON number 经 encoding/json
// 默认反序列化成 float64;为以防万一也兼容字符串形态。无法识别时返回 0。
func doubaoFileSize(v interface{}) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i
		}
	case string:
		if i, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64); err == nil {
			return i
		}
	}
	return 0
}

// doubaoFileContentType 尽力从文件名扩展名推 content-type;推不出留空(不退化为
// application/octet-stream)。docx/pdf 等常见办公格式显式覆盖,mime 注册表兜底其余。
func doubaoFileContentType(fileName string) string {
	switch strings.ToLower(filepath.Ext(fileName)) {
	case ".pdf":
		return "application/pdf"
	case ".doc":
		return "application/msword"
	case ".docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case ".txt", ".md", ".log":
		return "text/plain"
	case ".csv":
		return "text/csv"
	case ".json":
		return "application/json"
	}
	if ext := strings.ToLower(filepath.Ext(fileName)); ext != "" {
		if detected := mime.TypeByExtension(ext); detected != "" {
			return detected
		}
	}
	return ""
}

func isDoubaoWebCompletionRequest(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	host := normalizeHost(req.URL.Host)
	if host == "" {
		host = normalizeHost(req.Host)
	}
	if host != "www.doubao.com" && host != "doubao.com" {
		return false
	}
	return strings.Contains(strings.ToLower(req.URL.Path), "/chat/completion")
}

func decodeDoubaoWebResponse(body []byte, contentType string) (ExtractedContent, bool) {
	// 豆包网页版 /chat/completion 的 SSE 既不是 ChatGPT 的 patch(/message/content/parts)、
	// 也不是 OpenAI delta(choices[].delta) 或 Responses 格式。过去直接委托
	// decodeChatGPTWebResponse:对纯文本回复它三种重组都不匹配→回退 fallbackSSEContent 逐帧
	// collectJSONText 还能把正文捞出来;但当回复里夹带图片附件时,共享重组器会"假命中"
	// (matched=true、正文为空、只带这一张附件)从而短路掉 fallbackSSEContent→模型回答整段丢失
	// (生产实证:带图豆包记录 resplen 恒为 0)。这里先用豆包专属重组器按其真实结构抽正文+附件,
	// 抽到才返回;抽不到(如该端点偶发别的格式)再回退共享解码器,保持隔离不影响其它厂商。
	if c, ok := reassembleDoubaoWebStream(body, contentType); ok {
		return c, true
	}
	return decodeChatGPTWebResponse(body, contentType)
}

// reassembleDoubaoWebStream 解析豆包网页版响应 SSE,把模型回答正文按帧序拼回。正文经三种帧到达,
// 都是对"同一条正在增长的消息"的追加(增量,非快照),按出现顺序拼接即得完整回答、不重复:
//   - STREAM_MSG_NOTIFY:    content.content_block[].content.text_block.text(消息首块)
//   - STREAM_CHUNK(patch):  patch_op[].patch_value.content_block[].content.text_block.text(结构化追加)
//   - CHUNK_DELTA:          {"text":"..."}(轻量文本增量,正文主体)
// 显式排除:patch_object==111 的 tts_content(逐字音频镜像,取了会与正文重复、放大下游检测误报);
// FULL_MSG_NOTIFY 的 message(用户消息回显,user_type:1,含其上传图);SSE_ACK/VERBOSE 等协议元数据。
// 图片附件仍由 collectStreamAttachments 统一收集,与原路径一致,确保留证取图不受影响。
func reassembleDoubaoWebStream(body []byte, contentType string) (ExtractedContent, bool) {
	if !isEventStream(contentType, body) {
		return ExtractedContent{}, false
	}
	events := parseSSEDataEvents(body)
	var answer strings.Builder
	var convID, secID string
	matched := false
	for _, ev := range events {
		m, ok := ev.decoded.(map[string]interface{})
		if !ok {
			continue
		}
		// turn 分组键对所有帧扫描:SSE_ACK 帧带 ack_client_meta 但不命中下面 switch 任何 case,
		// 故必须在 switch 之外、continue 之后调用,否则会漏掉它。首个非空胜。
		liftDoubaoMeta(m, &convID, &secID)
		switch {
		case m["patch_op"] != nil:
			// STREAM_CHUNK。tts_content 补丁(patch_object==111)无 content_block,
			// appendDoubaoContentBlockText 天然忽略;无需按 patch_object 过滤即不会重复 tts。
			ops, _ := m["patch_op"].([]interface{})
			for _, op := range ops {
				om, ok := op.(map[string]interface{})
				if !ok {
					continue
				}
				pv, ok := om["patch_value"].(map[string]interface{})
				if !ok {
					continue
				}
				if appendDoubaoContentBlockText(pv, &answer) {
					matched = true
				}
			}
		case m["content"] != nil:
			// STREAM_MSG_NOTIFY。
			if cm, ok := m["content"].(map[string]interface{}); ok {
				if appendDoubaoContentBlockText(cm, &answer) {
					matched = true
				}
			}
		case m["text"] != nil:
			// CHUNK_DELTA。顶层裸 text 字符串仅此类帧具备(其余帧正文在 content/message 之下)。
			if txt, ok := m["text"].(string); ok && txt != "" {
				answer.WriteString(txt)
				matched = true
			}
		}
	}
	att := filterDoubaoResponseAttachments(collectStreamAttachments(events))
	if !matched && len(att) == 0 {
		return ExtractedContent{}, false
	}
	c := buildReassembledExtracted(answer.String(), "", att)
	c.ConversationID = convID
	c.SectionID = secID
	return c, true
}

// appendDoubaoContentBlockText 从豆包 content_block 数组里取出各块 content.text_block.text 追加到回答。
// 仅认 text_block.text:tts_content / attachment_block 等同级兄弟天然不在此路径,因此不会把音频镜像
// 或图片占位文本误当正文。返回是否写入了至少一段非空文本。
func appendDoubaoContentBlockText(container map[string]interface{}, answer *strings.Builder) bool {
	blocks, ok := container["content_block"].([]interface{})
	if !ok {
		return false
	}
	wrote := false
	for _, b := range blocks {
		bm, ok := b.(map[string]interface{})
		if !ok {
			continue
		}
		content, ok := bm["content"].(map[string]interface{})
		if !ok {
			continue
		}
		tb, ok := content["text_block"].(map[string]interface{})
		if !ok {
			continue
		}
		if txt, ok := tb["text"].(string); ok && txt != "" {
			answer.WriteString(txt)
			wrote = true
		}
	}
	return wrote
}

// doubaoDocThumbnailNamePattern 匹配"文档被渲染成图片的缩略图"文件名,形如
// a539ad96.docx~tplv-a9rns2rl98-image.jpeg / xxx.pdf~tplv...jpg:文档扩展名后紧跟 `~tplv`
// (豆包 TOS 图片处理变体标记)。真实图片是 *.png~tplv / *.jpg~tplv(图片扩展名),不会命中此模式,
// 故据此能精准识别"文档缩略图伪装成图片",而不误伤真实用户/模型图片。
var doubaoDocThumbnailNamePattern = regexp.MustCompile(`(?i)\.(docx?|pdf|pptx?|xlsx?|csv|txt|md|rtf|odt)~tplv`)

// filterDoubaoResponseAttachments 对豆包响应侧 collectStreamAttachments 抓到的附件做专属过滤,
// 只保留真正的用户/模型图片,抑制三类噪音(实证自生产库 access_content_logs,provider=bytedance,
// stage=response,详见 decoder_doubao_response_test.go 顶部注释):
//
//	⓪ 搜索引用装饰(FieldName 含 search_query_result):豆包带网页搜索的答案引用「N 篇资料」,
//	   响应 SSE 夹带搜索结果卡片的站点 logo 与结果页缩略图,field_name 形如
//	   patch_op.patch_value.content_block.content.search_query_result_block.results.text_card.{logo_url,url}。
//	   真模型/用户图走 attachment_block.attachments.image 路径,绝不含 search_query_result,
//	   故按路径剔除精准且零误删。
//	① 响应侧文件回显(Source==json_file_url):豆包把用户上传文件渲染成 *.docx~tplv...jpeg 缩略图
//	   在响应 SSE 里回吐——用户文件已由请求侧 decodeDoubaoWebRequest 以 json_file_object 捕获(带友好
//	   文件名),响应侧这条是重复且误归属(被当成"模型返回的文件"),整类丢弃。
//	   生产库实证:json_file_url 全部带文档缩略名,无一是真实模型产出文件。
//	② 机器人头像/装饰(Source==json_image_url 且 ReferenceID 含 FileBizType 或 FileName 以 bot_ 开头):
//	   来自 conversation_info.image / bot icon 等,是 UI 头像被误当"模型返图"。
//	   ②补:若 json_image_url 的文件名是文档渲染缩略图(*.docx~tplv 等),同属①的另一登记形态,一并丢弃。
//
// 保留:其余一切——真实用户上传图片、模型生成图片(json_image_url 普通 url)、json_file_object(请求侧
// 图片经 image_ori 提升而来的真图)。回归保护见 TestDecodeDoubaoWebResponse_ImagePlusTextCapturesAnswer
// (真实用户图 source=json_file_object,不在本过滤的丢弃面内,绝不被误删)。
func filterDoubaoResponseAttachments(in []ExtractedAttachment) []ExtractedAttachment {
	if len(in) == 0 {
		return in
	}
	out := in[:0:0] // 不复用底层数组,避免与 collectStreamAttachments 返回的切片别名
	for _, a := range in {
		// ⓪ 搜索引用装饰(站点 logo / 结果页缩略图):field_name 落在 search_query_result_block 下。
		//    实证(生产库 access_content_logs,provider=bytedance):豆包带网页搜索的答案引用「N 篇资料」,
		//    响应 SSE 夹带搜索结果卡片的站点 logo,field_name 形如
		//    patch_op.patch_value.content_block.content.search_query_result_block.results.text_card.{logo_url,url},
		//    被误当「模型返回图片」。真模型/用户图走 attachment_block.attachments.image 路径,绝不含
		//    search_query_result,故按路径剔除精准且零误删。
		if strings.Contains(a.FieldName, "search_query_result") {
			continue
		}
		// ① 响应侧文件回显:整类丢弃(用户文件已由请求侧捕获)。
		if a.Source == "json_file_url" {
			continue
		}
		if a.Source == "json_image_url" {
			// ② 机器人头像/装饰。
			if strings.Contains(a.ReferenceID, "FileBizType") || strings.HasPrefix(a.FileName, "bot_") {
				continue
			}
			// ②补:文档渲染缩略图伪装成图片(*.docx~tplv 等)。真图是图片扩展名+~tplv,不命中。
			if doubaoDocThumbnailNamePattern.MatchString(a.FileName) {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

// liftDoubaoMeta 从豆包帧的 ack_client_meta(SSE_ACK)或 meta(STREAM_MSG_NOTIFY)提取
// turn 分组键 conversation_id/section_id；首个非空胜（已取到的不被后续帧覆盖）。
func liftDoubaoMeta(m map[string]interface{}, conv, sec *string) {
	for _, key := range []string{"ack_client_meta", "meta"} {
		meta, ok := m[key].(map[string]interface{})
		if !ok {
			continue
		}
		if *conv == "" {
			if v, ok := meta["conversation_id"].(string); ok && v != "" {
				*conv = v
			}
		}
		if *sec == "" {
			if v, ok := meta["section_id"].(string); ok && v != "" {
				*sec = v
			}
		}
	}
}
