package handler

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"mime"
	"net/http"
	"strings"
)

func decodeKimiWebRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	if !isKimiWebChatRequest(req) {
		return ExtractedContent{}, false
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	payload := body
	if kimiRequestUsesConnectFrame(strings.ToLower(mediaType), body) {
		var ok bool
		payload, ok = stripSingleConnectJSONFrame(body)
		if !ok {
			return ExtractedContent{}, false
		}
	}
	if !isJSONContent(strings.ToLower(mediaType), payload) {
		return ExtractedContent{}, false
	}
	var decoded struct {
		Message struct {
			Role   string `json:"role"`
			Blocks []struct {
				Text struct {
					Content string `json:"content"`
				} `json:"text"`
				File struct {
					ID string `json:"id"`
				} `json:"file"`
			} `json:"blocks"`
		} `json:"message"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return ExtractedContent{}, false
	}
	if decoded.Message.Role != "" && decoded.Message.Role != "user" {
		return ExtractedContent{}, false
	}
	var parts []string
	var attachments []ExtractedAttachment
	for _, block := range decoded.Message.Blocks {
		if text := strings.TrimSpace(block.Text.Content); text != "" {
			parts = append(parts, text)
		}
		if id := strings.TrimSpace(block.File.ID); id != "" {
			attachments = append(attachments, ExtractedAttachment{
				Source:      "json_file_reference",
				FieldName:   "message.blocks.file.id",
				ReferenceID: id,
				ContentType: "reference/file-id",
			})
		}
	}
	if len(parts) == 0 && len(attachments) == 0 {
		return ExtractedContent{}, false
	}
	return buildExtracted(parts, attachments, "json"), true
}

func isKimiWebChatRequest(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	host := normalizeHost(req.URL.Host)
	if host == "" {
		host = normalizeHost(req.Host)
	}
	if host != "www.kimi.com" && host != "kimi.com" {
		return false
	}
	return strings.Contains(strings.ToLower(req.URL.Path), "chatservice/chat")
}

func kimiRequestUsesConnectFrame(mediaType string, body []byte) bool {
	return strings.Contains(mediaType, "connect") || strings.Contains(mediaType, "grpc") || looksLikeSingleConnectJSONFrame(body)
}

func looksLikeSingleConnectJSONFrame(body []byte) bool {
	_, ok := stripSingleConnectJSONFrame(body)
	return ok
}

func stripSingleConnectJSONFrame(body []byte) ([]byte, bool) {
	if len(body) < 5 {
		return nil, false
	}
	length := int(binary.BigEndian.Uint32(body[1:5]))
	if length < 0 || length != len(body)-5 {
		return nil, false
	}
	if body[0]&0x01 == 0x01 {
		return nil, false
	}
	payload := body[5:]
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return nil, false
	}
	if trimmed[0] != '{' && trimmed[0] != '[' {
		return nil, false
	}
	return payload, true
}

// decodeKimiWebResponse:kimi 网页版 /…/ChatService/Chat 响应是 Connect-RPC（application/connect+json）
// 连续帧，不是 ChatGPT 的 SSE。过去裸委托 decodeChatGPTWebResponse(只认 SSE data: 行)→ connect 二进制
// 帧解不出、模型答案基本没被正确留证。这里先用 kimi 专属重组器按其真实 op/mask 结构抽正文+文件+会话键,
// 抽到才返回;抽不到(如偶发别的格式)再回退共享解码器,套豆包"自己先跑、回退共享"的隔离模板。
func decodeKimiWebResponse(body []byte, contentType string) (ExtractedContent, bool) {
	if c, ok := reassembleKimiWebStream(body, contentType); ok {
		return c, true
	}
	return decodeChatGPTWebResponse(body, contentType)
}

// connectFrame 是一帧已解出的 Connect-RPC 消息（普通消息帧的 JSON 体反序列化结果）。
type connectFrame struct {
	decoded map[string]interface{}
}

// parseConnectFrames 按 Connect-RPC 帧格式切帧：1 字节 flag + 4 字节大端 uint32 长度 + JSON 体。
// 容错原则:
//   - flag 含 0x02 位 = end-stream 帧(体是 trailers),跳过、不当答案;
//   - flag 含 0x01 位 = 压缩帧,无法直接解 JSON,跳过;
//   - 帧头不足 5 字节或声明长度越界 → 停止解析(返回已解出的帧,不崩);
//   - 单帧 JSON 反序列化失败 → 跳过该帧、继续后续帧(坏帧不影响整体)。
func parseConnectFrames(body []byte) []connectFrame {
	var frames []connectFrame
	for offset := 0; offset < len(body); {
		if len(body)-offset < 5 {
			break
		}
		flags := body[offset]
		length := int(binary.BigEndian.Uint32(body[offset+1 : offset+5]))
		if length < 0 || length > len(body)-offset-5 {
			break
		}
		payload := body[offset+5 : offset+5+length]
		offset += 5 + length
		if flags&0x02 == 0x02 {
			// end-stream 帧:体是 trailers(如 {} 或 {"metadata":...}),不是答案。
			continue
		}
		if flags&0x01 == 0x01 {
			// 压缩帧:此协议下 kimi 不压缩;遇到也无法裸解 JSON,跳过。
			continue
		}
		trimmed := bytes.TrimSpace(payload)
		if len(trimmed) == 0 {
			continue
		}
		var decoded map[string]interface{}
		if err := json.Unmarshal(trimmed, &decoded); err != nil {
			// 坏帧:跳过、不崩。
			continue
		}
		frames = append(frames, connectFrame{decoded: decoded})
	}
	return frames
}

// reassembleKimiWebStream 解析 kimi 网页版响应 connect+json 帧,把模型答案按帧序拼回。
// 仅当 contentType 含 "connect" 时尝试(否则返回 false 让 decodeKimiWebResponse 回退共享解码器,保持隔离)。
// 实测帧分布(对真实 www.kimi.com /ChatService/Chat connect+json 抓包核对):
//   - op:"set",mask:"block.text"           —— 模型答案的【种子帧】,首段文本在 block.text.content,必须按帧序拼进答案,
//     否则丢答案开头(如真包 163:种子"你好"+后续 append"！…",只收 append 会丢"你好")。
//   - op:"append",mask:"block.text.content" —— 模型答案正文增量,文本在 block.text.content,按帧序拼接=完整答案。
//   - op:"append",mask:"chat.files"        —— 【用户上传文件被服务端回显】(真包 186 实证:chat.files[] 是用户上传的图片/
//     文档,带 blob.signUrl),不是模型产出。绝不登记为响应附件,否则后台误显示"模型返回了文件/图片"(隐私误归属——
//     如把用户上传的身份证图标成模型输出)。用户上传文件已在请求侧 + /file/upload 被捕获,响应侧不重复、更不能标成模型产出。
//   - op:"set",mask:"message"              —— 用户/消息元数据(role+blocks),非模型答案,忽略。
//   - {"heartbeat":{}}(无 op/mask)        —— 忽略。
//   - 凡带 chat.id 的帧,chat.id = 会话分组键(conversation_id)。
// 故响应 reassembler 只产出:答案正文(种子帧 + 增量帧)+ ConversationID(chat.id),不产出任何附件。
func reassembleKimiWebStream(body []byte, contentType string) (ExtractedContent, bool) {
	if !strings.Contains(strings.ToLower(contentType), "connect") {
		return ExtractedContent{}, false
	}
	frames := parseConnectFrames(body)
	var answer strings.Builder
	var chatID string
	matched := false
	for _, f := range frames {
		m := f.decoded
		// 会话分组键:凡带 chat.id 的帧都扫,首个非空胜。在 op 分发之外做,heartbeat 等帧也覆盖到。
		if chatID == "" {
			if cid := liftKimiChatID(m); cid != "" {
				chatID = cid
			}
		}
		op, _ := m["op"].(string)
		mask, _ := m["mask"].(string)
		switch {
		// 种子帧:模型答案首段。与 append 同一拼接逻辑,按帧出现顺序写入。
		case op == "set" && mask == "block.text":
			if txt := liftKimiBlockTextContent(m); txt != "" {
				answer.WriteString(txt)
				matched = true
			}
		case op == "append" && mask == "block.text.content":
			if txt := liftKimiBlockTextContent(m); txt != "" {
				answer.WriteString(txt)
				matched = true
			}
		}
	}
	if !matched {
		return ExtractedContent{}, false
	}
	// 不改 buildReassembledExtracted 签名:接出结果后再补 ConversationID(套豆包模板)。
	// 第三参 attachments 传 nil:chat.files 是用户上传回显,不是模型产出,响应侧不登记任何附件。
	c := buildReassembledExtracted(answer.String(), "", nil)
	c.ConversationID = chatID
	return c, true
}

// liftKimiChatID 从帧的 chat.id 取会话分组键。
func liftKimiChatID(m map[string]interface{}) string {
	chat, ok := m["chat"].(map[string]interface{})
	if !ok {
		return ""
	}
	if id, ok := chat["id"].(string); ok {
		return strings.TrimSpace(id)
	}
	return ""
}

// liftKimiBlockTextContent 从 op:"append",mask:"block.text.content" 帧取 block.text.content(字符串)。
func liftKimiBlockTextContent(m map[string]interface{}) string {
	block, ok := m["block"].(map[string]interface{})
	if !ok {
		return ""
	}
	text, ok := block["text"].(map[string]interface{})
	if !ok {
		return ""
	}
	if content, ok := text["content"].(string); ok {
		return content
	}
	return ""
}
