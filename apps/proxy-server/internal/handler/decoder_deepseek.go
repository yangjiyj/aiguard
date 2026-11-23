package handler

import (
	"encoding/json"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

func decodeDeepSeekWebRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	if !isDeepSeekWebCompletionRequest(req) {
		return ExtractedContent{}, false
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	// 单次反序列化成通用 map：既取 prompt，又喂给 collectJSONText 扫附件，避免对同一 body 解两遍。
	var decoded map[string]interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return ExtractedContent{}, false
	}
	prompt, _ := decoded["prompt"].(string)
	if strings.TrimSpace(prompt) == "" {
		return ExtractedContent{}, false
	}
	// 用户随提问上传的图片/文件（网页版经 biz_data.files 的自签 signed_path 短链、ref_file_ids
	// 或 inline 三种形态到达）此前被整段丢弃：旧实现只回 prompt 文本。这里在原 prompt 之外，再用
	// 通用 collectJSONText 扫一遍同一份请求 JSON 把附件捞出来合并回 Attachments——文本侧仍只认
	// prompt（附件元数据不进给人看的正文，signed_path 由 collectJSONText 内部统一丢弃文本侧），
	// 不改任何共享函数签名，参考 decoder_doubao.go「接出 buildExtracted 结果后再补字段」的隔离写法。
	var attachments []ExtractedAttachment
	var discard []string
	collectJSONText(decoded, "", &discard, &attachments)
	// deepseek 网页版同一张用户图常同时出现在 ref_file_ids（裸 file-id、无 DownloadURL）和
	// biz_data.files（带 signed_path 短链、能抓真字节）两处，两条 ReferenceID 相同。首次留证时
	// retention_store 的 seenReferences 去重还没记录 catalog → 两条都落库 = 一张图冒出「真字节 + 空壳」
	// 两条留证。这里在 buildExtracted 前按 ReferenceID 做 file-local 去重，保留能抓字节的那条。
	attachments = dedupeDeepSeekAttachmentsByReference(attachments)
	// turn 分组键：DeepSeek 网页版会话/轮次键只在请求体里（响应 SSE 不带，已实测确认）。
	// conversation_id ← chat_session_id；section_id ← parent_message_id（per-turn 键：上一轮
	// 助手消息 id，单调唯一；首轮 null → 空串，写侧 NULLIF 落 NULL）。套 decoder_doubao.go
	// 「接出 buildExtracted 结果后再补字段」的隔离写法，不改共享函数签名。
	c := buildExtracted([]string{prompt}, attachments, "json")
	c.ConversationID, _ = decoded["chat_session_id"].(string)
	c.SectionID = deepSeekSectionID(decoded["parent_message_id"])
	return c, true
}

// deepSeekSectionID 把 DeepSeek 请求体的 parent_message_id 归一成 section_id 字符串。
// 它是「上一轮助手消息 id」，每个 turn 唯一、单调递增，作为 turn 内分组键。encoding/json
// 默认把 JSON number 解成 float64；首轮提问无父消息为 null → 返回空串（写侧 NULLIF 落 NULL，
// 读侧按 NULL turn 分组，不与其它 turn 串台）。
func deepSeekSectionID(v interface{}) string {
	switch n := v.(type) {
	case float64:
		// 消息 id 是整数；用整数格式化避免 "2.000000"。
		return strconv.FormatInt(int64(n), 10)
	case json.Number:
		return n.String()
	case string:
		return strings.TrimSpace(n)
	}
	return ""
}

// dedupeDeepSeekAttachmentsByReference 对合并出的附件按 ReferenceID 去重（仅限 deepseek 请求解码，
// 不影响其它 decoder / 共享函数）：
//   - ReferenceID 为空的原样保留（可能是彼此不同的文件，无法据此判等）；
//   - 同一非空 ReferenceID 有多条时，优先保留带 DownloadURL 或 DataBase64（能抓到真字节）的那条，
//     都没有则保留首次出现的那条；
//   - 保持各附件首次出现的相对顺序。
func dedupeDeepSeekAttachmentsByReference(attachments []ExtractedAttachment) []ExtractedAttachment {
	if len(attachments) < 2 {
		return attachments
	}
	out := make([]ExtractedAttachment, 0, len(attachments))
	indexByRef := make(map[string]int)
	for _, att := range attachments {
		ref := strings.TrimSpace(att.ReferenceID)
		if ref == "" {
			out = append(out, att)
			continue
		}
		if pos, seen := indexByRef[ref]; seen {
			// 已有同 ReferenceID：若旧的没字节、新的有字节，则用新的替换（保留可抓字节者）。
			existing := out[pos]
			existingHasBytes := existing.DownloadURL != "" || existing.DataBase64 != ""
			candidateHasBytes := att.DownloadURL != "" || att.DataBase64 != ""
			if !existingHasBytes && candidateHasBytes {
				out[pos] = att
			}
			continue
		}
		indexByRef[ref] = len(out)
		out = append(out, att)
	}
	return out
}

func isDeepSeekWebCompletionRequest(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	host := normalizeHost(req.URL.Host)
	if host == "" {
		host = normalizeHost(req.Host)
	}
	if host != "chat.deepseek.com" {
		return false
	}
	return strings.Contains(strings.ToLower(req.URL.Path), "/api/v0/chat/completion")
}

func decodeDeepSeekWebResponse(body []byte, contentType string) (ExtractedContent, bool) {
	if !isEventStream(contentType, body) {
		return ExtractedContent{}, false
	}
	return reassembleDeepSeekPatchStream(parseSSEDataEvents(body))
}

type dsFragment struct {
	fragType string
	content  strings.Builder
}

// reassembleDeepSeekPatchStream 处理 chat.deepseek.com 网页端的 {o,p,v} JSON-patch 流：
// 把逐 token APPEND 到 response/fragments 的内容按片段重组，THINK 片段=思考，其余=回答。
func reassembleDeepSeekPatchStream(events []sseEvent) (ExtractedContent, bool) {
	matched := false
	for _, ev := range events {
		if looksLikeDeepSeekPatch(ev) {
			matched = true
			break
		}
	}
	if !matched {
		return ExtractedContent{}, false
	}
	st := &dsPatchState{}
	for _, ev := range events {
		if m, ok := ev.decoded.(map[string]interface{}); ok {
			st.apply(m)
		}
	}
	fragments := st.fragments
	var reasoning, answer strings.Builder
	for _, f := range fragments {
		txt := f.content.String()
		if txt == "" {
			continue
		}
		if f.fragType == "THINK" {
			reasoning.WriteString(txt)
		} else {
			answer.WriteString(txt)
		}
	}
	att := collectStreamAttachments(events)
	if answer.Len() == 0 && reasoning.Len() == 0 && len(att) == 0 {
		// 误判为 DeepSeek（如 ChatGPT 的 {p,o,v} 帧）时所有 patch 落到 default 被丢弃，
		// fragments 为空。回退到逐帧解析，正文（在 v 字段里）才不会被整段吞掉。
		return ExtractedContent{}, false
	}
	return buildReassembledExtracted(answer.String(), reasoning.String(), att), true
}

var deepSeekPatchSniffer = looksLikeDeepSeekPatchDefault

func looksLikeDeepSeekPatch(ev sseEvent) bool {
	return deepSeekPatchSniffer(ev)
}

func looksLikeDeepSeekPatchDefault(ev sseEvent) bool {
	m, ok := ev.decoded.(map[string]interface{})
	if !ok {
		return false
	}
	o, ok := m["o"].(string)
	if !ok {
		return false
	}
	if o == "BATCH" {
		return true
	}
	// SSE 正文里没有 host，只能靠路径区分：DeepSeek 的补丁路径 p 以 "response" 开头
	//（如 response、response/fragments、response/fragments/0/content）；ChatGPT 网页流的
	// 补丁帧 p 以 "/message" 开头，结构同形却语义不同。仅按 hasP 判定会把 ChatGPT 误判为
	// DeepSeek，导致正文落到 applyDeepSeekPath 的 default 分支被丢弃。
	p, ok := m["p"].(string)
	if !ok {
		return false
	}
	return strings.HasPrefix(p, "response")
}

// dsPatchState 跨帧重组 DeepSeek 网页流。真实 wire 有三种 content_extractor 之前漏掉的帧：
//  1. 初始快照帧：无 p、无 o，v 是整个 response 对象（含首批 fragments，常含 THINK 思考种子）；
//  2. sticky 裸帧：无 p、无 o，仅 {"v":...}，沿用上一条「指定了路径/op 的帧」的 path 与 op
//     继续 APPEND（思考/回答的绝大多数 token 都走这种帧）；
//  3. 隐式 op 帧：有 p、无 o，DeepSeek 对 content 的隐式 op 即 APPEND（旧码缺省走 else 把内容
//     RESET 成单字符）。
//
// 据此用 stickyPath/stickyOp 记忆游标：有 p 用 p、否则沿用 stickyPath；有 o 用 o、否则有 p 时
// 隐式 APPEND、纯裸帧沿用 stickyOp。APPEND 出新 fragment 后游标跟进到该新片段的 content，
// 后续裸帧才会续写正文而非空转。
type dsPatchState struct {
	fragments  []*dsFragment
	stickyPath string
	stickyOp   string
}

func (st *dsPatchState) apply(m map[string]interface{}) {
	if o, _ := m["o"].(string); o == "BATCH" {
		// BATCH 是收尾的成批元数据（token 用量 / status），逐条套用但不污染外层游标。
		savedPath, savedOp := st.stickyPath, st.stickyOp
		if arr, ok := m["v"].([]interface{}); ok {
			for _, item := range arr {
				if sub, ok := item.(map[string]interface{}); ok {
					st.apply(sub)
				}
			}
		}
		st.stickyPath, st.stickyOp = savedPath, savedOp
		return
	}
	v, hasV := m["v"]
	if !hasV {
		return
	}
	pRaw, hasP := m["p"].(string)
	oRaw, hasO := m["o"].(string)

	// 初始快照帧：无 p 无 o，v 是整个 response 对象，一次性 seed 首批 fragments（含 THINK 思考），
	// 并把游标钉到最后片段的 content。注意要和「无 p 无 o 但 v 是字符串」的 sticky 裸帧区分。
	if !hasP && !hasO {
		if obj, ok := v.(map[string]interface{}); ok {
			if respObj, ok := obj["response"]; ok {
				applyDeepSeekPath("", "response", respObj, &st.fragments)
				st.stickyPath = "response/fragments/-1/content"
				st.stickyOp = "APPEND"
				return
			}
		}
	}

	path := st.stickyPath
	if hasP {
		path = pRaw
	}
	op := st.stickyOp
	if hasO {
		op = oRaw
	} else if hasP {
		op = "APPEND" // 有 p 无 o：DeepSeek 对 content 的隐式 op 是 APPEND
	}
	st.stickyPath = path
	st.stickyOp = op

	applyDeepSeekPath(op, path, v, &st.fragments)

	// APPEND 出新 fragment 后，游标跟进到该新片段的 content，后续 sticky 裸帧续写其正文。
	if path == "response/fragments" && op == "APPEND" {
		st.stickyPath = "response/fragments/-1/content"
		st.stickyOp = "APPEND"
	}
}

func applyDeepSeekPath(op, path string, value interface{}, fragments *[]*dsFragment) {
	switch {
	case path == "response":
		if m, ok := value.(map[string]interface{}); ok {
			if fragsRaw, ok := m["fragments"].([]interface{}); ok {
				for _, fr := range fragsRaw {
					if fm, ok := fr.(map[string]interface{}); ok {
						pushDSFragment(fm, fragments)
					}
				}
			}
		}
	case path == "response/fragments":
		switch v := value.(type) {
		case map[string]interface{}:
			pushDSFragment(v, fragments)
		case []interface{}:
			for _, fr := range v {
				if fm, ok := fr.(map[string]interface{}); ok {
					pushDSFragment(fm, fragments)
				}
			}
		}
	case strings.HasPrefix(path, "response/fragments/") && strings.HasSuffix(path, "/content"):
		idxStr := strings.TrimSuffix(strings.TrimPrefix(path, "response/fragments/"), "/content")
		frag := resolveFragmentIndex(idxStr, fragments)
		if frag == nil {
			return
		}
		str, ok := value.(string)
		if !ok {
			return
		}
		if op == "APPEND" {
			frag.content.WriteString(str)
		} else {
			frag.content.Reset()
			frag.content.WriteString(str)
		}
	default:
		// 忽略 status / elapsed_secs / accumulated_token_usage / quasi_status 等协议字段。
	}
}

func pushDSFragment(m map[string]interface{}, fragments *[]*dsFragment) {
	fragType, _ := m["type"].(string)
	frag := &dsFragment{fragType: fragType}
	if c, ok := m["content"].(string); ok && c != "" {
		frag.content.WriteString(c)
	}
	*fragments = append(*fragments, frag)
}

func resolveFragmentIndex(idxStr string, fragments *[]*dsFragment) *dsFragment {
	if len(*fragments) == 0 {
		return nil
	}
	if idxStr == "-1" {
		return (*fragments)[len(*fragments)-1]
	}
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx < 0 || idx >= len(*fragments) {
		return nil
	}
	return (*fragments)[idx]
}

// buildReassembledExtracted 把重组后的回答与思考合并成审计正文：思考以 [reasoning] 标记
