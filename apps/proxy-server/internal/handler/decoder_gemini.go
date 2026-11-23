package handler

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

func decodeGeminiWebRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isFormURLEncodedContent(strings.ToLower(mediaType)) {
		return ExtractedContent{}, false
	}
	values, err := url.ParseQuery(safeText(body))
	if err != nil {
		return ExtractedContent{}, false
	}
	var parts []string
	var attachments []ExtractedAttachment
	matched := false
	for _, rawValue := range values["f.req"] {
		value := strings.TrimSpace(rawValue)
		if value == "" {
			continue
		}
		var decoded interface{}
		if err := json.Unmarshal([]byte(value), &decoded); err != nil {
			continue
		}
		matched = true
		walkGeminiFReqValue(decoded, &parts, &attachments)
	}
	if !matched {
		return ExtractedContent{}, false
	}
	return buildExtracted(parts, attachments, mediaType), true
}

func decodeGeminiWebResponse(body []byte, contentType string) (ExtractedContent, bool) {
	if !looksLikeXSSIGuardedJSON(body) {
		return ExtractedContent{}, false
	}
	return extractGoogleBatchExecuteContent(body), true
}

func looksLikeXSSIGuardedJSON(body []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(body, " \t\r\n"), []byte(")]}'"))
}

// extractGoogleBatchExecuteContent 解析 Google batchexecute 响应：剥掉 )]}' 前缀后，体内是
// "长度前缀数字 + 嵌套数组"反复拼接的流。用 json.Decoder 逐个解出顶层数组（长度前缀是裸数字，
// 会被当作独立的 JSON number 跳过），再递归下钻；其中 wrb.fr 行第 3 个元素是 JSON 编码字符串，
// 需二次 Unmarshal 才能拿到真正的回答。最终复用既有过滤管线，只留人类正文，丢弃协议字段与 ID。
func extractGoogleBatchExecuteContent(body []byte) ExtractedContent {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	trimmed = bytes.TrimPrefix(trimmed, []byte(")]}'"))

	// Gemini 网页真对话走 StreamGenerate：响应是同一回答的多帧增长快照（wrb.fr 行），
	// 结构化解析出唯一回答 + 思考过程；命中则直接返回，避免盲遍历把回答跨帧重复抓取、
	// 并夹带思考草稿/重复段落/UI 建议气泡（访问留存里「一堆乱七八糟」的根因）。
	// 未命中响应候选（如 batchexecute 摘要总线）则 ok=false，回退既有盲遍历。
	if c, ok := extractGeminiStreamGenerate(trimmed); ok {
		return c
	}

	var parts []string
	var attachments []ExtractedAttachment
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	for {
		var value interface{}
		// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- extractor needs arbitrary JSON text traversal; encoding/json does not instantiate arbitrary types.
		if err := dec.Decode(&value); err != nil {
			break
		}
		walkBatchExecuteValue(value, &parts, &attachments)
	}
	return buildExtracted(parts, attachments, "json")
}

// walkBatchExecuteValue 递归遍历 batchexecute 解出的值：遇到看起来像内嵌 JSON 的字符串就二次
// 解析后继续下钻，否则交给 appendJSONString 过滤；map 交给 collectJSONText 走既有文件/图片识别。
func walkBatchExecuteValue(value interface{}, parts *[]string, attachments *[]ExtractedAttachment) {
	switch v := value.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return
		}
		if (strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{")) && len(trimmed) >= 2 {
			// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- extractor needs arbitrary JSON text traversal; encoding/json does not instantiate arbitrary types.
			var inner interface{}
			if err := json.Unmarshal([]byte(trimmed), &inner); err == nil {
				walkBatchExecuteValue(inner, parts, attachments)
				return
			}
		}
		appendJSONString("", v, parts, attachments)
	case []interface{}:
		for _, item := range v {
			walkBatchExecuteValue(item, parts, attachments)
		}
	case map[string]interface{}:
		collectJSONText(v, "", parts, attachments)
	}
}

// geminiFileEntry 识别 Gemini 网页 f.req 内层的附件三元组 [[<签名路径>,<n>,null,<mime>],<文件名>]：
// 第一元素是 [路径,序号,null,MIME] 的元数据数组，第二元素是用户可读文件名。命中即登记为附件，
// 且【不再下钻】——避免把 Google 内部签名路径/MIME 当作文本泄露进访问留存。刻意不设 ReferenceID，
// 因为这里的签名路径是 Google 租户内部寻址，与本系统 reference_id→bytes 的回捞语义无关，不可混用。
func geminiFileEntry(arr []interface{}) (ExtractedAttachment, bool) {
	if len(arr) != 2 {
		return ExtractedAttachment{}, false
	}
	meta, ok := arr[0].([]interface{})
	if !ok || len(meta) < 4 {
		return ExtractedAttachment{}, false
	}
	path, ok := meta[0].(string)
	if !ok || strings.TrimSpace(path) == "" {
		return ExtractedAttachment{}, false
	}
	mime, ok := meta[3].(string)
	if !ok || !strings.Contains(mime, "/") {
		return ExtractedAttachment{}, false
	}
	filename, ok := arr[1].(string)
	if !ok || strings.TrimSpace(filename) == "" {
		return ExtractedAttachment{}, false
	}
	return ExtractedAttachment{
		Source:      "gemini_web_upload",
		FileName:    strings.TrimSpace(filename),
		ContentType: strings.TrimSpace(mime),
	}, true
}

// walkGeminiFReqValue 处理 Gemini 网页 StreamGenerate 的 f.req【双层编码】：外层 url-form 字段的值
// 是信封 [null,"<内层JSON字符串>"]，真正的 prompt(inner[0][0])/附件(inner[0][3]) 埋在内层 JSON 里。
// 必须像响应侧 walkBatchExecuteValue 一样，遇到内嵌 JSON 字符串就二次解析下钻，否则内层 JSON 整体
// 因含中文被 looksLikeHumanText 判为人类文本、原样作为一个叶子写入访问留存 → 用户提问显示成乱码数组。
func walkGeminiFReqValue(value interface{}, parts *[]string, attachments *[]ExtractedAttachment) {
	switch v := value.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return
		}
		if (strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{")) && len(trimmed) >= 2 {
			// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- extractor needs arbitrary JSON text traversal; encoding/json does not instantiate arbitrary types.
			var inner interface{}
			if err := json.Unmarshal([]byte(trimmed), &inner); err == nil {
				walkGeminiFReqValue(inner, parts, attachments)
				return
			}
		}
		appendJSONString("", v, parts, attachments)
	case []interface{}:
		if attachment, ok := geminiFileEntry(v); ok {
			*attachments = append(*attachments, attachment)
			return
		}
		for _, item := range v {
			walkGeminiFReqValue(item, parts, attachments)
		}
	case map[string]interface{}:
		collectJSONText(v, "", parts, attachments)
	}
}

func extractGeminiStreamGenerate(trimmed []byte) (ExtractedContent, bool) {
	snapshots := geminiWrbFrSnapshots(trimmed)
	var answer, reasoning string
	var lastSnap interface{}
	found := false
	for _, snap := range snapshots {
		if ans, rsn, ok := geminiStreamResponseSnapshot(snap); ok {
			answer, reasoning, lastSnap, found = ans, rsn, snap, true
		}
	}
	if !found {
		return ExtractedContent{}, false
	}
	// 仅从最后一帧响应候选里回收真正的附件（模型生成的图片/文件），文本丢弃——文本由结构化的
	// answer/reasoning 提供，避免盲遍历把同一回答跨帧重复抓取。
	var throwaway []string
	var attachments []ExtractedAttachment
	walkBatchExecuteValue(lastSnap, &throwaway, &attachments)
	return buildReassembledExtracted(answer, reasoning, attachments), true
}

// geminiWrbFrSnapshots 把 StreamGenerate 线格式拆成一组内层快照。线格式为反复的
// 「<chunk字节长度>\n[["wrb.fr",null,"<内层JSON>"]]」：长度前缀是裸数字（被 json.Decoder
// 当独立 number 跳过），wrb.fr 行第 3 个元素是 JSON 编码字符串，二次 Unmarshal 即得内层快照。
func geminiWrbFrSnapshots(trimmed []byte) []interface{} {
	var out []interface{}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	for {
		var value interface{}
		// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- extractor needs arbitrary JSON text traversal; encoding/json does not instantiate arbitrary types.
		if err := dec.Decode(&value); err != nil {
			break
		}
		collectWrbFr(value, &out)
	}
	return out
}

// collectWrbFr 递归找出 ["wrb.fr", null, "<内层JSON>", ...] 行，把第 3 个元素二次 Unmarshal
// 出的内层快照追加进 out；非 wrb.fr 行则继续下钻其数组元素。
func collectWrbFr(value interface{}, out *[]interface{}) {
	arr, ok := value.([]interface{})
	if !ok {
		return
	}
	if len(arr) >= 3 {
		if tag, ok := arr[0].(string); ok && tag == "wrb.fr" {
			if payload, ok := arr[2].(string); ok && payload != "" {
				// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- extractor needs arbitrary JSON text traversal; encoding/json does not instantiate arbitrary types.
				var inner interface{}
				if err := json.Unmarshal([]byte(payload), &inner); err == nil {
					*out = append(*out, inner)
				}
				return
			}
		}
	}
	for _, item := range arr {
		collectWrbFr(item, out)
	}
}

// geminiStreamResponseSnapshot 判定一帧内层快照是否是「响应候选」并取出回答与思考过程。
// 候选门槛（真实抓包 015 验证）：inner[4][0][0] 为 "rc_" 前缀的候选 ID，inner[4][0][1][0]
// 为非空回答正文。回答 = inner[4][0][1][0]；思考过程 = inner[4][0][37][0][0]（允许为空）。
// 非响应候选（如 batchexecute 摘要总线的 af.httprm 帧）返回 ok=false。
func geminiStreamResponseSnapshot(snap interface{}) (string, string, bool) {
	outer, ok := snap.([]interface{})
	if !ok || len(outer) <= 4 {
		return "", "", false
	}
	node4, ok := outer[4].([]interface{})
	if !ok || len(node4) == 0 {
		return "", "", false
	}
	first, ok := node4[0].([]interface{})
	if !ok || len(first) < 2 {
		return "", "", false
	}
	rcID, ok := first[0].(string)
	if !ok || !strings.HasPrefix(rcID, "rc_") {
		return "", "", false
	}
	ansList, ok := first[1].([]interface{})
	if !ok || len(ansList) == 0 {
		return "", "", false
	}
	answer, ok := ansList[0].(string)
	if !ok || strings.TrimSpace(answer) == "" {
		return "", "", false
	}
	return answer, geminiSnapshotReasoning(first), true
}

// geminiSnapshotReasoning 取响应候选的思考过程：first[37][0][0]（first[37] 为 len-2 列表、
// [0] 为 len-1 列表、[0] 为字符串）。任一层缺失返回空串（思考过程允许为空）。
func geminiSnapshotReasoning(first []interface{}) string {
	if len(first) <= 37 {
		return ""
	}
	r37, ok := first[37].([]interface{})
	if !ok || len(r37) == 0 {
		return ""
	}
	r0, ok := r37[0].([]interface{})
	if !ok || len(r0) == 0 {
		return ""
	}
	s, _ := r0[0].(string)
	return s
}
