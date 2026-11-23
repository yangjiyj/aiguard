package handler

import (
	"strings"
	"testing"
)

// qwenSSEFrame 把一个千问顶层信封 JSON 包成一行 SSE data: 帧（末尾带空行分隔）。
// 真实结构：data:{"error_msg":"","data":{...},"error_code":0,"communication":{"sessionid":"…",…}}。
func qwenSSEFrame(jsonStr string) string {
	return "data:" + jsonStr + "\n\n"
}

// 千问网页版（chat2.qianwen.com /api/v2/chat）响应是 SSE 信封：答案与一大坨 agent 控制面噪音都在
// data.messages[],靠 mime_type 区分。multi_load/iframe.content 是【累积快照】的真答案(取最长那帧),
// signal/post(agent控制面)、bar/*、paa/iframe 是噪音必须跳过。会话键=顶层 communication.sessionid。
// 本测试用合成夹具(无 PII、非真实抓样原文)验证:抽干净答案 + 剔两类前端技术记号([(...)] 占位符 +
// [[source_group_web_N]] 搜索引用锚点) + 跳过 agent 控制面 + 不产附件。
func TestDecodeQwenWebResponse_ExtractsAnswerSkipsAgentControlPlane(t *testing.T) {
	var sb strings.Builder
	// signal/post:agent 控制面信号(meta_data.intent_data 里一坨 agent_info/scene/…)——必须跳过,绝不进正文。
	sb.WriteString(qwenSSEFrame(`{"error_msg":"","error_code":0,"communication":{"sessionid":"sess-abc123","resid":1,"reqid":"req-1"},"data":{"messages":[{"mime_type":"signal/post","content":"","meta_data":{"intent_content":"路由决策","intent_data":{"agent_info":{"agent":"MainChatterAgent","version":"1"},"judge_type":"llm","scene":"general_qa","intent":"chitchat","search_intent":false}}}]}}`))
	// bar/progress:进度条 UI 噪音——跳过。
	sb.WriteString(qwenSSEFrame(`{"error_msg":"","error_code":0,"communication":{"sessionid":"sess-abc123","resid":2,"reqid":"req-1"},"data":{"messages":[{"mime_type":"bar/progress","content":"","meta_data":{"percent":30}}]}}`))
	// multi_load/iframe:真答案载体,content 是累积快照——第 1 帧。
	sb.WriteString(qwenSSEFrame(`{"error_msg":"","error_code":0,"communication":{"sessionid":"sess-abc123","resid":3,"reqid":"req-1"},"data":{"messages":[{"mime_type":"multi_load/iframe","status":"running","content":"杭州"}]}}`))
	// multi_load/iframe:累积增长——第 2 帧。
	sb.WriteString(qwenSSEFrame(`{"error_msg":"","error_code":0,"communication":{"sessionid":"sess-abc123","resid":4,"reqid":"req-1"},"data":{"messages":[{"mime_type":"multi_load/iframe","status":"running","content":"杭州，是一座"}]}}`))
	// multi_load/iframe:最后一帧 status=complete=完整答案。含两类前端技术记号:句中 [[source_group_web_1]]
	// 搜索引用锚点(贴在正文+标点旁,如"历史名城[[source_group_web_1]]。")+ 末尾 [(video_note_list_1)] 占位符;
	// meta_data.multi_load 是视频卡噪音(不应被碰)。两类记号都必须剔除、两侧正文完好保留。
	sb.WriteString(qwenSSEFrame(`{"error_msg":"","error_code":0,"communication":{"sessionid":"sess-abc123","resid":5,"reqid":"req-1"},"data":{"messages":[{"mime_type":"multi_load/iframe","status":"complete","content":"杭州，是一座历史名城[[source_group_web_1]]。\n\n## 简介\n位于浙江省。[(video_note_list_1)]","meta_data":{"multi_load":[{"type":"video","css":"https://g.alicdn.com/x.css","js":"https://g.alicdn.com/x.js"}]}}]}}`))
	// paa/iframe:"猜你想问"追问推荐 UI 噪音——跳过。
	sb.WriteString(qwenSSEFrame(`{"error_msg":"","error_code":0,"communication":{"sessionid":"sess-abc123","resid":6,"reqid":"req-1"},"data":{"messages":[{"mime_type":"paa/iframe","content":"","meta_data":{"questions":["杭州有哪些景点？"]}}]}}`))

	wantText := "杭州，是一座历史名城。\n\n## 简介\n位于浙江省。"

	got, ok := decodeQwenWebResponse([]byte(sb.String()), "text/event-stream")
	if !ok {
		t.Fatalf("expected decode to succeed")
	}
	// ① 取最长那帧 content 且占位符已剔、已 TrimSpace。
	if got.Text != wantText {
		t.Fatalf("answer mismatch (must be longest multi_load/iframe content with placeholder stripped):\n got=%q\nwant=%q", got.Text, wantText)
	}
	// ② 守卫:agent 控制面字样绝不回流到正文。
	for _, leaked := range []string{"agent_info", "MainChatterAgent", "general_qa", "intent", "judge_type", "search_intent"} {
		if strings.Contains(got.Text, leaked) {
			t.Fatalf("agent control-plane token %q leaked into answer: %q", leaked, got.Text)
		}
	}
	// 占位符必须被剔除。
	if strings.Contains(got.Text, "[(") {
		t.Fatalf("placeholder must be stripped, got: %q", got.Text)
	}
	// 搜索引用锚点 [[source_group_web_N]] 必须被剔除(别露原始技术 id)。
	for _, leaked := range []string{"[[source_group_web_1]]", "source_group"} {
		if strings.Contains(got.Text, leaked) {
			t.Fatalf("citation marker token %q must be stripped, got: %q", leaked, got.Text)
		}
	}
	// 标记两侧正文必须完好保留:剔除后是"历史名城。"而非吃掉前字的"历史名城[["残留。
	if !strings.Contains(got.Text, "历史名城。") {
		t.Fatalf("text around citation marker must be preserved (expect 历史名城。), got: %q", got.Text)
	}
	if strings.Contains(got.Text, "历史名城[[") {
		t.Fatalf("citation marker not fully stripped, leftover bracket: %q", got.Text)
	}
	// ③ 会话键 = communication.sessionid。
	if got.ConversationID != "sess-abc123" {
		t.Fatalf("conversation_id mismatch: got %q want %q", got.ConversationID, "sess-abc123")
	}
	// ④ 不产任何附件(搜索缩略图/视频卡图是 UI 噪音,非模型产出)。
	if len(got.Attachments) != 0 {
		t.Fatalf("qwen reassembler must not emit attachments, got %d: %+v", len(got.Attachments), got.Attachments)
	}
	// 累积快照守卫:结果长度=最长帧 content(去占位符后)长度,而非各帧之和(防误拼接成 N 倍)。
	if len([]rune(got.Text)) != len([]rune(wantText)) {
		t.Fatalf("accumulative-snapshot guard: answer must equal longest frame (not concatenation of frames): got len=%d want len=%d", len([]rune(got.Text)), len([]rune(wantText)))
	}
}

// 门控 + 回退:喂 ChatGPT 风格的 SSE patch(非千问结构),reassembleQwenWebStream 不得认领,
// decodeQwenWebResponse 经回退共享解码器仍能抽到正文。证明不会误吞非千问 SSE。
func TestDecodeQwenWebResponse_FallsBackToSharedForNonQwen(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"p":"/message/content/parts/0","o":"append","v":"普通回答"}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	// 千问专属重组器对非千问结构必须不认领。
	if _, ok := reassembleQwenWebStream(body, "text/event-stream"); ok {
		t.Fatalf("reassembleQwenWebStream must not claim non-qwen ChatGPT-style SSE")
	}

	// 经回退共享解码器仍能抽到正文。
	got, ok := decodeQwenWebResponse(body, "text/event-stream")
	if !ok {
		t.Fatalf("expected fallback shared decode to succeed")
	}
	if !strings.Contains(got.Text, "普通回答") {
		t.Fatalf("fallback shared decode should extract %q, got %q", "普通回答", got.Text)
	}
}

// 门控:非 SSE 必须直接不认领(返回 false),保持隔离。门控用共享 isEventStream(content-type 不含
// text/event-stream 且 body 不以 data: 开头 → 判非 SSE)。故 body 用普通 JSON(不以 data: 开头),
// 即便其内含千问信封字段也因非 SSE 被门控挡在外面——验证「非 SSE 不认领」的语义。
func TestReassembleQwenWebStream_GatesOnEventStreamContentType(t *testing.T) {
	// 普通 JSON body(不以 data: 开头),content-type 也非 event-stream → isEventStream 返 false。
	body := []byte(`{"communication":{"sessionid":"sess-x"},"data":{"messages":[{"mime_type":"multi_load/iframe","content":"答案"}]}}`)
	if _, ok := reassembleQwenWebStream(body, "application/json"); ok {
		t.Fatalf("reassembleQwenWebStream must gate on non-SSE body+content-type")
	}
}
