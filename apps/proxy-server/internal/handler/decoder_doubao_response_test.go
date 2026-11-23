package handler

import (
	"strings"
	"testing"
)

// 豆包网页版带图回复:模型回答正文经 STREAM_MSG_NOTIFY/STREAM_CHUNK(text_block)+CHUNK_DELTA 到达,
// tts_content(patch_object:111)是逐字音频镜像须排除,用户上传图经 FULL_MSG_NOTIFY 回显。
// 回归保护:曾因共享 ChatGPT 重组器对带图回复"假命中(空正文+仅附件)"短路掉逐帧兜底,导致模型回答整段丢失。
const doubaoWebImagePlusTextSSE = `id: 0
event: SSE_ACK
data: {"query_list":[{"question_id":"q1"}],"ack_client_meta":{"conversation_id":"conv1","section_id":"sec1"}}

id: 1
event: FULL_MSG_NOTIFY
data: {"message":{"conversation_id":"conv1","message_id":"u1","user_type":1,"content_type":9999,"content_block":[{"block_type":10052,"block_id":"ub1","content":{"attachment_block":{"attachments":[{"type":1,"identifier":"att1","image":{"uri":"tos-cn/x.jpg","image_ori":{"url":"https://example.com/ori.jpg","width":100,"height":100},"name":"id-card.jpg"},"review_state":1}]}},"is_finish":false}]}}

id: 5
event: STREAM_MSG_NOTIFY
data: {"content":{"content_block":[{"block_type":10000,"block_id":"c1","content":{"text_block":{"text":"标题A"}},"is_finish":false,"patch_type":1}],"content_type":9999,"tts_content":"标题A"},"meta":{"message_id":"m1","user_type":2}}

id: 7
event: STREAM_CHUNK
data: {"message_id":"m1","patch_op":[{"patch_object":1,"patch_type":1,"patch_value":{"content_block":[{"block_type":10000,"block_id":"c1","content":{"text_block":{"text":"标题B"}},"is_finish":false,"patch_type":1}]}}]}

id: 8
event: STREAM_CHUNK
data: {"message_id":"m1","patch_op":[{"patch_object":111,"patch_type":1,"patch_value":{"tts_content":"标题B"}}]}

id: 10
event: CHUNK_DELTA
data: {"text":"正文C"}

id: 11
event: STREAM_CHUNK
data: {"message_id":"m1","patch_op":[{"patch_object":111,"patch_type":1,"patch_value":{"tts_content":"正文C"}}]}

id: 13
event: CHUNK_DELTA
data: {"text":"正文D"}
`

func TestDecodeDoubaoWebResponse_ImagePlusTextCapturesAnswer(t *testing.T) {
	got, ok := decodeDoubaoWebResponse([]byte(doubaoWebImagePlusTextSSE), "text/event-stream")
	if !ok {
		t.Fatalf("expected decode to succeed")
	}
	// 正文 = 首块 + 结构化追加 + 文本增量,按帧序、各一次。
	const want = "标题A标题B正文C正文D"
	if got.Text != want {
		t.Fatalf("answer mismatch:\n got=%q\nwant=%q", got.Text, want)
	}
	// tts_content(标题B/正文C 的音频镜像)必须被排除,不得二次出现。
	if c := strings.Count(got.Text, "标题B"); c != 1 {
		t.Fatalf("tts 镜像未排除:'标题B' 出现 %d 次,应为 1", c)
	}
	if c := strings.Count(got.Text, "正文C"); c != 1 {
		t.Fatalf("tts 镜像未排除:'正文C' 出现 %d 次,应为 1", c)
	}
	// 用户上传图仍被捕获为附件(留证取图不受影响)。
	if len(got.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(got.Attachments))
	}
	if got.Attachments[0].DownloadURL != "https://example.com/ori.jpg" {
		t.Fatalf("attachment url mismatch: %q", got.Attachments[0].DownloadURL)
	}
	// turn 分组键:SSE_ACK 帧的 ack_client_meta 带 conversation_id/section_id,须被 lift。
	if got.ConversationID != "conv1" {
		t.Fatalf("conversation_id mismatch: got %q want %q", got.ConversationID, "conv1")
	}
	if got.SectionID != "sec1" {
		t.Fatalf("section_id mismatch: got %q want %q", got.SectionID, "sec1")
	}
}

// SP2 治本:豆包响应侧 collectStreamAttachments 会从 SSE 抓到三类附件混在一起——
// ①真实用户/模型图片(json_image_url,普通 url,无 FileBizType/bot_/文档缩略名);
// ②机器人头像(json_image_url,ref 含 FileBizType 或文件名以 bot_ 开头,实证来自 conversation_info.image 等);
// ③响应侧文件回显(json_file_url,豆包把用户上传 docx 渲染成的 *.docx~tplv...jpeg 缩略图,
//   用户文件已由请求侧 decodeDoubaoWebRequest 以 json_file_object 捕获,响应侧这条是重复+误归属)。
// 过滤后只应剩①那张真实图片;②③都被丢弃。
// 实证来源:生产库 access_content_logs(provider=bytedance,stage=response)——
//   json_file_url 全部带文档缩略名(has_doc_thumb=t),json_image_url 无一带文档缩略名(=真图+头像)。
const doubaoWebResponseMixedAttachmentsSSE = `id: 1
event: STREAM_MSG_NOTIFY
data: {"content":{"content_block":[{"content":{"text_block":{"text":"答案正文"}}}]}}

id: 2
event: STREAM_CHUNK
data: {"refs":{"image":{"image_url":"https://example.com/real-user.jpg"}}}

id: 3
event: SSE_ACK
data: {"image":{"image_ori":{"url":"https://p6.byteimg.com/ocean-cloud-tos/FileBizType.BIZ_BOT_ICON/bot_0817_03.png~tplv-a9rns2rl98-image-qvalue.png"}}}

id: 4
event: STREAM_CHUNK
data: {"file":{"file_name":"季度报告.docx","file_url":"https://tos.byteimg.com/tos-cn-i-ik7evvg4ik/a539ad96.docx~tplv-a9rns2rl98-image.jpeg"}}
`

func TestDecodeDoubaoWebResponse_FiltersFileEchoAndBotAvatar(t *testing.T) {
	got, ok := decodeDoubaoWebResponse([]byte(doubaoWebResponseMixedAttachmentsSSE), "text/event-stream")
	if !ok {
		t.Fatalf("expected decode to succeed")
	}
	if got.Text != "答案正文" {
		t.Fatalf("answer mismatch: got=%q want=%q", got.Text, "答案正文")
	}
	// 过滤后只剩那张真实用户图片;机器人头像(json_image_url+FileBizType/bot_)与
	// 文件缩略图回显(json_file_url + 同 URL 误冒的 json_image_url 文档缩略名)都被丢弃。
	if len(got.Attachments) != 1 {
		var dump []string
		for _, a := range got.Attachments {
			dump = append(dump, a.Source+":"+a.FileName)
		}
		t.Fatalf("expected 1 attachment (real user image), got %d: %v", len(got.Attachments), dump)
	}
	if got.Attachments[0].DownloadURL != "https://example.com/real-user.jpg" {
		t.Fatalf("kept attachment should be the real user image, got url=%q fn=%q src=%q",
			got.Attachments[0].DownloadURL, got.Attachments[0].FileName, got.Attachments[0].Source)
	}
	// 显式确认头像与文件回显都不在结果里(防止过滤规则被改宽/改窄)。
	for _, a := range got.Attachments {
		if strings.Contains(a.ReferenceID, "FileBizType") || strings.HasPrefix(a.FileName, "bot_") {
			t.Fatalf("机器人头像未被过滤: %+v", a)
		}
		if a.Source == "json_file_url" {
			t.Fatalf("响应侧文件回显(json_file_url)未被过滤: %+v", a)
		}
		if strings.Contains(a.FileName, ".docx~") || strings.Contains(a.FileName, ".pdf~") {
			t.Fatalf("文档渲染缩略图未被过滤: %+v", a)
		}
	}
}

// SP0 承重墙:buildAccessContentLogPayload 必须把 turn 分组键透传进 payload,
// response 优先;三键全空时 payload 留空(NULL 安全),不得编造。
func TestBuildAccessContentLogCarriesTurnGroupingKeys(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID:       "req_turn_keys",
		TenantID:        "tenant_default",
		Provider:        "doubao",
		Product:         "doubao",
		RetentionLevel:  "content",
		ContentRetained: true,
	}

	resp := ExtractedContent{
		Text:           "模型回答",
		ContentType:    "json",
		ConversationID: "convX",
		SectionID:      "secX",
		Model:          "mY",
	}

	payload, ok := buildAccessContentLogPayload(record, ExtractedContent{}, resp)
	if !ok {
		t.Fatal("含正文的 content 留存记录应构建出 payload")
	}
	if payload.ConversationID != "convX" {
		t.Fatalf("conversation_id 未透传: got %q want %q", payload.ConversationID, "convX")
	}
	if payload.SectionID != "secX" {
		t.Fatalf("section_id 未透传: got %q want %q", payload.SectionID, "secX")
	}
	if payload.Model != "mY" {
		t.Fatalf("model 未透传: got %q want %q", payload.Model, "mY")
	}

	// 三键全空(且有正文)时,payload 三键为空字符串('');写库时由 INSERT 的 NULLIF($n,'')
	// 落为 NULL,与老行(从不写这些列=NULL)一致,SP4 读侧判空只需处理 NULL 一态。
	payloadEmpty, ok := buildAccessContentLogPayload(record, ExtractedContent{}, ExtractedContent{Text: "只有正文没分组键"})
	if !ok {
		t.Fatal("仅正文也应构建出 payload")
	}
	if payloadEmpty.ConversationID != "" || payloadEmpty.SectionID != "" || payloadEmpty.Model != "" {
		t.Fatalf("分组键全空时 payload 应留空: conv=%q sec=%q model=%q",
			payloadEmpty.ConversationID, payloadEmpty.SectionID, payloadEmpty.Model)
	}
}

// TestFilterDoubaoResponseAttachments_DropsSearchResultDecorations 锁定 ⓪ 规则:
// 搜索引用装饰(站点 logo / 结果页缩略图)必须被剔除,真模型/用户图必须保留。
// 实证来源:生产库 access_content_logs(provider=bytedance),豆包带网页搜索的答案 SSE 里夹带
// search_query_result_block.results.text_card.logo_url / .url 两种 field_name,被误当「模型返回图片」。
// 真图走 attachment_block.attachments.image 路径,field_name 绝不含 search_query_result。
func TestFilterDoubaoResponseAttachments_DropsSearchResultDecorations(t *testing.T) {
	searchLogo := ExtractedAttachment{
		Source:      "json_image_url",
		FieldName:   "patch_op.patch_value.content_block.content.search_query_result_block.results.text_card.logo_url",
		FileName:    "abc~tplv-e9ol9do63j-thumbnail.jpg",
		ReferenceID: "isp-i18n-media/img/abc~tplv-e9ol9do63j-thumbnail.jpeg",
		ContentType: "image/jpeg",
		DownloadURL: "https://p3-spider-image-sign.byteimg.com/isp-i18n-media/img/abc~tplv-e9ol9do63j-thumbnail.jpeg",
	}
	searchResultThumb := ExtractedAttachment{
		Source:      "json_image_url",
		FieldName:   "patch_op.patch_value.content_block.content.search_query_result_block.results.text_card.url",
		FileName:    "result-thumb.jpg",
		ReferenceID: "isp-i18n-media/img/result-thumb.jpeg",
		ContentType: "image/jpeg",
		DownloadURL: "https://p3-spider-image-sign.byteimg.com/isp-i18n-media/img/result-thumb.jpeg",
	}
	realImage := ExtractedAttachment{
		Source:      "json_image_url",
		FieldName:   "message.content_block.content.attachment_block.attachments.image.image_ori.url",
		FileName:    "real.jpg",
		DownloadURL: "https://example.com/real.jpg",
		ContentType: "image/jpeg",
	}

	in := []ExtractedAttachment{searchLogo, searchResultThumb, realImage}
	out := filterDoubaoResponseAttachments(in)

	// 两条搜索装饰必须被剔除,只剩一条真图。
	if len(out) != 1 {
		var dump []string
		for _, a := range out {
			dump = append(dump, a.Source+":"+a.FieldName)
		}
		t.Fatalf("expected 1 attachment after filter, got %d: %v", len(out), dump)
	}
	if out[0].DownloadURL != "https://example.com/real.jpg" {
		t.Fatalf("保留下来的附件应是真图,实际 url=%q fn=%q", out[0].DownloadURL, out[0].FileName)
	}
	// 守卫循环:保留下来的附件不得含任何 search_query_result(防规则被改宽/改窄)。
	for _, a := range out {
		if strings.Contains(a.FieldName, "search_query_result") {
			t.Fatalf("search_query_result 装饰未被过滤: FieldName=%q", a.FieldName)
		}
	}
}

// 纯文本(无图)豆包回复也应抽到正文(此前走兜底能抽到,改造后由专属重组器抽,不得退化)。
func TestDecodeDoubaoWebResponse_TextOnlyCapturesAnswer(t *testing.T) {
	const sse = `id: 5
event: STREAM_MSG_NOTIFY
data: {"content":{"content_block":[{"block_type":10000,"content":{"text_block":{"text":"你好"}}}]},"meta":{"user_type":2}}

id: 10
event: CHUNK_DELTA
data: {"text":"世界"}
`
	got, ok := decodeDoubaoWebResponse([]byte(sse), "text/event-stream")
	if !ok {
		t.Fatalf("expected decode to succeed")
	}
	if got.Text != "你好世界" {
		t.Fatalf("answer mismatch: got=%q want=%q", got.Text, "你好世界")
	}
	if len(got.Attachments) != 0 {
		t.Fatalf("expected 0 attachments, got %d", len(got.Attachments))
	}
}
