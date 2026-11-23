package handler

import (
	"regexp"
	"strings"
)

// qwenPlaceholderPattern 匹配千问答案文本里的 widget 占位符 [(...)]（如 [(video_note_list_1)]、
// [(multimodal_chat_think_1)]）。这些是前端渲染卡片/思考块的占位记号，不是模型正文，全部剔除。
var qwenPlaceholderPattern = regexp.MustCompile(`\[\([^)]*\)\]`)

// qwenCitationMarkerPattern 匹配千问"带搜索引用"答案里的引用锚点 [[source_group_web_N]]
// (生产库实证:全库千问记录里 [[...]] 标记只有这一种)。这是前端渲染引用角标的技术 id,
// 不是模型正文,留在客户可见的留证里像半成品,剔除。锚定 source_group_ 前缀覆盖该引用族,不误伤无关 [[...]]。
var qwenCitationMarkerPattern = regexp.MustCompile(`\[\[source_group_[^\]]*\]\]`)

// decodeQwenWebResponse:千问网页版（provider=alibaba，chat2.qianwen.com /api/v2/chat）响应是
// text/event-stream（SSE），每行 data:{...} 是一个 agent 信封，答案与一大坨 agent 控制面噪音混在
// data.messages[] 里。过去裸委托 decodeChatGPTWebResponse（按 ChatGPT patch 协议解 SSE）→ 解不出
// 千问的信封结构，把内部 agent 路由控制面 JSON（agent_info/judge_type/scene/intent…）当正文 dump 出来，
// 真答案没干净抽出，图片还抓到搜索缩略图/视频卡噪音。这里先用千问专属重组器按其真实信封结构抽干净答案
// + 会话键，抽到才返回；抽不到（如偶发别的格式）再回退共享解码器，套豆包/kimi"自己先跑、回退共享"的隔离模板。
func decodeQwenWebResponse(body []byte, contentType string) (ExtractedContent, bool) {
	if c, ok := reassembleQwenWebStream(body, contentType); ok {
		return c, true
	}
	return decodeChatGPTWebResponse(body, contentType)
}

// reassembleQwenWebStream 解析千问网页版响应的 SSE 信封，抽出干净答案 + 会话键。
// 实测结构（对真实 chat2.qianwen.com /api/v2/chat SSE 抓样核对）：
//   - content-type text/event-stream，每行 data:{...} 是一个顶层信封：
//     {"error_msg":"","data":{...},"error_code":0,"communication":{"sessionid":"…","resid":N,"reqid":"…"}}
//   - 会话分组键 = 顶层 communication.sessionid（首个非空胜），作 ConversationID。
//   - 答案与噪音都在 data.messages[]，每个 message 有 mime_type：
//   - mime_type=="multi_load/iframe" —— 【真答案载体】，答案在 message 顶层 content（字符串，markdown）。
//     ⚠️是累积快照：每帧 content 是"到目前为止的完整答案"，单调增长，最后一帧 status=complete 是完整答案。
//     故取所有 multi_load/iframe 帧里 content 最长的那个（=完整答案），绝不拼接各帧（会重复 N 倍）。
//     只取 message 顶层 content，不碰 meta_data.multi_load[]（那是视频卡/widget 数据，含 css/js URL，是噪音）。
//     ⚠️已知范围限制（有意为之，非 bug）：此"取最长"假设单答案气泡流。多气泡场景（同一响应里先答 A、
//     再答 B 两条独立 multi_load/iframe 累积流）未观测到、暂不处理——取最长只会保留更长的那一条，另一条丢失。
//     若日后真出现多气泡，需改为按气泡 id 分组各取最长再按序拼接，届时再扩。
//   - mime_type=="signal/post" —— agent 控制面信号（meta_data.intent_content/intent_data 里一大坨
//     agent_info/judge_type/scene/search_intent…），是污染正文的元凶，跳过。
//   - mime_type=="bar/progress"(进度) / "bar/iframe"(sources) / "paa/iframe"("猜你想问"追问推荐) —— UI 噪音，跳过。
//   - 答案文本里两类前端技术记号用正则全部剔除再 TrimSpace：[(...)] widget 占位符（实样末尾
//     [(video_note_list_1)]）+ [[source_group_web_N]] 搜索引用锚点（带搜索引用的答案才出现，
//     生产库实证全库只有这一种 [[...]]）。
//
// 故响应 reassembler 只产出:干净答案正文 + ConversationID(sessionid),不产出任何附件——搜索缩略图/
// 视频卡图片是 UI 噪音、不是模型产出（共享解码器过去会 walk 出这些图误标成"模型返图"，专属 reassembler 根本不抽图）。
// 门控用共享 isEventStream(查 content-type 含 text/event-stream，并兜底 body 以 data: 开头)，与 doubao 一致：
// 千问真实响应偶尔 content-type 缺失/不规范时，裸 Contains 会漏跑 reassembler、退回共享解码器（噪音又回来），
// body 嗅探兜底更稳。注意：chatgpt 的 SSE 也会过这道 content-type 门，但真正挡 chatgpt 的是 sawQwenEnvelope
// （需 communication 或 multi_load/iframe，chatgpt 没有）→ 仍被认领门拒掉、回退共享，隔离不被削弱。
func reassembleQwenWebStream(body []byte, contentType string) (ExtractedContent, bool) {
	if !isEventStream(contentType, body) {
		return ExtractedContent{}, false
	}
	events := parseSSEDataEvents(body)
	var sessionID string
	var bestAnswer string
	sawQwenEnvelope := false
	for _, ev := range events {
		m, ok := ev.decoded.(map[string]interface{})
		if !ok {
			continue
		}
		// 会话分组键:顶层 communication.sessionid,首个非空胜。
		if sessionID == "" {
			sessionID = liftQwenSessionID(m)
		}
		// 结构标志:见到顶层 communication 即认作千问信封结构(下面见到 multi_load/iframe 也置位)。
		if _, ok := m["communication"].(map[string]interface{}); ok {
			sawQwenEnvelope = true
		}
		data, ok := m["data"].(map[string]interface{})
		if !ok {
			continue
		}
		messages, ok := data["messages"].([]interface{})
		if !ok {
			continue
		}
		for _, msg := range messages {
			mm, ok := msg.(map[string]interface{})
			if !ok {
				continue
			}
			mimeType, _ := mm["mime_type"].(string)
			// 只认 multi_load/iframe 的 content;signal/post(agent控制面)、bar/*、paa/iframe 全是噪音,跳过。
			if mimeType != "multi_load/iframe" {
				continue
			}
			sawQwenEnvelope = true
			content, _ := mm["content"].(string)
			// 累积快照:取最长的那帧 content(=完整答案),绝不拼接。
			if len(content) > len(bestAnswer) {
				bestAnswer = content
			}
		}
	}
	answer := strings.TrimSpace(stripQwenPlaceholders(bestAnswer))
	// 认领门:不是千问结构 / 没抽到答案 → 回退共享解码器,保持隔离。
	if !sawQwenEnvelope || answer == "" {
		return ExtractedContent{}, false
	}
	// 不改 buildReassembledExtracted 签名:接出结果后再补 ConversationID(套豆包/kimi 模板)。
	// 第三参 attachments 传 nil:搜索缩略图/视频卡图是 UI 噪音、不是模型产出,响应侧不登记任何附件。
	c := buildReassembledExtracted(answer, "", nil)
	c.ConversationID = sessionID
	return c, true
}

// liftQwenSessionID 从顶层 communication.sessionid 取会话分组键,TrimSpace;取不到返回 ""。
func liftQwenSessionID(m map[string]interface{}) string {
	comm, ok := m["communication"].(map[string]interface{})
	if !ok {
		return ""
	}
	if sid, ok := comm["sessionid"].(string); ok {
		return strings.TrimSpace(sid)
	}
	return ""
}

// stripQwenPlaceholders 剔除答案文本里两类前端渲染技术记号、非模型正文:
//   - [(...)] widget 占位符(如 [(video_note_list_1)]/[(multimodal_chat_think_1)],抓样实证);
//   - [[source_group_web_N]] 搜索引用锚点(带搜索引用的答案才出现,生产库实证全库只有这一种 [[...]])。
//
// 标记紧贴正文/标点(如 "特大城市[[source_group_web_1]]。"→"特大城市。"),直接 ReplaceAll 即可,
// 不额外折叠空格以免误伤正常文本。
func stripQwenPlaceholders(s string) string {
	s = qwenPlaceholderPattern.ReplaceAllString(s, "")
	s = qwenCitationMarkerPattern.ReplaceAllString(s, "")
	return s
}
