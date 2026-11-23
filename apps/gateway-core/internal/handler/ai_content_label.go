package handler

// AI 生成内容标识（显式标识 + 零宽水印）的交付层实现。
//
// 只在回复发给客户端的最后一步执行：先还原脱敏占位符，再给可见正文加标识。
// 内容日志、输出检测、计费都在这之前完成，所以留存正文不带标识，水印也不会被
// 自家的隐写检测当成攻击。只改可见正文：工具参数、推理内容、tool_use 输入一律不动。
//
// 经过这里的回复体有两种：完整 JSON（Chat、Messages、Responses、经 Chat 转换的 Gemini）
// 和先攒后发的完整 SSE（Messages、Responses 原生流式）。实时流不经过这里，需要加标识的
// 请求由各实时流入口改为先攒后发（needsAIContentLabel）。

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/aicontentlabel"
)

type aiContentLabelSettingsCache struct {
	mu    sync.Mutex
	value *aicontentlabel.Settings
}

// AIContentLabelSettings 返回后台轮询拿到的最近一次配置；首次加载前为出厂默认（全部关闭）。
func (c *ToolRiskClient) AIContentLabelSettings() aicontentlabel.Settings {
	if c == nil {
		return aicontentlabel.DefaultSettings()
	}
	c.aiContentLabelCache.mu.Lock()
	defer c.aiContentLabelCache.mu.Unlock()
	if c.aiContentLabelCache.value == nil {
		return aicontentlabel.DefaultSettings()
	}
	return *c.aiContentLabelCache.value
}

func (c *ToolRiskClient) setAIContentLabelSettings(settings aicontentlabel.Settings) {
	if c == nil {
		return
	}
	c.aiContentLabelCache.mu.Lock()
	defer c.aiContentLabelCache.mu.Unlock()
	c.aiContentLabelCache.value = &settings
}

// aiContentLabelPlan 是一次交付要加的标识；零值表示不加。
type aiContentLabelPlan struct {
	explicit  string
	watermark string
}

func (p aiContentLabelPlan) empty() bool { return p.explicit == "" && p.watermark == "" }

// planAIContentLabel 决定本请求加哪些标识。客户端类型不在生效范围时什么都不加；
// 请求号不是 UUID 或没有内部密钥时不加水印。
func planAIContentLabel(client *ToolRiskClient, envelope *modelrouter.RequestEnvelope) aiContentLabelPlan {
	if client == nil || envelope == nil {
		return aiContentLabelPlan{}
	}
	settings := client.AIContentLabelSettings()
	if !settings.AppliesTo(envelope.AgentType) {
		return aiContentLabelPlan{}
	}
	plan := aiContentLabelPlan{explicit: settings.ExplicitLine()}
	if settings.WatermarkEnabled {
		if frame, ok := aicontentlabel.Encode(envelope.RequestID, aicontentlabel.DeriveKey(client.internalAPISecret)); ok {
			plan.watermark = frame
		}
	}
	return plan
}

// needsAIContentLabel 供实时流门控使用：需要加标识的请求改为先攒后发。
func needsAIContentLabel(client *ToolRiskClient, envelope *modelrouter.RequestEnvelope) bool {
	return !planAIContentLabel(client, envelope).empty()
}

// deliverResponseBody 是回复发往客户端前的最后一步：先还原脱敏占位符，再加内容标识。
func deliverResponseBody(ctx context.Context, client *ToolRiskClient, envelope *modelrouter.RequestEnvelope, body []byte) []byte {
	body = restoreRedactionBody(ctx, envelope, body)
	plan := planAIContentLabel(client, envelope)
	if plan.empty() {
		return body
	}
	return applyAIContentLabel(body, plan)
}

// applyAIContentLabel 给 JSON 或 SSE 回复体加标识。无法识别或不满足条件时原样返回。
func applyAIContentLabel(body []byte, plan aiContentLabelPlan) []byte {
	if plan.empty() || len(body) == 0 {
		return body
	}
	if value, err := decodeRedactionJSON(body); err == nil {
		root, ok := value.(map[string]any)
		if !ok || !labelJSONDocument(root, plan) {
			return body
		}
		if raw, err := json.Marshal(root); err == nil {
			return raw
		}
		return body
	}
	return labelSSEBody(body, plan)
}

// labelText 给一段正文加标识：水印放在最后一个不在代码块里的段落末尾，显式标识另起一段放在最后。
// 只插入、不删除原有字符。
func labelText(text string, plan aiContentLabelPlan) string {
	if strings.TrimSpace(text) == "" {
		return text
	}
	if plan.watermark != "" {
		if end := lastProseEnd(text); end >= 0 {
			text = text[:end] + plan.watermark + text[end:]
		}
	}
	if plan.explicit != "" {
		trimmed := strings.TrimRight(text, " \t\r\n")
		text = trimmed + "\n\n" + plan.explicit + text[len(trimmed):]
	}
	return text
}

// lastProseEnd 返回最后一个不在代码块里的非空白行的行尾（字节位置）；整篇都是代码块时返回 -1。
func lastProseEnd(text string) int {
	inFence := false
	pos, best := 0, -1
	for _, line := range strings.SplitAfter(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~"):
			inFence = !inFence
		case !inFence && trimmed != "":
			best = pos + len(strings.TrimRight(line, " \t\r\n"))
		}
		pos += len(line)
	}
	return best
}

// ---- 完整 JSON 回复 ----

// labelJSONDocument 识别 Chat、Messages、Responses 三种完整回复，改写可见正文。返回是否改动。
func labelJSONDocument(root map[string]any, plan aiContentLabelPlan) bool {
	if choices, ok := root["choices"].([]any); ok {
		return labelChatChoices(choices, plan)
	}
	if root["type"] == "message" && root["role"] == "assistant" {
		if root["stop_reason"] != "end_turn" {
			return false
		}
		return labelTextField(lastTextPart(asSlice(root["content"]), "text"), plan)
	}
	if root["object"] == "response" {
		if root["status"] != "completed" {
			return false
		}
		part := lastResponsesOutputText(root["output"])
		if part == nil {
			return false
		}
		before, _ := part["text"].(string)
		labelTextField(part, plan)
		if root["output_text"] == before {
			root["output_text"] = part["text"]
		}
		return true
	}
	return false
}

func labelChatChoices(choices []any, plan aiContentLabelPlan) bool {
	changed := false
	for _, raw := range choices {
		choice, _ := raw.(map[string]any)
		if choice == nil || choice["finish_reason"] != "stop" {
			continue
		}
		message, _ := choice["message"].(map[string]any)
		if message == nil {
			continue
		}
		if content, ok := message["content"].(string); ok && strings.TrimSpace(content) != "" {
			message["content"] = labelText(content, plan)
			changed = true
		}
	}
	return changed
}

func labelTextField(part map[string]any, plan aiContentLabelPlan) bool {
	if part == nil {
		return false
	}
	text, _ := part["text"].(string)
	part["text"] = labelText(text, plan)
	return true
}

// lastTextPart 返回最后一个指定类型、带非空 text 的片段。
func lastTextPart(parts []any, kind string) map[string]any {
	for i := len(parts) - 1; i >= 0; i-- {
		part, _ := parts[i].(map[string]any)
		if part == nil || part["type"] != kind {
			continue
		}
		if text, ok := part["text"].(string); ok && strings.TrimSpace(text) != "" {
			return part
		}
	}
	return nil
}

// lastResponsesOutputText 返回最后一个 message 输出项里最后一个 output_text 片段。
func lastResponsesOutputText(output any) map[string]any {
	items := asSlice(output)
	for i := len(items) - 1; i >= 0; i-- {
		item, _ := items[i].(map[string]any)
		if item == nil || item["type"] != "message" {
			continue
		}
		if part := lastTextPart(asSlice(item["content"]), "output_text"); part != nil {
			return part
		}
	}
	return nil
}

func asSlice(value any) []any {
	items, _ := value.([]any)
	return items
}

// ---- 先攒后发的完整 SSE ----

type sseFrame struct {
	line  int
	value map[string]any
}

// textSlot 指向某一帧里的一段 delta 正文。
type textSlot struct {
	frame  int
	parent map[string]any
	key    string
}

// labelSSEBody 改写 Messages 或 Responses 的完整 SSE。目标正文的 delta 拼成整段后加标识，
// 再按原帧长回填、余量放最后一帧（与 restoreRedactionBody 同法），帧数和顺序不变。
func labelSSEBody(body []byte, plan aiContentLabelPlan) []byte {
	lines := strings.Split(string(body), "\n")
	var frames []sseFrame
	for i, line := range lines {
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if raw == "" || raw == "[DONE]" {
			continue
		}
		value, err := decodeRedactionJSON([]byte(raw))
		if err != nil {
			continue
		}
		if root, ok := value.(map[string]any); ok {
			frames = append(frames, sseFrame{line: i, value: root})
		}
	}
	var changed map[int]bool
	if hasFrameType(frames, "response.completed") {
		changed = labelResponsesSSE(frames, plan)
	} else if hasFrameType(frames, "message_delta") {
		changed = labelMessagesSSE(frames, plan)
	}
	if len(changed) == 0 {
		return body
	}
	for fi := range changed {
		if raw, err := json.Marshal(frames[fi].value); err == nil {
			lines[frames[fi].line] = "data: " + string(raw)
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

func hasFrameType(frames []sseFrame, kind string) bool {
	for _, f := range frames {
		if f.value["type"] == kind {
			return true
		}
	}
	return false
}

// rewriteSlots 把一组 delta 改成 labelText 后的全文，返回原全文、新全文和被改动的帧。
func rewriteSlots(slots []textSlot, plan aiContentLabelPlan) (string, string, map[int]bool) {
	var b strings.Builder
	for _, s := range slots {
		text, _ := s.parent[s.key].(string)
		b.WriteString(text)
	}
	full := b.String()
	labeled := labelText(full, plan)
	if labeled == full {
		return full, full, nil
	}
	changed := map[int]bool{}
	pending := []rune(labeled)
	for i, s := range slots {
		text, _ := s.parent[s.key].(string)
		count := len([]rune(text))
		if i == len(slots)-1 || count > len(pending) {
			count = len(pending)
		}
		if next := string(pending[:count]); next != text {
			s.parent[s.key] = next
			changed[s.frame] = true
		}
		pending = pending[count:]
	}
	return full, labeled, changed
}

// labelMessagesSSE 改写最后一个 text 块的 text_delta；要求 message_delta 的 stop_reason 是 end_turn。
func labelMessagesSSE(frames []sseFrame, plan aiContentLabelPlan) map[int]bool {
	stopped := false
	textBlocks := map[string]bool{}
	blocks := map[string][]textSlot{}
	lastBlock := ""
	for fi, f := range frames {
		switch f.value["type"] {
		case "content_block_start":
			if block, _ := f.value["content_block"].(map[string]any); block != nil && block["type"] == "text" {
				textBlocks[jsonKey(f.value["index"])] = true
			}
		case "content_block_delta":
			index := jsonKey(f.value["index"])
			delta, _ := f.value["delta"].(map[string]any)
			if delta == nil || delta["type"] != "text_delta" || !textBlocks[index] {
				continue
			}
			if _, ok := delta["text"].(string); ok {
				blocks[index] = append(blocks[index], textSlot{frame: fi, parent: delta, key: "text"})
				lastBlock = index
			}
		case "message_delta":
			if delta, _ := f.value["delta"].(map[string]any); delta != nil && delta["stop_reason"] == "end_turn" {
				stopped = true
			}
		}
	}
	if !stopped || lastBlock == "" {
		return nil
	}
	_, _, changed := rewriteSlots(blocks[lastBlock], plan)
	return changed
}

// labelResponsesSSE 改写最后一个 output_text 片段的 delta，并把同一片段的 output_text.done、
// content_part.done、output_item.done 与 response.completed 快照改成相同的全文。
func labelResponsesSSE(frames []sseFrame, plan aiContentLabelPlan) map[int]bool {
	completedOK := false
	for _, f := range frames {
		if f.value["type"] == "response.completed" {
			resp, _ := f.value["response"].(map[string]any)
			completedOK = resp != nil && resp["status"] == "completed"
		}
	}
	if !completedOK {
		return nil
	}
	type partKey struct{ item, content string }
	parts := map[partKey][]textSlot{}
	var last partKey
	found := false
	for fi, f := range frames {
		if f.value["type"] != "response.output_text.delta" {
			continue
		}
		if _, ok := f.value["delta"].(string); !ok {
			continue
		}
		key := partKey{jsonKey(f.value["item_id"]), jsonKey(f.value["content_index"])}
		parts[key] = append(parts[key], textSlot{frame: fi, parent: f.value, key: "delta"})
		last, found = key, true
	}
	if !found {
		return nil
	}
	full, labeled, changed := rewriteSlots(parts[last], plan)
	if len(changed) == 0 {
		return nil
	}
	samePart := func(v map[string]any) bool {
		return jsonKey(v["item_id"]) == last.item && jsonKey(v["content_index"]) == last.content
	}
	replaceIn := func(m map[string]any) bool {
		if m != nil && m["text"] == full {
			m["text"] = labeled
			return true
		}
		return false
	}
	itemMatches := func(item map[string]any) bool {
		return item != nil && jsonKey(item["id"]) == last.item
	}
	for fi, f := range frames {
		v := f.value
		touched := false
		switch v["type"] {
		case "response.output_text.done":
			touched = samePart(v) && replaceIn(v)
		case "response.content_part.done":
			part, _ := v["part"].(map[string]any)
			touched = samePart(v) && replaceIn(part)
		case "response.output_item.done":
			if item, _ := v["item"].(map[string]any); itemMatches(item) {
				touched = replaceOutputText(item, full, labeled)
			}
		case "response.completed":
			resp, _ := v["response"].(map[string]any)
			for _, raw := range asSlice(resp["output"]) {
				if item, _ := raw.(map[string]any); itemMatches(item) && replaceOutputText(item, full, labeled) {
					touched = true
				}
			}
			if resp != nil && resp["output_text"] == full {
				resp["output_text"] = labeled
				touched = true
			}
		}
		if touched {
			changed[fi] = true
		}
	}
	return changed
}

func replaceOutputText(item map[string]any, from, to string) bool {
	touched := false
	for _, raw := range asSlice(item["content"]) {
		if part, _ := raw.(map[string]any); part != nil && part["type"] == "output_text" && part["text"] == from {
			part["text"] = to
			touched = true
		}
	}
	return touched
}

func jsonKey(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
