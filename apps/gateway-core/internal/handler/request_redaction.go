package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

type requestRedactionKey struct{}
type requestRedaction struct {
	mu                  sync.Mutex
	tenantID, requestID string
	values              map[string]string
	gapSink             func(context.Context, *modelrouter.RequestEnvelope)
	gapReported         bool
}

var requestRedactionPlaceholder = regexp.MustCompile(`^<JJD_[\p{L}\p{N}_]{1,40}_[0-9a-f]{32}_[0-9]+>$`)

func withRequestRedaction(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Value(requestRedactionKey{}).(*requestRedaction); ok {
		return ctx
	}
	return context.WithValue(ctx, requestRedactionKey{}, &requestRedaction{values: map[string]string{}})
}

// Only the input result that actually rewrote this request can register a value.
// No global cache, logging, auditing, or persistence of this map is permitted.
func addRequestRedaction(ctx context.Context, envelope *modelrouter.RequestEnvelope, masked string, values map[string]string) {
	if ctx == nil || envelope == nil || len(values) == 0 {
		return
	}
	state, _ := ctx.Value(requestRedactionKey{}).(*requestRedaction)
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.requestID != "" && (state.requestID != envelope.RequestID || state.tenantID != envelope.TenantID) {
		return
	}
	state.requestID, state.tenantID = envelope.RequestID, envelope.TenantID
	for token, value := range values {
		if requestRedactionPlaceholder.MatchString(token) && strings.Contains(masked, token) && value != "" {
			if previous, ok := state.values[token]; !ok || previous == value {
				state.values[token] = value
			}
		}
	}
}
func requestRedactionValues(ctx context.Context, envelope *modelrouter.RequestEnvelope) map[string]string {
	if ctx == nil || envelope == nil {
		return nil
	}
	state, _ := ctx.Value(requestRedactionKey{}).(*requestRedaction)
	if state == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.requestID != envelope.RequestID || state.tenantID != envelope.TenantID {
		return nil
	}
	result := make(map[string]string, len(state.values))
	for k, v := range state.values {
		result[k] = v
	}
	return result
}
func hasRequestRedaction(ctx context.Context, envelope *modelrouter.RequestEnvelope) bool {
	return len(requestRedactionValues(ctx, envelope)) > 0
}

func replaceRedactionText(value string, mapping map[string]string) string {
	return newRedactionRestorer(mapping).Replace(value)
}

type redactionTextSlot struct {
	parent    map[string]any
	key, path string
}

func redactionTextSlots(value any, path string) []redactionTextSlot {
	result := []redactionTextSlot{}
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			childPath := path + "." + key
			if _, ok := child.(string); ok {
				switch key {
				case "content", "text", "reasoning_content", "thinking", "delta", "arguments", "partial_json", "revised_prompt":
					result = append(result, redactionTextSlot{node, key, childPath})
				}
			} else {
				result = append(result, redactionTextSlots(child, childPath)...)
			}
		}
	case []any:
		for index, child := range node {
			identity := any(index)
			if item, ok := child.(map[string]any); ok && item["index"] != nil {
				identity = item["index"]
			}
			result = append(result, redactionTextSlots(child, fmt.Sprintf("%s[%v]", path, identity))...)
		}
	}
	return result
}
func restoreRedactionSlot(slot redactionTextSlot, mapping *redactionRestorer) {
	value, _ := slot.parent[slot.key].(string)
	if slot.key == "arguments" || slot.key == "partial_json" {
		var structured any
		decoder := json.NewDecoder(strings.NewReader(value))
		decoder.UseNumber()
		if decoder.Decode(&structured) == nil {
			// Tool arguments are JSON strings themselves; preserve quoting and types.
			restoreArgumentValues(structured, mapping)
			if raw, err := json.Marshal(structured); err == nil {
				slot.parent[slot.key] = string(raw)
				return
			}
		}
	}
	slot.parent[slot.key] = mapping.Replace(value)
}
func restoreArgumentValues(value any, mapping *redactionRestorer) {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if text, ok := child.(string); ok {
				node[key] = mapping.Replace(text)
			} else {
				restoreArgumentValues(child, mapping)
			}
		}
	case []any:
		for index, child := range node {
			if text, ok := child.(string); ok {
				node[index] = mapping.Replace(text)
			} else {
				restoreArgumentValues(child, mapping)
			}
		}
	}
}
func decodeRedactionJSON(raw []byte) (any, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	err := decoder.Decode(&value)
	return value, err
}

// Delivery-only: call after security inspection, retention and usage accounting.
// Buffered SSE groups text by its event/index/field so split placeholders cannot
// escape restoration or consume text from another completion choice/block.
func restoreRedactionBody(ctx context.Context, envelope *modelrouter.RequestEnvelope, body []byte) []byte {
	values := requestRedactionValues(ctx, envelope)
	if len(values) == 0 {
		return body
	}
	mapping := newRedactionRestorer(values)
	defer func() { noteRedactionRestoreGap(ctx, envelope, mapping) }()
	if value, err := decodeRedactionJSON(body); err == nil {
		for _, slot := range redactionTextSlots(value, "") {
			restoreRedactionSlot(slot, mapping)
		}
		if raw, err := json.Marshal(value); err == nil {
			return raw
		}
		return body
	}
	lines := strings.Split(string(body), "\n")
	nodes := map[int]any{}
	groups := map[string][]redactionTextSlot{}
	for index, line := range lines {
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if raw == "[DONE]" {
			continue
		}
		value, err := decodeRedactionJSON([]byte(raw))
		if err != nil {
			continue
		}
		nodes[index] = value
		root, _ := value.(map[string]any)
		kind, _ := root["type"].(string)
		if kind == "" {
			kind, _ = root["object"].(string)
		}
		delta := strings.Contains(kind, "delta") || strings.HasSuffix(kind, ".chunk")
		for _, slot := range redactionTextSlots(value, "") {
			if delta {
				group := fmt.Sprintf("%s/%v/%v/%v/%v/%s", kind, root["index"], root["output_index"], root["content_index"], root["item_id"], slot.path)
				groups[group] = append(groups[group], slot)
			} else {
				restoreRedactionSlot(slot, mapping)
			}
		}
	}
	for _, slots := range groups {
		var combined strings.Builder
		for _, slot := range slots {
			text, _ := slot.parent[slot.key].(string)
			combined.WriteString(text)
		}
		original := combined.String()
		restored := mapping.Replace(original)
		if slots[0].key == "arguments" || slots[0].key == "partial_json" {
			temp := map[string]any{"arguments": original}
			restoreRedactionSlot(redactionTextSlot{parent: temp, key: "arguments"}, mapping)
			restored, _ = temp["arguments"].(string)
		}
		if restored == original {
			continue
		}
		// Keep event framing/order and distribute complete Unicode characters.
		pending := []rune(restored)
		for index, slot := range slots {
			text, _ := slot.parent[slot.key].(string)
			count := len([]rune(text))
			if index == len(slots)-1 || count > len(pending) {
				count = len(pending)
			}
			slot.parent[slot.key] = string(pending[:count])
			pending = pending[count:]
		}
	}
	for index, value := range nodes {
		if raw, err := json.Marshal(value); err == nil {
			lines[index] = "data: " + string(raw)
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// setRedactionGapSink 登记"无法还原"告警的写出方（由持有审计写入器的处理器在请求入口登记）。
func setRedactionGapSink(ctx context.Context, sink func(context.Context, *modelrouter.RequestEnvelope)) {
	if state, _ := ctx.Value(requestRedactionKey{}).(*requestRedaction); state != nil {
		state.mu.Lock()
		state.gapSink = sink
		state.mu.Unlock()
	}
}

// noteRedactionRestoreGap 还原后仍残留本请求占位符时，每个请求只告警一次。
func noteRedactionRestoreGap(ctx context.Context, envelope *modelrouter.RequestEnvelope, restorer *redactionRestorer) {
	if restorer == nil || !restorer.gap || ctx == nil || envelope == nil {
		return
	}
	state, _ := ctx.Value(requestRedactionKey{}).(*requestRedaction)
	if state == nil {
		return
	}
	state.mu.Lock()
	sink := state.gapSink
	already := state.gapReported
	if sink != nil && !already {
		state.gapReported = true
	}
	state.mu.Unlock()
	if sink != nil && !already {
		sink(ctx, envelope)
	}
}
