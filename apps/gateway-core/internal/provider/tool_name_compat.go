package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	kiroToolNameMaxBytes  = 64
	toolNameHashHexLength = 13
)

// compatibleToolNameMap keeps the client-visible tool identity separate from
// the stricter wire name accepted by Kiro-compatible Anthropic relays.
type compatibleToolNameMap struct {
	forward map[string]string
	reverse map[string]string
	used    map[string]string
}

func newCompatibleToolNameMap(names []string) *compatibleToolNameMap {
	m := &compatibleToolNameMap{
		forward: make(map[string]string, len(names)),
		reverse: make(map[string]string, len(names)),
		used:    make(map[string]string, len(names)),
	}

	// Reserve valid client names first. An earlier invalid name must never take
	// a later valid name after punctuation normalization.
	for _, name := range names {
		if name != "" && isKiroCompatibleToolName(name) {
			m.forward[name] = name
			m.used[name] = name
		}
	}
	for _, name := range names {
		m.compatible(name)
	}
	return m
}

func (m *compatibleToolNameMap) compatible(original string) string {
	if original == "" || m == nil {
		return original
	}
	if mapped, ok := m.forward[original]; ok {
		return mapped
	}
	if isKiroCompatibleToolName(original) {
		m.forward[original] = original
		m.used[original] = original
		return original
	}

	candidate := normalizeKiroToolName(original)
	if len(candidate) > kiroToolNameMaxBytes {
		candidate = hashedCompatibleToolName(candidate, original, 0)
	}
	if owner, exists := m.used[candidate]; exists && owner != original {
		for collision := 0; ; collision++ {
			candidate = hashedCompatibleToolName(normalizeKiroToolName(original), original, collision)
			if owner, exists = m.used[candidate]; !exists || owner == original {
				break
			}
		}
	}

	m.forward[original] = candidate
	m.reverse[candidate] = original
	m.used[candidate] = original
	return candidate
}

func (m *compatibleToolNameMap) original(wireName string) string {
	if m == nil {
		return wireName
	}
	if original, ok := m.reverse[wireName]; ok {
		return original
	}
	return wireName
}

func isKiroCompatibleToolName(name string) bool {
	if len(name) == 0 || len(name) > kiroToolNameMaxBytes || !isASCIIAlpha(name[0]) {
		return false
	}
	for index := 1; index < len(name); index++ {
		if !isASCIIAlpha(name[index]) && !isASCIIDigit(name[index]) && name[index] != '_' {
			return false
		}
	}
	return true
}

func normalizeKiroToolName(original string) string {
	var normalized strings.Builder
	lastUnderscore := false
	for _, character := range original {
		valid := character <= 127 && (isASCIIAlpha(byte(character)) || isASCIIDigit(byte(character)) || character == '_')
		if valid {
			normalized.WriteRune(character)
			lastUnderscore = character == '_'
			continue
		}
		if !lastUnderscore {
			normalized.WriteByte('_')
			lastUnderscore = true
		}
	}
	candidate := strings.Trim(normalized.String(), "_")
	if candidate == "" {
		candidate = "tool"
	}
	if !isASCIIAlpha(candidate[0]) {
		candidate = "tool_" + candidate
	}
	return candidate
}

func hashedCompatibleToolName(base, original string, collision int) string {
	seed := original
	if collision > 0 {
		seed += "#" + strconv.Itoa(collision)
	}
	digest := sha256.Sum256([]byte(seed))
	suffix := hex.EncodeToString(digest[:])[:toolNameHashHexLength]
	prefixBytes := kiroToolNameMaxBytes - 1 - len(suffix)
	if len(base) > prefixBytes {
		base = base[:prefixBytes]
	}
	base = strings.TrimRight(base, "_")
	if base == "" || !isASCIIAlpha(base[0]) {
		base = "tool"
	}
	return base + "_" + suffix
}

func isASCIIAlpha(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func isASCIIDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

// normalizeChatToolNames rewrites only tool identity fields. Compatible
// requests retain their original bytes so proxy transparency does not regress.
func normalizeChatToolNames(rawBody []byte) ([]byte, *compatibleToolNameMap, error) {
	var body map[string]any
	decoder := json.NewDecoder(bytes.NewReader(rawBody))
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		return nil, nil, fmt.Errorf("decode Chat request for tool compatibility: %w", err)
	}

	names := collectChatToolNames(body)
	nameMap := newCompatibleToolNameMap(names)
	changed := rewriteChatToolNames(body, nameMap)
	if !changed {
		return rawBody, nameMap, nil
	}
	rewritten, err := json.Marshal(body)
	if err != nil {
		return nil, nil, fmt.Errorf("encode Chat request after tool compatibility: %w", err)
	}
	return rewritten, nameMap, nil
}

func collectChatToolNames(body map[string]any) []string {
	names := make([]string, 0)
	collectName := func(raw any) {
		if name, ok := raw.(string); ok && name != "" {
			names = append(names, name)
		}
	}
	for _, rawTool := range anySlice(body["tools"]) {
		tool, _ := rawTool.(map[string]any)
		collectName(openAIToolDefinition(tool)["name"])
	}
	for _, rawFunction := range anySlice(body["functions"]) {
		function, _ := rawFunction.(map[string]any)
		collectName(function["name"])
	}
	for _, rawMessage := range anySlice(body["messages"]) {
		message, _ := rawMessage.(map[string]any)
		for _, rawCall := range anySlice(message["tool_calls"]) {
			call, _ := rawCall.(map[string]any)
			_, name, _, ok := openAIToolCall(call)
			if ok {
				collectName(name)
			}
		}
		if functionCall, ok := message["function_call"].(map[string]any); ok {
			collectName(functionCall["name"])
		}
	}
	if choice, ok := body["tool_choice"].(map[string]any); ok {
		if function, ok := choice["function"].(map[string]any); ok {
			collectName(function["name"])
		}
	}
	if functionCall, ok := body["function_call"].(map[string]any); ok {
		collectName(functionCall["name"])
	}
	return names
}

func rewriteChatToolNames(body map[string]any, nameMap *compatibleToolNameMap) bool {
	changed := false
	rewrite := func(container map[string]any) {
		if container == nil {
			return
		}
		original, _ := container["name"].(string)
		if original == "" {
			return
		}
		compatible := nameMap.compatible(original)
		if compatible != original {
			container["name"] = compatible
			changed = true
		}
	}
	for _, rawTool := range anySlice(body["tools"]) {
		tool, _ := rawTool.(map[string]any)
		rewrite(openAIToolDefinition(tool))
	}
	for _, rawFunction := range anySlice(body["functions"]) {
		function, _ := rawFunction.(map[string]any)
		rewrite(function)
	}
	for _, rawMessage := range anySlice(body["messages"]) {
		message, _ := rawMessage.(map[string]any)
		for _, rawCall := range anySlice(message["tool_calls"]) {
			call, _ := rawCall.(map[string]any)
			rewrite(openAIToolCallNameCarrier(call))
		}
		if functionCall, ok := message["function_call"].(map[string]any); ok {
			rewrite(functionCall)
		}
	}
	if choice, ok := body["tool_choice"].(map[string]any); ok {
		if function, ok := choice["function"].(map[string]any); ok {
			rewrite(function)
		}
	}
	if functionCall, ok := body["function_call"].(map[string]any); ok {
		rewrite(functionCall)
	}
	return changed
}

func openAIToolCallNameCarrier(call map[string]any) map[string]any {
	if function, ok := call["function"].(map[string]any); ok {
		return function
	}
	if custom, ok := call["custom"].(map[string]any); ok {
		return custom
	}
	return call
}

func restoreChatToolNames(rawBody []byte, nameMap *compatibleToolNameMap) ([]byte, error) {
	if nameMap == nil || len(nameMap.reverse) == 0 {
		return rawBody, nil
	}
	var body map[string]any
	decoder := json.NewDecoder(bytes.NewReader(rawBody))
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		return nil, err
	}
	changed := false
	for _, rawChoice := range anySlice(body["choices"]) {
		choice, _ := rawChoice.(map[string]any)
		message, _ := choice["message"].(map[string]any)
		for _, rawCall := range anySlice(message["tool_calls"]) {
			call, _ := rawCall.(map[string]any)
			function, _ := call["function"].(map[string]any)
			wireName, _ := function["name"].(string)
			original := nameMap.original(wireName)
			if original != wireName {
				function["name"] = original
				changed = true
			}
		}
		if functionCall, ok := message["function_call"].(map[string]any); ok {
			wireName, _ := functionCall["name"].(string)
			original := nameMap.original(wireName)
			if original != wireName {
				functionCall["name"] = original
				changed = true
			}
		}
	}
	if !changed {
		return rawBody, nil
	}
	return json.Marshal(body)
}

func anySlice(value any) []any {
	items, _ := value.([]any)
	return items
}
