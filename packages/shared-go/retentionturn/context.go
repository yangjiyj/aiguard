// Package retentionturn retains compact correlation evidence, never prompt bodies.
package retentionturn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

type Request struct {
	Tools       []ToolObservation `json:"tools,omitempty"`
	HistoryKey  string            `json:"history_key"`
	IdentityKey string            `json:"identity_key"`
	UserCount   int               `json:"user_count"`
	Links       []string          `json:"links"`
	Partial     bool              `json:"partial"`
}
type Response struct {
	Tools []ToolObservation `json:"tools,omitempty"`
	Links []string          `json:"links"`
}
type Context struct {
	Version  int       `json:"version"`
	Request  *Request  `json:"request,omitempty"`
	Response *Response `json:"response,omitempty"`
}

func Digest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
func TextLink(text string) string {
	text = aimsg.NormalizeRetainedAssistantText(text)
	if strings.TrimSpace(text) == "" {
		return ""
	}
	return Digest("assistant\x00" + strings.TrimSpace(text))
}
func BuildRequest(messages []aimsg.ConvMessage, raw []byte, identity string) *Request {
	out := &Request{IdentityKey: Digest(identity), Links: toolLinks(raw), Tools: toolObservations(raw, true)}
	hasToolLinks := len(out.Links) > 0
	history := []string{}
	for _, m := range messages {
		switch m.Source {
		case aimsg.SourceUser:
			text, status, _ := aimsg.NormalizeAgentEnvelope(m.Content)
			// Complete client context is not a missing human submission.
			if status != aimsg.ParseComplete && (!aimsg.IsRetainedUserTurnCandidate(m) || aimsg.IsWorkBuddyUserContextEnvelope(m.Content) || aimsg.IsRetainedUserTransportOnly(m.Content)) {
				continue
			}
			if status != aimsg.ParseComplete {
				out.Partial = true
				continue
			}
			text = aimsg.NormalizeRetainedUserText(text)
			if text == "" {
				continue
			}
			if strings.Contains(text, "...[truncated]") {
				out.Partial = true
			}
			history = append(history, text)
		case aimsg.SourceAssistantHistory:
			if link := TextLink(m.Content); link != "" {
				out.Links = append(out.Links, link)
			}
		}
	}
	out.UserCount = len(history)
	if out.UserCount == 0 {
		out.Links = unique(out.Links)
		// Incremental APIs may send only function_call_output. Carry links, never
		// manufacture a human question or a history key.
		if hasToolLinks {
			return out
		}
		return nil
	}
	framed, _ := json.Marshal(history)
	out.HistoryKey = Digest(string(framed))
	out.Links = unique(out.Links)
	return out
}
func BuildResponse(raw []byte, visibleText string) *Response {
	links := toolLinks(raw)
	if link := TextLink(visibleText); link != "" {
		links = append(links, link)
	}
	return &Response{Links: unique(links), Tools: toolObservations(raw, false)}
}
func unique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// Tool IDs are accepted only in known protocol positions, not arbitrary user JSON.
// JSON responses and SSE frames share the same constrained traversal.
func toolLinks(raw []byte) []string {
	links := []string{}
	add := func(id interface{}) {
		if s, ok := id.(string); ok && s != "" {
			links = append(links, Digest("tool-id\x00"+s))
		}
	}
	var visit func(interface{}, string, int)
	visit = func(value interface{}, key string, depth int) {
		if depth > 32 {
			return
		}
		switch v := value.(type) {
		case []interface{}:
			for _, item := range v {
				visit(item, key, depth+1)
			}
		case map[string]interface{}:
			typ, _ := v["type"].(string)
			if key == "tool_calls" {
				add(v["id"])
			}
			switch typ {
			case "tool_use":
				add(v["id"])
			case "tool_result":
				add(v["tool_use_id"])
			case "function_call", "function_call_output":
				add(v["call_id"])
			}
			if role, _ := v["role"].(string); role == "tool" {
				add(v["tool_call_id"])
			}
			for _, child := range []string{"messages", "input", "output", "content", "choices", "message", "delta", "tool_calls", "content_block", "item", "response"} {
				if val, ok := v[child]; ok {
					visit(val, child, depth+1)
				}
			}
		}
	}
	var decoded interface{}
	if json.Unmarshal(raw, &decoded) == nil {
		visit(decoded, "", 0)
	} else {
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "data:") {
				continue
			}
			data := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "data:"))
			if json.Unmarshal([]byte(data), &decoded) == nil {
				visit(decoded, "", 0)
			}
		}
	}
	return unique(links)
}

// Patches let streaming finalization add response evidence without replacing
// the already-written request history. Tenant and deployment scope are required.
const UpdateSQL = `UPDATE request_logs
SET retention_turn_context = COALESCE(retention_turn_context, '{}'::jsonb) || $4::jsonb
WHERE tenant_id=$1 AND request_id=$2 AND environment_scope=$3`

func Patch(request *Request, response *Response) []byte {
	raw, _ := json.Marshal(Context{Version: 1, Request: request, Response: response})
	return raw
}
