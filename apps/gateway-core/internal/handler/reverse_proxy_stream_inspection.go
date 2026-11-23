package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// Retention is a bounded head/tail preview. Inspection has its own protocol
// projection, consuming every SSE event, including those outside that preview.
const maxInspectionSSEEvent = 8 * 1024 * 1024
const maxInspectionOutputText = 8 * 1024 * 1024

type streamInspectionCapture struct {
	path       string
	line, data []byte
	event      string
	text       strings.Builder
	visible    strings.Builder
	auxiliary  reverseAuxiliaryOutput
	reason     string
	done       bool
}

// Text is append-only so raw frames can be released by projection byte offset.
func (c *streamInspectionCapture) Text() string { return c.text.String() }
func (c *streamInspectionCapture) InspectionText() string {
	extras, reason := c.auxiliary.inspectionText()
	if c.reason == "" && reason != "" {
		c.reason = reason
	}
	if extras == "" {
		return c.Text()
	}
	text, _ := joinReverseInspectionOutput(c.visible.String(), extras)
	return text
}
func (c *streamInspectionCapture) HoldUntilComplete() bool { return c.auxiliary.hold }

func (c *streamInspectionCapture) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 && c.reason == "" {
		index := bytes.IndexByte(p, '\n')
		size := len(p)
		if index >= 0 {
			size = index + 1
		}
		if len(c.line)+size > maxInspectionSSEEvent {
			c.reason = "output_event_limit_exceeded"
			break
		}
		c.line = append(c.line, p[:size]...)
		p = p[size:]
		if index >= 0 {
			c.consumeLine()
			c.line = c.line[:0]
		}
	}
	return n, nil // Inspection resource failures must never corrupt the relay.
}
func (c *streamInspectionCapture) consumeLine() {
	line := strings.TrimRight(string(c.line), "\r\n")
	if line == "" {
		c.consumeEvent()
		return
	}
	if strings.HasPrefix(line, "event:") {
		c.event = strings.TrimSpace(line[6:])
	}
	if strings.HasPrefix(line, "data:") {
		value := strings.TrimPrefix(line[5:], " ")
		if len(c.data)+len(value)+1 > maxInspectionSSEEvent {
			c.reason = "output_event_limit_exceeded"
			return
		}
		if len(c.data) > 0 {
			c.data = append(c.data, '\n')
		}
		c.data = append(c.data, value...)
	}
}
func (c *streamInspectionCapture) appendText(value string) {
	if c.text.Len()+len(value) > maxInspectionOutputText {
		c.reason = "output_text_limit_exceeded"
		return
	}
	c.text.WriteString(value)
}

func (c *streamInspectionCapture) appendVisibleText(value string) {
	c.appendText(value)
	if c.reason == "" {
		c.visible.WriteString(value)
	}
}
func (c *streamInspectionCapture) consumeEvent() {
	defer func() { c.data = c.data[:0]; c.event = "" }()
	if len(c.data) == 0 {
		return
	}
	if strings.TrimSpace(string(c.data)) == "[DONE]" {
		c.done = true
		return
	}
	var event map[string]json.RawMessage
	if json.Unmarshal(c.data, &event) != nil {
		c.reason = "output_stream_invalid_json"
		return
	}
	var kind string
	_ = json.Unmarshal(event["type"], &kind)
	if kind != "" && c.event != "" && kind != c.event {
		c.reason = "output_stream_invalid_json"
		return
	}
	if kind == "" {
		kind = c.event
	}
	if extra := c.auxiliary.event(c.path, kind, c.data); extra != "" {
		c.appendText("\n" + extra)
	}
	switch {
	case strings.Contains(c.path, "/responses"):
		switch kind {
		case "response.output_text.delta":
			var delta string
			_ = json.Unmarshal(event["delta"], &delta)
			c.appendVisibleText(delta)
		case "response.output_text.done":
			var text string
			_ = json.Unmarshal(event["text"], &text)
			// Keep streamed bytes even when the terminal text differs. Replacing them
			// with a benign final object could hide a secret already sent to the user.
			if text != "" && !strings.Contains(c.visible.String(), text) {
				c.appendVisibleText("\n" + text)
			}
		case "response.completed":
			if c.visible.Len() == 0 {
				if text, ok := extractResponsesJSONOutput(event["response"]); ok {
					c.appendVisibleText(text)
				}
			}
			c.done = true
		case "response.failed", "response.incomplete", "error":
			c.reason = "output_stream_incomplete"
		}
	case strings.Contains(c.path, "/messages"):
		if kind == "message_stop" {
			c.done = true
		}
		if kind == "error" {
			c.reason = "output_stream_incomplete"
		}
		if kind == "content_block_delta" {
			var d struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}
			_ = json.Unmarshal(event["delta"], &d)
			if d.Type == "text_delta" {
				c.appendVisibleText(d.Text)
			}
		}
		if kind == "content_block_start" {
			var b struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}
			_ = json.Unmarshal(event["content_block"], &b)
			if b.Type == "text" {
				c.appendVisibleText(b.Text)
			}
		}
	default:
		if _, failed := event["error"]; failed {
			c.reason = "output_stream_incomplete"
		}
		var choices []struct {
			Delta struct {
				Content json.RawMessage `json:"content"`
			} `json:"delta"`
			Finish json.RawMessage `json:"finish_reason"`
		}
		_ = json.Unmarshal(event["choices"], &choices)
		for _, choice := range choices {
			c.appendVisibleText(llmDeltaTextContent(choice.Delta.Content))
			if len(choice.Finish) > 0 && string(choice.Finish) != "null" {
				c.done = true
			}
		}
	}
}
func (c *streamInspectionCapture) Finish(copyFailed bool) (string, string) {
	if c.reason == "" && len(c.line) > 0 {
		c.consumeLine()
		c.line = nil
	}
	if c.reason == "" && len(c.data) > 0 {
		c.consumeEvent()
	}
	if copyFailed {
		c.reason = "output_stream_incomplete"
	}
	if c.reason == "" && !c.done {
		c.reason = "output_stream_incomplete"
	}
	text := c.InspectionText()
	return text, c.reason
}

// Windows cover the complete output. Rune offsets refer to the full visible
// output projection; overlap protects credentials across adjacent boundaries.
func (h *ReverseProxyHandler) checkStreamInspection(ctx context.Context, requestID, text, reason, host, path string) (reverseProxySecurityDecision, error) {
	out := reverseProxySecurityDecision{Allowed: true, Action: "allow", Stage: "output", ContentSource: "verified_final_output", VerifiedContent: text}
	if h.runtimeConfigClient != nil && !h.runtimeConfigClient.InspectionPolicy(ctx).InspectModelOutput {
		return out, nil
	}
	runes := []rune(text)
	const size = 32768
	const overlap = 1024
	for start := 0; start < len(runes); start += size - overlap {
		end := start + size
		if end > len(runes) {
			end = len(runes)
		}
		part := string(runes[start:end])
		d, err := h.checkSecurityWithExtras(ctx, requestID, "/check-output/", []byte(part), part, "text/plain", host, path, "model_output", map[string]interface{}{"verified_content": true, "verified_stage": "output", "extraction": "verified_final_output", "output_window_start": start, "output_window_end": end})
		if clientGoneDuring(ctx, err) {
			// 客户端已断开：立即返回哨兵，不要标 incomplete 也不再扫后面的窗口。
			// out 只含此前已扫窗口的真实命中，不含本窗口。
			return out, err
		}
		for i := range d.Findings {
			d.Findings[i] = offsetStreamFinding(d.Findings[i], start)
		}
		mergeReverseStreamDecision(&out, d)
		if err != nil {
			out.SemanticStatus = "incomplete"
		}
		if end == len(runes) {
			break
		}
	}
	if reason != "" {
		mergeReverseStreamDecision(&out, h.reverseInspectionFailure(ctx, nil, reason))
	}
	return h.applyReverseInspectionPolicy(ctx, out), nil
}

func mergeReverseStreamDecision(out *reverseProxySecurityDecision, d reverseProxySecurityDecision) {
	out.RetryTaskIDs = append(out.RetryTaskIDs, d.RetryTaskIDs...)
	out.RetryUnavailable = out.RetryUnavailable || d.RetryUnavailable
	if d.SemanticStatus == "incomplete" {
		out.SemanticStatus, out.SemanticReason = d.SemanticStatus, d.SemanticReason
	}
	out.Findings = append(out.Findings, d.Findings...)
	if out.RawAction == "" || securityexit.Blocks(d.RawAction) {
		out.RawAction = d.RawAction
	}
	if !d.Allowed || securityexit.Blocks(d.Action) {
		out.Action, out.Allowed, out.DetectionFailed = d.Action, d.Allowed, d.DetectionFailed
	} else if !securityexit.Blocks(out.Action) && d.Action != "" && d.Action != "allow" {
		out.Action = d.Action
		out.DetectionFailed = d.DetectionFailed
	}
	out.MaskUnavailable = out.MaskUnavailable || d.MaskUnavailable
}

// offsetStreamFinding 把分段检测的段内位置改写成整段输出的偏移；段内原始位置留在 EvidenceLocation，
// 截原文和前后文时用它（引擎给的前后文是段内的）。
func offsetStreamFinding(f SecurityFinding, offset int) SecurityFinding {
	var start, end int
	if n, err := fmt.Sscanf(f.MatchedLocation, "content[%d:%d]", &start, &end); err == nil && n == 2 {
		if f.EvidenceLocation == "" {
			f.EvidenceLocation = f.MatchedLocation
		}
		f.MatchedLocation = fmt.Sprintf("content[%d:%d]", offset+start, offset+end)
	}
	return f
}
