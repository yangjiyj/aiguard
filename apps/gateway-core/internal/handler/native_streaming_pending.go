package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
	"sort"
	"strings"
	"time"
)

// Native transports use the same inspection/holdback state as Chat while their
// writers retain item/content/block identities from the original frame.
func newNativePendingEmitter(ctx context.Context, h *ChatCompletionsHandler, envelope *modelrouter.RequestEnvelope, mode relay.OutputSecurityMode, acc *liveStreamAccumulator, pending *livePendingOutput,
	legacy, write func(relay.StreamEvent) error, incomplete func(string) error, first func(relay.StreamEvent), accept func(relay.StreamEvent) bool) func(relay.StreamEvent) error {
	pending.preserveRaw = true
	check := func(content string, index int) (bool, error) {
		if h.securityClient == nil {
			return false, nil
		}
		started := time.Now()
		action, _, findings, err := h.checkStreamOutput(withOutputProjection(ctx), envelope, content, index)
		recordSecurityTiming(envelope, h.relayMetrics, "output_security_ms", time.Since(started))
		if err != nil {
			if h.relayMetrics != nil && !clientGoneDuring(ctx, err) {
				h.relayMetrics.Inc("security_check_failed")
			}
			return false, h.streamInspectionFailure(ctx, err, incomplete)
		}
		acc.rememberOutputFindings(index, findings)
		if securityexit.Decide(liveStreamExitMode(mode), action, securityexit.RuleHit).Enforce {
			return false, fmt.Errorf("%w: choice=%d", errLiveStreamOutputBlocked, index)
		}
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "mask":
			return true, nil
		}
		return false, nil
	}
	metadataCache := make(map[[32]byte]struct{})
	inspectMetadata := func(event relay.StreamEvent) error {
		if h.securityClient == nil || len(event.Raw) == 0 {
			return nil
		}
		content, err := nativeRetainedMetadataText(event)
		if err != nil {
			return incomplete("native_metadata_parse_failed")
		}
		if content == "" {
			return nil
		}
		if len(content) > maxLiveOutputScanBytes {
			return incomplete("native_metadata_scan_limit")
		}
		key := sha256.Sum256([]byte(content))
		if _, ok := metadataCache[key]; ok {
			return nil
		}
		started := time.Now()
		// 元数据帧（含 instructions 回显）不是模型生成的文字，不设 output_projection。
		action, _, findings, checkErr := h.checkStreamOutput(withoutOutputProjection(ctx), envelope, content, event.Index)
		recordSecurityTiming(envelope, h.relayMetrics, "output_security_ms", time.Since(started))
		if checkErr != nil {
			return h.streamInspectionFailure(ctx, checkErr, incomplete)
		}
		acc.rememberOutputFindings(event.Index, findings)
		exitMode := liveStreamExitMode(mode)
		if securityexit.Decide(exitMode, action, securityexit.RuleHit).Enforce {
			return fmt.Errorf("%w: retained native metadata requires blocking", errLiveStreamOutputBlocked)
		}
		// Retained native metadata cannot be redacted in place. The configured
		// action is "mask", not "block": the frame is forwarded unchanged and an
		// alert is raised once per stream (2026-09-23 定案，与聊天流式、附件一致).
		if exitMode == securityexit.Protect && strings.EqualFold(strings.TrimSpace(action), "mask") {
			if !pending.maskUnavailableAlerted && h.auditWriter != nil {
				h.writeSecurityEvent(withMaskUnavailable(withSecurityEventStage(ctx, "output")), envelope, findings,
					"security_audit", "native stream metadata matched a mask rule and cannot be rewritten; forwarded unmasked")
			}
			pending.maskUnavailableAlerted = true
		}
		if len(metadataCache) >= 256 {
			clear(metadataCache)
		}
		metadataCache[key] = struct{}{}
		return nil
	}
	return func(event relay.StreamEvent) error {
		if mode == relay.OutputSecurityStreamAudit {
			return legacy(event)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if h.relayMetrics != nil {
			h.relayMetrics.Inc("stream_events")
		}
		if event.Type == relay.EventStreamError {
			if event.Err != nil {
				return event.Err
			}
			return errors.New("upstream native stream error")
		}
		acc.observeEvent(event)
		first(event)
		if mode == relay.OutputSecurityStrictBuffered && acc.totalOutputBytes > pending.limit {
			return incomplete("strict_output_budget")
		}
		if acc.outputScanReason != "" || acc.choiceOverflow || liveToolArgumentsIncomplete(acc) {
			if err := incomplete(firstNonEmptyLive(acc.outputScanReason, "response_content_limit")); err != nil {
				return err
			}
		}
		switch event.Type {
		case relay.EventMessageEnd, relay.EventToolCallStart, relay.EventToolArgumentsDelta, relay.EventToolArgumentsDone:
			return nil
		}
		if !accept(event) {
			return nil
		}
		if !liveIsText(event) {
			if len(event.Raw) > maxLiveOutputScanBytes {
				if err := incomplete("opaque_event_limit"); err != nil {
					return err
				}
			}
			if nativeMetadataContainsOutput(event.Raw) {
				if err := incomplete("unscanned_native_snapshot"); err != nil {
					return err
				}
			}
		}
		if err := inspectMetadata(event); err != nil {
			return err
		}
		return pending.add(ctx, event, check, write, incomplete)
	}
}

// Non-delta start/metadata events must not smuggle uninspected initial content.
// Unsupported nonempty snapshots are explicit incomplete checks in enforce;
// audit mode retains its original pass-through contract.
func nativeMetadataContainsOutput(raw []byte) bool {
	var value interface{}
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return false
	}
	var contains func(interface{}) bool
	contains = func(value interface{}) bool {
		switch node := value.(type) {
		case map[string]interface{}:
			for key, item := range node {
				switch key {
				case "text", "thinking", "arguments", "input", "content", "output":
					if str, ok := item.(string); ok && str != "" {
						return true
					}
					if list, ok := item.([]interface{}); ok && len(list) > 0 {
						return true
					}
					if object, ok := item.(map[string]interface{}); ok && len(object) > 0 {
						return true
					}
				}
				if contains(item) {
					return true
				}
			}
		case []interface{}:
			for _, item := range node {
				if contains(item) {
					return true
				}
			}
		}
		return false
	}
	return contains(value)
}

func checkNativeResponsesTerminal(ctx context.Context, h *ChatCompletionsHandler, envelope *modelrouter.RequestEnvelope, raw []byte, messages []Message) (*AuditResult, error) {
	var terminal struct {
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(raw, &terminal); err != nil || len(terminal.Response) == 0 {
		return nil, errors.New("native Responses terminal has no response snapshot")
	}
	view, err := nativeResponsesSecurityView(terminal.Response)
	if err != nil {
		return nil, err
	}
	var response ChatCompletionResponse
	if err = json.Unmarshal(view, &response); err != nil {
		return nil, err
	}
	// The normalized view supplies structured tool decisions. Also inspect every
	// string in the terminal snapshot so reasoning/extension fields cannot bypass
	// the check by appearing only in the last native frame.
	// The final writer preserves the whole envelope, including extension keys
	// and numeric values outside response. Scan the exact retained envelope.
	allText, err := nativeRetainedMetadataText(relay.StreamEvent{Type: relay.EventMessageEnd, Raw: raw})
	if err != nil {
		return nil, err
	}
	if len(response.Choices) == 0 {
		response.Choices = []Choice{{Index: 0, Message: ChoiceMessage{Role: "assistant"}}}
	}
	response.Choices[0].Message.Content = allText
	response.Choices[0].Message.ReasoningContent = ""
	view, err = json.Marshal(response)
	if err != nil {
		return nil, err
	}
	// 终态快照的 Content 是整个终态事件的全部字符串（含 instructions 回显、mcp_call 输出），
	// 与普通路径共用 applyOutputSecurityCore，这里让其中的自动标注（含工具参数）全部失效。
	_, audit, err := h.applyOutputSecurity(withoutOutputProjection(ctx), envelope, messages, view)
	if err != nil {
		// 客户端在终态快照扫描期间已断开（Esc / 中断）：先于「audit 里已有 block 动作」的判断。
		// 前面的工具调用可能已被破坏性工具闸门拦截（只把 OutputAction 设成 block、不返回 error），
		// 随后另一个调用的参数扫描因断开返回哨兵；若在这里包成 errLiveStreamOutputBlocked，
		// 调用方会对已断开的客户端记一次 security_blocked/403。原样返回哨兵，调用方记 client_canceled。
		if clientGoneDuring(ctx, err) {
			return audit, err
		}
		if securityexit.Blocks(outputActionOf(audit)) {
			// A verdict, not an inspection failure.
			return audit, fmt.Errorf("%w: %v", errLiveStreamOutputBlocked, err)
		}
		return audit, err
	}
	// Only called for enforcing live streams. A blocking verdict stops the
	// stream. A configured mask is not a block: the retained snapshot is not
	// replayed, the caller emits the terminal rebuilt from the masked output
	// (nativeTerminalNeedsRewrite).
	if securityexit.Blocks(outputActionOf(audit)) {
		return audit, fmt.Errorf("%w: native terminal requires a structural output change", errLiveStreamOutputBlocked)
	}
	return audit, nil
}

// nativeTerminalNeedsRewrite reports a terminal snapshot that matched a mask
// rule: it must not be replayed verbatim and is rebuilt from the masked output.
func nativeTerminalNeedsRewrite(audit *AuditResult) bool {
	return strings.EqualFold(outputActionOf(audit), "mask")
}

// Inspect everything the native writer retains outside the delta text; only
// transport sequence/index scalars are omitted from the cache identity. Plain
// values and property names are visited in stable order, without JSON escaping.
func nativeRetainedMetadataText(event relay.StreamEvent) (string, error) {
	var value map[string]interface{}
	decoder := json.NewDecoder(strings.NewReader(string(event.Raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	delete(value, "sequence_number") // writer regenerates this field
	if event.Type != relay.EventMessageEnd {
		for _, key := range []string{"index", "output_index", "content_index", "summary_index"} {
			delete(value, key)
		}
	}
	if liveIsText(event) {
		if delta, ok := value["delta"].(map[string]interface{}); ok {
			delete(delta, "text")
			delete(delta, "thinking")
		} else {
			delete(value, "delta")
		}
	}
	var parts []string
	var visit func(interface{})
	visit = func(value interface{}) {
		switch node := value.(type) {
		case string:
			if node != "" {
				parts = append(parts, node)
			}
		case json.Number:
			parts = append(parts, node.String())
		case []interface{}:
			for _, item := range node {
				visit(item)
			}
		case map[string]interface{}:
			keys := make([]string, 0, len(node))
			for key := range node {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				parts = append(parts, key)
				visit(node[key])
			}
		}
	}
	visit(value)
	return strings.Join(parts, "\n"), nil
}
