package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

const (
	defaultLiveHoldbackBytes  = 256
	defaultLiveScanBatchBytes = 1024
	defaultLivePendingBytes   = 4 << 20
	maxLivePendingEvents      = 8192
)

var errLivePendingLimit = errors.New("output pending buffer limit")

type liveTextLaneKey struct {
	index int
	kind  relay.StreamEventType
}
type liveTextLane struct {
	tail      string
	fresh     string
	pending   int
	emitted   int
	deferMask bool
}
type livePendingOutput struct {
	queue                  []relay.StreamEvent
	lanes                  map[liveTextLaneKey]*liveTextLane
	bytes                  int
	holdback, batch, limit int
	strict                 bool
	preserveRaw            bool
	// maskUnavailable records that a configured mask could not be applied and
	// the original text was forwarded; the stream owner raises the alert.
	maskUnavailable bool
	// maskUnavailableAlerted records a native frame that matched a mask rule but
	// cannot be rewritten: it was forwarded and already alerted; the stream owner
	// only marks the request log.
	maskUnavailableAlerted bool
}

// newLivePendingOutput 按本次请求的输出检测方式快照（mode）建待发缓冲；缓冲严格的上限按请求读控制台值。
func newLivePendingOutput(h *ChatCompletionsHandler, mode relay.OutputSecurityMode) *livePendingOutput {
	p := &livePendingOutput{lanes: make(map[liveTextLaneKey]*liveTextLane), holdback: defaultLiveHoldbackBytes, batch: defaultLiveScanBatchBytes, limit: defaultLivePendingBytes}
	if h.cfg != nil {
		if h.cfg.OutputStreamHoldbackBytes > 0 {
			p.holdback = h.cfg.OutputStreamHoldbackBytes
		}
		if h.cfg.OutputStreamScanBatchBytes > 0 {
			p.batch = h.cfg.OutputStreamScanBatchBytes
		}
		if h.cfg.OutputStreamPendingBytes > 0 {
			p.limit = h.cfg.OutputStreamPendingBytes
		}
	}
	if mode == relay.OutputSecurityStrictBuffered {
		p.strict = true
		p.limit = effectiveOutputStrictMaxBytes(h.toolRiskClient, h.cfg)
		if p.limit <= 0 {
			p.limit = maxLiveOutputAuditBytes
		}
	}
	return p
}
func liveIsText(event relay.StreamEvent) bool {
	return event.Type == relay.EventTextDelta || event.Type == relay.EventReasoningDelta
}
func (p *livePendingOutput) lane(event relay.StreamEvent) *liveTextLane {
	key := liveTextLaneKey{event.Index, event.Type}
	if p.lanes[key] == nil {
		p.lanes[key] = &liveTextLane{}
	}
	return p.lanes[key]
}

// UTF-8 offsets are byte offsets, but every emitted delta is a valid string.
func liveUTF8Prefix(value string, n int) int {
	if n >= len(value) {
		return len(value)
	}
	if n < 0 {
		return 0
	}
	for n > 0 && !utf8.RuneStart(value[n]) {
		n--
	}
	return n
}
func (p *livePendingOutput) appendEvent(event relay.StreamEvent) error {
	if !p.preserveRaw {
		event.Raw = nil
	}

	if len(p.queue) > 0 && liveIsText(event) {
		last := &p.queue[len(p.queue)-1]
		// Bound concatenation cost when an earlier channel holds the queue.
		if last.Type == event.Type && last.Index == event.Index && len(last.Delta)+len(event.Delta) <= p.batch && bytes.Equal(last.Raw, event.Raw) {
			last.Delta += event.Delta
			p.bytes += len(event.Delta)
			if p.bytes > p.limit {
				return errLivePendingLimit
			}
			return nil
		}
	}
	p.queue = append(p.queue, event)
	p.bytes += len(event.Delta) + len(event.Raw)
	if p.bytes > p.limit || len(p.queue) > maxLivePendingEvents {
		return errLivePendingLimit
	}
	return nil
}
func (p *livePendingOutput) add(ctx context.Context, event relay.StreamEvent, check func(string, int) (bool, error), write func(relay.StreamEvent) error, incomplete func(string) error) error {
	if p.preserveRaw && liveIsText(event) {
		var payload map[string]interface{}
		if json.Unmarshal(event.Raw, &payload) == nil {
			delete(payload, "sequence_number")
			if delta, ok := payload["delta"].(map[string]interface{}); ok {
				if _, ok := delta["text"]; ok {
					delta["text"] = ""
				}
				if _, ok := delta["thinking"]; ok {
					delta["thinking"] = ""
				}
			} else {
				payload["delta"] = ""
			}
			event.Raw, _ = json.Marshal(payload)
		}
	}
	if liveIsText(event) {
		key := liveTextLaneKey{event.Index, event.Type}
		if p.lanes[key] == nil && len(p.lanes) >= 2*maxLiveChoices {
			return errors.New("output channel resource limit")
		}
	}
	if p.strict {
		if liveIsText(event) {
			p.lane(event).pending += len(event.Delta)
		}
		if err := p.appendEvent(event); err != nil {
			return incomplete("strict_output_budget")
		}
		return nil
	}
	if !liveIsText(event) {
		if err := p.appendEvent(event); err != nil {
			if failure := incomplete("output_pending_limit"); failure != nil {
				return failure
			}
			return p.drainIncomplete(ctx, write)
		}
		return p.drain(ctx, false, write)
	}
	lane := p.lane(event)
	// Split oversized provider deltas before scanning, never silently truncate.
	for remaining := event.Delta; remaining != ""; {
		if err := ctx.Err(); err != nil {
			return err
		}
		size := liveUTF8Prefix(remaining, p.batch-len(lane.fresh))
		if size == 0 { // Finish the current batch before adding a multibyte rune.
			if err := p.scan(lane, event.Index, check); err != nil {
				return err
			}
			size = liveUTF8Prefix(remaining, p.batch)
		}
		part := event
		part.Delta = remaining[:size]
		lane.pending += size
		lane.fresh += part.Delta
		if err := p.appendEvent(part); err != nil {
			if failure := incomplete("output_pending_limit"); failure != nil {
				return failure
			}
			if err := p.drainIncomplete(ctx, write); err != nil {
				return err
			}
		}
		remaining = remaining[size:]
		if len(lane.fresh) >= p.batch-utf8.UTFMax+1 {
			if err := p.scan(lane, event.Index, check); err != nil {
				return err
			}
			if err := p.drain(ctx, false, write); err != nil {
				return err
			}
		}
	}
	return nil
}
func (p *livePendingOutput) scan(lane *liveTextLane, index int, check func(string, int) (bool, error)) error {
	if lane.fresh == "" {
		return nil
	}
	window := lane.tail + lane.fresh
	masked, err := check(window, index)
	if err != nil {
		return err
	}
	lane.deferMask = lane.deferMask || masked
	lane.tail = appendLiveTail(window, maxLiveOutputTailBytes)
	lane.fresh = ""
	return nil
}
func (p *livePendingOutput) drain(ctx context.Context, final bool, write func(relay.StreamEvent) error) error {
	for len(p.queue) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		event := p.queue[0]
		emitBytes := len(event.Delta)
		if liveIsText(event) {
			lane := p.lane(event)
			if !final {
				if lane.fresh != "" || lane.deferMask {
					return nil
				}
				available := lane.pending - p.holdback
				if available <= 0 {
					return nil
				}
				if emitBytes > available {
					emitBytes = liveUTF8Prefix(event.Delta, available)
				}
				if emitBytes == 0 {
					return nil
				}
			}
			event.Delta = event.Delta[:emitBytes]
			if err := write(event); err != nil {
				return err
			}
			lane.emitted += emitBytes
			lane.pending -= emitBytes
		} else if err := write(event); err != nil {
			return err
		}
		p.bytes -= emitBytes
		if emitBytes < len(p.queue[0].Delta) {
			p.queue[0].Delta = strings.Clone(p.queue[0].Delta[emitBytes:])
			return nil
		}
		p.bytes -= len(p.queue[0].Raw)
		p.queue[0] = relay.StreamEvent{}
		p.queue = p.queue[1:]
	}
	p.queue = nil
	return nil
}

// Reconcile all lanes before flushing any pending byte. Already released text
// must remain an identical prefix of the final checked response. Ambiguous
// redaction across interleaved fields is rejected rather than reordered.
func (p *livePendingOutput) reconcile(acc *liveStreamAccumulator, response ChatCompletionResponse) error {
	secured := make(map[liveTextLaneKey]string)
	for _, choice := range response.Choices {
		secured[liveTextLaneKey{choice.Index, relay.EventTextDelta}] = choice.Message.Content
		secured[liveTextLaneKey{choice.Index, relay.EventReasoningDelta}] = choice.Message.ReasoningContent
	}
	replacements := make(map[liveTextLaneKey]string)
	for key, lane := range p.lanes {
		rawChoice := acc.choices[key.index]
		if rawChoice == nil {
			return fmt.Errorf("missing accumulated choice %d", key.index)
		}
		raw := rawChoice.content.String()
		if key.kind == relay.EventReasoningDelta {
			raw = rawChoice.reasoning.String()
		}
		final := secured[key]
		if lane.emitted > len(raw) || lane.emitted > len(final) || raw[:lane.emitted] != final[:lane.emitted] {
			return errors.New("final output check changed text already committed")
		}
		if raw == final {
			if lane.deferMask {
				return errors.New("pending output mask was not resolved by the final check")
			}
			continue
		}
		seen, ended := false, false
		identity := ""
		for _, event := range p.queue {
			matches := liveIsText(event) && event.Index == key.index && event.Type == key.kind
			if matches {
				if p.preserveRaw {
					nextIdentity := nativePendingFrameIdentity(event.Raw)
					if seen && identity != nextIdentity {
						return errors.New("redaction cannot safely align native output item identities")
					}
					identity = nextIdentity
				}
				if ended {
					return errors.New("redaction cannot safely align interleaved output fields")
				}
				seen = true
			} else if seen {
				ended = true
			}
		}
		if !seen && len(final) != lane.emitted {
			return errors.New("redaction has no pending output segment")
		}
		replacements[key] = final[lane.emitted:]
	}
	for key, replacement := range replacements {
		first := true
		for i := range p.queue {
			event := &p.queue[i]
			if !liveIsText(*event) || event.Index != key.index || event.Type != key.kind {
				continue
			}
			p.bytes -= len(event.Delta)
			if first {
				event.Delta = replacement
				first = false
			} else {
				event.Delta = ""
			}
			p.bytes += len(event.Delta)
		}
		p.lanes[key].pending = len(replacement)
	}
	return nil
}

func (p *livePendingOutput) hasDeferredMask() bool {
	for _, lane := range p.lanes {
		if lane.deferMask {
			return true
		}
	}
	return false
}

// A mask that cannot be resolved never turns into a block: the configured
// action is "mask", so the held original text is released and the caller
// raises an alert (maskUnavailable).
func (p *livePendingOutput) drainIncomplete(ctx context.Context, write func(relay.StreamEvent) error) error {
	if p.hasDeferredMask() {
		p.maskUnavailable = true
	}
	return p.drain(ctx, true, write)
}
func (p *livePendingOutput) finish(ctx context.Context, acc *liveStreamAccumulator, response ChatCompletionResponse, audit *AuditResult, write func(relay.StreamEvent) error) error {
	if p.hasDeferredMask() && audit != nil && audit.ResponseMetadata != nil && audit.ResponseMetadata["output_scan_incomplete"] == true {
		p.maskUnavailable = true
		return p.drain(ctx, true, write)
	}
	if !acc.outputScanIncomplete || p.hasDeferredMask() {
		if err := p.reconcile(acc, response); err != nil {
			p.maskUnavailable = true
		}
	}
	return p.drain(ctx, true, write)
}

func nativePendingFrameIdentity(raw []byte) string {
	var payload map[string]interface{}
	if json.Unmarshal(raw, &payload) != nil {
		return string(raw)
	}
	identity := make(map[string]interface{})
	for _, key := range []string{"type", "index", "item_id", "output_index", "content_index", "summary_index"} {
		if value, ok := payload[key]; ok {
			identity[key] = value
		}
	}
	encoded, _ := json.Marshal(identity)
	return string(encoded)
}
