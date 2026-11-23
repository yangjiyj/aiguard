package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
)

var errReverseOutputBlocked = errors.New("output_security_blocked")

type reverseHeldFrame struct {
	raw []byte
	end int
}

func (h *ReverseProxyHandler) SetOutputStreamConfig(cfg *config.Config) { h.outputStreamConfig = cfg }
func (h *ForwardProxyHandler) SetOutputStreamConfig(cfg *config.Config) {
	if h != nil && h.reverseProxy != nil {
		h.reverseProxy.SetOutputStreamConfig(cfg)
	}
}

// The chat pending core scans text; raw native frames remain separate because
// splitting a provider delta must never duplicate or reorder protocol objects.
func (h *ReverseProxyHandler) copyGuardedReverseSSE(ctx context.Context, w http.ResponseWriter, body io.Reader, capture *headTailReverseProxyCapture, requestID, host, path string) (int64, reverseProxySecurityDecision, bool, error) {
	if llmcatalog.IsTelemetry(host, path) || (h.runtimeConfigClient != nil && !h.runtimeConfigClient.InspectionPolicy(ctx).InspectModelOutput) {
		n, err := copySSEWithFlush(w, capture, body)
		return n, reverseProxySecurityDecision{Allowed: true, Action: "allow", SemanticStatus: "disabled", SemanticReason: "inspection_scope_excluded"}, false, err
	}
	projection := &streamInspectionCapture{path: path}
	// 反向代理流式缓冲同样按请求读控制台的输出检测方式与缓冲上限（2.9.22 代码质量审查）。
	pending := newLivePendingOutput(&ChatCompletionsHandler{cfg: h.outputStreamConfig, toolRiskClient: h.runtimeConfigClient},
		effectiveOutputSecurityMode(h.runtimeConfigClient, h.outputStreamConfig))
	out := reverseProxySecurityDecision{Allowed: true, Action: "allow", Stage: "output", ContentSource: "verified_final_output"}
	reader := relay.NewSSEReader(body, relay.SSELimits{MaxLineBytes: maxInspectionSSEEvent, MaxEventBytes: maxInspectionSSEEvent, PreserveRaw: true})
	var frames []reverseHeldFrame
	var received int64
	heldBytes, released := 0, 0
	degraded := false
	flush := func(force bool) error {
		for len(frames) > 0 && (force || (!projection.HoldUntilComplete() && frames[0].end <= released)) {
			frame := frames[0]
			if _, err := w.Write(frame.raw); err != nil {
				return err
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			heldBytes -= len(frame.raw)
			frames[0] = reverseHeldFrame{}
			frames = frames[1:]
		}
		return nil
	}
	write := func(event relay.StreamEvent) error { released += len(event.Delta); return flush(false) }
	incomplete := func(reason string) error {
		d := h.reverseInspectionFailure(ctx, nil, reason)
		mergeReverseStreamDecision(&out, d)
		if !d.Allowed {
			return errGuardrailDetectionUnavailable
		}
		degraded = true
		return nil
	}
	check := func(text string, _ int) (bool, error) {
		d, err := h.checkSecurityWithExtras(ctx, requestID, "/check-output/", []byte(text), text, "text/plain", host, path, "model_output", map[string]interface{}{"verified_content": true, "verified_stage": "output", "extraction": "verified_final_output"})
		if clientGoneDuring(ctx, err) {
			// 客户端已断开：不设 degraded（否则 flush(true) 会把持有帧放出去）、不合并 decision、
			// 不走 incomplete 回调。pending 对 check 的错误原样透传，stop(err) 原样返回，
			// 不写 writeReverseSecurityTermination 终止帧。
			return false, err
		}
		mergeReverseStreamDecision(&out, d)
		if !d.Allowed {
			if d.SemanticStatus == "incomplete" && len(d.Findings) == 0 {
				return false, errGuardrailDetectionUnavailable
			}
			return false, errReverseOutputBlocked
		}
		if err != nil {
			degraded = true
		}
		// Native frames cannot be rewritten safely using flattened text offsets.
		if d.Action == "mask" || d.Action == "redact" {
			out.MaskUnavailable = true
			out.Action = "audit"
		}
		return false, nil
	}
	stop := func(err error) (int64, reverseProxySecurityDecision, bool, error) {
		out.VerifiedContent = projection.InspectionText()
		if errors.Is(err, errReverseOutputBlocked) || isGuardrailDetectionUnavailable(err) {
			code := "output_security_blocked"
			if isGuardrailDetectionUnavailable(err) {
				code = guardrailDetectionUnavailableCode
			}
			notice := h.reverseBlockNotice(ctx, requestID, "output", out.Findings)
			if isGuardrailDetectionUnavailable(err) {
				notice.Text = guardrailDetectionUnavailableMessage + "\n请求 ID：" + requestID
			}
			terminalErr := writeReverseSecurityTermination(w, path, code, notice)
			return received, out, true, terminalErr
		}
		if clientGoneDuring(ctx, err) && !errors.Is(err, errClientGoneDuringSecurity) {
			// 排空持有帧时 pending 自己检查 ctx 发现客户端已断开：统一成断开哨兵，调用方按 cancelled 收尾。
			err = fmt.Errorf("%w: reverse proxy stream: %w", errClientGoneDuringSecurity, err)
		}
		return received, out, false, err
	}
	for {
		event, err := reader.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				if errors.Is(ctx.Err(), context.Canceled) {
					// 上游请求绑在请求 ctx 上：客户端断开后读流必然失败，错误不一定包装 Canceled（传输层
					// 可能直接关连接，报 use of closed network connection），所以这里按请求 ctx 判，不按 err 判。
					// 不是上游断流：不标 incomplete、不放持有帧、不写终止帧。总超时到期是 DeadlineExceeded，
					// 和请求仍活着时的真实上游读失败一样走下面原逻辑。
					return stop(fmt.Errorf("%w: reverse proxy upstream read: %w", errClientGoneDuringSecurity, err))
				}
				reason := "output_stream_incomplete"
				if errors.Is(err, relay.ErrSSELineTooLong) || errors.Is(err, relay.ErrSSEEventTooLong) {
					reason = "output_event_limit_exceeded"
				}
				if failure := incomplete(reason); failure != nil {
					return stop(failure)
				}
				if flushErr := flush(true); flushErr != nil {
					return stop(flushErr)
				}
				n, copyErr := copySSEWithFlush(w, capture, reader.RemainingRaw())
				received += n
				return stop(copyErr)
			}
			break
		}
		received += int64(len(event.Raw))
		_, _ = capture.Write(event.Raw)
		before := len(projection.Text())
		_, _ = projection.Write(event.Raw)
		if !isReverseProxyChatEndpoint(host, path) && event.Data != "" && event.Data != "[DONE]" {
			projection.appendText(event.Data)
			projection.done = true
		}
		text := projection.Text()
		frames = append(frames, reverseHeldFrame{raw: event.Raw, end: len(text)})
		heldBytes += len(event.Raw)
		if heldBytes > pending.limit || len(frames) > maxLivePendingEvents {
			if failure := incomplete("output_pending_limit"); failure != nil {
				return stop(failure)
			}
		}
		if projection.reason != "" {
			if failure := incomplete(projection.reason); failure != nil {
				return stop(failure)
			}
		}
		if degraded {
			if err := flush(true); err != nil {
				return stop(err)
			}
			continue
		}
		if len(text) > before {
			if err := pending.add(ctx, relay.StreamEvent{Type: relay.EventTextDelta, Delta: text[before:]}, check, write, incomplete); err != nil {
				return stop(err)
			}
		} else if err := flush(false); err != nil {
			return stop(err)
		}
	}
	_, reason := projection.Finish(false)
	if !degraded {
		d, err := h.checkStreamInspection(ctx, requestID, projection.InspectionText(), reason, host, path)
		if clientGoneDuring(ctx, err) {
			// 客户端已断开：保留此前窗口的真实命中作为留证，但不标 incomplete、不写终止帧。
			mergeReverseStreamDecision(&out, d)
			return stop(err)
		}
		mergeReverseStreamDecision(&out, d)
		if !d.Allowed {
			if d.SemanticStatus == "incomplete" && len(d.Findings) == 0 {
				return stop(errGuardrailDetectionUnavailable)
			}
			return stop(errReverseOutputBlocked)
		}
		if err != nil {
			degraded = true
		}
	}
	if err := pending.drain(ctx, true, write); err != nil {
		return stop(err)
	}
	if err := flush(true); err != nil {
		return stop(err)
	}
	out.VerifiedContent = projection.InspectionText()
	return received, out, false, nil
}

func writeReverseSecurityTermination(w http.ResponseWriter, path, code string, notices ...securityBlockNotice) error {
	message := "Response stopped by security policy"
	if code == guardrailDetectionUnavailableCode {
		message = guardrailDetectionUnavailableMessage
	}
	errorBody := map[string]string{"code": code, "message": message}
	if len(notices) > 0 {
		errorBody["message"] = notices[0].Text
		if notices[0].Attribution.RequestID != "" {
			errorBody["request_id"] = notices[0].Attribution.RequestID
		}
		if notices[0].Attribution.BlockID != "" {
			errorBody["block_id"] = notices[0].Attribution.BlockID
		}
	}
	var raw []byte
	switch {
	case strings.Contains(path, "/responses"):
		payload, _ := json.Marshal(map[string]interface{}{"type": "response.failed", "response": map[string]interface{}{"status": "failed", "error": errorBody}})
		raw = []byte("event: response.failed\ndata: " + string(payload) + "\n\n")
	case strings.Contains(path, "/messages"):
		errorBody["type"] = code
		payload, _ := json.Marshal(map[string]interface{}{"type": "error", "error": errorBody})
		raw = []byte("event: error\ndata: " + string(payload) + "\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	default:
		payload, _ := json.Marshal(map[string]interface{}{"error": errorBody})
		raw = []byte(fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", payload))
	}
	_, err := w.Write(raw)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return err
}
