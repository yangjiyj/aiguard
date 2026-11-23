package handler

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

// streamKeepalive 在流式请求"先攒后发"期间保持连接不空闲，chat / messages / responses / Gemini
// 四条流式路径共用；保活字节按协议配置（chat、messages、responses 为 SSE 注释，Gemini 为空行）。
//
// 攒满一个间隔仍未完成时，先回 200 + text/event-stream 头，之后每个间隔写一次保活字节。
// 默认的 SSE 注释 ": keepalive"（OpenAI 兼容客户端按 SSE 规范忽略冒号开头的行）防止 Dify 插件的
// 300s 读超时或客户中间层的空闲超时把长任务掐断。间隔内就完成的请求一个字节都不提前写，
// 响应与改造前完全一致（含 4xx/5xx 状态码与 JSON 错误体）。
//
// 头一旦发出就改不了状态码：之后的拦截/错误都改用 SSE 错误帧告知（与实时流提交后、writeSSEError
// 同一约定：错误帧后不补 [DONE]），审计口径不变。
// 安全语义不变：内容仍在完整扫描之后才写出，保活期间只写注释，不写任何模型输出。
type streamKeepalive struct {
	w       http.ResponseWriter
	flusher http.Flusher
	spec    streamKeepaliveSpec

	mu        sync.Mutex
	committed bool
	stopped   bool
	stop      chan struct{}
	done      chan struct{}
}

// streamKeepaliveSpec 描述保活写什么、提交头时用什么缓存策略。
// chat / messages / responses 用 SSE 注释；Gemini 客户端会把注释当成非法 JSON 报错，只能发单个换行。
type streamKeepaliveSpec struct {
	payload      []byte
	cacheControl string
}

// defaultStreamKeepaliveSpec 是 chat 一直在用的形态（SSE 注释 + no-cache），messages / responses 沿用。
// 返回副本：payload 切片不会被调用方改动而影响其他请求。
func defaultStreamKeepaliveSpec() streamKeepaliveSpec {
	return streamKeepaliveSpec{payload: []byte(": keepalive\n\n"), cacheControl: "no-cache"}
}

// streamSecurityActionField 是保活提交头后随末帧带出最终安全动作的扩展字段（企业门户读取，与 X-Security-Action 同值域）。
const streamSecurityActionField = "x_jjdguard_security_action"

// startStreamKeepalive 在 interval>0 且 w 支持 Flush 时启动保活；否则返回 nil（调用方照旧直接写 w）。
// alreadyCommitted=true 表示头已由之前的保活发出，本次只续写注释。
func startStreamKeepalive(w http.ResponseWriter, interval time.Duration, alreadyCommitted bool, prepareHeaders func()) *streamKeepalive {
	return startStreamKeepaliveWithSpec(w, interval, alreadyCommitted, defaultStreamKeepaliveSpec(), prepareHeaders)
}

// startStreamKeepaliveWithSpec 与 startStreamKeepalive 相同，但保活字节和缓存策略可配置。
func startStreamKeepaliveWithSpec(w http.ResponseWriter, interval time.Duration, alreadyCommitted bool, spec streamKeepaliveSpec, prepareHeaders func()) *streamKeepalive {
	if interval <= 0 {
		return nil
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil
	}
	// 保活字节和缓存策略分别回落默认值：只配了其中一个时，另一个不能留空。
	defaults := defaultStreamKeepaliveSpec()
	if len(spec.payload) == 0 {
		spec.payload = defaults.payload
	}
	if spec.cacheControl == "" {
		spec.cacheControl = defaults.cacheControl
	}
	k := &streamKeepalive{w: w, flusher: flusher, spec: spec, committed: alreadyCommitted, stop: make(chan struct{}), done: make(chan struct{})}
	go k.run(interval, prepareHeaders)
	return k
}

func (k *streamKeepalive) run(interval time.Duration, prepareHeaders func()) {
	defer close(k.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-k.stop:
			return
		case <-ticker.C:
			k.mu.Lock()
			if k.stopped {
				k.mu.Unlock()
				return
			}
			if !k.committed {
				if prepareHeaders != nil {
					prepareHeaders()
				}
				k.w.Header().Set("Content-Type", "text/event-stream")
				k.w.Header().Set("Cache-Control", k.spec.cacheControl)
				k.w.Header().Set("Connection", "keep-alive")
				k.w.Header().Set("X-Accel-Buffering", "no")
				k.w.Header().Del("Content-Length")
				k.w.WriteHeader(http.StatusOK)
				k.committed = true
			}
			_, err := k.w.Write(k.spec.payload)
			if err == nil {
				k.flusher.Flush()
			}
			k.mu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

// Committed 返回保活是否已经把响应头发出；加锁读取，保活仍在运行时也可安全调用。nil 接收者安全。
func (k *streamKeepalive) Committed() bool {
	if k == nil {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.committed
}

// Finish 停掉保活并返回头是否已提交。之后由调用方独占 w。nil 接收者安全。
func (k *streamKeepalive) Finish() bool {
	if k == nil {
		return false
	}
	k.mu.Lock()
	if !k.stopped {
		k.stopped = true
		close(k.stop)
	}
	committed := k.committed
	k.mu.Unlock()
	<-k.done
	return committed
}

func (h *ChatCompletionsHandler) streamKeepaliveInterval() time.Duration {
	if h == nil || h.cfg == nil {
		return 0
	}
	return h.cfg.StreamKeepaliveInterval
}

// writeCommittedStreamError 在头已提交（状态码固定为 200）后用 SSE 错误帧告知客户端并收尾。
func writeCommittedStreamError(w http.ResponseWriter, detail ErrorDetail) {
	payload, _ := json.Marshal(ErrorResponse{Error: detail})
	writeSSEData(w, string(payload))
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// writeCommittedChatMessageBlock 是保活已发头时的 message 模式拦截：帧与快请求相同（助手消息展示阻断说明），
// 只在 [DONE] 前多一帧 choices 为空的扩展字段，把 block 带给读不到响应头的客户端（门户据此落库为已拦截）。
func writeCommittedChatMessageBlock(w http.ResponseWriter, model, requestID string, notice securityBlockNotice, actionEnabled bool) {
	id := "chatcmpl-" + requestID
	created := time.Now().Unix()
	chunk, _ := json.Marshal(SSEChunk{
		ID: id, Object: "chat.completion.chunk", Created: created, Model: model,
		Choices: []SSEChoice{{Index: 0, Delta: SSEDelta{Role: "assistant", Content: notice.Text}, FinishReason: "stop"}},
	})
	writeSSEData(w, string(chunk))
	if actionEnabled {
		frame, _ := json.Marshal(map[string]any{"id": id, "object": "chat.completion.chunk", "created": created, "model": model, "choices": []any{}, streamSecurityActionField: "block"})
		writeSSEData(w, string(frame))
	}
	writeSSEData(w, "[DONE]")
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// committedUpstreamErrorDetail 与 writeUpstreamErrorResponse 同一口径（净化后的上游信息），只是改走 SSE。
func committedUpstreamErrorDetail(upstreamErr *provider.UpstreamHTTPError, requestID, stage string) ErrorDetail {
	status := http.StatusBadGateway
	if upstreamErr != nil {
		status = upstreamErr.StatusCode
	}
	logUpstreamHTTPError(requestID, stage, upstreamErr)
	return ErrorDetail{
		Code:           "upstream_error",
		Message:        clientUpstreamErrorMessage(upstreamErr, "upstream request failed"),
		RequestID:      requestID,
		Stage:          stage,
		UpstreamStatus: status,
	}
}
