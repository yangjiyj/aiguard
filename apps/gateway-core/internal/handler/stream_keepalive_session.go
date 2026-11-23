package handler

import (
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

// keepaliveSession 把"启动 / 停止 / 头是否已由保活发出"收在一处，供 messages / responses / gemini 共用。
// chat 的 handleStreamingRequest 暂未接入，仍保留自己的内联闭包。
//
// 约定（与 chat 相同）：handler 在调用 Stop 返回之前不得写 w、也不得改 w.Header()；
// Stop 返回后 handler 独占 w。所有方法对 nil 接收者安全（非流式请求、保活关闭时传 nil 即可）。
// 非并发安全，只在 handler goroutine 内使用（保活 goroutine 由 streamKeepalive 自己同步）。
type keepaliveSession struct {
	w         http.ResponseWriter
	interval  time.Duration
	spec      streamKeepaliveSpec
	prepare   func()
	active    *streamKeepalive
	committed bool
}

// newKeepaliveSession 在 interval<=0 时返回 nil（保活关闭，调用方照旧直接写 w）。
func newKeepaliveSession(w http.ResponseWriter, interval time.Duration, spec streamKeepaliveSpec, prepare func()) *keepaliveSession {
	if interval <= 0 {
		return nil
	}
	return &keepaliveSession{w: w, interval: interval, spec: spec, prepare: prepare}
}

// Start 启动保活；已在运行时无操作。头已由之前的保活发出时，只续写保活字节。
func (s *keepaliveSession) Start() {
	if s == nil || s.active != nil {
		return
	}
	s.active = startStreamKeepaliveWithSpec(s.w, s.interval, s.committed, s.spec, s.prepare)
}

// Stop 停掉保活并返回响应头是否已发出（之后的错误/拦截只能走流内帧）。可重复调用。
func (s *keepaliveSession) Stop() bool {
	if s == nil {
		return false
	}
	if s.active != nil {
		if s.active.Finish() {
			s.committed = true
		}
		s.active = nil
	}
	return s.committed
}

// Committed 返回响应头是否已由保活发出。保活仍在运行时也可调用（读取在保活内部加锁），不会停掉或重启保活。
func (s *keepaliveSession) Committed() bool {
	if s == nil {
		return false
	}
	return s.committed || s.active.Committed()
}

// TryLive 在尝试实时流前保证 try 期间只有 try 在写 w；头已由保活发出时不能再走实时流
// （否则两路并发写 w、重复发头）。
//
//   - 头已由保活发出：不调用 try，保活不停也不重启（计时不被打断），返回 (false, nil)，调用方改走先攒后发。
//   - 头未发出：先停保活再调用 try（期间 try 可以独占 w）；try 返回 attempted=false 时重新启动保活。
//   - attempted=true：实时流已接管 w，保活不再恢复，try 的结果原样返回。
//
// nil 接收者（保活关闭或非流式请求）直接透传 try。
func (s *keepaliveSession) TryLive(try func() (attempted bool, err error)) (bool, error) {
	if s == nil {
		return try()
	}
	if s.Committed() {
		s.Start() // 保活在跑时是空操作（不重启计时）；只有此前被 Stop 过才会续上
		return false, nil
	}
	// Committed()==false 与 Stop() 之间保活可能恰好 tick 并提交头：以 Stop() 的结果为准再判一次。
	if s.Stop() {
		s.Start()
		return false, nil
	}
	attempted, err := try()
	if !attempted {
		s.Start()
	}
	return attempted, err
}

// streamKeepaliveIntervalOf 读配置里的保活间隔；cfg 为 nil 时视为关闭。
func streamKeepaliveIntervalOf(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	return cfg.StreamKeepaliveInterval
}
