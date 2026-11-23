package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

type StreamEventType string

const (
	EventStreamStart        StreamEventType = "stream_start"
	EventMessageStart       StreamEventType = "message_start"
	EventTextDelta          StreamEventType = "text_delta"
	EventReasoningDelta     StreamEventType = "reasoning_delta"
	EventToolCallStart      StreamEventType = "tool_call_start"
	EventToolArgumentsDelta StreamEventType = "tool_arguments_delta"
	EventToolArgumentsDone  StreamEventType = "tool_arguments_done"
	EventToolResult         StreamEventType = "tool_result"
	EventUsageDelta         StreamEventType = "usage_delta"
	EventUsageFinal         StreamEventType = "usage_final"
	EventCacheUsage         StreamEventType = "cache_usage"
	EventMessageEnd         StreamEventType = "message_end"
	EventStreamError        StreamEventType = "stream_error"
	EventUnknown            StreamEventType = "unknown"
)

type OutputSecurityMode string

const (
	OutputSecurityStrictBuffered OutputSecurityMode = "strict_buffered"
	OutputSecurityStreamEnforce  OutputSecurityMode = "stream_enforce"
	OutputSecurityStreamAudit    OutputSecurityMode = "stream_audit"
)

func NormalizeOutputSecurityMode(value string) OutputSecurityMode {
	mode, err := ParseOutputSecurityMode(value)
	if err != nil {
		return OutputSecurityStreamEnforce
	}
	return mode
}

func ParseOutputSecurityMode(value string) (OutputSecurityMode, error) {
	normalized := OutputSecurityMode(strings.ToLower(strings.TrimSpace(value)))
	if normalized == "" {
		return OutputSecurityStreamEnforce, nil
	}
	switch normalized {
	case OutputSecurityStrictBuffered, OutputSecurityStreamEnforce, OutputSecurityStreamAudit:
		return normalized, nil
	default:
		return "", fmt.Errorf("unknown output security mode %q", value)
	}
}

type Usage struct {
	InputTokens              int64
	OutputTokens             int64
	ReasoningTokens          int64
	CacheReadInputTokens     int64
	CacheCreationInputTokens int64
	CacheMissInputTokens     int64
}

type CacheUsage struct {
	ReadTokens     int64
	CreationTokens int64
}

type ToolCall struct {
	ID        string
	Name      string
	Arguments string
	Index     int
	// ProviderExecuted：由模型服务方执行的工具块（Anthropic server_tool_use、mcp_tool_use 等非 tool_use 块），
	// 参数会离开本机。只供网关内部送检判断，不改变转给客户端的内容。
	ProviderExecuted bool
}

type StreamEvent struct {
	Type         StreamEventType
	ID           string
	Model        string
	Index        int
	Delta        string
	FinishReason string
	ToolCall     *ToolCall
	ToolResult   []byte
	Usage        *Usage
	CacheUsage   *CacheUsage
	Raw          []byte
	Err          error
}

type StreamReader interface {
	Next(context.Context) (StreamEvent, error)
	Close() error
}

type StreamSink interface {
	Send(context.Context, StreamEvent) error
}

type CommitState string

const (
	CommitNotStarted        CommitState = "not_started"
	CommitHeadersCommitted  CommitState = "headers_committed"
	CommitFirstEventFlushed CommitState = "first_event_flushed"
	CommitCompleted         CommitState = "completed"
	CommitAborted           CommitState = "aborted"
)

var ErrCommitStateRegression = errors.New("stream commit state regression")
var ErrInvalidCommitStateTransition = errors.New("invalid stream commit state transition")

type CommitTracker struct {
	mu    sync.RWMutex
	state CommitState
}

func (t *CommitTracker) State() CommitState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.state == "" {
		return CommitNotStarted
	}
	return t.state
}

func (t *CommitTracker) Transition(next CommitState) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	current := t.state
	if current == "" {
		current = CommitNotStarted
	}
	if !validCommitState(current) || !validCommitState(next) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidCommitStateTransition, current, next)
	}
	if current == next {
		return nil
	}
	if !validCommitTransition(current, next) {
		if commitRank(next) < commitRank(current) {
			return fmt.Errorf("%w: %s -> %s", ErrCommitStateRegression, current, next)
		}
		return fmt.Errorf("%w: %s -> %s", ErrInvalidCommitStateTransition, current, next)
	}
	t.state = next
	return nil
}

func (t *CommitTracker) CanRetry() bool {
	return t.State() == CommitNotStarted
}

// Abort records an interrupted response only after downstream commitment.
// A failure before the first possible write remains retryable not_started.
func (t *CommitTracker) Abort() error {
	switch t.State() {
	case CommitNotStarted, CommitCompleted, CommitAborted:
		return nil
	case CommitHeadersCommitted, CommitFirstEventFlushed:
		return t.Transition(CommitAborted)
	default:
		return fmt.Errorf("%w: %s", ErrInvalidCommitStateTransition, t.State())
	}
}

func commitRank(state CommitState) int {
	switch state {
	case CommitNotStarted:
		return 0
	case CommitHeadersCommitted:
		return 1
	case CommitFirstEventFlushed:
		return 2
	case CommitCompleted:
		return 3
	case CommitAborted:
		return 4
	default:
		return 5
	}
}

func validCommitState(state CommitState) bool {
	switch state {
	case CommitNotStarted, CommitHeadersCommitted, CommitFirstEventFlushed, CommitCompleted, CommitAborted:
		return true
	default:
		return false
	}
}

func validCommitTransition(current, next CommitState) bool {
	switch current {
	case CommitNotStarted:
		return next == CommitHeadersCommitted
	case CommitHeadersCommitted:
		return next == CommitFirstEventFlushed || next == CommitAborted
	case CommitFirstEventFlushed:
		return next == CommitCompleted || next == CommitAborted
	case CommitCompleted, CommitAborted:
		return false
	default:
		return false
	}
}

var ErrEventQueueClosed = errors.New("stream event queue closed")

type EventQueue struct {
	events chan StreamEvent
	done   chan struct{}
	once   sync.Once
}

func NewEventQueue(capacity int) *EventQueue {
	if capacity < 1 {
		capacity = 1
	}
	return &EventQueue{events: make(chan StreamEvent, capacity), done: make(chan struct{})}
}

func (q *EventQueue) Push(ctx context.Context, event StreamEvent) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-q.done:
		return ErrEventQueueClosed
	default:
	}
	select {
	case q.events <- event:
		return nil
	case <-q.done:
		return ErrEventQueueClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (q *EventQueue) Next(ctx context.Context) (StreamEvent, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case event := <-q.events:
		return event, nil
	case <-q.done:
		select {
		case event := <-q.events:
			return event, nil
		default:
			return StreamEvent{}, ErrEventQueueClosed
		}
	case <-ctx.Done():
		return StreamEvent{}, ctx.Err()
	}
}

func (q *EventQueue) Close() {
	q.once.Do(func() { close(q.done) })
}

// Relay reads one event at a time and does not read another event while the
// sink is blocked. That makes the sink's write latency the backpressure signal.
func Relay(ctx context.Context, source StreamReader, sink StreamSink, tracker *CommitTracker) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		event, err := source.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if tracker != nil && tracker.State() == CommitFirstEventFlushed {
					_ = tracker.Transition(CommitCompleted)
				}
				return nil
			}
			if tracker != nil {
				_ = tracker.Abort()
			}
			return err
		}
		if tracker != nil && tracker.State() == CommitNotStarted {
			if err := tracker.Transition(CommitHeadersCommitted); err != nil {
				return err
			}
		}
		if err := sink.Send(ctx, event); err != nil {
			if tracker != nil {
				_ = tracker.Abort()
			}
			return err
		}
		if tracker != nil && tracker.State() == CommitHeadersCommitted {
			if err := tracker.Transition(CommitFirstEventFlushed); err != nil {
				return err
			}
		}
	}
}
