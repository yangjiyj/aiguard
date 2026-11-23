// Package ratelog 提供按 key 计数的限频日志：同一 key 第 1 次必打，之后每 N 次打一条并带累计次数。
//
// 用途：现场某一类错误一秒内可达数百次（如工具审计上报 400 单秒 562 次），逐条打印会淹没日志、
// 拖慢磁盘已经紧张的主机；完全不打又无法排查。这里折中为「首次 + 每 N 次」，累计次数始终准确。
package ratelog

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// maxKeys 限制 key 数量，防止调用方把不可信内容拼进 key 导致内存增长。
const maxKeys = 256

const overflowKey = "_other"

// DefaultQuietWindow：同一 key 超过这么久没出现，就视为上一轮故障已结束，计数归零。
// 否则长期运行的进程里，第二轮故障的第一条日志可能因为累计值不是 1 而被吞掉。
const DefaultQuietWindow = 10 * time.Minute

type entry struct {
	count uint64
	last  time.Time
}

type Logger struct {
	every  uint64
	window time.Duration
	now    func() time.Time // 测试可注入
	mu     sync.Mutex
	counts map[string]*entry
}

// New 返回使用 DefaultQuietWindow 的限频器。
func New(every int) *Logger { return NewWithWindow(every, DefaultQuietWindow, nil) }

// NewWithWindow 指定静默窗口（<=0 表示永不归零）与时钟（nil 用 time.Now）。
func NewWithWindow(every int, window time.Duration, now func() time.Time) *Logger {
	if every <= 0 {
		every = 1 << 30 // 只打首条
	}
	if now == nil {
		now = time.Now
	}
	return &Logger{every: uint64(every), window: window, now: now, counts: make(map[string]*entry)}
}

// Printf 记一次 key 事件；仅在首次与每 every 次输出。输出行尾追加 total=累计次数。
func (l *Logger) Printf(key, format string, args ...any) {
	if l == nil {
		return
	}
	l.mu.Lock()
	// 预留一个名额给溢出桶，保证 key 总数（含 _other）不超过 maxKeys。
	if _, ok := l.counts[key]; !ok && len(l.counts) >= maxKeys-1 {
		key = overflowKey
	}
	e := l.counts[key]
	if e == nil {
		e = &entry{}
		l.counts[key] = e
	}
	now := l.now()
	if l.window > 0 && e.count > 0 && now.Sub(e.last) > l.window {
		e.count = 0 // 安静了足够久：新一轮故障，从第 1 条重新开始
	}
	e.last = now
	e.count++
	n := e.count
	l.mu.Unlock()
	if n == 1 || n%l.every == 0 {
		log.Printf("%s total=%d", fmt.Sprintf(format, args...), n)
	}
}

// Count 返回某 key 当前一轮的累计次数（含被抑制的；静默超过窗口后重新计）。
func (l *Logger) Count(key string) uint64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.counts[key]; e != nil {
		return e.count
	}
	return 0
}

// Keys 返回当前 key 数量（测试用）。
func (l *Logger) Keys() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.counts)
}
