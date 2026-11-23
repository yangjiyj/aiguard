// Package backoff 提供「指数退避 + 抖动」，用于后台任务在依赖（数据库、控制面）失败时的重试节奏。
//
// 背景：现场数据库连接打满（too many clients）时，固定 2 秒一次的重试 worker 会持续争抢连接，
// 把本就紧张的连接池再顶一把。失败时拉长间隔、成功后复位，并加抖动避免多副本同步冲击。
package backoff

import (
	"math/rand"
	"time"
)

// DefaultJitter 是抖动占比：实际等待时间落在 [delay*(1-DefaultJitter), delay]，不会超过上限。
const DefaultJitter = 0.5

// Backoff 不是并发安全的；每个循环一个实例。
type Backoff struct {
	base, max time.Duration
	failures  int
	rand      func() float64 // 返回 [0,1)；测试中可替换
}

// New 返回退避器。base<=0 取 1 秒；max<base 时取 base。
func New(base, max time.Duration) *Backoff {
	if base <= 0 {
		base = time.Second
	}
	if max < base {
		max = base
	}
	return &Backoff{base: base, max: max, rand: rand.Float64}
}

// Next 记一次失败并返回下次等待时间。
func (b *Backoff) Next() time.Duration {
	delay := b.base
	for i := 0; i < b.failures && delay < b.max; i++ {
		delay *= 2
	}
	if delay > b.max {
		delay = b.max
	}
	if b.failures < 1<<20 { // 防止长期失败时计数溢出
		b.failures++
	}
	jittered := time.Duration(float64(delay) * (1 - DefaultJitter*b.rand()))
	if jittered <= 0 {
		jittered = delay
	}
	return jittered
}

// Reset 在成功后调用，下次失败从 base 重新开始。
func (b *Backoff) Reset() { b.failures = 0 }

// Base 返回基础间隔（成功路径使用）。
func (b *Backoff) Base() time.Duration { return b.base }

// Failures 返回连续失败次数。
func (b *Backoff) Failures() int { return b.failures }
