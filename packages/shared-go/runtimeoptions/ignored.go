package runtimeoptions

import (
	"sort"
	"sync"
)

// IgnoredValues 记住上次因取值不认识而被忽略的键和值，供周期刷新的读取方只在变化时打日志
// （网关、独立代理每次刷新都会遇到同一份配置，不能刷屏）。零值可用，并发安全。
type IgnoredValues struct {
	mu   sync.Mutex
	last map[string]string
}

// Changed 用本次被忽略的键值（键 → 原始取值）替换上次的记录，返回新出现或取值变了的键（已排序）。
// 键恢复正常后再次出现，会重新报告。
func (l *IgnoredValues) Changed(current map[string]string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var changed []string
	for key, value := range current {
		if previous, ok := l.last[key]; !ok || previous != value {
			changed = append(changed, key)
		}
	}
	l.last = make(map[string]string, len(current))
	for key, value := range current {
		l.last[key] = value
	}
	sort.Strings(changed)
	return changed
}
