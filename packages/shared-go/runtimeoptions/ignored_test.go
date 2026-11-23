package runtimeoptions

import (
	"reflect"
	"testing"
)

// 复审第四轮：不认识的取值周期刷新时只在变化时打日志。
func TestIgnoredValuesReportsOnlyChanges(t *testing.T) {
	var log IgnoredValues
	if got := log.Changed(map[string]string{"a": "x", "b": "y"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("首次应报两个键：%v", got)
	}
	if got := log.Changed(map[string]string{"a": "x", "b": "y"}); len(got) != 0 {
		t.Fatalf("取值没变不再报：%v", got)
	}
	if got := log.Changed(map[string]string{"a": "z"}); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("取值变化才报：%v", got)
	}
	if got := log.Changed(nil); len(got) != 0 {
		t.Fatalf("恢复正常不报：%v", got)
	}
	if got := log.Changed(map[string]string{"b": "y"}); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("恢复后又出现要再报：%v", got)
	}
}
