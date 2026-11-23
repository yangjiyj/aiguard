package alert

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeSettings struct {
	values map[string]string
}

func (f *fakeSettings) Get(ctx context.Context, key string) (*repository.SystemSetting, error) {
	if v, ok := f.values[key]; ok {
		return &repository.SystemSetting{Key: key, Value: v}, nil
	}
	return nil, nil
}

func (f *fakeSettings) Set(ctx context.Context, key, value string) error {
	if f.values == nil {
		f.values = map[string]string{}
	}
	f.values[key] = value
	return nil
}

func TestGroupBackfillSkipsWhenDone(t *testing.T) {
	settings := &fakeSettings{values: map[string]string{backfillDoneKey: "true"}}
	// db/groups 均为 nil：若 done 短路未生效将 panic/报错
	g := NewGroupBackfill(nil, nil, settings)
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("done 标记应短路直接返回, got err=%v", err)
	}
}

func TestBackfillCheckpointRoundTrip(t *testing.T) {
	cp := backfillCheckpoint{CreatedAt: time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC), ID: "evt_x"}
	raw := marshalBackfillCheckpoint(cp)
	got := parseBackfillCheckpoint(raw)
	if !got.CreatedAt.Equal(cp.CreatedAt) || got.ID != cp.ID {
		t.Fatalf("断点序列化回环失败: %+v vs %+v", got, cp)
	}
	// 空/坏值回退零起点（从头扫，幂等无害）
	zero := parseBackfillCheckpoint("")
	if !zero.CreatedAt.Equal(time.Unix(0, 0).UTC()) || zero.ID != "" {
		t.Fatalf("空断点应回退零起点: %+v", zero)
	}
	if bad := parseBackfillCheckpoint("{not json"); !bad.CreatedAt.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("坏断点应回退零起点: %+v", bad)
	}
}
