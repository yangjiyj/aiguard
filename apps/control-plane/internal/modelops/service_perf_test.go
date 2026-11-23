package modelops

import (
	"context"
	"errors"
	"testing"
	"time"
)

type perfStore struct {
	Store
	calls  int
	report ModelPerformanceReport
}

func (p *perfStore) GetModelPerformance(_ context.Context, _ string, hours int) (ModelPerformanceReport, error) {
	p.calls++
	r := p.report
	r.WindowHours = hours
	return r, nil
}

func TestServicePortalPerformanceFiltersAuthorisedModelsAndCaches(t *testing.T) {
	store := &perfStore{report: ModelPerformanceReport{Data: []ModelPerformance{{ModelName: "a"}, {ModelName: "b"}, {ModelName: "c"}}}}
	svc := NewService(store, nil)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	got, err := svc.PortalPerformance(context.Background(), "t", 168, []string{"c", " a ", "zz"})
	if err != nil || len(got.Data) != 2 || got.Data[0].ModelName != "a" || got.Data[1].ModelName != "c" {
		t.Fatalf("授权过滤错误: %+v %v", got, err)
	}
	if _, err = svc.PortalPerformance(context.Background(), "t", 168, []string{"b"}); err != nil || store.calls != 1 {
		t.Fatalf("60 秒内必须命中缓存: calls=%d", store.calls)
	}
	if empty, _ := svc.PortalPerformance(context.Background(), "t", 168, nil); len(empty.Data) != 0 || store.calls != 1 {
		t.Fatal("空授权列表不查库且返回空")
	}
	if _, err = svc.PortalPerformance(context.Background(), "t", 24, []string{"a"}); err != nil || store.calls != 2 {
		t.Fatalf("不同窗口独立缓存: calls=%d", store.calls)
	}
	if _, err = svc.PortalPerformance(context.Background(), "other", 168, []string{"a"}); err != nil || store.calls != 3 {
		t.Fatalf("不同租户独立缓存: calls=%d", store.calls)
	}
	now = now.Add(61 * time.Second)
	if _, err = svc.PortalPerformance(context.Background(), "t", 168, []string{"a"}); err != nil || store.calls != 4 {
		t.Fatalf("过期后必须重新查询: calls=%d", store.calls)
	}
	if _, err = svc.PortalPerformance(context.Background(), "t", 6, []string{"a"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("非法窗口: %v", err)
	}
}
