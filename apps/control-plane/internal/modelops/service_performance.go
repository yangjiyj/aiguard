package modelops

import (
	"context"
	"strconv"
	"strings"
	"time"
)

type portalPerfEntry struct {
	at     time.Time
	report ModelPerformanceReport
}

const portalPerformanceTTL = 60 * time.Second

func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Service) ProviderMonitor(ctx context.Context, tenant string, f ReadFilter) (ProviderMonitor, error) {
	return s.store.GetProviderMonitor(ctx, tenant, f)
}

// PortalPerformance 按「租户 + 窗口」缓存租户内全部模型的聚合 60 秒，再按员工授权列表过滤。
// 空授权列表返回空结果，绝不返回全部模型。
func (s *Service) PortalPerformance(ctx context.Context, tenant string, windowHours int, models []string) (ModelPerformanceReport, error) {
	hours, _, _, err := portalPerformanceWindow(windowHours)
	if err != nil {
		return ModelPerformanceReport{}, err
	}
	allowed := map[string]bool{}
	for _, model := range models {
		if model = strings.TrimSpace(model); model != "" {
			allowed[model] = true
		}
	}
	if len(allowed) == 0 {
		return ModelPerformanceReport{Data: []ModelPerformance{}, WindowHours: hours, GeneratedAt: s.clock().UTC()}, nil
	}
	key := tenant + "\x00" + strconv.Itoa(hours)
	s.perfMu.Lock()
	entry, ok := s.perf[key]
	s.perfMu.Unlock()
	if !ok || s.clock().Sub(entry.at) >= portalPerformanceTTL {
		report, err := s.store.GetModelPerformance(ctx, tenant, hours)
		if err != nil {
			return ModelPerformanceReport{}, err
		}
		entry = portalPerfEntry{at: s.clock(), report: report}
		s.perfMu.Lock()
		if s.perf == nil {
			s.perf = map[string]portalPerfEntry{}
		}
		s.perf[key] = entry
		s.perfMu.Unlock()
	}
	out := entry.report
	out.Data = make([]ModelPerformance, 0, len(allowed))
	for _, item := range entry.report.Data {
		if allowed[item.ModelName] {
			out.Data = append(out.Data, item)
		}
	}
	return out, nil
}
