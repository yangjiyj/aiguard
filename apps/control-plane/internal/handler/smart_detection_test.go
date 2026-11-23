package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// SFIX-1(b): 编译期锁死——真 *repository.SecurityEventRepository 必须满足 SemanticEventReader，
// 这样 cmd/server/main.go 的 `SemanticEventReader: securityEventRepo` 接线才是类型安全的、
// 不会悄悄退化成 nil（reader 未接线时生产 cascade/hits 恒 0）。接口变更破坏接线会在此处编译失败。
var _ SemanticEventReader = (*repository.SecurityEventRepository)(nil)

// SFIX-1(c): 同理锁死 TriageSuppressedReader 接线——真 repo 经 CountTriageSuppressedSince 满足，
// main.go 的 `TriageSuppressedReader: securityEventRepo` 才类型安全，不退化成 nil（fp_suppressed 恒 0）。
var _ TriageSuppressedReader = (*repository.SecurityEventRepository)(nil)

// mkEvent 构造一个 event_type=semantic_attack 的 SecurityEvent，findings 由入参装配。
func mkSemanticEvent(findings []any) *repository.SecurityEvent {
	return &repository.SecurityEvent{
		EventType: "semantic_attack",
		MatchedSummary: map[string]interface{}{
			"findings": findings,
		},
	}
}

func TestAggregateSmartDetectionSplitsTier1VsEscalated(t *testing.T) {
	events := []*repository.SecurityEvent{
		mkSemanticEvent([]any{map[string]any{"rule_id": "semantic_tier1", "category": "jailbreak"}}),
		mkSemanticEvent([]any{map[string]any{"rule_id": "semantic_judge_3b", "category": "role_play"}}),
		mkSemanticEvent([]any{map[string]any{"rule_id": "semantic_tier1", "category": "jailbreak"}}),
	}

	cascade, _ := aggregateSmartDetection(events)

	if cascade.Total != 3 {
		t.Errorf("total = %d, want 3", cascade.Total)
	}
	if cascade.Tier1Direct != 2 {
		t.Errorf("tier1_direct = %d, want 2", cascade.Tier1Direct)
	}
	if cascade.Escalated3B != 1 {
		t.Errorf("escalated_3b = %d, want 1", cascade.Escalated3B)
	}
	if math.Abs(cascade.GrayRate-(1.0/3.0)) >= 1e-9 {
		t.Errorf("gray_rate = %v, want ~%v", cascade.GrayRate, 1.0/3.0)
	}
	if math.Abs(cascade.CapacityMultiplier-3.0) >= 1e-9 {
		t.Errorf("capacity_multiplier = %v, want 3.0", cascade.CapacityMultiplier)
	}
}

func TestAggregateSmartDetectionCountsFpSuppressed(t *testing.T) {
	suppressible := mkSemanticEvent([]any{
		map[string]any{
			"rule_id":  "semantic_tier1",
			"category": "jailbreak",
			"triage":   map[string]any{"verdict": "likely_false_positive"},
		},
	})

	_, hits := aggregateSmartDetection([]*repository.SecurityEvent{suppressible})

	if hits.FpSuppressed != 1 {
		t.Errorf("fp_suppressed = %d, want 1", hits.FpSuppressed)
	}
}

func TestAggregateSmartDetectionCategoryHistogram(t *testing.T) {
	events := []*repository.SecurityEvent{
		mkSemanticEvent([]any{map[string]any{"rule_id": "semantic_tier1", "category": "jailbreak"}}),
		mkSemanticEvent([]any{map[string]any{"rule_id": "semantic_judge_3b", "category": "role_play"}}),
		mkSemanticEvent([]any{map[string]any{"rule_id": "semantic_tier1", "category": "jailbreak"}}),
	}

	_, hits := aggregateSmartDetection(events)

	if hits.Attacks != 3 {
		t.Errorf("attacks = %d, want 3", hits.Attacks)
	}
	if hits.ByCategory["jailbreak"] != 2 {
		t.Errorf("by_category[jailbreak] = %d, want 2", hits.ByCategory["jailbreak"])
	}
	if hits.ByCategory["role_play"] != 1 {
		t.Errorf("by_category[role_play] = %d, want 1", hits.ByCategory["role_play"])
	}
}

func TestAggregateSmartDetectionEmptyNoPanic(t *testing.T) {
	cascade, hits := aggregateSmartDetection(nil)

	if cascade.Total != 0 || cascade.Tier1Direct != 0 || cascade.Escalated3B != 0 || cascade.Passed != 0 {
		t.Errorf("expected all-zero cascade, got %+v", cascade)
	}
	if cascade.GrayRate != 0 {
		t.Errorf("gray_rate = %v, want 0", cascade.GrayRate)
	}
	if cascade.CapacityMultiplier != 0 {
		t.Errorf("capacity_multiplier = %v, want 0", cascade.CapacityMultiplier)
	}
	if hits.Attacks != 0 || hits.FpSuppressed != 0 {
		t.Errorf("expected all-zero hits, got %+v", hits)
	}
	if len(hits.ByCategory) != 0 {
		t.Errorf("by_category should be empty, got %v", hits.ByCategory)
	}
}

// fakeSemanticReader 是 CP-2 测试用的最小 SemanticEventReader 假实现（CP-3 会让真 repo 满足同接口）。
type fakeSemanticReader struct {
	events []*repository.SecurityEvent
	err    error
}

func (f *fakeSemanticReader) ListSemanticSince(ctx context.Context, hours int) ([]*repository.SecurityEvent, error) {
	return f.events, f.err
}

// fakeTriageReader 是 SFIX-1(c) 测试用的 TriageSuppressedReader 假实现：
// 误报压制发生在 security_check 桶（意图类 finding 带 triage.verdict=likely_false_positive），
// 不在 semantic_attack 桶。故 fp_suppressed 不能从 semantic_attack 切片推（恒 0 假指标），
// 必须从这条跨桶计数读源取。
type fakeTriageReader struct {
	count int
	err   error
	// gotHours 记录 handler 传入的窗，验证与 overview 时间窗一致。
	gotHours int
}

func (f *fakeTriageReader) CountTriageSuppressedSince(ctx context.Context, hours int) (int, error) {
	f.gotHours = hours
	return f.count, f.err
}

// TestGetSmartDetectionOverviewFpSuppressedFromTriageReader：
// SFIX-1(c) 红线——fp_suppressed 必须取自跨桶 triage 压制计数（fakeTriageReader），
// 而非 semantic_attack 命中切片。构造：semantic 切片里没有任何可压制事件（会让旧口径为 0），
// 但跨桶 reader 报 7 → overview.hits.fp_suppressed 必须 == 7。
func TestGetSmartDetectionOverviewFpSuppressedFromTriageReader(t *testing.T) {
	t.Setenv("TIER1_CLASSIFIER_URL", "http://127.0.0.1:1")

	repo := &capturingSystemRepo{settings: map[string]string{}}
	// semantic 切片全是未压制命中（无 triage）→ 旧口径 fp_suppressed=0。
	semReader := &fakeSemanticReader{events: []*repository.SecurityEvent{
		mkSemanticEvent([]any{map[string]any{"rule_id": "semantic_tier1", "category": "jailbreak"}}),
	}}
	triageReader := &fakeTriageReader{count: 7}
	deps := &Dependencies{
		SystemRepo:             repo,
		SemanticEventReader:    semReader,
		TriageSuppressedReader: triageReader,
	}

	w := httptest.NewRecorder()
	GetSmartDetectionOverview(deps).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/security/smart-detection/overview", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got struct {
		Hits struct {
			Attacks      int `json:"attacks"`
			FpSuppressed int `json:"fp_suppressed"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	if got.Hits.FpSuppressed != 7 {
		t.Errorf("hits.fp_suppressed = %d, want 7（取自跨桶 triage 压制计数，非 semantic_attack 切片）", got.Hits.FpSuppressed)
	}
	// 命中数仍来自 semantic 切片，不受 triage reader 影响。
	if got.Hits.Attacks != 1 {
		t.Errorf("hits.attacks = %d, want 1", got.Hits.Attacks)
	}
	// 传入窗须与 overview 时间窗一致。
	if triageReader.gotHours != smartConsoleWindowHours() {
		t.Errorf("triage reader hours = %d, want %d", triageReader.gotHours, smartConsoleWindowHours())
	}
}

// TestGetSmartDetectionOverviewFpSuppressedReaderMissingDegradesToZero：
// TriageSuppressedReader 未接线（nil）或探测出错 → fp_suppressed 降级为 0，不崩、仍出 200。
func TestGetSmartDetectionOverviewFpSuppressedReaderMissingDegradesToZero(t *testing.T) {
	t.Setenv("TIER1_CLASSIFIER_URL", "http://127.0.0.1:1")

	repo := &capturingSystemRepo{settings: map[string]string{}}
	semReader := &fakeSemanticReader{events: nil}
	// TriageSuppressedReader 故意不接线。
	deps := &Dependencies{SystemRepo: repo, SemanticEventReader: semReader}

	w := httptest.NewRecorder()
	GetSmartDetectionOverview(deps).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/security/smart-detection/overview", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got struct {
		Hits struct {
			FpSuppressed int `json:"fp_suppressed"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	if got.Hits.FpSuppressed != 0 {
		t.Errorf("reader 缺失应降级 fp_suppressed=0, got %d", got.Hits.FpSuppressed)
	}
}

// TestGetSmartDetectionOverviewShapeAndConfigEcho：配置回显 + sidecar 探测健康 + 聚合形状。
func TestGetSmartDetectionOverviewShapeAndConfigEcho(t *testing.T) {
	// 冒充 sidecar：/health 报健康+模型已加载；/stats 报延迟分位。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			_, _ = w.Write([]byte(`{"status":"ok","model_loaded":true}`))
		case "/stats":
			_, _ = w.Write([]byte(`{"classify_count":10,"latency_p50_ms":4.2,"latency_p95_ms":9.1}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("TIER1_CLASSIFIER_URL", srv.URL)

	repo := &capturingSystemRepo{settings: map[string]string{
		"tier1_enabled":        "true",
		"tier1_low_threshold":  "0.35",
		"tier1_high_threshold": "0.9",
	}}
	reader := &fakeSemanticReader{events: []*repository.SecurityEvent{
		mkSemanticEvent([]any{map[string]any{"rule_id": "semantic_tier1", "category": "jailbreak"}}),
		mkSemanticEvent([]any{map[string]any{"rule_id": "semantic_judge_3b", "category": "role_play"}}),
	}}
	deps := &Dependencies{SystemRepo: repo, SemanticEventReader: reader}

	w := httptest.NewRecorder()
	GetSmartDetectionOverview(deps).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/security/smart-detection/overview", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got struct {
		Status struct {
			SidecarHealthy bool `json:"sidecar_healthy"`
			ModelLoaded    bool `json:"model_loaded"`
			Thresholds     struct {
				Low  float64 `json:"low"`
				High float64 `json:"high"`
			} `json:"thresholds"`
			Switches struct {
				Tier1Enabled         bool `json:"tier1_enabled"`
				FpSuppressionEnabled bool `json:"fp_suppression_enabled"`
			} `json:"switches"`
		} `json:"status"`
		Cascade struct {
			Total       int `json:"total"`
			Tier1Direct int `json:"tier1_direct"`
			Escalated3B int `json:"escalated_3b"`
		} `json:"cascade"`
		Hits struct {
			Attacks    int            `json:"attacks"`
			ByCategory map[string]int `json:"by_category"`
		} `json:"hits"`
		Latency struct {
			P50Ms float64 `json:"p50_ms"`
			P95Ms float64 `json:"p95_ms"`
		} `json:"latency"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}

	// 配置回显
	if got.Status.Thresholds.Low != 0.35 {
		t.Errorf("thresholds.low = %v, want 0.35", got.Status.Thresholds.Low)
	}
	if got.Status.Thresholds.High != 0.9 {
		t.Errorf("thresholds.high = %v, want 0.9", got.Status.Thresholds.High)
	}
	if !got.Status.Switches.Tier1Enabled {
		t.Errorf("switches.tier1_enabled = false, want true（显式配置 tier1_enabled=true）")
	}
	// fp_suppression_enabled 未在 settings 配置 → 走出厂兜底；引擎/compose 默认关，故必须回显 false。
	if got.Status.Switches.FpSuppressionEnabled {
		t.Errorf("switches.fp_suppression_enabled = true, want false（未配置走出厂兜底=false，与 security-engine SECURITY_FP_SUPPRESSION_ENABLED 默认关一致）")
	}
	// sidecar 探测
	if !got.Status.SidecarHealthy {
		t.Errorf("sidecar_healthy = false, want true")
	}
	if !got.Status.ModelLoaded {
		t.Errorf("model_loaded = false, want true")
	}
	if got.Latency.P50Ms != 4.2 {
		t.Errorf("latency.p50_ms = %v, want 4.2", got.Latency.P50Ms)
	}
	if got.Latency.P95Ms != 9.1 {
		t.Errorf("latency.p95_ms = %v, want 9.1", got.Latency.P95Ms)
	}
	// 聚合
	if got.Cascade.Total != 2 {
		t.Errorf("cascade.total = %d, want 2", got.Cascade.Total)
	}
	if got.Cascade.Tier1Direct != 1 {
		t.Errorf("cascade.tier1_direct = %d, want 1", got.Cascade.Tier1Direct)
	}
	if got.Cascade.Escalated3B != 1 {
		t.Errorf("cascade.escalated_3b = %d, want 1", got.Cascade.Escalated3B)
	}
	if got.Hits.Attacks != 2 {
		t.Errorf("hits.attacks = %d, want 2", got.Hits.Attacks)
	}
	if got.Hits.ByCategory["jailbreak"] != 1 || got.Hits.ByCategory["role_play"] != 1 {
		t.Errorf("by_category = %v, want jailbreak:1 role_play:1", got.Hits.ByCategory)
	}
}

// TestGetSmartDetectionOverviewSidecarDownStillReturnsStats：sidecar 不可达仍 200、统计照出、状态降级。
func TestGetSmartDetectionOverviewSidecarDownStillReturnsStats(t *testing.T) {
	// 指向关闭端口，探测必失败。
	t.Setenv("TIER1_CLASSIFIER_URL", "http://127.0.0.1:1")

	repo := &capturingSystemRepo{settings: map[string]string{}}
	reader := &fakeSemanticReader{events: []*repository.SecurityEvent{
		mkSemanticEvent([]any{map[string]any{"rule_id": "semantic_tier1", "category": "jailbreak"}}),
	}}
	deps := &Dependencies{SystemRepo: repo, SemanticEventReader: reader}

	w := httptest.NewRecorder()
	GetSmartDetectionOverview(deps).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/security/smart-detection/overview", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got struct {
		Status struct {
			SidecarHealthy bool `json:"sidecar_healthy"`
			ModelLoaded    bool `json:"model_loaded"`
		} `json:"status"`
		Cascade struct {
			Total int `json:"total"`
		} `json:"cascade"`
		Hits struct {
			Attacks int `json:"attacks"`
		} `json:"hits"`
		Latency struct {
			P50Ms float64 `json:"p50_ms"`
		} `json:"latency"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	if got.Status.SidecarHealthy {
		t.Errorf("sidecar_healthy = true, want false (探测失败降级)")
	}
	if got.Status.ModelLoaded {
		t.Errorf("model_loaded = true, want false (探测失败降级)")
	}
	if got.Latency.P50Ms != 0 {
		t.Errorf("latency.p50_ms = %v, want 0 (探测失败置0)", got.Latency.P50Ms)
	}
	// 统计照出
	if got.Cascade.Total != 1 {
		t.Errorf("cascade.total = %d, want 1 (sidecar 不影响聚合)", got.Cascade.Total)
	}
	if got.Hits.Attacks != 1 {
		t.Errorf("hits.attacks = %d, want 1", got.Hits.Attacks)
	}
}

// TestGetSmartDetectionOverviewDefaultThresholdsMatchEngine：CP-2 修复轮。
// system_settings 缺键时，overview 必须回显与免配置交付一致的确定默认值。
func TestGetSmartDetectionOverviewDefaultThresholdsMatchEngine(t *testing.T) {
	t.Setenv("TIER1_CLASSIFIER_URL", "http://127.0.0.1:1")

	// 空 settings：三键（low/high 阈值 + 两开关）全走出厂兜底。
	repo := &capturingSystemRepo{settings: map[string]string{}}
	reader := &fakeSemanticReader{events: nil}
	deps := &Dependencies{SystemRepo: repo, SemanticEventReader: reader}

	w := httptest.NewRecorder()
	GetSmartDetectionOverview(deps).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/security/smart-detection/overview", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got struct {
		Status struct {
			Thresholds struct {
				Low  float64 `json:"low"`
				High float64 `json:"high"`
			} `json:"thresholds"`
			Switches struct {
				Tier1Enabled         bool `json:"tier1_enabled"`
				FpSuppressionEnabled bool `json:"fp_suppression_enabled"`
			} `json:"switches"`
		} `json:"status"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	// 与 control-plane 投影和 compose 交付默认保持一致。
	if got.Status.Thresholds.Low != 0.30 {
		t.Errorf("thresholds.low(default fallback) = %v, want 0.30", got.Status.Thresholds.Low)
	}
	if got.Status.Thresholds.High != 0.70 {
		t.Errorf("thresholds.high(default fallback) = %v, want 0.70", got.Status.Thresholds.High)
	}
	// Tier-1 默认开启；误报压制仍默认关闭。
	if !got.Status.Switches.Tier1Enabled {
		t.Errorf("switches.tier1_enabled(default fallback) = false, want true")
	}
	if got.Status.Switches.FpSuppressionEnabled {
		t.Errorf("switches.fp_suppression_enabled(默认兜底) = true, want false（与 security-engine SECURITY_FP_SUPPRESSION_ENABLED 默认关一致）")
	}
}

// TestGetSmartDetectionOverviewRequiresUser：无 auth user → 401。
func TestGetSmartDetectionOverviewRequiresUser(t *testing.T) {
	deps := &Dependencies{SystemRepo: &capturingSystemRepo{settings: map[string]string{}}}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/security/smart-detection/overview", nil)
	w := httptest.NewRecorder()

	GetSmartDetectionOverview(deps).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// ---- CP-4: config 写端点（PUT）----

// smartConfigBody 把 map 序列化成请求体字节，测试用。
func smartConfigBody(t *testing.T, m map[string]interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return b
}

// nonAdminCtxRequest 注入非 platform_admin 用户（tenant_admin），用于 403 门禁验证。
func nonAdminCtxRequest(method, target string, body []byte) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_tenant_admin",
		TenantID: "tenant_default",
		Role:     "tenant_admin",
		Status:   "active",
	})
	return req.WithContext(ctx)
}

// TestUpdateSmartConfigWritesFourKeys：四键（两开关 + 两阈值）全传，正常落库。
func TestUpdateSmartConfigWritesFourKeys(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	deps := &Dependencies{SystemRepo: repo}
	body := smartConfigBody(t, map[string]interface{}{
		"tier1_enabled":          true,
		"tier1_low_threshold":    0.25,
		"tier1_high_threshold":   0.75,
		"fp_suppression_enabled": false,
	})

	w := httptest.NewRecorder()
	UpdateSmartDetectionConfig(deps).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/security/smart-detection/config", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if repo.settings["tier1_enabled"] != "true" {
		t.Errorf("tier1_enabled = %q, want \"true\"", repo.settings["tier1_enabled"])
	}
	if repo.settings["tier1_low_threshold"] != "0.25" {
		t.Errorf("tier1_low_threshold = %q, want \"0.25\"", repo.settings["tier1_low_threshold"])
	}
	if repo.settings["tier1_high_threshold"] != "0.75" {
		t.Errorf("tier1_high_threshold = %q, want \"0.75\"", repo.settings["tier1_high_threshold"])
	}
	if repo.settings["fp_suppression_enabled"] != "false" {
		t.Errorf("fp_suppression_enabled = %q, want \"false\"", repo.settings["fp_suppression_enabled"])
	}
}

// TestUpdateSmartConfigRejectsLowGtHigh：同传 low>high → 400，且一个键都不写。
func TestUpdateSmartConfigRejectsLowGtHigh(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	deps := &Dependencies{SystemRepo: repo}
	body := smartConfigBody(t, map[string]interface{}{
		"tier1_low_threshold":  0.9,
		"tier1_high_threshold": 0.2,
	})

	w := httptest.NewRecorder()
	UpdateSmartDetectionConfig(deps).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/security/smart-detection/config", body))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}
	if len(repo.settings) != 0 {
		t.Errorf("校验失败必须不写库, got settings=%v", repo.settings)
	}
}

// TestUpdateSmartConfigRejectsOutOfRange：阈值越界(>1) → 400。
func TestUpdateSmartConfigRejectsOutOfRange(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	deps := &Dependencies{SystemRepo: repo}
	body := smartConfigBody(t, map[string]interface{}{
		"tier1_low_threshold": 1.5,
	})

	w := httptest.NewRecorder()
	UpdateSmartDetectionConfig(deps).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/security/smart-detection/config", body))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}
	if len(repo.settings) != 0 {
		t.Errorf("校验失败必须不写库, got settings=%v", repo.settings)
	}
}

// TestUpdateSmartConfigRequiresPlatformAdmin：非 platform_admin → 403。
func TestUpdateSmartConfigRequiresPlatformAdmin(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	deps := &Dependencies{SystemRepo: repo}
	body := smartConfigBody(t, map[string]interface{}{"tier1_enabled": true})

	w := httptest.NewRecorder()
	UpdateSmartDetectionConfig(deps).ServeHTTP(w, nonAdminCtxRequest(http.MethodPut, "/admin/v1/security/smart-detection/config", body))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusForbidden, w.Body.String())
	}
	if len(repo.settings) != 0 {
		t.Errorf("门禁拒绝必须不写库, got settings=%v", repo.settings)
	}
}

// TestUpdateSmartConfigIgnoresEnforcementFields：红线——body 里出现 audit_only/enforce
// 等拦截意图字段一律忽略，绝不透传落库。
func TestUpdateSmartConfigIgnoresEnforcementFields(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	deps := &Dependencies{SystemRepo: repo}
	body := smartConfigBody(t, map[string]interface{}{
		"tier1_enabled": true,
		"audit_only":    false,
		"enforce":       true,
	})

	w := httptest.NewRecorder()
	UpdateSmartDetectionConfig(deps).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/security/smart-detection/config", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if repo.settings["tier1_enabled"] != "true" {
		t.Errorf("tier1_enabled = %q, want \"true\"", repo.settings["tier1_enabled"])
	}
	if _, ok := repo.settings["audit_only"]; ok {
		t.Errorf("红线破坏：audit_only 被透传落库 = %q", repo.settings["audit_only"])
	}
	if _, ok := repo.settings["enforce"]; ok {
		t.Errorf("红线破坏：enforce 被透传落库 = %q", repo.settings["enforce"])
	}
}

// TestUpdateSmartConfigPartialRespectsExistingHigh：只传 low，需与现有 high 比较；
// 预置 high=0.6，传 low=0.7（0.7>0.6 破坏 low<=high）→ 400。
func TestUpdateSmartConfigPartialRespectsExistingHigh(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{"tier1_high_threshold": "0.6"}}
	deps := &Dependencies{SystemRepo: repo}
	body := smartConfigBody(t, map[string]interface{}{
		"tier1_low_threshold": 0.7,
	})

	w := httptest.NewRecorder()
	UpdateSmartDetectionConfig(deps).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/security/smart-detection/config", body))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}
	// 现有 high 未被覆盖，且 low 未落库。
	if repo.settings["tier1_high_threshold"] != "0.6" {
		t.Errorf("现有 tier1_high_threshold 被改动 = %q, want \"0.6\"", repo.settings["tier1_high_threshold"])
	}
	if _, ok := repo.settings["tier1_low_threshold"]; ok {
		t.Errorf("校验失败仍写了 tier1_low_threshold = %q", repo.settings["tier1_low_threshold"])
	}
}

// TestUpdateSmartConfigWritesAudit：写成功后必须留一条审计记录（与全仓所有变更类 admin
// 端点一致，锁死安全敏感写路径的可审计性）。断言 action_type/target 对齐，且明细以
// map[string]interface{} 承载——否则 logAudit 会静默丢空明细。
func TestUpdateSmartConfigWritesAudit(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	deps := &Dependencies{SystemRepo: repo}
	body := smartConfigBody(t, map[string]interface{}{
		"tier1_enabled":          true,
		"tier1_low_threshold":    0.25,
		"tier1_high_threshold":   0.75,
		"fp_suppression_enabled": false,
	})

	w := httptest.NewRecorder()
	UpdateSmartDetectionConfig(deps).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/security/smart-detection/config", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if len(repo.auditOps) != 1 {
		t.Fatalf("应记录 1 条审计, got %d", len(repo.auditOps))
	}
	op := repo.auditOps[0]
	if op.ActionType != "update_smart_detection_config" {
		t.Errorf("action_type = %q, want \"update_smart_detection_config\"", op.ActionType)
	}
	if op.TargetType != "system" || op.TargetID != "settings" {
		t.Errorf("audit target = %s/%s, want system/settings", op.TargetType, op.TargetID)
	}
	// 明细须以 map[string]interface{} 承载（否则被 logAudit 静默丢空）——校验写入的键出现在明细里。
	if op.ActionDetail["tier1_enabled"] != "true" {
		t.Errorf("audit detail tier1_enabled = %v, want \"true\"（明细被丢空说明未传 map[string]interface{}）", op.ActionDetail["tier1_enabled"])
	}
	if op.ActionDetail["tier1_low_threshold"] != "0.25" {
		t.Errorf("audit detail tier1_low_threshold = %v, want \"0.25\"", op.ActionDetail["tier1_low_threshold"])
	}
}
