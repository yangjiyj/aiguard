package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

// SemanticEventReader 是 overview 端点的数据源窄接口：拉时间窗内 event_type=semantic_attack
// 事件。CP-3 让 *repository.SecurityEventRepository 自动满足此接口（新增 ListSemanticSince），
// 届时在路由装配处把真 repo 注入 deps.SemanticEventReader；测试可注入 fake。
type SemanticEventReader interface {
	ListSemanticSince(ctx context.Context, hours int) ([]*repository.SecurityEvent, error)
}

// TriageSuppressedReader 是 fp_suppressed 指标的独立跨桶计数源（SFIX-1(c)）。
//
// security_check 等意图类命中桶，不在 semantic_attack 桶——因为承载被压制 finding 的事件按
// eventTypeForFindings 落到 security_check（纯语义命中才落 semantic_attack）。故 fp_suppressed
// 若仅从 semantic_attack 切片推，对生产恒 0（假指标）。此接口跨全部桶计窗内被 triage 闸压制的
// 事件数，*repository.SecurityEventRepository 经 CountTriageSuppressedSince 满足；测试注入 fake。
type TriageSuppressedReader interface {
	CountTriageSuppressedSince(ctx context.Context, hours int) (int, error)
}

// smartCascade 汇总智能检测级联漏斗的一屏计数（供 CP-2 组装 overview JSON）。
// 本切片全部是命中事件（event_type=semantic_attack）——放行事件不落 security_events，
// 故 Passed 无法从命中事件推出，恒置 0，作为契约占位字段保留（由 CP-2/前端另行说明）。
type smartCascade struct {
	Total       int     // 命中总数 = Tier1Direct + Escalated3B
	Tier1Direct int     // Tier-1 分类器直接判定的命中（含 semantic_tier1 finding）
	Escalated3B int     // 无 Tier-1 finding、经 3B 大模型复核判定的命中
	Passed      int     // 放行数（命中切片无法推出，恒 0 占位）
	GrayRate    float64 // 灰区上抛率 = Escalated3B / Total（Total=0 时为 0）
	// CapacityMultiplier: Tier-1 省下的复核倍数 = Total / max(Escalated3B,1)。
	// Total=0 时为 0。
	CapacityMultiplier float64
}

// smartHits 汇总命中侧统计（供 CP-2 组装 overview JSON）。
type smartHits struct {
	Attacks    int            // 攻击命中数（= smartCascade.Total）
	ByCategory map[string]int // 按 finding.category 计数的类目直方图
	// FpSuppressed 仅计 semantic_attack 桶内被 triage 闸压制的命中，非对外 fp_suppressed 指标源。
	// 对外 hits.fp_suppressed 由 GetSmartDetectionOverview 从 TriageSuppressedReader 跨桶取（SFIX-1(c)：
	// 误报压制多落 security_check 桶，仅从本切片推对生产恒 0）。此字段保留为纯函数自身契约。
	FpSuppressed int
}

// aggregateSmartDetection 把已由 repo 过滤好的 semantic_attack 事件切片聚合成
// 级联/命中两组中间结构。纯函数：不碰 DB、不碰 HTTP，可单测。
//
// 分桶口径（见共享契约「聚合源」）：
//   - event 任一 finding rule_id=="semantic_tier1" → 计入 tier1_direct（Tier-1 直出）。
//   - event 无任何 semantic_tier1 finding → 计入 escalated_3b（经 3B 复核）。
//   - total = tier1_direct + escalated_3b（本切片全是 semantic_attack）。
func aggregateSmartDetection(events []*repository.SecurityEvent) (smartCascade, smartHits) {
	cascade := smartCascade{}
	hits := smartHits{ByCategory: map[string]int{}}

	for _, ev := range events {
		if ev == nil {
			continue
		}
		findingsRaw, _ := ev.MatchedSummary["findings"].([]any)

		// 类目直方图：逐 finding 取非空 category。
		hasTier1 := false
		for _, raw := range findingsRaw {
			fm, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if rid, _ := fm["rule_id"].(string); rid == "semantic_tier1" {
				hasTier1 = true
			}
			if cat, _ := fm["category"].(string); cat != "" {
				hits.ByCategory[cat]++
			}
		}

		cascade.Total++
		if hasTier1 {
			cascade.Tier1Direct++
		} else {
			cascade.Escalated3B++
		}

		if allSemanticTriageSuppressible(findingsRaw) {
			hits.FpSuppressed++
		}
	}

	hits.Attacks = cascade.Total

	if cascade.Total > 0 {
		cascade.GrayRate = float64(cascade.Escalated3B) / float64(cascade.Total)
		denom := cascade.Escalated3B
		if denom < 1 {
			denom = 1
		}
		cascade.CapacityMultiplier = float64(cascade.Total) / float64(denom)
	}

	return cascade, hits
}

// allSemanticTriageSuppressible 照搬 alert.allTriageSuppressible 的语义（本包内实现，
// 不跨包 import alert）：仅当事件的每个 finding 都满足「被标 likely_false_positive
// finding 都让整事件穿透（绝不因个别 FP 藏掉真信号）。
func allSemanticTriageSuppressible(findingsRaw []any) bool {
	sawSuppressible := false
	for _, raw := range findingsRaw {
		fm, ok := raw.(map[string]any)
		if !ok {
			return false // 形状异常 → 不压（fail open）
		}
		if !semanticTriageSaysLikelyFP(fm) {
			return false // 存在非 FP finding → 整事件提升
		}
		sawSuppressible = true
	}
	return sawSuppressible
}

// semanticTriageSaysLikelyFP 报告某 finding 是否被 LLM 异步裁判标为 likely_false_positive。
func semanticTriageSaysLikelyFP(fm map[string]any) bool {
	tr, ok := fm["triage"].(map[string]any)
	if !ok {
		return false
	}
	v, _ := tr["verdict"].(string)
	return v == "likely_false_positive"
}

// ---- CP-2: overview 读端点（配置回显 + sidecar 探测降级 + 聚合组装）----

// 出厂兜底与免配置 full 包一致：Tier-1 默认开启，0.30/0.70 作为性能自适应前的
// 保守阈值；误报压制仍保持关闭，避免弱证据被默认丢弃。
const (
	defaultTier1LowThreshold  = 0.30
	defaultTier1HighThreshold = 0.70
	defaultTier1Enabled       = true
	defaultFpSuppressEnabled  = false
	defaultSmartConsoleWindow = 24 // SMART_CONSOLE_WINDOW_HOURS 缺省窗（小时）
)

// smartSidecarClient 探测 tier1-classifier /health + /stats。
// SSRF 取舍同 lseProbeClient：sidecar 私有化部署在内网，靠克制护栏（只 GET、固定路径、
// 禁跨主机重定向、10s 超时、限响应体）防滥用。
var smartSidecarClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return errCrossHostRedirect
		}
		if len(via) >= 3 {
			return errTooManyRedirects
		}
		return nil
	},
}

var (
	errCrossHostRedirect = &sidecarProbeError{"跨主机重定向已被拒绝"}
	errTooManyRedirects  = &sidecarProbeError{"重定向次数过多"}
)

type sidecarProbeError struct{ msg string }

func (e *sidecarProbeError) Error() string { return e.msg }

// tier1BaseURL 读 sidecar 基址；缺省 http://tier1-classifier:8000（compose 服务名，见 feature_flags.py）。
func tier1BaseURL() string {
	if v := strings.TrimSpace(os.Getenv("TIER1_CLASSIFIER_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://tier1-classifier:8000"
}

// smartConsoleWindowHours 读时间窗（小时），缺省/非法回退默认窗。
func smartConsoleWindowHours() int {
	v := strings.TrimSpace(os.Getenv("SMART_CONSOLE_WINDOW_HOURS"))
	if v == "" {
		return defaultSmartConsoleWindow
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return defaultSmartConsoleWindow
	}
	return n
}

// smartInternalSecret sidecar /stats 鉴权用的内部共享密钥（与 tier1-classifier 同信任域）；
// 仅 env，不上界面。与 lseIntegrationSecret 同源口径。
func smartInternalSecret() string {
	s := strings.TrimSpace(os.Getenv("JJD_INTERNAL_API_SECRET"))
	if s == "" {
		s = strings.TrimSpace(os.Getenv("JJD_PROVIDER_SECRET_KEY"))
	}
	return s
}

// sidecarProbeResult sidecar 一屏状态：健康/模型/延迟。探测失败时全为零值（降级）。
type sidecarProbeResult struct {
	Healthy     bool
	ModelLoaded bool
	P50Ms       float64
	P95Ms       float64
}

// probeSmartSidecar 探 /health（不鉴权，读 model_loaded）+ /stats（带内部 token，读延迟分位）。
// 任何失败都吞错降级（返回零值 result），绝不影响 cascade/hits 输出。
func probeSmartSidecar(ctx context.Context, base, token string) sidecarProbeResult {
	res := sidecarProbeResult{}

	// /health：确认可达 + model_loaded。
	{
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
		if err == nil {
			req.Header.Set("accept", "application/json")
			resp, derr := smartSidecarClient.Do(req)
			if derr == nil {
				func() {
					defer resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						return
					}
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
					var h struct {
						Status      string `json:"status"`
						ModelLoaded bool   `json:"model_loaded"`
					}
					if json.Unmarshal(body, &h) == nil {
						res.Healthy = true
						res.ModelLoaded = h.ModelLoaded
					}
				}()
			}
		}
	}
	// sidecar 不可达 → 不再探 /stats，延迟保持 0。
	if !res.Healthy {
		return res
	}
	// /stats：带内部 token 读延迟分位（探测失败仅丢延迟，不翻转 Healthy）。
	{
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/stats", nil)
		if err == nil {
			req.Header.Set("accept", "application/json")
			if token != "" {
				req.Header.Set(InternalAPISecretHeader, token)
			}
			resp, derr := smartSidecarClient.Do(req)
			if derr == nil {
				func() {
					defer resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						return
					}
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
					var s struct {
						P50Ms float64 `json:"latency_p50_ms"`
						P95Ms float64 `json:"latency_p95_ms"`
					}
					if json.Unmarshal(body, &s) == nil {
						res.P50Ms = s.P50Ms
						res.P95Ms = s.P95Ms
					}
				}()
			}
		}
	}
	return res
}

// parseFloatSetting 从 settings 取 key 的浮点值，缺/非法回退 def。
func parseFloatSetting(s map[string]string, key string, def float64) float64 {
	raw, ok := s[key]
	if !ok {
		return def
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return def
	}
	return f
}

// parseBoolSetting 从 settings 取 key 的布尔值，缺/非法回退 def。
func parseBoolSetting(s map[string]string, key string, def bool) bool {
	raw, ok := s[key]
	if !ok {
		return def
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	return strings.EqualFold(raw, "true")
}

// GetSmartDetectionOverview 组装智能检测 overview：管理员鉴权 → system_settings 回显阈值/开关 →
// 拉窗内 semantic_attack 事件聚合 cascade/hits → 探 sidecar 合并 status/latency（探测失败降级但统计照出）。
func GetSmartDetectionOverview(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}

		// 1) 配置回显（缺键→出厂兜底默认，与 security-engine env 一致）。
		s := map[string]string{}
		if deps != nil && deps.SystemRepo != nil {
			if settings, err := deps.SystemRepo.GetAll(r.Context()); err == nil {
				for _, kv := range settings {
					s[kv.Key] = kv.Value
				}
			}
		}
		low := parseFloatSetting(s, "tier1_low_threshold", defaultTier1LowThreshold)
		high := parseFloatSetting(s, "tier1_high_threshold", defaultTier1HighThreshold)
		tier1Enabled := parseBoolSetting(s, "tier1_enabled", defaultTier1Enabled)
		fpEnabled := parseBoolSetting(s, "fp_suppression_enabled", defaultFpSuppressEnabled)

		// 2) 拉窗内 semantic_attack 事件聚合（reader 缺失时按空聚合，仍出确定态）。
		var events []*repository.SecurityEvent
		if deps != nil && deps.SemanticEventReader != nil {
			if evs, err := deps.SemanticEventReader.ListSemanticSince(r.Context(), smartConsoleWindowHours()); err == nil {
				events = evs
			}
		}
		cascade, hits := aggregateSmartDetection(events)

		// 2.5) fp_suppressed 独立跨桶计数（SFIX-1(c)）：误报压制落在 security_check 桶而非
		// semantic_attack，故不能用 aggregateSmartDetection 从命中切片推（对生产恒 0）。
		// reader 缺失/出错 → 降级为 0，绝不崩、不影响其余输出。
		fpSuppressed := 0
		if deps != nil && deps.TriageSuppressedReader != nil {
			if n, err := deps.TriageSuppressedReader.CountTriageSuppressedSince(r.Context(), smartConsoleWindowHours()); err == nil {
				fpSuppressed = n
			}
		}

		// 3) 探 sidecar（吞错降级；不影响上面的聚合输出）。
		probe := probeSmartSidecar(r.Context(), tier1BaseURL(), smartInternalSecret())

		// 4) 组装契约 JSON（by_category 恒非 nil，前端无需判空）。
		byCategory := hits.ByCategory
		if byCategory == nil {
			byCategory = map[string]int{}
		}
		writeJSON(w, map[string]any{
			"status": map[string]any{
				"sidecar_healthy": probe.Healthy,
				"model_loaded":    probe.ModelLoaded,
				"thresholds": map[string]any{
					"low":  low,
					"high": high,
				},
				"switches": map[string]any{
					"tier1_enabled":          tier1Enabled,
					"fp_suppression_enabled": fpEnabled,
				},
				// C1: low<0.05 turns the cascade off, so every semantic window reaches
				// the judge (measured 10.8 judge calls per request in production).
				// Warn on read; never silently rewrite a value an operator saved.
				"warnings": smartThresholdWarnings(low),
			},
			"cascade": map[string]any{
				"total":               cascade.Total,
				"tier1_direct":        cascade.Tier1Direct,
				"escalated_3b":        cascade.Escalated3B,
				"passed":              cascade.Passed,
				"gray_rate":           cascade.GrayRate,
				"capacity_multiplier": cascade.CapacityMultiplier,
			},
			"hits": map[string]any{
				"attacks":     hits.Attacks,
				"by_category": byCategory,
				// 跨桶 triage 压制计数（非 semantic_attack 切片推导）——见 TriageSuppressedReader 口径。
				"fp_suppressed": fpSuppressed,
			},
			"latency": map[string]any{
				"p50_ms": probe.P50Ms,
				"p95_ms": probe.P95Ms,
			},
		})
	}
}

// ---- CP-4: config 写端点（PUT）----

// smartThresholdOutOfRange 报告阈值是否落在 [0,1] 之外。
// tier1CascadeDisabledBelow is the lower bound under which tier-1 passes (almost)
// every window to the judge, i.e. the cascade is effectively off. Same cut-off as
// security-engine runtime_profile.cascade_warnings.
const tier1CascadeDisabledBelow = 0.05

func smartThresholdOutOfRange(v float64) bool {
	return v < 0 || v > 1
}

// smartThresholdWarnings reports values that materially change cost or coverage.
// Same cut-off as security-engine runtime_profile.cascade_warnings (<0.05), so the
// operator sees one story from the console and from /health.
func smartThresholdWarnings(low float64) []string {
	warnings := []string{}
	if low < tier1CascadeDisabledBelow {
		warnings = append(warnings, "tier1_cascade_disabled")
	}
	return warnings
}

// UpdateSmartDetectionConfig 写智能检测四键（tier1_enabled / tier1_low_threshold /
// tier1_high_threshold / fp_suppression_enabled）到 system_settings，热生效。
//
// 门禁：仅 platform_admin（照搬 UpdateSystemSettings 范式）。
// 校验：阈值须在 [0,1] 且下限不高于上限——单传一个时与对方现有值（缺则出厂兜底默认）比较，
//
//	保证不破坏 low<=high；任一越界/非法/类型不符 → 400。
//
// 红线：只调阈值与两开关，绝不接受/透传任何 enforce/block/audit_only/mode 拦截意图字段——
// 白名单外的键天然被丢弃（不进 settings map），不改变生产 observe-only 姿态。
func UpdateSmartDetectionConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		var raw map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			writeError(w, "invalid_request", "请求体不是合法的 JSON")
			return
		}

		settings := map[string]string{}

		// 两开关：类型须为 bool。
		for _, key := range []string{"tier1_enabled", "fp_suppression_enabled"} {
			if v, ok := raw[key]; ok {
				b, isBool := v.(bool)
				if !isBool {
					writeError(w, "invalid_request", "开关字段必须是布尔值")
					return
				}
				settings[key] = strconv.FormatBool(b)
			}
		}

		// 两阈值：传入者类型须为 number（JSON 解成 float64）。
		lowRaw, lowGiven := raw["tier1_low_threshold"]
		highRaw, highGiven := raw["tier1_high_threshold"]

		var low, high float64
		if lowGiven {
			f, ok := lowRaw.(float64)
			if !ok {
				writeError(w, "invalid_request", "阈值必须是数字")
				return
			}
			low = f
		}
		if highGiven {
			f, ok := highRaw.(float64)
			if !ok {
				writeError(w, "invalid_request", "阈值必须是数字")
				return
			}
			high = f
		}

		// 仅当有阈值传入时才做 low<=high 交叉校验；缺失的一侧用现有值（缺则出厂兜底）补齐。
		if lowGiven || highGiven {
			existing := map[string]string{}
			if deps != nil && deps.SystemRepo != nil {
				if s, err := deps.SystemRepo.Get(r.Context(), "tier1_low_threshold"); err == nil && s != nil {
					existing["tier1_low_threshold"] = s.Value
				}
				if s, err := deps.SystemRepo.Get(r.Context(), "tier1_high_threshold"); err == nil && s != nil {
					existing["tier1_high_threshold"] = s.Value
				}
			}
			if !lowGiven {
				low = parseFloatSetting(existing, "tier1_low_threshold", defaultTier1LowThreshold)
			}
			if !highGiven {
				high = parseFloatSetting(existing, "tier1_high_threshold", defaultTier1HighThreshold)
			}

			if smartThresholdOutOfRange(low) || smartThresholdOutOfRange(high) || low > high {
				writeError(w, "invalid_request", "阈值须在 0 到 1 之间且下限不高于上限")
				return
			}

			if lowGiven {
				settings["tier1_low_threshold"] = strconv.FormatFloat(low, 'f', -1, 64)
			}
			if highGiven {
				settings["tier1_high_threshold"] = strconv.FormatFloat(high, 'f', -1, 64)
			}
		}

		if len(settings) > 0 && deps != nil && deps.SystemRepo != nil {
			if err := deps.SystemRepo.SetMultiple(r.Context(), settings); err != nil {
				writeError(w, "internal_error", "保存配置失败")
				return
			}
			// 审计：安全敏感写路径必留操作痕迹（与 UpdateSystemSettings 等所有变更类端点一致）。
			// 明细须以 map[string]interface{} 承载，否则 logAudit 会静默丢空。
			auditDetail := make(map[string]interface{}, len(settings))
			for k, v := range settings {
				auditDetail[k] = v
			}
			// C1: record the side effect, not just the value. Without this line the
			// only way to find out who disabled the cascade is to diff raw settings.
			if raw, ok := settings["tier1_low_threshold"]; ok {
				if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
					if len(smartThresholdWarnings(parsed)) > 0 {
						auditDetail["warning"] = "tier1_cascade_disabled"
					}
				}
			}
			logAudit(r, deps, "update_smart_detection_config", auditDetail, "system", "settings")
		}

		resp := map[string]interface{}{"message": "已保存，热生效"}
		// The write is accepted on purpose (this is the deliberate path for it), but a caller
		// that turns the cascade off must hear it in the response, not only in the audit trail.
		// No warning means the response keeps exactly the shape it always had.
		if raw, ok := settings["tier1_low_threshold"]; ok {
			if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
				if warnings := smartThresholdWarnings(parsed); len(warnings) > 0 {
					resp["warnings"] = warnings
				}
			}
		}
		writeJSON(w, resp)
	}
}
