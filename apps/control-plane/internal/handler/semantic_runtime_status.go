package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

const (
	semanticRuntimeStatusUnavailable    = "unavailable"
	semanticRuntimeStatusPending        = "pending"
	semanticRuntimeStatusPartial        = "partially_applied"
	semanticRuntimeStatusApplied        = "applied"
	semanticRuntimeStatusDegraded       = "degraded"
	semanticRuntimeReportTTL            = 2 * time.Minute
	semanticRuntimeMaxNodesPerComponent = 128
	semanticRuntimeMaxNodesGlobal       = 256
)

// 运行态诚实的门槛：探针答得上一句寒暄，证明不了真实请求能成。窗口样本太少就
// 不评率（n=1 不是率），成功率低于下限才算降级，并按失败构成给出具体原因。
const (
	semanticJudgeMinWindowAttempts = 5
	semanticJudgeSuccessFloor      = 0.95
)

var (
	semanticRevisionPattern      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	semanticErrorCodePattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	errSemanticRuntimeLedgerFull = errors.New("semantic runtime ledger is full")
)

type semanticRuntimeReport struct {
	Component                string                                  `json:"component"`
	NodeID                   string                                  `json:"node_id"`
	AppliedRevision          string                                  `json:"applied_revision,omitempty"`
	HeldRevision             string                                  `json:"held_revision,omitempty"`
	DesiredRevision          string                                  `json:"desired_revision,omitempty"`
	Posture                  *inspectionscope.GatewaySecurityPosture `json:"posture,omitempty"`
	ConfigLoaded             *bool                                   `json:"config_loaded"`
	JudgeRequired            *bool                                   `json:"judge_required,omitempty"`
	JudgeOperational         *bool                                   `json:"judge_operational,omitempty"`
	JudgeConsecutiveFailures int                                     `json:"judge_consecutive_failures,omitempty"`
	JudgeBreakerOpen         bool                                    `json:"judge_breaker_open,omitempty"`
	JudgeLastAttemptAt       string                                  `json:"judge_last_attempt_at,omitempty"`
	JudgeLastSuccessAt       string                                  `json:"judge_last_success_at,omitempty"`
	JudgeWindowAttempts      int                                     `json:"judge_window_attempts,omitempty"`
	JudgeWindowSuccesses     int                                     `json:"judge_window_successes,omitempty"`
	JudgeWindowTimeouts      int                                     `json:"judge_window_timeouts,omitempty"`
	JudgeP50LatencyMS        float64                                 `json:"judge_p50_latency_ms,omitempty"`
	ErrorCode                string                                  `json:"error_code,omitempty"`
	LastError                string                                  `json:"-"`
	ReportedAt               time.Time                               `json:"-"`
}

type semanticRuntimeNodeStatus struct {
	NodeID                   string    `json:"node_id"`
	Status                   string    `json:"status"`
	AppliedRevision          string    `json:"applied_revision,omitempty"`
	HeldRevision             string    `json:"held_revision,omitempty"`
	ConfigLoaded             bool      `json:"config_loaded"`
	JudgeRequired            bool      `json:"judge_required"`
	JudgeOperational         bool      `json:"judge_operational"`
	JudgeConsecutiveFailures int       `json:"judge_consecutive_failures"`
	JudgeBreakerOpen         bool      `json:"judge_breaker_open"`
	JudgeLastAttemptAt       string    `json:"judge_last_attempt_at,omitempty"`
	JudgeLastSuccessAt       string    `json:"judge_last_success_at,omitempty"`
	JudgeSuccessRatio        float64   `json:"judge_success_ratio,omitempty"`
	DegradedReason           string    `json:"degraded_reason,omitempty"`
	JudgeWindowAttempts      int       `json:"judge_window_attempts,omitempty"`
	JudgeWindowSuccesses     int       `json:"judge_window_successes,omitempty"`
	JudgeWindowTimeouts      int       `json:"judge_window_timeouts,omitempty"`
	JudgeP50LatencyMS        float64   `json:"judge_p50_latency_ms,omitempty"`
	ErrorCode                string    `json:"error_code,omitempty"`
	ReportedAt               time.Time `json:"reported_at"`
	Fresh                    bool      `json:"fresh"`
}

type semanticRuntimeComponentStatus struct {
	Component                string                      `json:"component"`
	NodeID                   string                      `json:"node_id,omitempty"`
	Status                   string                      `json:"status"`
	DesiredRevision          string                      `json:"desired_revision"`
	AppliedRevision          string                      `json:"applied_revision,omitempty"`
	HeldRevision             string                      `json:"held_revision,omitempty"`
	ConfigLoaded             bool                        `json:"config_loaded"`
	JudgeRequired            bool                        `json:"judge_required"`
	JudgeOperational         bool                        `json:"judge_operational"`
	JudgeConsecutiveFailures int                         `json:"judge_consecutive_failures"`
	JudgeBreakerOpen         bool                        `json:"judge_breaker_open"`
	JudgeLastAttemptAt       string                      `json:"judge_last_attempt_at,omitempty"`
	JudgeLastSuccessAt       string                      `json:"judge_last_success_at,omitempty"`
	JudgeSuccessRatio        float64                     `json:"judge_success_ratio,omitempty"`
	DegradedReason           string                      `json:"degraded_reason,omitempty"`
	JudgeWindowAttempts      int                         `json:"judge_window_attempts,omitempty"`
	JudgeWindowSuccesses     int                         `json:"judge_window_successes,omitempty"`
	JudgeWindowTimeouts      int                         `json:"judge_window_timeouts,omitempty"`
	JudgeP50LatencyMS        float64                     `json:"judge_p50_latency_ms,omitempty"`
	LastError                string                      `json:"last_error,omitempty"`
	ReportedAt               time.Time                   `json:"reported_at,omitempty"`
	Fresh                    bool                        `json:"fresh"`
	ActiveNodes              int                         `json:"active_nodes"`
	AppliedNodes             int                         `json:"applied_nodes"`
	Nodes                    []semanticRuntimeNodeStatus `json:"nodes"`
}

type semanticRuntimeStatus struct {
	ProxyRequired    bool                             `json:"proxy_required"`
	DesiredRevision  string                           `json:"desired_revision,omitempty"`
	DesiredRevisions semanticDesiredRevisions         `json:"desired_revisions"`
	Status           string                           `json:"status"`
	RuntimeVerified  bool                             `json:"runtime_verified"`
	Components       []semanticRuntimeComponentStatus `json:"components"`
}

var semanticRuntimeLedger = struct {
	sync.RWMutex
	reports map[string]semanticRuntimeReport
}{reports: map[string]semanticRuntimeReport{}}

func validSemanticRuntimeComponent(component string) bool {
	return component == "security-engine" || component == "gateway-core"
}

func GetSemanticRuntimeStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		configs, err := buildSemanticComponentConfigs(r.Context(), deps)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "semantic_config_unavailable", "semantic configuration is unavailable")
			return
		}
		runtime := buildSemanticRuntimeStatus(semanticDesiredRevisions{
			Engine: configs.EngineRevision, Gateway: configs.GatewayRevision,
			EngineJudgeRequired: semanticEngineJudgeRequired(configs.Engine),
		}, time.Now().UTC())
		includeProxyInspectionScope(r.Context(), deps, &runtime, configs.GatewayRevision)
		writeAgentGuardJSON(w, map[string]any{"runtime": runtime})
	}
}

func semanticEngineJudgeRequired(config map[string]any) bool {
	master, _ := config["semantic_enabled"].(bool)
	input, _ := config["semantic_input_enabled"].(bool)
	agent, _ := config["semantic_agent_enabled"].(bool)
	output, _ := config["semantic_output_enabled"].(bool)
	return master && (input || agent || output)
}

func pruneSemanticRuntimeLedgerLocked(now time.Time) {
	for key, report := range semanticRuntimeLedger.reports {
		if now.Sub(report.ReportedAt) > semanticRuntimeReportTTL {
			delete(semanticRuntimeLedger.reports, key)
		}
	}
}

func recordSemanticRuntime(report semanticRuntimeReport, now time.Time) error {
	if report.ReportedAt.IsZero() {
		report.ReportedAt = now
	}
	key := report.Component + "\x1f" + report.NodeID
	semanticRuntimeLedger.Lock()
	defer semanticRuntimeLedger.Unlock()
	pruneSemanticRuntimeLedgerLocked(now)
	if _, exists := semanticRuntimeLedger.reports[key]; !exists {
		if len(semanticRuntimeLedger.reports) >= semanticRuntimeMaxNodesGlobal {
			return errSemanticRuntimeLedgerFull
		}
		componentNodes := 0
		for _, existing := range semanticRuntimeLedger.reports {
			if existing.Component == report.Component {
				componentNodes++
			}
		}
		if componentNodes >= semanticRuntimeMaxNodesPerComponent {
			return errSemanticRuntimeLedgerFull
		}
	}
	semanticRuntimeLedger.reports[key] = report
	return nil
}

func reportSemanticRuntime(report semanticRuntimeReport) {
	now := report.ReportedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_ = recordSemanticRuntime(report, now)
}

func resetSemanticRuntimeReportsForTest() {
	semanticRuntimeLedger.Lock()
	semanticRuntimeLedger.reports = map[string]semanticRuntimeReport{}
	semanticRuntimeLedger.Unlock()
}

func semanticRuntimeLedgerSizeForTest() int {
	semanticRuntimeLedger.RLock()
	defer semanticRuntimeLedger.RUnlock()
	return len(semanticRuntimeLedger.reports)
}

func normalizeSemanticRuntimeReport(report *semanticRuntimeReport, expected string) bool {
	report.Component = strings.TrimSpace(report.Component)
	report.NodeID = strings.TrimSpace(report.NodeID)
	report.AppliedRevision = strings.TrimSpace(report.AppliedRevision)
	report.HeldRevision = strings.TrimSpace(report.HeldRevision)
	report.DesiredRevision = strings.TrimSpace(report.DesiredRevision)
	report.ErrorCode = strings.TrimSpace(report.ErrorCode)
	if report.Component != expected || !validSemanticRuntimeComponent(report.Component) {
		return false
	}
	if report.NodeID == "" || len(report.NodeID) > 128 || strings.ContainsAny(report.NodeID, "\r\n\x00") {
		return false
	}
	if report.AppliedRevision != "" && !semanticRevisionPattern.MatchString(report.AppliedRevision) {
		return false
	}
	if report.HeldRevision != "" && !semanticRevisionPattern.MatchString(report.HeldRevision) {
		return false
	}
	if report.DesiredRevision != "" && !semanticRevisionPattern.MatchString(report.DesiredRevision) {
		return false
	}
	if report.Component == semanticEngineComponent && (report.Posture != nil || report.DesiredRevision != "") {
		return false
	}
	if report.Posture != nil && (report.DesiredRevision == "" || report.Posture.Validate() != nil) {
		return false
	}
	if report.ConfigLoaded == nil || report.JudgeConsecutiveFailures < 0 || report.JudgeConsecutiveFailures > 1000000 {
		return false
	}
	if report.Component == semanticEngineComponent {
		if report.JudgeRequired == nil || report.JudgeOperational == nil {
			return false
		}
	} else if report.JudgeRequired != nil || report.JudgeOperational != nil || report.JudgeConsecutiveFailures != 0 || report.JudgeBreakerOpen || report.JudgeLastAttemptAt != "" || report.JudgeLastSuccessAt != "" {
		return false
	}
	for _, raw := range []string{report.JudgeLastAttemptAt, report.JudgeLastSuccessAt} {
		if raw == "" {
			continue
		}
		if len(raw) > 64 {
			return false
		}
		if _, err := time.Parse(time.RFC3339Nano, raw); err != nil {
			return false
		}
	}
	if report.ErrorCode == "" {
		return report.AppliedRevision != "" && *report.ConfigLoaded
	}
	return semanticErrorCodePattern.MatchString(report.ErrorCode)
}

func reportSemanticRuntimeHandler(deps *Dependencies, expected string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if expected == semanticEngineComponent {
			if status, code := verifySemanticEngineAttestation(deps, r); status != 0 {
				writeErrorWithStatus(w, status, code, "semantic engine attestation failed")
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var report semanticRuntimeReport
		if err := decoder.Decode(&report); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid semantic runtime report")
			return
		}
		component := expected
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid semantic runtime report")
			return
		}
		if component == "" {
			component = strings.TrimSpace(report.Component)
		}
		if !normalizeSemanticRuntimeReport(&report, component) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid semantic runtime report fields")
			return
		}
		if expected == "" && component == semanticEngineComponent {
			if status, code := verifySemanticEngineAttestation(deps, r); status != 0 {
				writeErrorWithStatus(w, status, code, "semantic engine attestation failed")
				return
			}
		}
		now := time.Now().UTC()
		report.ReportedAt = now
		if err := recordSemanticRuntime(report, now); err != nil {
			writeErrorWithStatus(w, http.StatusTooManyRequests, "semantic_runtime_ledger_full", "semantic runtime report capacity reached")
			return
		}
		writeAgentGuardJSON(w, map[string]any{"ok": true})
	}
}

func ReportSemanticRuntimeComponent(deps *Dependencies, component string) http.HandlerFunc {
	return reportSemanticRuntimeHandler(deps, component)
}

func ReportSemanticRuntime(deps *Dependencies) http.HandlerFunc {
	return reportSemanticRuntimeHandler(deps, "")
}

func activeSemanticRuntimeReports(now time.Time) map[string][]semanticRuntimeReport {
	semanticRuntimeLedger.Lock()
	pruneSemanticRuntimeLedgerLocked(now)
	active := make(map[string][]semanticRuntimeReport, 2)
	for _, report := range semanticRuntimeLedger.reports {
		active[report.Component] = append(active[report.Component], report)
	}
	semanticRuntimeLedger.Unlock()
	for component := range active {
		sort.Slice(active[component], func(i, j int) bool {
			return active[component][i].NodeID < active[component][j].NodeID
		})
	}
	return active
}

func desiredSemanticRevision(desired semanticDesiredRevisions, component string) string {
	if component == semanticEngineComponent {
		return desired.Engine
	}
	return desired.Gateway
}

// semanticJudgeWindowVerdict 判断真实流量窗口是否推翻了探针结论。
//
// 返回（成功率, 降级原因）。原因非空即代表降级。样本不足时不评率，避免一条
// 偶发失败就把整个组件标降级；失败里超时占多数才叫 judge_timeouts，否则是
// judge_failures——把连接失败说成超时，正是这次要消灭的那类谎报。
func semanticJudgeWindowVerdict(attempts, successes, timeouts int) (float64, string) {
	if attempts <= 0 {
		return 0, ""
	}
	ratio := float64(successes) / float64(attempts)
	if attempts < semanticJudgeMinWindowAttempts || ratio >= semanticJudgeSuccessFloor {
		return ratio, ""
	}
	failures := attempts - successes
	if failures > 0 && timeouts*2 >= failures {
		return ratio, "judge_timeouts"
	}
	return ratio, "judge_failures"
}

func buildSemanticRuntimeStatus(desired semanticDesiredRevisions, now time.Time) semanticRuntimeStatus {
	active := activeSemanticRuntimeReports(now)
	status := semanticRuntimeStatus{
		DesiredRevisions: desired,
		Status:           semanticRuntimeStatusPending,
		Components:       make([]semanticRuntimeComponentStatus, 0, 2),
	}
	appliedComponents := 0
	degraded := false
	for _, component := range []string{semanticEngineComponent, semanticGatewayComponent} {
		desiredRevision := desiredSemanticRevision(desired, component)
		componentStatus := semanticRuntimeComponentStatus{
			Component: component, Status: semanticRuntimeStatusPending,
			DesiredRevision: desiredRevision, Nodes: []semanticRuntimeNodeStatus{},
			JudgeRequired: component == semanticEngineComponent && desired.EngineJudgeRequired,
		}
		reports := active[component]
		componentStatus.ActiveNodes = len(reports)
		allApplied := len(reports) > 0
		allConfigLoaded := len(reports) > 0
		allJudgeOperational := !componentStatus.JudgeRequired || len(reports) > 0
		for _, report := range reports {
			configLoaded := report.ConfigLoaded != nil && *report.ConfigLoaded
			judgeRequired := report.JudgeRequired != nil && *report.JudgeRequired
			judgeOperational := report.JudgeOperational != nil && *report.JudgeOperational
			judgeRatio, judgeDegradedReason := semanticJudgeWindowVerdict(
				report.JudgeWindowAttempts, report.JudgeWindowSuccesses, report.JudgeWindowTimeouts)
			judgeHealthy := !componentStatus.JudgeRequired || (judgeRequired && judgeOperational)
			if componentStatus.JudgeRequired && judgeRequired && judgeDegradedReason != "" {
				// 探针说"能答"，真实流量说"成不了"：以真实流量为准。
				judgeHealthy = false
			}
			allConfigLoaded = allConfigLoaded && configLoaded
			allJudgeOperational = allJudgeOperational && judgeHealthy
			node := semanticRuntimeNodeStatus{
				NodeID: report.NodeID, Status: semanticRuntimeStatusPending,
				AppliedRevision: report.AppliedRevision, HeldRevision: report.HeldRevision,
				ConfigLoaded: configLoaded, JudgeRequired: judgeRequired, JudgeOperational: judgeOperational,
				JudgeConsecutiveFailures: report.JudgeConsecutiveFailures, JudgeBreakerOpen: report.JudgeBreakerOpen,
				JudgeLastAttemptAt: report.JudgeLastAttemptAt, JudgeLastSuccessAt: report.JudgeLastSuccessAt,
				JudgeSuccessRatio: judgeRatio, DegradedReason: judgeDegradedReason,
				JudgeWindowAttempts: report.JudgeWindowAttempts, JudgeWindowSuccesses: report.JudgeWindowSuccesses,
				JudgeWindowTimeouts: report.JudgeWindowTimeouts, JudgeP50LatencyMS: report.JudgeP50LatencyMS,
				ErrorCode: report.ErrorCode, ReportedAt: report.ReportedAt, Fresh: true,
			}
			if report.ErrorCode != "" {
				node.Status = semanticRuntimeStatusDegraded
				componentStatus.Status = semanticRuntimeStatusDegraded
				if componentStatus.LastError == "" {
					componentStatus.LastError = report.ErrorCode
					componentStatus.HeldRevision = report.HeldRevision
				}
				degraded = true
				allApplied = false
			} else if report.AppliedRevision == desiredRevision && configLoaded && judgeHealthy {
				node.Status = semanticRuntimeStatusApplied
				componentStatus.AppliedNodes++
			} else if report.AppliedRevision == desiredRevision && configLoaded && !judgeHealthy {
				node.Status = semanticRuntimeStatusDegraded
				componentStatus.Status = semanticRuntimeStatusDegraded
				if componentStatus.LastError == "" {
					componentStatus.LastError = judgeDegradedReason
					if componentStatus.LastError == "" {
						componentStatus.LastError = "judge_unavailable"
					}
				}
				degraded = true
				allApplied = false
			} else {
				allApplied = false
			}
			if componentStatus.ReportedAt.Before(report.ReportedAt) {
				componentStatus.NodeID = report.NodeID
				componentStatus.AppliedRevision = report.AppliedRevision
				componentStatus.ReportedAt = report.ReportedAt
				componentStatus.JudgeConsecutiveFailures = report.JudgeConsecutiveFailures
				componentStatus.JudgeBreakerOpen = report.JudgeBreakerOpen
				componentStatus.JudgeLastAttemptAt = report.JudgeLastAttemptAt
				componentStatus.JudgeLastSuccessAt = report.JudgeLastSuccessAt
				componentStatus.JudgeSuccessRatio = judgeRatio
				componentStatus.DegradedReason = judgeDegradedReason
				componentStatus.JudgeWindowAttempts = report.JudgeWindowAttempts
				componentStatus.JudgeWindowSuccesses = report.JudgeWindowSuccesses
				componentStatus.JudgeWindowTimeouts = report.JudgeWindowTimeouts
				componentStatus.JudgeP50LatencyMS = report.JudgeP50LatencyMS
			}
			componentStatus.Nodes = append(componentStatus.Nodes, node)
		}
		componentStatus.Fresh = len(reports) > 0
		componentStatus.ConfigLoaded = allConfigLoaded
		componentStatus.JudgeOperational = allJudgeOperational
		if allApplied && componentStatus.Status != semanticRuntimeStatusDegraded {
			componentStatus.Status = semanticRuntimeStatusApplied
			appliedComponents++
		}
		status.Components = append(status.Components, componentStatus)
	}
	sort.Slice(status.Components, func(i, j int) bool {
		return status.Components[i].Component < status.Components[j].Component
	})
	if degraded {
		status.Status = semanticRuntimeStatusDegraded
	} else if appliedComponents == 2 {
		status.Status = semanticRuntimeStatusApplied
		status.RuntimeVerified = true
	} else if appliedComponents > 0 {
		status.Status = semanticRuntimeStatusPartial
	}
	return status
}
