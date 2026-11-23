package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/executionmode"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// executionModeBaselineKey 在 system_settings 里记录看门狗最近一次确认的模式。
//
// 当前格式（v2）："v2|<生效>/<配置>|<确认时间>|<模式键最近写入 unix 微秒>|<HMAC>"；
// HMAC 由部署内部密钥派生，只能改库的人无法同时伪造"模式 + 基线"来躲过告警。
// 旧格式 "<生效>/<配置>|<时间>" 与 "<模式>|<时间>" 仍可读取（升级兼容）。
// 持久化基线让重启、停机期间发生的变更仍能被发现，多个控制面副本也读到同一条基线。
// 该键由服务端维护，不接受 API 写入。
const executionModeBaselineKey = "security_execution_mode_watch_baseline"

const (
	modeChangeKindChanged   = "mode_changed"
	modeChangeKindRewritten = "transient_rewrite"
	modeChangeKindDeleted   = "baseline_deleted"
	modeChangeKindTampered  = "baseline_tampered"
	// 控制台写模式时 modified_at（应用时钟）与 updated_at（数据库 NOW()）在同一语句里，
	// 允许的时钟差；超出即认为 modified_by 是旧值，不能归因到这次写入。
	modeAttributionTolerance = 5 * time.Second
)

// executionModeKeys 是决定执行模式的库键；它们的 updated_at 用来发现"两次巡检之间
// 切过去又切回来"的短暂变更。
var executionModeKeys = []string{
	securityAuditOnlySettingKey,
	securityExecutionModeSettingKey,
	securityExecutionModeModifiedBySettingKey,
	securityExecutionModeModifiedAtSettingKey,
}

// executionModeWatcher 在执行模式变化时产出一条高危安全事件。
//
// 同时比对"生效模式"（部署锁优先）和"配置模式"（库里的值）：09-20 那次绕过控制台的
// 直接写库不会经过控制台审计；而在部署锁开着的机器上，直接写库不会改变生效模式，
// 但仍是需要告警的越权变更。
//
// 检测边界（如实记录）：
//   - 巡检间隔内"切过去又切回来"靠模式键的 updated_at 发现。控制台/仓储写入都会推进
//     updated_at；但 system_settings 目前没有 updated_at 触发器，直接写库的 UPDATE 若不
//     显式改 updated_at，这类短暂切换发现不了（切换后未切回的情况仍会在下一轮巡检告警）。
//   - 基线被删除/篡改/回放旧签名基线：进程运行期间必告警。配置了签名密钥时，启动时读到
//     未签名或签名无效的基线一律告警；启动时基线缺失，除全新安装（从未有人在控制台改过
//     模式，即 modified_by 为空）外也告警。
//   - 无法发现的情况：控制面停机期间回放一条更早的合法签名基线（进程重启后没有可对照的
//     内存状态）；停机期间删掉基线并清空 modified_by（与"全新安装"无法区分）；切换后又
//     切回并把 updated_at 原样恢复为已确认的值（等同于"不改 updated_at"）。
//   - 轮换 JJD_INTERNAL_API_SECRET 会让已有签名失效，产生一次基线篡改告警。
//   - 多副本：各副本每轮先采信库里的签名基线，确认时间取数据库写入时间，同一次变更得到
//     相同事件 ID。极端情况下一个副本的整轮巡检跨过另一副本的一次写入，可能产生一次
//     基线回退告警（误报方向，不会漏报）。
type executionModeWatcher struct {
	mu            sync.Mutex
	lastEffective string
	lastConfig    string
	lastAt        string
	lastModeWrite time.Time
	seen          bool
	pending       string
	key           []byte
	// 启动时库里基线不可信（缺失/未签名/签名无效）：等首次观察拿到当前模式后再告警。
	unverifiedKind  string
	unverifiedClaim string
}

// watcherState 是一轮巡检开始前的内存快照：告警或基线没写进库时整轮回滚，
// 下一轮从库里的基线重新发现同一次变更（事件 ID 相同，收件箱去重）。
type watcherState struct {
	lastEffective, lastConfig, lastAt string
	lastModeWrite                     time.Time
	seen                              bool
	pending                           string
	unverifiedKind, unverifiedClaim   string
}

func (w *executionModeWatcher) snapshot() watcherState {
	w.mu.Lock()
	defer w.mu.Unlock()
	return watcherState{w.lastEffective, w.lastConfig, w.lastAt, w.lastModeWrite, w.seen, w.pending, w.unverifiedKind, w.unverifiedClaim}
}

func (w *executionModeWatcher) rollback(s watcherState) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastEffective, w.lastConfig, w.lastAt, w.lastModeWrite = s.lastEffective, s.lastConfig, s.lastAt, s.lastModeWrite
	w.seen, w.pending, w.unverifiedKind, w.unverifiedClaim = s.seen, s.pending, s.unverifiedKind, s.unverifiedClaim
}

// baselineAt 是基线的确认时间：有数据库写入时间就用它（各副本一致），否则用本地时间。
func baselineAt(modeWrite time.Time, stamp string) string {
	if modeWrite.IsZero() {
		return stamp
	}
	return modeWrite.UTC().Format(time.RFC3339Nano)
}

func newExecutionModeWatcher(secret string) *executionModeWatcher {
	w := &executionModeWatcher{}
	if secret = strings.TrimSpace(secret); secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte("jjdguard/mode-watch-baseline/v2"))
		w.key = mac.Sum(nil)
	}
	return w
}

type modeBaseline struct {
	effective, configured, at string
	modeWrite                 time.Time
}

const (
	baselineFormatLegacy  = "legacy"
	baselineFormatSigned  = "signed"
	baselineFormatInvalid = "invalid"
)

func (w *executionModeWatcher) sign(payload string) string {
	if len(w.key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, w.key)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// encodeLocked 返回当前内存基线的持久化值；调用方持有 w.mu。
func (w *executionModeWatcher) encodeLocked() string {
	write := ""
	if !w.lastModeWrite.IsZero() {
		write = strconv.FormatInt(w.lastModeWrite.UnixMicro(), 10)
	}
	payload := "v2|" + w.lastEffective + "/" + w.lastConfig + "|" + w.lastAt + "|" + write
	return payload + "|" + w.sign(payload)
}

func (w *executionModeWatcher) decode(value string) (modeBaseline, string) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "v2|") {
		idx := strings.LastIndex(value, "|")
		payload, mac := value[:idx], value[idx+1:]
		parts := strings.Split(payload, "|")
		if len(parts) != 4 {
			return modeBaseline{}, baselineFormatInvalid
		}
		b, ok := splitModes(parts[1])
		if !ok {
			return modeBaseline{}, baselineFormatInvalid
		}
		b.at = parts[2]
		if parts[3] != "" {
			micros, err := strconv.ParseInt(parts[3], 10, 64)
			if err != nil {
				return modeBaseline{}, baselineFormatInvalid
			}
			b.modeWrite = time.UnixMicro(micros).UTC()
		}
		if len(w.key) == 0 {
			// 没有签名能力的部署：只能按未签名处理。
			return b, baselineFormatLegacy
		}
		if mac == "" || !hmac.Equal([]byte(mac), []byte(w.sign(payload))) {
			return b, baselineFormatInvalid
		}
		return b, baselineFormatSigned
	}
	mode, at, _ := strings.Cut(value, "|")
	b, ok := splitModes(mode)
	if !ok {
		return modeBaseline{}, baselineFormatInvalid
	}
	b.at = strings.TrimSpace(at)
	return b, baselineFormatLegacy
}

func splitModes(value string) (modeBaseline, bool) {
	effective, configured, _ := strings.Cut(strings.TrimSpace(value), "/")
	effective, configured = strings.TrimSpace(effective), strings.TrimSpace(configured)
	if effective == "" {
		return modeBaseline{}, false
	}
	if configured == "" {
		configured = effective
	}
	return modeBaseline{effective: effective, configured: configured}, true
}

// restore 载入持久化的基线（旧的两参数形式，供兼容与测试）。
func (w *executionModeWatcher) restore(value, at string) {
	b, ok := splitModes(value)
	if !ok {
		return
	}
	b.at = strings.TrimSpace(at)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.adoptLocked(b)
}

func (w *executionModeWatcher) adoptLocked(b modeBaseline) {
	w.lastEffective, w.lastConfig, w.lastAt, w.lastModeWrite, w.seen = b.effective, b.configured, b.at, b.modeWrite, true
}

// syncBaseline 以数据库里的基线为准同步内存状态，并检查基线自身的完整性。
// present=false 表示库里没有基线行；consoleWritten 表示库里有控制台写模式留下的
// modified_by（用于区分"全新安装"与"基线被删"）。
func (w *executionModeWatcher) syncBaseline(present bool, value string, consoleWritten bool) *repository.SecurityEventUpsert {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.unverifiedKind, w.unverifiedClaim = "", ""
	if !present {
		if !w.seen {
			if consoleWritten && len(w.key) > 0 {
				// 有人在控制台改过模式却没有基线：可能是停机期间被删，也可能是首次升级到
				// 带看门狗的版本。无法区分，告警并按当前状态重建（误报方向，不漏报）。
				w.unverifiedKind = modeChangeKindDeleted
			}
			return nil // 由 observe 按当前状态建立基线。
		}
		w.pending = w.encodeLocked()
		return w.integrityEventLocked(modeChangeKindDeleted, "",
			fmt.Sprintf("执行模式看门狗基线被删除（最近确认为 %s/%s）", w.lastEffective, w.lastConfig))
	}
	b, format := w.decode(value)
	claimed := strings.TrimSpace(value)
	if len(claimed) > 160 {
		claimed = claimed[:160]
	}
	switch {
	case format == baselineFormatSigned && w.seen && w.lastModeWrite.After(b.modeWrite):
		// 签名合法但比本进程确认的更旧：有人回放了历史基线。
		w.pending = w.encodeLocked()
		return w.integrityEventLocked(modeChangeKindTampered, claimed,
			"执行模式看门狗基线被回退为更早的记录，已按本进程确认的状态重建")
	case format == baselineFormatSigned:
		w.adoptLocked(b)
		return nil
	case format == baselineFormatLegacy && len(w.key) == 0:
		// 没有签名能力的部署只能信任未签名基线（检测边界见类型注释）。
		w.adoptLocked(b)
		return nil
	}
	// 配置了密钥却读到未签名或签名无效的基线：被改写。
	if w.seen {
		w.pending = w.encodeLocked()
		return w.integrityEventLocked(modeChangeKindTampered, claimed,
			"执行模式看门狗基线被改写或签名无效，已按本进程确认的状态重建")
	}
	// 启动时没有可信基线：放弃该值，等 observe 拿到当前模式后告警并重建。
	w.unverifiedKind, w.unverifiedClaim = modeChangeKindTampered, claimed
	return nil
}

func (w *executionModeWatcher) integrityEventLocked(kind, claimed, summary string) *repository.SecurityEventUpsert {
	sum := sha256.Sum256([]byte(kind + "|" + w.lastEffective + "/" + w.lastConfig + "|" + w.lastAt + "|" + claimed))
	id := "secevt_mode_" + hex.EncodeToString(sum[:])[:24]
	return modeEvent(id, map[string]interface{}{
		"change_kind":         kind,
		"old_mode":            w.lastEffective,
		"new_mode":            w.lastEffective,
		"old_configured_mode": w.lastConfig,
		"new_configured_mode": w.lastConfig,
		"claimed_baseline":    claimed,
		"attributed":          false,
		"observed_at":         time.Now().UTC().Format(time.RFC3339Nano),
		"summary":             summary,
	})
}

func modeEvent(id string, summary map[string]interface{}) *repository.SecurityEventUpsert {
	return &repository.SecurityEventUpsert{
		ID:             id,
		RequestID:      "req_" + id,
		TenantID:       semanticConfigTenant,
		ProjectID:      defaultEvalIntegrationProjectID,
		EventType:      "security_mode_changed",
		Severity:       "high",
		ActionTaken:    "audit",
		MatchedSummary: summary,
	}
}

// baseline 返回应持久化的基线值；首次观察或发生变化后才需要写回。
func (w *executionModeWatcher) baseline() (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending == "" {
		return "", false
	}
	value := w.pending
	w.pending = ""
	return value, true
}

// observe 只比对生效模式（配置模式视为与生效模式相同）。
func (w *executionModeWatcher) observe(effective, modifiedBy, source string) *repository.SecurityEventUpsert {
	return w.observeConfigured(effective, effective, modifiedBy, source)
}

func (w *executionModeWatcher) observeConfigured(effective, configured, modifiedBy, source string) *repository.SecurityEventUpsert {
	return w.observeState(modeObservation{effective: effective, configured: configured, modifiedBy: modifiedBy, source: source})
}

type modeObservation struct {
	effective, configured, modifiedBy, modifiedAt, source string
	// modeWrite 是模式相关库键的最近 updated_at；零值表示未知（不做短暂变更检测）。
	modeWrite time.Time
}

func (w *executionModeWatcher) observeState(o modeObservation) *repository.SecurityEventUpsert {
	effective, configured := strings.TrimSpace(o.effective), strings.TrimSpace(o.configured)
	if effective == "" {
		return nil
	}
	if configured == "" {
		configured = effective
	}
	modeWrite := o.modeWrite.UTC().Truncate(time.Microsecond)
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	if !w.seen {
		w.adoptLocked(modeBaseline{effective: effective, configured: configured, at: baselineAt(modeWrite, stamp), modeWrite: modeWrite})
		w.pending = w.encodeLocked()
		kind, claimed := w.unverifiedKind, w.unverifiedClaim
		w.unverifiedKind, w.unverifiedClaim = "", ""
		switch kind {
		case modeChangeKindTampered:
			return w.integrityEventLocked(kind, claimed, fmt.Sprintf(
				"启动时执行模式看门狗基线未签名或签名无效，已按当前状态 %s/%s 重建；停机期间的模式变更无法确认", effective, configured))
		case modeChangeKindDeleted:
			return w.integrityEventLocked(kind, "", fmt.Sprintf(
				"启动时执行模式看门狗基线缺失（控制台曾修改过执行模式），已按当前状态 %s/%s 重建；停机期间的模式变更无法确认", effective, configured))
		}
		// 全新安装：只记录，不告警。
		return nil
	}
	changed := effective != w.lastEffective || configured != w.lastConfig
	rewritten := !changed && !modeWrite.IsZero() && !w.lastModeWrite.IsZero() && modeWrite.After(w.lastModeWrite)
	if !changed && !modeWrite.IsZero() && !w.lastModeWrite.IsZero() && modeWrite.Before(w.lastModeWrite) {
		// 模式键的写入时间比已确认的还早：updated_at 被回拨，常见于掩盖短暂切换。
		// 回拨状态存在期间每轮都报（同一回拨值得到同一事件 ID，收件箱合并为一条），
		// 不做"只报一次"去重——否则反复回拨到同一个值的短暂切换会被静默吸收。
		// 基线的写入时间不跟着回退，否则下次回放旧基线就会被采信。
		return w.integrityEventLocked(modeChangeKindTampered, modeWrite.Format(time.RFC3339Nano), fmt.Sprintf(
			"执行模式配置的写入时间被回拨（当前仍为 %s/%s，可能掩盖了一次短暂切换）", effective, configured))
	}
	if !changed && !rewritten {
		if !modeWrite.IsZero() && w.lastModeWrite.IsZero() {
			// 旧基线没有写入时间：静默补上，从下一次起才能发现短暂变更。
			w.lastModeWrite = modeWrite
			w.pending = w.encodeLocked()
		}
		return nil
	}
	oldEffective, oldConfig, oldAt, oldWrite := w.lastEffective, w.lastConfig, w.lastAt, w.lastModeWrite
	w.lastEffective, w.lastConfig, w.lastAt = effective, configured, baselineAt(modeWrite, stamp)
	if modeWrite.After(w.lastModeWrite) {
		w.lastModeWrite = modeWrite
	}
	w.pending = w.encodeLocked()

	kind := modeChangeKindChanged
	var sum [32]byte
	if changed {
		// 同一条基线上的同一次变更在各副本得到相同 ID，Upsert 按 ID 去重只落一条。
		sum = sha256.Sum256([]byte(oldEffective + "/" + oldConfig + "|" + oldAt + "|" + effective + "/" + configured))
	} else {
		kind = modeChangeKindRewritten
		sum = sha256.Sum256([]byte("rewrite|" + oldEffective + "/" + oldConfig + "|" + oldAt + "|" +
			strconv.FormatInt(modeWrite.UnixMicro(), 10)))
	}
	id := "secevt_mode_" + hex.EncodeToString(sum[:])[:24]
	modifiedBy := strings.TrimSpace(o.modifiedBy)
	summary := fmt.Sprintf("全局执行模式由 %s 变为 %s", oldEffective, effective)
	switch {
	case !changed:
		summary = fmt.Sprintf("执行模式配置在两次巡检之间被改写（当前仍为 %s/%s，可能发生过短暂切换）", effective, configured)
	case effective == oldEffective:
		summary = fmt.Sprintf("执行模式配置由 %s 被改为 %s（部署锁生效，实际仍为 %s）", oldConfig, configured, effective)
	}
	body := map[string]interface{}{
		"change_kind":         kind,
		"old_mode":            oldEffective,
		"new_mode":            effective,
		"old_configured_mode": oldConfig,
		"new_configured_mode": configured,
		"mode_source":         o.source,
		"modified_by":         modifiedBy,
		// 没有控制台用户身份的变更（例如直接写库）单独标出，需要重点核查。
		"attributed":  modeChangeAttributed(modifiedBy, o.modifiedAt, modeWrite),
		"observed_at": stamp,
		"summary":     summary,
	}
	if !modeWrite.IsZero() {
		body["mode_written_at"] = modeWrite.Format(time.RFC3339Nano)
	}
	if !oldWrite.IsZero() {
		body["previous_mode_written_at"] = oldWrite.Format(time.RFC3339Nano)
	}
	return modeEvent(id, body)
}

// modeChangeAttributed：modified_by 只有和这次写入一起写下时才算归因。直接写库改模式
// 不会更新 modified_by/modified_at，留下的是上一次控制台操作者（09-20 的
// codex_restore_user_configuration 就是这样被误读成"有人刚改过"）。
func modeChangeAttributed(modifiedBy, modifiedAt string, modeWrite time.Time) bool {
	if strings.TrimSpace(modifiedBy) == "" {
		return false
	}
	if modeWrite.IsZero() {
		return true // 没有写入时间可比对，保持原口径。
	}
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(modifiedAt))
	if err != nil {
		return false
	}
	diff := modeWrite.Sub(at)
	if diff < 0 {
		diff = -diff
	}
	return diff <= modeAttributionTolerance
}

// modeAlertWriter 是告警收件箱的写入口（repository.AlertGroupRepository 满足）。
//
// 模式变更是管理面配置变更，不对应任何一条代理请求：security_events.request_id
// 外键指向 request_logs，没有真实请求就写不进去（2026-09-27 线上验证）。因此直接写
// 告警收件箱，alert_groups 只要求租户与 group_key；group_key 用确定性事件 ID，
// 多个副本对同一次变更只合并成一条告警。
type modeAlertWriter interface {
	UpsertOpen(ctx context.Context, input repository.AlertGroupUpsertInput) (*repository.AlertGroup, bool, error)
}

func writeModeChangeAlert(ctx context.Context, sink modeAlertWriter, ev *repository.SecurityEventUpsert) error {
	if sink == nil || ev == nil {
		return nil
	}
	observed := time.Now().UTC()
	if at, _ := ev.MatchedSummary["observed_at"].(string); at != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, at); err == nil {
			observed = parsed
		}
	}
	body := map[string]any{"event_type": ev.EventType}
	for key, value := range ev.MatchedSummary {
		body[key] = value
	}
	summary, _ := ev.MatchedSummary["summary"].(string)
	_, _, err := sink.UpsertOpen(ctx, repository.AlertGroupUpsertInput{
		TenantID:          ev.TenantID,
		ProjectID:         ev.ProjectID,
		GroupKey:          ev.ID,
		Severity:          ev.Severity,
		AlertType:         ev.EventType,
		Title:             "执行模式变更 · " + summary,
		OccurredAt:        observed,
		BodyJSON:          body,
		EffectiveSeverity: ev.Severity,
		DispositionClass:  "action_required",
	})
	return err
}

// configuredExecutionModeFromSettings 读取库里配置的模式（不套部署锁）。
func configuredExecutionModeFromSettings(settings []*repository.SystemSetting) string {
	values := map[string]string{}
	for _, setting := range settings {
		if setting != nil {
			values[setting.Key] = setting.Value
		}
	}
	auditOnly, _ := executionmode.FromValues(values, false)
	return executionmode.ModeName(auditOnly)
}

func latestExecutionModeWrite(settings []*repository.SystemSetting) time.Time {
	var latest time.Time
	for _, setting := range settings {
		if setting == nil {
			continue
		}
		for _, key := range executionModeKeys {
			if setting.Key == key && setting.UpdatedAt.After(latest) {
				latest = setting.UpdatedAt
			}
		}
	}
	return latest.UTC()
}

// modeWatchTick 做一次完整巡检：同步并校验基线、比对模式、写告警、回写基线。
func modeWatchTick(ctx context.Context, deps *Dependencies, sink modeAlertWriter, watcher *executionModeWatcher) {
	settings, err := deps.SystemRepo.GetAll(ctx)
	if err != nil {
		log.Printf("[mode-watch] read settings failed: %v", err)
		return
	}
	present, baselineValue := false, ""
	var modifiedAt string
	consoleWritten := false
	for _, setting := range settings {
		if setting == nil {
			continue
		}
		switch setting.Key {
		case executionModeBaselineKey:
			present, baselineValue = true, setting.Value
		case securityExecutionModeModifiedAtSettingKey:
			modifiedAt = setting.Value
		case securityExecutionModeModifiedBySettingKey:
			consoleWritten = strings.TrimSpace(setting.Value) != ""
		}
	}
	before := watcher.snapshot()
	events := []*repository.SecurityEventUpsert{watcher.syncBaseline(present, baselineValue, consoleWritten)}
	view := securityExecutionModeForSettings(ctx, deps, settings)
	events = append(events, watcher.observeState(modeObservation{
		effective:  view.EffectiveMode,
		configured: configuredExecutionModeFromSettings(settings),
		modifiedBy: view.LastModifiedBy,
		modifiedAt: modifiedAt,
		source:     view.Source,
		modeWrite:  latestExecutionModeWrite(settings),
	}))
	for _, event := range events {
		if event == nil {
			continue
		}
		if err := writeModeChangeAlert(ctx, sink, event); err != nil {
			// 告警没写进去就整轮回滚：内存与库里的基线都不推进，下一轮重新发现并重试。
			log.Printf("[mode-watch] write alert failed: %v", err)
			watcher.rollback(before)
			return
		}
		log.Printf("[mode-watch] %s (kind=%v attributed=%v)", event.MatchedSummary["summary"],
			event.MatchedSummary["change_kind"], event.MatchedSummary["attributed"])
	}
	if value, ok := watcher.baseline(); ok {
		if err := deps.SystemRepo.Set(ctx, executionModeBaselineKey, value); err != nil {
			log.Printf("[mode-watch] persist baseline failed: %v", err)
			// 内存不能领先于库：否则下一轮会把库里的旧基线当成回放。
			watcher.rollback(before)
		}
	}
}

// startExecutionModeWatch 按 interval 比对一次执行模式，变化时写入告警收件箱。
func startExecutionModeWatch(ctx context.Context, deps *Dependencies, sink modeAlertWriter, interval time.Duration) {
	if deps == nil || deps.SystemRepo == nil || sink == nil {
		return
	}
	secret := os.Getenv("JJD_INTERNAL_API_SECRET")
	if strings.TrimSpace(secret) == "" {
		secret = os.Getenv("JJD_PROVIDER_SECRET_KEY")
	}
	watcher := newExecutionModeWatcher(secret)
	if len(watcher.key) == 0 {
		log.Printf("[mode-watch] no internal secret configured; baseline is stored unsigned")
	}
	go func() {
		modeWatchTick(ctx, deps, sink, watcher)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				modeWatchTick(ctx, deps, sink, watcher)
			}
		}
	}()
}

// StartExecutionModeWatch 是供 cmd/server 装配的入口。
func StartExecutionModeWatch(ctx context.Context, deps *Dependencies, sink modeAlertWriter) {
	startExecutionModeWatch(ctx, deps, sink, time.Minute)
}
