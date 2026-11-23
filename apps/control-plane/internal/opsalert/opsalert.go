// Package opsalert 把计费、审计链等“运维类”事件统一送进告警组（alert_groups），
// 同时在消息中心（alert_inbox）留一条可读记录，并在新告警首次出现时走告警渠道外发。
//
// 与 SecEventBridge 的安全事件告警分开：这里的事件不是攻击发现，不参与安全检测判定；
// 告警组的 stage 留空，现有 TTL 自动关闭（只关 stage=input）永远不会关掉它们，需要人工处置。
package opsalert

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 运维告警类型（写入 alert_groups.alert_type / alert_inbox.type）。
const (
	TypeBudgetExhausted     = "billing_budget_exhausted"
	TypeUnpricedRejected    = "billing_unpriced_rejected"
	TypeBudgetUnavailable   = "billing_budget_unavailable"
	TypeWalletOverdraft     = "billing_wallet_overdraft"
	TypeFinalizeFailed      = "billing_finalize_failed"
	TypeReservationLeak     = "billing_reservation_leak"
	TypeProxyUsageUnknown   = "billing_proxy_usage_unknown"
	TypeBudgetThreshold80   = "billing_budget_threshold_80"
	TypeBudgetThreshold100  = "billing_budget_threshold_100"
	TypeAuditRecordDropped  = "audit_chain_record_dropped"
	TypeAuditWriteFailed    = "audit_chain_write_failed"
	TypeAuditVerifyFailed   = "audit_chain_verify_failed"
	TypeAuditHMACDefaultKey = "audit_chain_hmac_default_key"
	// TypeLocalIdentityCleanupExhausted：删除用户后 Keycloak 孤儿清理重试到上限仍失败，需人工处置。
	TypeLocalIdentityCleanupExhausted = "local_identity_cleanup_exhausted"
)

// Kind 是一种运维告警的中文名称、默认严重度、风险域和处置建议。
type Kind struct {
	Type       string
	Label      string
	Severity   string
	Domain     string
	Suggestion string
}

// targetURL 是消息中心里“查看”跳转的位置：计费类去消息中心，审计类去操作审计。
func (k Kind) targetURL() string {
	if strings.HasPrefix(k.Type, "audit_chain_") || k.Type == TypeLocalIdentityCleanupExhausted {
		return "/system/audit-operations"
	}
	return "/cost/alerts"
}

var kinds = map[string]Kind{
	TypeBudgetExhausted: {TypeBudgetExhausted, "预算用尽断流", "high", "access",
		"确认是否需要为该员工、部门或组织追加预算；如属正常用尽，可在下个周期自动恢复后关闭本告警。"},
	TypeUnpricedRejected: {TypeUnpricedRejected, "未定价模型被拒", "high", "access",
		"在“价格与成本”中为该模型配置价格（可用一键导入），配置后请求即恢复。"},
	TypeBudgetUnavailable: {TypeBudgetUnavailable, "额度状态无法确认被拒", "high", "system",
		"预算断流开启时额度服务不可用，请求被保守拒绝。请检查控制面、数据库和缓存服务是否正常。"},
	TypeWalletOverdraft: {TypeWalletOverdraft, "钱包透支", "high", "access",
		"实际结算金额超过钱包余额，钱包已为负数。请核对账本流水后充值或调账，并检查该用户的预估输出上限。"},
	TypeFinalizeFailed: {TypeFinalizeFailed, "计费结算失败", "high", "system",
		"网关结算重试后仍失败，费用暂未入账（预占保留，待对账补结）。请检查控制面计费接口与数据库，必要时在“账单与对账”中处理待结算记录。"},
	TypeReservationLeak: {TypeReservationLeak, "预占泄漏清理", "warning", "system",
		"有请求超过最大请求时长仍未结算，系统已释放其额度预占。偶发属正常；持续出现请排查网关是否异常退出或结算失败。"},
	TypeProxyUsageUnknown: {TypeProxyUsageUnknown, "正向代理用量未知", "warning", "access",
		"正向代理请求未能解析出用量，已记为“用量未知”且未计费。请在“账单与对账 → 待处理”中核对，必要时补充该站点的用量解析。"},
	TypeBudgetThreshold80: {TypeBudgetThreshold80, "预算已用 80%", "warning", "access",
		"本周期预算已用到 80%，用完后将按断流设置停用。如需继续使用，请提前在“预算与额度”中追加预算或提醒相关人员控制用量。"},
	TypeBudgetThreshold100: {TypeBudgetThreshold100, "预算已用尽 100%", "high", "access",
		"本周期预算已用尽。开启预算断流时后续调用会被拒绝；如需继续使用，请在“预算与额度”中追加预算，否则将在下个周期自动恢复。"},
	TypeAuditRecordDropped: {TypeAuditRecordDropped, "审计记录丢失", "high", "system",
		"审计链写入队列已满，部分非关键审计记录未进入审计链（操作审计表仍有记录）。请检查数据库写入性能，并关注是否持续发生。"},
	TypeAuditWriteFailed: {TypeAuditWriteFailed, "关键审计写入失败", "critical", "system",
		"改执行模式、价格、预算、断流开关、资费或钱包等关键操作已生效，但审计链写入重试后仍失败。请立即检查数据库，并在操作审计中核对该操作。"},
	TypeAuditVerifyFailed: {TypeAuditVerifyFailed, "审计链完整性校验失败", "critical", "system",
		"审计链校验发现断链或签名不符，审计记录可能被篡改或签名密钥已变更。请保留现场、导出审计链并联系安全负责人排查。"},
	TypeAuditHMACDefaultKey: {TypeAuditHMACDefaultKey, "审计签名密钥未配置", "critical", "system",
		"控制面未配置 UAG_AUDIT_HMAC_KEY，正在使用开发默认密钥，审计记录可被伪造。请在部署配置中设置随机密钥（离线安装包会自动生成）后重启控制面。"},
	TypeLocalIdentityCleanupExhausted: {TypeLocalIdentityCleanupExhausted, "本地身份清理失败", "high", "system",
		"删除用户后，身份服务（Keycloak）里的对应账号多次重试仍删除失败。该账号已被禁用、无法登录，但仍占用用户名。请检查身份服务是否可达，并在身份服务管理台手工删除该账号（可用告警里的指纹到操作审计中核对）。"},
}

// informationalTypes 是只提示、不进“待处置”的类型：80% 预警是提醒，不是故障。
var informationalTypes = map[string]bool{TypeBudgetThreshold80: true}

// KindOf 返回告警类型的中文定义；未知类型返回 false。
func KindOf(typ string) (Kind, bool) {
	k, ok := kinds[typ]
	return k, ok
}

// Types 返回全部运维告警类型（按字母序），供界面与测试核对中文名称。
func Types() []string {
	out := make([]string, 0, len(kinds))
	for typ := range kinds {
		out = append(out, typ)
	}
	sort.Strings(out)
	return out
}

// Event 是一次运维事件。ScopeKey 决定聚合粒度：同类型同作用域的事件合并到同一个打开的告警组。
type Event struct {
	TenantID   string
	Type       string
	ScopeKey   string
	ScopeLabel string
	Count      int
	OccurredAt time.Time
	Detail     map[string]any
}

type groupUpserter interface {
	UpsertOpen(ctx context.Context, input repository.AlertGroupUpsertInput) (*repository.AlertGroup, bool, error)
}

type inboxUpserter interface {
	UpsertByGroup(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL, groupKey string) (bool, error)
}

type notifier interface {
	Dispatch(ctx context.Context, tenantID, severity, title string, body map[string]any) error
}

// Emitter 把运维事件写进告警组与消息中心，并在新告警时外发。
type Emitter struct {
	groups   groupUpserter
	inbox    inboxUpserter
	notifier notifier
}

func NewEmitter(groups groupUpserter, inbox inboxUpserter, n notifier) *Emitter {
	return &Emitter{groups: groups, inbox: inbox, notifier: n}
}

// GroupKey 是同类型同作用域事件聚合用的键。
func GroupKey(typ, scope string) string {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		scope = "tenant"
	}
	key := "ops|" + typ + "|" + scope
	if len(key) > 128 {
		key = key[:128]
	}
	return key
}

// Emit 写入一次运维事件。返回 created=true 表示这是新告警（已尝试外发）。
func (e *Emitter) Emit(ctx context.Context, ev Event) (bool, error) {
	if e == nil || e.groups == nil {
		return false, errors.New("ops alert emitter is not configured")
	}
	kind, ok := kinds[ev.Type]
	if !ok {
		return false, fmt.Errorf("unknown ops alert type %q", ev.Type)
	}
	if strings.TrimSpace(ev.TenantID) == "" {
		return false, errors.New("ops alert tenant is required")
	}
	if ev.Count <= 0 {
		ev.Count = 1
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}
	title := kind.Label
	if label := strings.TrimSpace(ev.ScopeLabel); label != "" {
		title = kind.Label + " · " + label
	}
	if len([]rune(title)) > 120 {
		title = string([]rune(title)[:120])
	}
	body := map[string]any{
		"ops_alert":  true,
		"alert_type": kind.Type,
		"type_label": kind.Label,
		"suggestion": kind.Suggestion,
		"domain":     kind.Domain,
		"scope_key":  ev.ScopeKey,
		"count":      ev.Count,
	}
	if ev.ScopeLabel != "" {
		body["scope_label"] = ev.ScopeLabel
	}
	for k, v := range ev.Detail {
		if _, reserved := body[k]; !reserved {
			body[k] = v
		}
	}
	groupKey := GroupKey(kind.Type, ev.ScopeKey)
	group, created, err := e.groups.UpsertOpen(ctx, repository.AlertGroupUpsertInput{
		TenantID: ev.TenantID, GroupKey: groupKey, Severity: kind.Severity, AlertType: kind.Type,
		Title: title, OccurredAt: ev.OccurredAt, BodyJSON: body,
		EffectiveSeverity: effectiveSeverity(kind.Severity), DispositionClass: dispositionClass(kind.Type),
		ClassKey: "ops|" + kind.Type, Domain: kind.Domain,
	})
	if err != nil {
		return false, err
	}
	if group != nil {
		body["alert_group_id"] = group.ID
	}
	if e.inbox != nil {
		if _, err := e.inbox.UpsertByGroup(ctx, ev.TenantID, kind.Severity, kind.Type, title, body, kind.targetURL(), groupKey); err != nil {
			log.Printf("[ops_alert] inbox upsert failed type=%s tenant=%s: %v", kind.Type, ev.TenantID, err)
		}
	}
	if created && e.notifier != nil {
		if err := e.notifier.Dispatch(ctx, ev.TenantID, kind.Severity, title, map[string]any{
			"类型": kind.Label, "范围": firstNonEmpty(ev.ScopeLabel, "全租户"), "次数": ev.Count, "处置建议": kind.Suggestion,
		}); err != nil {
			log.Printf("[ops_alert] notify failed type=%s tenant=%s: %v", kind.Type, ev.TenantID, err)
		}
	}
	return created, nil
}

func dispositionClass(typ string) string {
	if informationalTypes[typ] {
		return "informational"
	}
	return "action_required"
}

func effectiveSeverity(severity string) string {
	switch severity {
	case "critical", "high":
		return severity
	case "warning":
		return "medium"
	default:
		return "low"
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
