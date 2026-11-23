package handler

import (
	"context"
	"log"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/opsalert"
)

// criticalAuditActions 是必须同步写入审计链、不得因队列满而丢失的操作：
// 改执行模式、改价格、改预算、改断流开关、发布资费、钱包调账。
var criticalAuditActions = map[string]bool{
	// 价格
	"price.import": true, "price.update": true, "update_model_pricing": true,
	"billing.price.create": true, "billing.ratio_price.create": true, "billing.price.zero_rejected": true,
	"billing.upstream.rate.update":      true,
	"billing.upstream.rate.delete":      true,
	"billing.channel_fixed_cost.upsert": true,
	"billing.channel_fixed_cost.delete": true,
	// 币种切换与作废其他币种价格会让大批价格失效、钱包改标，属于关键操作。
	"billing.currency.switch": true, "billing.price.retire_other_currencies": true,
	// 预算与额度
	"quota_policy.update": true, "team.budget.update": true, "user.personal_budget.update": true,
	"billing.employee.defaults.update": true, "billing.employee.allowances.update": true,
	"budget.pause_key": true, "budget.unpause_key": true,
	// 断流开关
	// 资费
	"billing.tariff.create": true, "billing.tariff.edit": true, "billing.tariff.publish": true, "billing.tariff.delete": true,
	// 查看脱敏原文与开关变更：原文外泄风险最高的操作，必须同步写入审计链。
	"reveal_raw_evidence": true, "update_raw_evidence_setting": true,
	// 钱包调账
	"billing.credit": true, "billing.adjustment": true,
}

// isCriticalAudit 判断一次审计是否关键。系统设置只有在改执行模式时才是关键事件。
func isCriticalAudit(actionType string, detail map[string]interface{}) bool {
	if criticalAuditActions[actionType] {
		return true
	}
	if actionType == "update_system_settings" {
		_, modeChanged := detail["new_configured_mode"]
		return modeChanged
	}
	return strings.HasPrefix(actionType, "billing.tariff.")
}

// appendAuditChain 把一条操作审计写进审计链：关键事件同步写入（失败产生高危告警并返回错误），
// 其余异步写入（返回 nil）。审计链未配置时返回 nil；必须以审计链成功为前提的调用方
// （如查看脱敏原文）要自行先检查 deps.AuditAppender。
func appendAuditChain(ctx context.Context, deps *Dependencies, tenantID, actionType, opID string, detail map[string]interface{}) error {
	if deps == nil || deps.AuditAppender == nil {
		return nil
	}
	if !isCriticalAudit(actionType, detail) {
		deps.AuditAppender.Enqueue(tenantID, "audit_op", opID, detail)
		return nil
	}
	err := deps.AuditAppender.AppendSync(ctx, tenantID, "audit_op", opID, detail)
	if err != nil {
		log.Printf("[audit_chain] critical append failed action=%s op=%s: %v", actionType, opID, err)
		if deps.OpsAlerts != nil {
			if _, alertErr := deps.OpsAlerts.Emit(context.WithoutCancel(ctx), opsalert.Event{
				TenantID: tenantID, Type: opsalert.TypeAuditWriteFailed, ScopeKey: "action:" + actionType,
				ScopeLabel: auditActionLabel(actionType), Detail: map[string]any{"operation_id": opID},
			}); alertErr != nil {
				log.Printf("[audit_chain] critical append alert failed: %v", alertErr)
			}
		}
	}
	return err
}

// auditActionLabel 给告警标题用的中文操作名。
func auditActionLabel(actionType string) string {
	switch {
	case actionType == "update_system_settings":
		return "修改安全执行模式"
	case actionType == "billing.currency.switch":
		return "切换系统币种"
	case strings.Contains(actionType, "price") || actionType == "update_model_pricing" || strings.HasSuffix(actionType, "rate.update"):
		return "修改价格"
	case strings.HasPrefix(actionType, "billing.tariff."):
		return "资费变更"
	case actionType == "billing.credit" || actionType == "billing.adjustment":
		return "钱包调账"
	default:
		return "修改预算或额度"
	}
}
