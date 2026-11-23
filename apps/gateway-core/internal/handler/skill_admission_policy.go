package handler

import (
	"context"
	"fmt"
	"log"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// resolveSkillAdmissionForAnalysis 查 Skill 版本的准入状态。查询失败从不复用缓存里的批准：
// 失败一律记为“准入服务不可用”，即防护项 skill.admission_unavailable 的命中，动作按租户配置
// （默认告警放行）。2.9.22 起不再读 SKILL_ADMISSION_FAIL_MODE。
func resolveSkillAdmissionForAnalysis(ctx context.Context, client *ToolRiskClient, audit AuditWriter, envelope *modelrouter.RequestEnvelope, identity agentguard.SkillIdentity, mode securityexit.Mode) (skillAdmissionResolution, agentguard.SkillAdmissionStatus, error) {
	tenantID := ""
	if envelope != nil {
		tenantID = envelope.TenantID
	}
	resolution, err := client.ResolveSkillAdmission(ctx, tenantID, identity)
	status := agentguardSkillAdmission(resolution.Status)
	if err == nil {
		return resolution, status, nil
	}
	// 客户端在准入查询期间断开（请求 ctx 已取消，查询用它发 HTTP 而失败）：不是准入服务不可用，是客户端走了。
	// 不写覆盖缺口事件、不打 coverage_gap 日志；错误上挂哨兵，调用方据此记 client_canceled。
	if clientGoneDuring(ctx, err) {
		return resolution, agentguard.SkillAdmissionUnavailable, fmt.Errorf("%w: skill admission lookup: %w", errClientGoneDuringSecurity, err)
	}
	message := fmt.Sprintf("Skill admission unavailable (record_only=%t)", mode == securityexit.Record)
	if audit != nil && envelope != nil {
		audit.WriteSecurityEvent(ctx, envelope, nil, "skill_admission_coverage_gap", message)
	} else {
		log.Printf("[coverage_gap] %s", message)
	}
	return resolution, agentguard.SkillAdmissionUnavailable, err
}
