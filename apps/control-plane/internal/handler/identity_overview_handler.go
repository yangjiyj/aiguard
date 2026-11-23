package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
)

// overviewTimeout 限制总览对运行态的探活；超时即降级为 runtime_healthy=false。
// 2 秒上限与 identity_publication_handler 的 status 探活保持一致，避免拖垮控制面。
const overviewTimeout = 2 * time.Second

// identityOverviewLogin 是企业 SSO 登录侧的总览状态。
// 只暴露客户可理解的状态字段，绝不返回 secret、Bind DN 密码、管理 URL、runtime token。
type identityOverviewLogin struct {
	State           string `json:"state"`                       // unconfigured|draft|tested|active|abnormal
	LastTestedAt    string `json:"last_tested_at,omitempty"`    // RFC3339，无则省略
	LastPublishedAt string `json:"last_published_at,omitempty"` // RFC3339，无则省略
	RuntimeHealthy  bool   `json:"runtime_healthy"`             // 运行态可达且无 drift
	RuntimeMessage  string `json:"runtime_message,omitempty"`   // 客户可执行建议
}

// identityOverviewDirectorySummary 是最近一次目录同步运行的脱敏摘要。
type identityOverviewDirectorySummary struct {
	Created    int `json:"created"`
	Updated    int `json:"updated"`
	Disabled   int `json:"disabled"`
	Conflicts  int `json:"conflicts"`
	Unassigned int `json:"unassigned"`
}

// identityOverviewDirectory 是目录账号侧的总览状态。
type identityOverviewDirectory struct {
	State           string                            `json:"state"` // unconfigured|draft|tested|active|abnormal
	LastPreviewAt   string                            `json:"last_preview_at,omitempty"`
	LastSyncAt      string                            `json:"last_sync_at,omitempty"`
	LastSyncSummary *identityOverviewDirectorySummary `json:"last_sync_summary,omitempty"`
	RuntimeHealthy  bool                              `json:"runtime_healthy"`
	RuntimeMessage  string                            `json:"runtime_message,omitempty"`
}

// identityOverviewResponse 是 GET /admin/v1/identity/overview 的契约。
// login 与 directory 是两个独立状态，互不影响。
type identityOverviewResponse struct {
	Login                  identityOverviewLogin     `json:"login"`
	Directory              identityOverviewDirectory `json:"directory"`
	ReconciliationRequired int                       `json:"reconciliation_required"`
}

// loginRuntimeUnavailableMessage 是登录运行态不可达时的客户可执行建议。
// 与 GetIdentityStatus 保持一致：本地管理员登录不受影响。
const loginRuntimeUnavailableMessage = "身份服务暂不可用，本地管理员登录不受影响"

// loginRuntimeDriftedMessage 与 loginPublishErrorMessage 保留已知配置异常的可执行建议。
const loginRuntimeDriftedMessage = "当前配置尚未完整发布，可在企业 SSO 配置页执行修复"
const loginPublishErrorMessage = "身份配置发布失败，原有登录配置未切换，请在企业 SSO 配置页重试"

// directoryRuntimeUnavailableMessage 是目录运行态不可达时的客户可执行建议。
const directoryRuntimeUnavailableMessage = "目录同步服务暂不可用，已发布配置与历史记录不受影响"

// directoryReconciliationRequiredMessage 只暴露客户可执行建议，不暴露内部稳定 reason 或运行态原始错误。
const directoryReconciliationRequiredMessage = "目录运行状态需要重新对账，请重新执行目录激活"

type overviewRuntimeProbe struct {
	healthy bool
	drifted bool
	message string
}

// GetIdentityOverview GET /admin/v1/identity/overview
//
// 返回企业 SSO 登录与目录账号两路独立状态 + 待对账用户计数。
// 安全：响应只含客户可理解的状态/计数/RFC3339 时间，绝不返回 secret、Bind DN 密码、
// 管理 URL、runtime token；运行态不可达时仍返回 200 + runtime_healthy=false + 建议，
// 不报 500 也不留空白。
func GetIdentityOverview(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		tenantID := user.TenantID

		resp := identityOverviewResponse{
			Login:     buildLoginOverview(r.Context(), deps, tenantID),
			Directory: buildDirectoryOverview(r.Context(), deps, tenantID),
		}
		resp.ReconciliationRequired = countReconciliationRequired(r.Context(), deps, tenantID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// buildLoginOverview 聚合企业 SSO 登录侧状态：DB 已发布/草稿/测试态 + 运行态健康。
func buildLoginOverview(ctx context.Context, deps *Dependencies, tenantID string) identityOverviewLogin {
	out := identityOverviewLogin{State: "unconfigured"}

	active, err := deps.IdentitySourceRepo.GetActive(ctx, tenantID)
	if err != nil {
		// 数据库错误不外泄，按未配置降级（与 GetIdentitySources 现有兜底一致）。
		return out
	}
	if active != nil {
		if active.LastTestedAt != nil {
			out.LastTestedAt = active.LastTestedAt.Format(time.RFC3339)
		}
		if active.LastPublishedAt != nil {
			out.LastPublishedAt = active.LastPublishedAt.Format(time.RFC3339)
		}
		out.State = "active"
		probe := probeLoginRuntime(ctx, deps, active.ConfigDigest)
		out.RuntimeHealthy = probe.healthy
		out.RuntimeMessage = probe.message

		switch active.PublishStatus {
		case "drifted":
			out.State = "abnormal"
			out.RuntimeMessage = loginRuntimeDriftedMessage
		case "error":
			out.State = "abnormal"
			out.RuntimeMessage = loginPublishErrorMessage
		default:
			if probe.drifted {
				out.State = "abnormal"
			}
		}
		return out
	}

	// 无 active：从 draft/tested 推断草稿态。
	draft, err := deps.IdentitySourceRepo.GetPending(ctx, tenantID)
	if err != nil || draft == nil {
		return out
	}
	if draft.LastTestResult != nil && draft.LastTestResult.Success {
		out.State = "tested"
	} else {
		out.State = "draft"
	}
	if draft.LastTestedAt != nil {
		out.LastTestedAt = draft.LastTestedAt.Format(time.RFC3339)
	}
	// 草稿态不发布到运行态，runtime_healthy 保持 false（未发布）。
	return out
}

// probeLoginRuntime 探测企业 SSO 运行态健康：可达且无 drift 才算 healthy。
// 运行态缺失/超时/错误一律降级为 healthy=false + 客户可执行建议，绝不报错。
func probeLoginRuntime(ctx context.Context, deps *Dependencies, digest string) overviewRuntimeProbe {
	if deps.IdentityRuntime == nil {
		return overviewRuntimeProbe{message: loginRuntimeUnavailableMessage}
	}
	checkCtx, cancel := context.WithTimeout(ctx, overviewTimeout)
	defer cancel()
	status, err := deps.IdentityRuntime.Status(checkCtx, identityruntime.DesiredIdentitySource{
		Realm:  identityruntime.RealmName,
		Alias:  identityruntime.ProviderAlias,
		Digest: digest,
	})
	if err != nil {
		return overviewRuntimeProbe{message: loginRuntimeUnavailableMessage}
	}
	if status.Drifted || !status.Exists || !status.Enabled {
		// 状态接口可达但组件缺失、停用或漂移，按配置异常给出修复建议。
		return overviewRuntimeProbe{drifted: true, message: loginRuntimeDriftedMessage}
	}
	return overviewRuntimeProbe{healthy: true}
}

// buildDirectoryOverview 聚合目录账号侧状态：DB 草稿/测试/已发布 + 最近预览/同步 + 运行态健康。
func buildDirectoryOverview(ctx context.Context, deps *Dependencies, tenantID string) identityOverviewDirectory {
	out := identityOverviewDirectory{State: "unconfigured"}

	draft, err := deps.DirectorySourceRepo.GetDraft(ctx, tenantID)
	if err != nil || draft == nil {
		// 无草稿也可能存在历史预览/同步（已激活后删除草稿场景），仍尝试展示历史。
		out.LastPreviewAt, out.LastSyncAt, out.LastSyncSummary = loadDirectoryHistory(ctx, deps, tenantID)
		if out.LastSyncAt != "" && out.State == "unconfigured" {
			out.State = "active"
		}
		if out.State == "active" {
			applyDirectoryRuntimeProbe(&out, probeDirectoryRuntime(ctx, deps))
		}
		return out
	}

	switch draft.Status {
	case "active", "synced":
		out.State = "active"
	case "tested":
		out.State = "tested"
	case "error":
		out.State = "abnormal"
	case "draft":
		out.State = "draft"
	default:
		out.State = "draft"
	}

	out.LastPreviewAt, out.LastSyncAt, out.LastSyncSummary = loadDirectoryHistory(ctx, deps, tenantID)
	if draft.RuntimeReconciliationRequired {
		out.State = "abnormal"
		out.RuntimeHealthy = false
		out.RuntimeMessage = directoryReconciliationRequiredMessage
		return out
	}
	if out.State == "active" {
		applyDirectoryRuntimeProbe(&out, probeDirectoryRuntime(ctx, deps))
	}
	return out
}

// loadDirectoryHistory 取最近一次预览生成时间、最近一次同步运行完成时间与摘要。
// 任一查询失败都按空值降级，绝不外泄数据库错误。
func loadDirectoryHistory(ctx context.Context, deps *Dependencies, tenantID string) (string, string, *identityOverviewDirectorySummary) {
	var lastPreviewAt, lastSyncAt string
	var summary *identityOverviewDirectorySummary

	if deps.DirectorySyncPreviewRepo != nil {
		if preview, err := deps.DirectorySyncPreviewRepo.LatestPreview(ctx, tenantID); err == nil && preview != nil {
			lastPreviewAt = preview.CreatedAt.Format(time.RFC3339)
		}
		if run, err := deps.DirectorySyncPreviewRepo.LatestSyncRun(ctx, tenantID); err == nil && run != nil {
			if run.FinishedAt != nil {
				lastSyncAt = run.FinishedAt.Format(time.RFC3339)
			} else if !run.StartedAt.IsZero() {
				// 仍在 running 的同步暴露 started_at，避免页面误以为从不同步。
				lastSyncAt = run.StartedAt.Format(time.RFC3339)
			}
			summary = &identityOverviewDirectorySummary{
				Created:    run.CreatedCount,
				Updated:    run.UpdatedCount,
				Disabled:   run.DisabledCount,
				Conflicts:  run.ConflictCount,
				Unassigned: 0, // 同步运行头不携带 unassigned，保持 0 而非杜撰
			}
		}
	}
	return lastPreviewAt, lastSyncAt, summary
}

// probeDirectoryRuntime 探测目录运行态健康：组件存在、启用且无漂移才算 healthy。
// 运行态缺失/超时/错误一律降级为 healthy=false + 客户可执行建议，绝不报错。
func probeDirectoryRuntime(ctx context.Context, deps *Dependencies) overviewRuntimeProbe {
	if deps.DirectoryRuntime == nil {
		return overviewRuntimeProbe{message: directoryRuntimeUnavailableMessage}
	}
	checkCtx, cancel := context.WithTimeout(ctx, overviewTimeout)
	defer cancel()
	status, err := deps.DirectoryRuntime.Status(checkCtx)
	if err != nil {
		return overviewRuntimeProbe{message: directoryRuntimeUnavailableMessage}
	}
	if !status.Exists {
		return overviewRuntimeProbe{message: directoryRuntimeUnavailableMessage}
	}
	if status.Drifted {
		return overviewRuntimeProbe{drifted: true, message: directoryReconciliationRequiredMessage}
	}
	if !status.Enabled {
		return overviewRuntimeProbe{message: directoryRuntimeUnavailableMessage}
	}
	return overviewRuntimeProbe{healthy: true}
}

func applyDirectoryRuntimeProbe(out *identityOverviewDirectory, probe overviewRuntimeProbe) {
	out.RuntimeHealthy = probe.healthy
	out.RuntimeMessage = probe.message
	if probe.drifted {
		out.State = "abnormal"
	}
}

// countReconciliationRequired 统计租户内需要重新对账的用户数（users.status=reconciliation_required）。
// 查询失败按 0 降级，绝不外泄数据库错误。
func countReconciliationRequired(ctx context.Context, deps *Dependencies, tenantID string) int {
	if deps.UserRepo == nil {
		return 0
	}
	count, err := deps.UserRepo.CountByStatus(ctx, tenantID, "reconciliation_required")
	if err != nil {
		count = 0
	}
	if deps.DirectorySourceRepo != nil {
		if source, sourceErr := deps.DirectorySourceRepo.GetDraft(ctx, tenantID); sourceErr == nil &&
			source != nil && source.RuntimeReconciliationRequired {
			count++
		}
	}
	return count
}
