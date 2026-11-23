package handler

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// localIdentityDeletionPlan 是删除本地身份用户前解析出的清理计划。
//
// 为什么必须在删库「之前」解析：user_identity_links 对 users 是 ON DELETE CASCADE
// （137_enterprise_identity_department.sql），users 行一删，link 随之消失，ExternalSubject 就再也查不到 Keycloak subject，
// 清理被静默跳过，Keycloak 用户永久遗留——同名账号因此无法重建（409 用户名已被占用）。
type localIdentityDeletionPlan struct {
	subject string
	// unresolved 表示 subject 无法解析且又不是「非本地身份」（查询失败）：删除前就要中止，不能带着未知状态删库。
	unresolved bool
}

// planLocalIdentityDeletion 在 DB 删除之前解析需要清理的 Keycloak subject。
//
// 触发条件（全部满足才需要清理）：
//   - 用户 DepartmentAssignmentSource == "local"（该用户由本地身份体系托管）
//   - LocalIdentityProvisioner.ExternalSubject 能解析出 subject（ErrNotFound 视为"非 local 身份"，跳过）
func planLocalIdentityDeletion(r *http.Request, deps *Dependencies, existing *repository.User) localIdentityDeletionPlan {
	if deps == nil || deps.LocalIdentityProvisioner == nil || deps.LocalIdentityClient == nil {
		return localIdentityDeletionPlan{}
	}
	if existing.DepartmentAssignmentSource != "local" {
		return localIdentityDeletionPlan{}
	}
	// 单机模式（未配置身份运行时）的本地账号凭据只在控制面里，没有 Keycloak 账号可禁用或删除；
	// 此时 LocalIdentityClient 是 nil 指针，继续往下调用会 panic 并让删除用户返回空 500。
	if standalone, err := standaloneLocalCredential(r.Context(), deps, existing); err != nil {
		return localIdentityDeletionPlan{unresolved: true}
	} else if standalone {
		return localIdentityDeletionPlan{}
	}
	subject, err := deps.LocalIdentityProvisioner.ExternalSubject(r.Context(), existing.TenantID, existing.ID)
	if err != nil {
		if errors.Is(err, localidentity.ErrNotFound) {
			return localIdentityDeletionPlan{}
		}
		return localIdentityDeletionPlan{unresolved: true}
	}
	return localIdentityDeletionPlan{subject: subject}
}

// disableLocalIdentityBeforeDelete 在删库之前先把 Keycloak 里的用户禁用。
//
// 这一步失败必须中止删除（调用方返回 502，库里什么都不动）：否则 Keycloak 里是仍可登录的用户，而本地 users 行已经没了，
// 它凭 Keycloak 登录 Chat 门户时会被 JIT 重新建成一个新的 chat_user。先禁用再删库，即使后面删除 Keycloak 用户失败，
// 孤儿也已经无法登录。
func disableLocalIdentityBeforeDelete(r *http.Request, deps *Dependencies, plan localIdentityDeletionPlan) error {
	if plan.unresolved {
		return localidentity.ErrUnavailable
	}
	if plan.subject == "" {
		return nil
	}
	return deps.LocalIdentityClient.SetEnabled(r.Context(), plan.subject, false)
}

// finishLocalIdentityDeletion 在 DB 用户行已删除、会话已吊销后，删除 Keycloak 用户。
// 此时账号已禁用，删除失败不影响安全性，但必须持续重试：失败时写入持久化队列，由 CleanupWorker 带指数退避重试。
// 入队本身也失败时才退回到 reconciliation 审计标记（尽力而为），并记录日志。
//
// 安全：不向响应体或日志泄露 KC 错误细节、subject 原文、DSN 或 secret。
func finishLocalIdentityDeletion(
	r *http.Request,
	deps *Dependencies,
	existing *repository.User,
	plan localIdentityDeletionPlan,
) {
	if plan.subject == "" {
		return
	}
	actor := platformAdminActorID(r)
	if err := deps.LocalIdentityClient.DeleteUser(r.Context(), plan.subject); err == nil {
		if deps.LocalIdentityCleanupQ != nil {
			if err := deps.LocalIdentityCleanupQ.MarkDoneBySubject(r.Context(), existing.TenantID, plan.subject, time.Now().UTC()); err != nil {
				// 标记失败无害：worker 之后再删一次，Keycloak 对已删除用户返回不存在会被当作成功。
				log.Printf("component=local_identity_cleanup stage=mark_done_failed tenant=%s user=%s", existing.TenantID, existing.ID)
			}
		}
		return
	}
	if deps.LocalIdentityCleanupQ != nil {
		// 已在删库前预登记，worker 会按退避继续清理（耗尽后每日续试）。
		recordLocalIdentityCleanupPending(r, deps, existing, actor, plan.subject)
		return
	}
	// 没有配置队列：留下对账审计标记，人工可见。
	provision := localidentity.ProvisionInput{
		ID: existing.ID, TenantID: existing.TenantID, ActorID: actor, ExternalSubject: plan.subject,
	}
	_ = markLocalIdentityReconciliation(r, deps, provision, "delete_user_keycloak_cleanup_failed")
}

// preEnqueueLocalIdentityCleanup 在任何破坏性动作之前把清理任务写入持久化队列。
// 没有 subject（非本地身份）或未配置队列时直接放行；入队失败返回错误，调用方中止删除。
func preEnqueueLocalIdentityCleanup(r *http.Request, deps *Dependencies, existing *repository.User, plan localIdentityDeletionPlan) error {
	if plan.subject == "" || deps == nil || deps.LocalIdentityCleanupQ == nil {
		return nil
	}
	return deps.LocalIdentityCleanupQ.Enqueue(r.Context(), existing.TenantID, existing.ID, platformAdminActorID(r), plan.subject, time.Now().UTC())
}

// recordLocalIdentityCleanupPending 在 audit_operations 里留一条「清理已入队」记录：只含用户 ID 与 subject 指纹。
func recordLocalIdentityCleanupPending(r *http.Request, deps *Dependencies, existing *repository.User, actor, subject string) {
	logAudit(r, deps, "local_identity.cleanup_queued", map[string]interface{}{
		"tenant_id": existing.TenantID, "user_id": existing.ID, "actor_id": actor,
		"subject_fingerprint": localidentity.SubjectFingerprint(existing.TenantID, subject),
	}, "user", existing.ID)
}

// platformAdminActorID 从请求上下文取出 actor ID，供 reconciliation 审计使用。
func platformAdminActorID(r *http.Request) string {
	if u := auth.GetUser(r.Context()); u != nil {
		return u.ID
	}
	return ""
}
