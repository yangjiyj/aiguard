package handler

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// dispositionEnforcer 是 DispositionEnforcer 的生产实现：把审计处置动作派发到
// 既有执行链路，而非新建执行通道（沿用「改造建议优先暴露/串接现有功能」）。
//
//   - revoke_key    复用 InternalKeyRepository.Revoke —— 与正常吊销同一路径，
//     吊销后该 key 在网关鉴权处立即失效；
//   - ban_user      复用用户停用流程（Status=disabled + 踢除会话），等价于
//     ToggleUserStatus，被封用户在鉴权中间件处被拒；
//   - block_session 在暂停键具备 tenant namespace 前明确拒绝，避免跨租户碰撞。
type dispositionEnforcer struct {
	keyRepo      *repository.InternalKeyRepository
	userRepo     *repository.UserRepository
	sessionRepo  *repository.SessionRepository
	pauseLogRepo *repository.PauseLogRepository
	redis        *redis.Client
}

// NewDispositionEnforcer 构造生产用的处置执行器。
func NewDispositionEnforcer(
	keyRepo *repository.InternalKeyRepository,
	userRepo *repository.UserRepository,
	sessionRepo *repository.SessionRepository,
	pauseLogRepo *repository.PauseLogRepository,
	redisClient *redis.Client,
) DispositionEnforcer {
	return &dispositionEnforcer{
		keyRepo:      keyRepo,
		userRepo:     userRepo,
		sessionRepo:  sessionRepo,
		pauseLogRepo: pauseLogRepo,
		redis:        redisClient,
	}
}

// Enforce 按动作类型派发到对应的既有执行流程。
func (e *dispositionEnforcer) Enforce(ctx context.Context, action DispositionAction) error {
	switch action.Action {
	case "revoke_key":
		if e.keyRepo == nil {
			return fmt.Errorf("key repository is not configured")
		}
		return e.keyRepo.Revoke(ctx, action.TenantID, action.Target)

	case "ban_user":
		if e.userRepo == nil {
			return fmt.Errorf("user repository is not configured")
		}
		updated, err := e.userRepo.UpdateStatusForTenant(ctx, action.TenantID, action.Target, "disabled")
		if err != nil {
			return err
		}
		if !updated {
			return fmt.Errorf("user not found: %s", action.Target)
		}
		// 与 ToggleUserStatus 一致：封禁即踢除其活跃会话，避免旧会话续用。
		if e.sessionRepo != nil {
			_ = e.sessionRepo.DeleteByUser(ctx, action.Target)
		}
		return nil

	case "block_session":
		return fmt.Errorf("block_session is unavailable until enforcement keys are tenant scoped")

	default:
		return fmt.Errorf("unsupported disposition action: %s", action.Action)
	}
}
