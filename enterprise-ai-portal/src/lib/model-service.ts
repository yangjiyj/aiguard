/**
 * 模型权限校验服务（任务11步骤4）。
 *
 * 门户在敏感模型列表/密钥操作前向控制面校验当前部门：部门迁移（管理员把用户从 A
 * 挪到 B）后，旧会话持有的 departmentId/departmentVersion 立即过期，本服务检测到
 * 不一致就返回 stale=true，调用方必须丢弃缓存的模型列表并重新拉取。
 *
 * 数据流：
 *   1. 会话建立时 control-plane.ts 的 ensurePortalUser 返回 departmentId + departmentVersion；
 *   2. 会话存这两项作为基线；
 *   3. 敏感操作前调 verifyCurrentDepartment 重新解析，比对 departmentId/departmentVersion；
 *   4. 不一致（部门变了）或 chat_allowed=false（应急）→ 返回 stale/denied，调用方刷新或拒绝。
 *
 * 红线：错误信息不含 DSN/secret/完整 claims；ControlPlaneError 透传其分类码。
 */
import {
  ensurePortalUser,
  type EnsurePortalUserOptions,
  type StableIdentityClaims,
  PORTAL_DEFAULT_TENANT_ID,
  ControlPlaneError,
} from './control-plane';

/** 会话里持有的部门授权基线（登录时由 ensurePortalUser 写入）。 */
export interface SessionDepartmentBaseline {
  userId: string;
  departmentId: string;
  departmentVersion: number;
  chatAllowed: boolean;
}

/** verifyCurrentDepartment 的结果。 */
export interface DepartmentVerification {
  /** true 表示会话基线仍有效，可继续敏感操作。 */
  ok: boolean;
  /** 部门已变化（部门迁移），调用方必须刷新会话基线并丢弃旧模型列表。 */
  stale: boolean;
  /** 用户处于应急态（chat_allowed=false），模型列表必须为空。 */
  denied: boolean;
  /** 控制面最新解析结果；ok=false 时调用方据此刷新基线。 */
  latest?: {
    userId: string;
    departmentId: string;
    departmentVersion: number;
    chatAllowed: boolean;
  };
  /** 失败分类码（控制面不可达/拒绝），不含敏感细节。 */
  errorCode?: string;
}

/**
 * 校验当前部门是否与会话基线一致。
 *
 * @param baseline 会话基线（登录时写入）
 * @param identity 已验证 OIDC token 提取的稳定身份
 * @param options 注入 fetch/env（测试用）
 */
export async function verifyCurrentDepartment(
  baseline: SessionDepartmentBaseline,
  identity: StableIdentityClaims,
  options: EnsurePortalUserOptions = {},
): Promise<DepartmentVerification> {
  // 基线本身是应急态（chat_allowed=false）：模型列表必须为空，直接 denied。
  if (!baseline.chatAllowed) {
    return { ok: false, stale: false, denied: true };
  }

  let resolution;
  try {
    resolution = await ensurePortalUser(PORTAL_DEFAULT_TENANT_ID, identity, options);
  } catch (e) {
    if (e instanceof ControlPlaneError) {
      // 控制面不可达/拒绝：fail-closed，不放过敏感操作。
      return { ok: false, stale: false, denied: false, errorCode: e.code };
    }
    return { ok: false, stale: false, denied: false, errorCode: 'unknown' };
  }

  // 应急态（被管理员设为 emergency）：模型列表必须为空。
  if (!resolution.chatAllowed) {
    return {
      ok: false,
      stale: false,
      denied: true,
      latest: {
        userId: resolution.userId,
        departmentId: resolution.departmentId,
        departmentVersion: resolution.departmentVersion,
        chatAllowed: resolution.chatAllowed,
      },
    };
  }

  // 部门迁移检测：departmentId 或 departmentVersion 变化都视为 stale。
  // departmentVersion 是 users.department_version 单调 revision，部门迁移必刷新；
  // 即便 departmentId 因回迁相同，version 变化也意味着中间发生过迁移，必须刷新。
  const departmentChanged =
    resolution.departmentId !== baseline.departmentId ||
    (resolution.departmentVersion !== 0 &&
      resolution.departmentVersion !== baseline.departmentVersion);

  if (departmentChanged) {
    return {
      ok: false,
      stale: true,
      denied: false,
      latest: {
        userId: resolution.userId,
        departmentId: resolution.departmentId,
        departmentVersion: resolution.departmentVersion,
        chatAllowed: resolution.chatAllowed,
      },
    };
  }

  return {
    ok: true,
    stale: false,
    denied: false,
    latest: {
      userId: resolution.userId,
      departmentId: resolution.departmentId,
      departmentVersion: resolution.departmentVersion,
      chatAllowed: resolution.chatAllowed,
    },
  };
}
