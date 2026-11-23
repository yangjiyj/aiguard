// 会话类路由（conversations / export / chat / upload）的身份门。
// 6.10：接入 W2 的 requireActivePortalUser——每次请求向控制面复核账号仍有效，
// 已停用/移除/无对话权限的用户即使 JWT 未过期也被拒；控制面不可用时 fail-closed（502）。
// 拒绝响应统一补上映射表文案（helper 本身只返回 {error}）。
import { auth } from '@/auth';
import { describePortalError } from './portal-errors';
import {
  requireActivePortalUser,
  type ActivePortalUser,
  type PortalSessionLike,
  type RequireActivePortalUserOptions,
} from './require-active-user';

export type ConversationUser = ActivePortalUser;

async function withMessage(denied: Response): Promise<Response> {
  let code = 'unauthorized';
  try {
    const body = (await denied.clone().json()) as { error?: unknown };
    if (typeof body.error === 'string' && body.error) code = body.error;
  } catch {
    // 保持默认 code
  }
  const e = describePortalError({ code, status: denied.status });
  return Response.json(
    { error: e.code, message: e.message, status: denied.status },
    { status: denied.status, headers: { 'cache-control': 'private, no-store' } },
  );
}

/** 已拿到 session 的路由用这个（chat/upload 还要用 session 里的 externalSubject 等字段）。 */
export async function requireActiveSessionUser(
  session: PortalSessionLike | null | undefined,
  options: RequireActivePortalUserOptions = {},
): Promise<ConversationUser | Response> {
  const result = await requireActivePortalUser(session, options);
  if (result instanceof Response) return withMessage(result);
  return result.user;
}

export async function requireConversationUser(
  options: RequireActivePortalUserOptions = {},
): Promise<ConversationUser | Response> {
  return requireActiveSessionUser(await auth(), options);
}

export { DEFAULT_TRASH_RETENTION_DAYS, trashRetentionDays, trashCutoff } from './trash-policy';
