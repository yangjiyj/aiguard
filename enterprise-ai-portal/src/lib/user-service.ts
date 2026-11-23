import { prisma } from '@/lib/prisma';
import type { PortalUserResolution } from './control-plane';

export interface UserProfileInput {
  id: string;
  email: string;
  name: string | null;
  department: string | null;
  role: string;
}

// 登录时 upsert 用户档案（sub 为主键）——旧路径，保留兼容。
export async function ensureUserProfile(input: UserProfileInput) {
  await prisma.userProfile.upsert({
    where: { id: input.id },
    create: input,
    update: {
      email: input.email,
      name: input.name,
      department: input.department,
      role: input.role,
    },
  });
}

export interface ResolvedUserProfile {
  userId: string;
  email: string;
  name: string | null;
  departmentId: string;
  chatAllowed: boolean;
}

// 任务7：以控制面 EnsurePortalUser 返回的 user_id/department_id/chat_allowed 为授权依据。
// 本地档案的主键改为控制面 user_id（而非 OIDC sub）——稳定身份解析后用户跨 IdP 重绑也能保持档案。
// 无模型权限的账号也有个人档案；个人入口由 portal_allowed 决定。
export async function applyControlPlaneResolution(
  oidcSubject: string,
  email: string,
  name: string | null,
  displayDepartment: string | null,
  resolution: PortalUserResolution,
): Promise<ResolvedUserProfile> {
  await prisma.userProfile.upsert({
    where: { id: resolution.userId },
    create: {
      id: resolution.userId,
      email,
      name,
      // department 是员工可见的企业声明；内部授权 ID 单独保存在会话的 departmentId。
      // 不把控制面内部 ID 暴露给门户展示层。
      department: displayDepartment?.trim() || null,
      role: 'employee',
    },
    update: {
      email,
      name,
      department: displayDepartment?.trim() || null,
      role: 'employee',
    },
  });
  return {
    userId: resolution.userId,
    email,
    name,
    departmentId: resolution.departmentId,
    chatAllowed: resolution.chatAllowed,
  };
}
