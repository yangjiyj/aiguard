import { useMemo } from 'react'
import { useAuthStore } from '../stores/auth'
import {
  canAccessPath,
  canManagePlatformSecuritySettings,
  canManageSecurityPolicy,
  canManageSkillAdmission,
  canWriteSystemSettings,
  isPlatformLevelRole,
  isSystemAdminRole,
} from '../utils/access'

// 当前账号的权限判断，自动带上租户（平台级判断要用）。纯函数仍在 utils/access.ts。
export function useAccess() {
  const role = useAuthStore((state) => state.user?.role)
  const tenantId = useAuthStore((state) => state.user?.tenant_id)
  return useMemo(() => ({
    role,
    tenantId,
    isSystemAdmin: isSystemAdminRole(role),
    isPlatformLevel: isPlatformLevelRole(role, tenantId),
    canWriteSystemSettings: canWriteSystemSettings(role),
    canManageSecurityPolicy: canManageSecurityPolicy(role),
    canManagePlatformSecuritySettings: canManagePlatformSecuritySettings(role, tenantId),
    canManageSkillAdmission: canManageSkillAdmission(role),
    canAccessPath: (path: string) => canAccessPath(role, path, tenantId),
  }), [role, tenantId])
}
