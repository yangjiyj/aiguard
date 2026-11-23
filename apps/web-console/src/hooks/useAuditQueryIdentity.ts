import { useAuthStore } from '../stores/auth'

export const auditQueryIdentity = (user: { tenant_id?: string; id: string; role: string } | null) => (
  user ? [user.tenant_id || '', user.id, user.role].join('|') : 'anonymous'
)

export const useAuditQueryIdentity = () => useAuthStore((state) => auditQueryIdentity(state.user))
