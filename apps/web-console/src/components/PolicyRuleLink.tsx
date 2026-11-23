import { Typography } from 'antd'
import { Link } from 'react-router-dom'
import type { PolicyLink } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { canAccessPath } from '../utils/access'
import { withEvent } from '../utils/policyEventLink'

// name 传已清洗的显示名；当前角色打不开目标页时显示纯文本，免得被路由守卫悄悄送回首页。
export default function PolicyRuleLink({ link, name, eventId }: { link?: PolicyLink | null; name?: string; eventId?: string }) {
  const role = useAuthStore((state) => state.user?.role)
  const tenantId = useAuthStore((state) => state.user?.tenant_id)
  if (link?.kind === 'deleted') {
    const original = (name || link.label || '').trim()
    return <Typography.Text>{original && original !== '未记录规则' ? `${original}（已删除）` : '该策略已删除'}</Typography.Text>
  }
  const label = (name || link?.label || '').trim() || '未记录规则'
  if (!link?.path || !canAccessPath(role, link.path.split('?')[0], tenantId)) return <Typography.Text>{label}</Typography.Text>
  return <Link to={withEvent(link.path, eventId)} data-testid="policy-rule-link">{label}</Link>
}
