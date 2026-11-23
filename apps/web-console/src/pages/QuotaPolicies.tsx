import { useEffect, useMemo, useState } from 'react'
import { ConfigProvider, Segmented, Select, Card, Space, Alert } from 'antd'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { EnterprisePageHeader } from '../components/EnterpriseUI'
import { ScopedQuotaForm } from '../components/ai-permissions/ScopedQuotaForm'
import { TeamModelWhitelist } from '../components/team-tabs/BudgetModelsTab'
import { contentAuditApi, orgApi, keyApi, projectApi } from '../services/api'
import { useAuthStore } from '../stores/auth'

type ScopeType = 'tenant' | 'team' | 'project' | 'user' | 'key'

const SCOPE_OPTIONS = [
  { label: '单位', value: 'tenant' },
  { label: '部门', value: 'team' },
  { label: '应用', value: 'project' },
  { label: '用户', value: 'user' },
  { label: '密钥', value: 'key' },
]

const SCOPE_PLACEHOLDER: Record<Exclude<ScopeType, 'tenant'>, string> = {
  team: '选择部门',
  project: '选择应用',
  user: '选择用户',
  key: '选择密钥',
}

function toArray(r: any): any[] {
  if (Array.isArray(r?.items)) return r.items
  if (Array.isArray(r?.data)) return r.data
  if (Array.isArray(r)) return r
  return []
}

export default function QuotaPolicies({ embedded = false }: { embedded?: boolean }) {
  const [searchParams, setSearchParams] = useSearchParams()
  const currentUser = useAuthStore((state) => state.user)
  const role = currentUser?.role || ''
  const isFullTenantAdmin = role === 'platform_admin' || role === 'tenant_owner' || role === 'tenant_admin'
  const canChooseScope = isFullTenantAdmin
  const spScope = searchParams.get('scope_type') as ScopeType | null
  const [scopeType, setScopeType] = useState<ScopeType>(
    spScope && (['tenant', 'team', 'project', 'user', 'key'] as string[]).includes(spScope) ? spScope : 'team')
  const [scopeId, setScopeId] = useState<string>(searchParams.get('scope_id') || '')
  const [userSearch, setUserSearch] = useState('')
  const [debouncedUserSearch, setDebouncedUserSearch] = useState('')

  useEffect(() => {
    const nextScope = searchParams.get('scope_type') as ScopeType | null
    const normalizedScope = nextScope && (['tenant', 'team', 'project', 'user', 'key'] as string[]).includes(nextScope)
      ? nextScope
      : canChooseScope ? 'team' : isFullTenantAdmin ? 'tenant' : 'project'
    setScopeType(normalizedScope)
    setScopeId(searchParams.get('scope_id') || '')
  }, [canChooseScope, isFullTenantAdmin, searchParams])

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedUserSearch(userSearch.trim()), 300)
    return () => window.clearTimeout(timer)
  }, [userSearch])

  const identityKey = currentUser?.tenant_id + ':' + currentUser?.id
  const teamsQuery = useQuery({ queryKey: ['quota-teams', identityKey], queryFn: () => orgApi.listTeams(), enabled: canChooseScope && scopeType === 'team' })
  const projectsQuery = useQuery({ queryKey: ['quota-projects', identityKey], queryFn: () => projectApi.list(), enabled: canChooseScope && scopeType === 'project' })
  const usersQuery = useQuery({
    queryKey: ['quota-users', identityKey, debouncedUserSearch],
    queryFn: ({ signal }) => contentAuditApi.listUsers({ q: debouncedUserSearch, limit: 100, signal }),
    enabled: canChooseScope && scopeType === 'user',
  })
  const keysQuery = useQuery({ queryKey: ['quota-keys', identityKey], queryFn: () => keyApi.list(), enabled: canChooseScope && scopeType === 'key' })

  const entityOptions = useMemo(() => {
    if (scopeType === 'team') return toArray(teamsQuery.data?.data).map((t: any) => ({ value: t.id, label: t.name || t.id }))
    if (scopeType === 'project') return toArray(projectsQuery.data?.data).map((p: any) => ({ value: p.id, label: p.name || p.id }))
    if (scopeType === 'user') return toArray(usersQuery.data?.data).map((u: any) => ({
      value: u.id,
      label: [u.username || u.id, u.department_name].filter(Boolean).join(' · '),
    }))
    if (scopeType === 'key') return toArray(keysQuery.data?.data)
      .filter((k: any) => k.id)
      .map((k: any) => ({
        value: k.id,
        label: `${k.name || '未命名密钥'}${k.key_prefix ? ` · ${k.key_prefix}…` : ''}`,
      }))
    return []
  }, [scopeType, teamsQuery.data, projectsQuery.data, usersQuery.data, keysQuery.data])

  const handleScopeChange = (val: any) => {
    const nextScope = val as ScopeType
    setScopeType(nextScope)
    setScopeId('')
    setSearchParams({ scope_type: nextScope })
  }

  const handleScopeIDChange = (value: string) => {
    setScopeId(value)
    setSearchParams({ scope_type: scopeType, scope_id: value })
  }

  const entityLoading = teamsQuery.isFetching || projectsQuery.isFetching || usersQuery.isFetching || keysQuery.isFetching
  const scopeAllowed = isFullTenantAdmin ||
    ((role === 'dept_manager' || role === 'team_owner') && ['team', 'project', 'user'].includes(scopeType)) ||
    ((role === 'project_owner' || role === 'project_developer' || role === 'project_viewer' || role === 'developer' || role === 'viewer') && ['project', 'key'].includes(scopeType)) ||
    (role === 'auditor' && ['team', 'project'].includes(scopeType))
  const canWrite = isFullTenantAdmin ||
    (role === 'team_owner' && ['team', 'project', 'key'].includes(scopeType)) ||
    (role === 'project_owner' && ['project', 'key'].includes(scopeType))
  const hasTarget = scopeType === 'tenant' || !!scopeId

  return (
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <div style={{ padding: embedded ? 0 : 24 }}>
        {embedded ? null : <EnterprisePageHeader
          eyebrow="费用治理"
          title="配额策略"
          description="按单位 / 部门 / 应用 / 用户 / 密钥五个维度设置 Token、费用、RPM 与并发配额及超额处理动作。各作用域独立核算，上级与下级约束同时生效。"
        />}

        <Card style={{ marginBottom: 16 }}>
          <Space direction="vertical" size="middle" style={{ width: '100%' }}>
            {canChooseScope ? (
              <div>
                <div style={{ marginBottom: 8, color: 'rgba(0,0,0,0.65)' }}>配额维度</div>
                <Segmented options={SCOPE_OPTIONS} value={scopeType} onChange={handleScopeChange} />
              </div>
            ) : null}
            {!scopeAllowed ? (
              <Alert type="error" showIcon message="无权访问此配额范围" />
            ) : scopeType === 'tenant' ? (
              <Alert type="info" showIcon message="单位级配额对当前单位全局生效，无需选择具体对象。" />
            ) : canChooseScope ? (
              <div style={{ maxWidth: 360 }}>
                <Select
                  style={{ width: '100%' }}
                  showSearch
                  filterOption={scopeType === 'user' ? false : undefined}
                  optionFilterProp="label"
                  placeholder={SCOPE_PLACEHOLDER[scopeType]}
                  value={scopeId || undefined}
                  onChange={handleScopeIDChange}
                  onSearch={scopeType === 'user' ? setUserSearch : undefined}
                  options={entityOptions}
                  loading={entityLoading}
                  notFoundContent={entityLoading ? '加载中…' : '暂无数据'}
                />
              </div>
            ) : hasTarget ? (
              <Alert
                type="info"
                showIcon
                message={(SCOPE_OPTIONS.find((item) => item.value === scopeType)?.label || scopeType) + '：' + scopeId}
              />
            ) : null}
          </Space>
        </Card>

        {scopeAllowed && hasTarget ? <ScopedQuotaForm scopeType={scopeType} scopeId={scopeId} readOnly={!canWrite} budgetReadOnly={embedded} /> : null}
        {embedded && scopeAllowed && scopeType === 'team' && scopeId ? <Card title="模型范围" style={{ marginTop: 16 }}><TeamModelWhitelist teamId={scopeId} readOnly={!canWrite} /></Card> : null}
      </div>
    </ConfigProvider>
  )
}
