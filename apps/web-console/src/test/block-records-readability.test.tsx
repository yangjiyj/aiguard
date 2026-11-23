import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import BlockRecords from '../pages/BlockRecords'
import * as api from '../services/api'
import { useAuthStore } from '../stores/auth'
import { getRiskCategoryLabel } from '../utils/risk'
import { getFindingCategoryLabel } from '../utils/alertOccurrenceDisplay'

// 客户现场 2.9.15（2026-11-12）：阻断记录要能说明这次调用为什么危险；没有可靠来源时不显示。

const floorBlock: api.SecurityBlockRecord = {
  block_id: 'evt_floor',
  created_at: '2026-11-11T03:34:20Z',
  request_id: 'req-floor',
  source: 'gateway',
  event_type: 'tool_attempt_blocked',
  action_taken: 'block',
  severity: 'critical',
  layer: 'agent_tool',
  reason: '智能体工具调用触及产品内置安全底线',
  rule_name: '产品内置安全底线',
  detail: 'Read · ~/.ssh/id_rsa',
  basis: '产品内置安全底线拦截，不受「智能体行为 → 敏感资源访问」动作配置控制',
  explanation: '读取 SSH 私钥文件，可能泄露服务器登录凭据',
}

describe('BlockRecords readability', () => {
  let queryClient: QueryClient
  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.restoreAllMocks()
    useAuthStore.setState({ user: { id: 'a', username: 'a', role: 'auditor', tenant_id: 't1' } as any, isAuthenticated: true } as any)
    vi.spyOn(api.statsApi, 'getOverview').mockResolvedValue({ data: { timezone: 'Asia/Shanghai' } } as any)
    vi.spyOn(api.blockRecordsApi, 'trace').mockResolvedValue({ data: { block: floorBlock, alerts: null, alerts_status: 'unavailable', audit: null } } as any)
  })

  const renderPage = () => render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/security/blocks']}><BlockRecords /></MemoryRouter>
    </QueryClientProvider>,
  )

  it('shows why the call was dangerous in the list and the drawer', async () => {
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [floorBlock], total: 1, limit: 20, offset: 0 } } as any)
    renderPage()
    expect(await screen.findByText('读取 SSH 私钥文件，可能泄露服务器登录凭据')).toBeInTheDocument()
    fireEvent.click(screen.getByText('查看告警与留痕'))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('风险说明')).toBeInTheDocument()
    expect(within(drawer).getByText('读取 SSH 私钥文件，可能泄露服务器登录凭据')).toBeInTheDocument()
  })

  const asAdmin = () => useAuthStore.setState({ user: { id: 'a', username: 'a', role: 'platform_admin', tenant_id: 't1' } as any, isAuthenticated: true } as any)

  it('links the hit rule to the policy that decided the block', async () => {
    asAdmin()
    const contentBlock: api.SecurityBlockRecord = {
      ...floorBlock, block_id: 'evt_content', layer: 'input_content', rule_id: 'rule_631f3819', rule_name: '证书/私钥检测',
      policy_link: { kind: 'policy', path: '/security/policies?policy=rule_631f3819', label: '证书/私钥检测' },
    }
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [contentBlock, floorBlock], total: 2, limit: 20, offset: 0 } } as any)
    renderPage()
    const link = await screen.findByRole('link', { name: '证书/私钥检测' })
    expect(link).toHaveAttribute('href', '/security/policies?policy=rule_631f3819&event=evt_content')
    expect(screen.queryByText(/rule_631f3819/)).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '产品内置安全底线' })).not.toBeInTheDocument()
    fireEvent.click(screen.getAllByText('查看告警与留痕')[0])
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByRole('link', { name: '证书/私钥检测' })).toHaveAttribute('href', '/security/policies?policy=rule_631f3819&event=evt_content')
  })

  it('never shows the internal rule id: link label, then 未记录规则; deleted policies say so', async () => {
    asAdmin()
    const labelled = { ...floorBlock, block_id: 'evt_label', rule_name: undefined, rule_id: 'block_model_egress', policy_link: { kind: 'policy', path: '/security/policies?policy=x', label: '模型外联策略' } }
    const bare = { ...floorBlock, block_id: 'evt_bare', layer: 'weird_layer', rule_name: undefined, rule_id: 'rule_9f3a1c' }
    const deleted = { ...floorBlock, block_id: 'evt_del', rule_name: '已删规则', policy_link: { kind: 'deleted' } }
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [labelled, bare, deleted], total: 3, limit: 20, offset: 0 } } as any)
    renderPage()
    expect(await screen.findByRole('link', { name: '模型外联策略' })).toBeInTheDocument()
    expect(screen.getByText('未记录规则')).toBeInTheDocument()
    expect(screen.getByText('已删规则（已删除）')).toBeInTheDocument()
    expect(screen.queryByText(/block_model_egress|rule_9f3a1c/)).not.toBeInTheDocument()
  })

  it('keeps tool-like categories out of the rule filter: restricted file block keeps its name', async () => {
    asAdmin()
    const restricted = { ...floorBlock, block_id: 'evt_rf', layer: 'restricted_file', category: 'restricted_file_access', rule_name: '受限文件', detail: 'Read · .env' }
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [restricted], total: 1, limit: 20, offset: 0 } } as any)
    renderPage()
    const matches = await screen.findAllByText('受限文件')
    // 位置列的标签和命中规则格各一次；规则格里只断言规则名那一处。
    expect(matches.filter((el) => el.closest('strong')).length).toBe(1)
    expect(matches.filter((el) => el.closest('.ant-tag')).length).toBe(1)
    expect(screen.queryByText('未记录规则')).not.toBeInTheDocument()
  })

  it('falls back to the block layer name when the rule name is an internal id and there is no link label', async () => {
    const shaped = { ...floorBlock, block_id: 'evt_id', layer: 'mcp_tool', rule_name: 'disable_mcp', rule_id: 'disable_mcp' }
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [shaped], total: 1, limit: 20, offset: 0 } } as any)
    renderPage()
    expect((await screen.findAllByText('MCP 工具调用')).length).toBe(2)
    expect(screen.queryByText(/disable_mcp|未记录规则/)).not.toBeInTheDocument()
  })

  it('falls back to the category name, then the layer name, when the rule name is a generic word', async () => {
    const generic = { ...floorBlock, block_id: 'evt_gen', layer: 'input_content', rule_name: '自定义', category: 'plain_password' }
    const noCategory = { ...floorBlock, block_id: 'evt_gen2', layer: 'mcp_tool', rule_name: '自定义', category: undefined }
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [generic, noCategory], total: 2, limit: 20, offset: 0 } } as any)
    renderPage()
    const label = getFindingCategoryLabel('plain_password')
    expect((await screen.findAllByText(label)).filter((el) => el.closest('strong')).length).toBe(1)
    expect(screen.getAllByText('MCP 工具调用').filter((el) => el.closest('strong')).length).toBe(1)
    expect(screen.queryByText('自定义')).not.toBeInTheDocument()
  })

  it('does not show a spliced English category name for an unlisted agent_ category', async () => {
    const unlisted = { ...floorBlock, block_id: 'evt_unl', layer: 'mcp_tool', rule_name: '自定义', category: 'agent_zzz_unlisted' }
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [unlisted], total: 1, limit: 20, offset: 0 } } as any)
    renderPage()
    expect((await screen.findAllByText('MCP 工具调用')).filter((el) => el.closest('strong')).length).toBe(1)
    expect(screen.queryByText(/zzz/)).not.toBeInTheDocument()
  })

  it('shows the hit rule as plain text for a role that cannot open the policy page', async () => {
    const linked = { ...floorBlock, block_id: 'evt_plain', policy_link: { kind: 'policy', path: '/security/policies?policy=p1', label: '产品内置安全底线' } }
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [linked], total: 1, limit: 20, offset: 0 } } as any)
    renderPage()
    expect(await screen.findByText('产品内置安全底线')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '产品内置安全底线' })).not.toBeInTheDocument()
  })

  it('translates the hit text and hides unknown reason codes', async () => {
    const coded = { ...floorBlock, detail: 'Bash · filesystem_delete:2-targets', reason: 'some_unknown_gateway_code' }
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [coded], total: 1, limit: 20, offset: 0 } } as any)
    renderPage()
    expect(await screen.findByText('Bash · 删除文件（2 个目标）')).toBeInTheDocument()
    expect(screen.queryByText(/filesystem_delete|some_unknown_gateway_code/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByText('查看告警与留痕'))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('Bash · 删除文件（2 个目标）')).toBeInTheDocument()
    // 下方“阻断提示示例”是按模板重建的客户原文，不在此断言；详情表里不出现原因码和原始摘要。
    expect(within(drawer).queryByText('阻断原因')).not.toBeInTheDocument()
    expect(within(drawer).queryByText('Bash · filesystem_delete:2-targets')).not.toBeInTheDocument()
  })

  it('shows no risk explanation row when none was recorded', async () => {
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [{ ...floorBlock, explanation: undefined }], total: 1, limit: 20, offset: 0 } } as any)
    renderPage()
    await screen.findByText('Read · ~/.ssh/id_rsa')
    fireEvent.click(screen.getByText('查看告警与留痕'))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).queryByText('风险说明')).not.toBeInTheDocument()
  })
})

describe('alert class_key labels seen on the customer site', () => {
  it('names customer and agent categories instead of guessing from substrings', () => {
    expect(getRiskCategoryLabel('keyword_classic_injection_en')).toBe('Prompt 注入')
    expect(getRiskCategoryLabel('customer_sensitive_data')).toBe('客户敏感数据')
    expect(getRiskCategoryLabel('tool_attempt_blocked')).toBe('智能体工具调用拦截')
    expect(getRiskCategoryLabel('destructive_change')).toBe('删除与破坏操作')
    expect(getRiskCategoryLabel('skill_invocation_risk')).toBe('Skill 调用风险')
  })
})
