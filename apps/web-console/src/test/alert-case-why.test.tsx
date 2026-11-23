import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import AlertCaseDetail from '../components/AlertCaseDetail'
import PolicyRuleLink from '../components/PolicyRuleLink'
import { alertOccurrencesApi, type AlertOccurrence } from '../services/alertOccurrences'
import { accessRetentionApi } from '../services/api'
import { useAuthStore } from '../stores/auth'

const base = {
  id: 'case-1', case_id: 'ac1_x', event_id: 'e1', request_id: 'req-1', project_id: 'p1', finding_index: 0,
  type: 'custom', category: 'customer_sensitive_data', severity: 'medium', rule_id: 'rule_997bd32c',
  rule_name: '密钥相关', rule_type: 'regex', rule_ids: ['rule_997bd32c'], duplicate_count: 1,
  redacted_evidence: 'PA****RD (sha256:0be64ae8)', evidence_status: 'available', event_action_taken: 'security_audit',
  severity_downgrade_reason: '只命中字段名，未见真实值', hit_count: 5, request_count: 5, source_ip: '10.9.8.7',
  policy_link: { kind: 'policy', path: '/security/policies?policy=rule_997bd32c', label: '密钥相关' },
  disposition_status: 'open', content_source: 'tool_result', stage: 'input', created_at: '2026-11-13T05:27:17Z',
}
const make = (o: Record<string, unknown> = {}) => ({ ...base, ...o }) as unknown as AlertOccurrence

function renderDetail(item: AlertOccurrence, canReadContent = true) {
  return render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <AlertCaseDetail item={item} params={{} as never} identityLabel="dev.user3" canManage={false} saving={false} onDisposition={vi.fn()} canReadContent={canReadContent} />
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

const asRole = (role: string) => useAuthStore.setState({ user: { id: 'u', username: 'u', role, tenant_id: 't' }, isAuthenticated: true } as never)

describe('alert case overview', () => {
  beforeEach(() => asRole('platform_admin'))
  afterEach(() => vi.restoreAllMocks())

  it('leads with why the alert fired', () => {
    renderDetail(make())
    const why = screen.getByTestId('alert-case-why')
    expect(within(why).getByRole('link', { name: '密钥相关' })).toHaveAttribute('href', '/security/policies?policy=rule_997bd32c&event=e1')
    expect(why).toHaveTextContent('PA****RD (sha256:0be64ae8)')
    expect(why).toHaveTextContent('仅记录')
    expect(why).toHaveTextContent('中危（只命中字段名，未见真实值）')
  })

  it('keeps the policy link on the case event after another hit is selected', async () => {
    const other = make({ id: 'case-2', event_id: 'e2', request_id: 'req-2' })
    vi.spyOn(alertOccurrencesApi, 'list').mockResolvedValue({ data: { items: [other], total: 1, limit: 20, offset: 0, counts: {} } } as never)
    vi.spyOn(alertOccurrencesApi, 'getEvidence').mockResolvedValue(other as never)
    vi.spyOn(accessRetentionApi, 'getContent').mockResolvedValue({ data: {} } as never)
    renderDetail(make())
    fireEvent.click(screen.getByRole('button', { name: /次命中明细/ }))
    fireEvent.click(await screen.findByRole('button', { name: '查看这条证据' }))
    fireEvent.click(screen.getByRole('tab', { name: '1. 问题概况' }))
    const link = within(await screen.findByTestId('alert-case-why')).getByRole('link', { name: '密钥相关' })
    expect(link).toHaveAttribute('href', '/security/policies?policy=rule_997bd32c&event=e1')
  })

  it('asks the hit list for originals only when the viewer may read content evidence', async () => {
    const list = vi.spyOn(alertOccurrencesApi, 'list').mockResolvedValue({ data: { items: [make()], total: 1, limit: 20, offset: 0, counts: {} } } as never)
    for (const allowed of [true, false]) {
      list.mockClear()
      const view = renderDetail(make(), allowed)
      fireEvent.click(screen.getByRole('button', { name: /次命中明细/ }))
      await screen.findByRole('button', { name: '查看这条证据' })
      expect(list).toHaveBeenCalledWith(expect.objectContaining({ grouping: 'hits', include_raw: allowed }))
      view.unmount()
    }
  })

  it('has exactly four rows and no heading or explanation text', () => {
    renderDetail(make())
    const why = screen.getByTestId('alert-case-why')
    expect(Array.from(why.querySelectorAll('.ant-descriptions-item-label')).map(n => n.textContent)).toEqual(['命中规则', '命中内容', '处置结果', '告警级别'])
  })

  it('writes the severity without brackets when nothing downgraded it, and says so when the result is missing', () => {
    renderDetail(make({ severity_downgrade_reason: '', event_action_taken: '' }))
    const why = screen.getByTestId('alert-case-why')
    expect(why).toHaveTextContent('中危')
    expect(why).not.toHaveTextContent('（')
    expect(why).toHaveTextContent('处置结果未记录')
  })

  it('shows plain text when the rule has no policy page, and says a deleted policy is deleted', () => {
    const { unmount } = renderDetail(make({ policy_link: { kind: 'none', label: '产品内置安全底线' }, rule_name: '' }))
    expect(within(screen.getByTestId('alert-case-why')).queryByRole('link')).not.toBeInTheDocument()
    expect(screen.getByTestId('alert-case-why')).toHaveTextContent('产品内置安全底线')
    unmount()
    const { unmount: unmount2 } = renderDetail(make({ policy_link: { kind: 'deleted', path: '/security/policies?policy=rule_997bd32c' } }))
    const why = screen.getByTestId('alert-case-why')
    expect(within(why).queryByRole('link')).not.toBeInTheDocument()
    expect(why).toHaveTextContent('密钥相关（已删除）')
    unmount2()
    render(<MemoryRouter><PolicyRuleLink link={{ kind: 'deleted' }} name="" /></MemoryRouter>)
    expect(screen.getByText('该策略已删除')).toBeInTheDocument()
  })

  it('writes plain 未记录 for empty hit text and result, without repeating the row name', () => {
    renderDetail(make({ redacted_evidence: '', event_action_taken: '' }))
    const why = screen.getByTestId('alert-case-why')
    expect(Array.from(why.querySelectorAll('.ant-descriptions-item-content')).map(n => n.textContent).slice(1, 3)).toEqual(['未记录', '未记录'])
  })

  it('never shows a tool name as the hit rule', () => {
    const tool = { category: 'agent_behavior_policy', rule_name: 'Bash', rule_type: 'agentguard', event_action_taken: 'alert' }
    const { unmount } = renderDetail(make({ ...tool, policy_link: null }))
    expect(screen.getByTestId('alert-case-why')).not.toHaveTextContent('Bash')
    unmount()
    renderDetail(make({ ...tool, policy_link: { kind: 'agent_behavior', path: '/security/agents?behavior=filesystem_destructive', label: '删除与破坏' } }))
    const link = within(screen.getByTestId('alert-case-why')).getByRole('link', { name: '删除与破坏' })
    expect(link).toHaveAttribute('href', '/security/agents?behavior=filesystem_destructive')
    expect(screen.getByTestId('alert-case-why')).not.toHaveTextContent('Bash')
  })

  it.each([
    ['platform_admin', '/security/policies?policy=rule_997bd32c', true],
    ['security_officer', '/security/policies?policy=rule_997bd32c', true],
    ['tenant_admin', '/security/policies?policy=rule_997bd32c', false],
    ['auditor', '/security/policies?policy=rule_997bd32c', false],
    ['dept_admin', '/mcp-gateway/policies', false],
    ['tenant_admin', '/security/skills', true],
    // 2.9.22 起安全员可进 Skill 页（改 Skill 调用防护）。
    ['security_officer', '/security/skills', true],
  ])('role %s opening %s gets a link: %s', (role, path, linked) => {
    asRole(role)
    renderDetail(make({ policy_link: { kind: 'policy', path, label: '密钥相关' } }))
    const why = screen.getByTestId('alert-case-why')
    expect(within(why).queryByRole('link') !== null).toBe(linked)
    expect(why).toHaveTextContent('密钥相关')
  })

  it('keeps first seen, last seen and scope outside the identity fold', () => {
    renderDetail(make({ first_seen: '2026-11-13T01:00:00Z', last_seen: '2026-11-13T02:00:00Z' }))
    expect(screen.getByText('首次发生')).toBeInTheDocument()
    expect(screen.getByText('影响范围')).toBeInTheDocument()
    expect(screen.queryByText('来源 IP')).not.toBeInTheDocument()
  })

  it('folds the identity fields into one collapsed line', () => {
    renderDetail(make())
    expect(screen.queryByText('来源 IP')).not.toBeInTheDocument()
    fireEvent.click(screen.getByText('dev.user3'))
    expect(screen.getByText('来源 IP')).toBeInTheDocument()
    expect(screen.getByText('10.9.8.7')).toBeInTheDocument()
  })

  it('names the hit source from the shared dictionary and falls back to "未记录消息来源"', () => {
    renderDetail(make({ content_source: 'mystery', message_role: '' }))
    fireEvent.click(screen.getByText('dev.user3'))
    expect(screen.getByText(/未记录消息来源 \/ 输入检测/)).toBeInTheDocument()
  })

  it('translates the detection reason code and drops the row for an unknown one', async () => {
    vi.spyOn(accessRetentionApi, 'getContent').mockResolvedValue({ data: {} } as never)
    const evidenceFor = (reason: string) => vi.spyOn(alertOccurrencesApi, 'getEvidence').mockResolvedValue(make({ reason, raw_evidence: 'PASSWORD' }))
    evidenceFor('explicit_block')
    const { unmount } = renderDetail(make())
    fireEvent.click(screen.getByRole('tab', { name: '3. 证据与留痕' }))
    expect(await screen.findByText('智能体行为策略要求阻断')).toBeInTheDocument()
    expect(screen.queryByText('explicit_block')).not.toBeInTheDocument()
    unmount()
    evidenceFor('some_future_reason')
    renderDetail(make())
    fireEvent.click(screen.getByRole('tab', { name: '3. 证据与留痕' }))
    await screen.findByText('本次命中片段')
    expect(screen.queryByText('some_future_reason')).not.toBeInTheDocument()
    expect(screen.queryByText('未记录进一步检测理由')).not.toBeInTheDocument()
  })

  it('drops the engine-appended severity explanation from the detection reason and keeps the rest', async () => {
    vi.spyOn(accessRetentionApi, 'getContent').mockResolvedValue({ data: {} } as never)
    const evidenceFor = (reason: string) => vi.spyOn(alertOccurrencesApi, 'getEvidence').mockResolvedValue(make({ reason, raw_evidence: 'PASSWORD' }))
    evidenceFor('命中口令字段；策略级别：高危；告警级别：中危（只命中字段名，未见真实值）')
    const { unmount } = renderDetail(make())
    fireEvent.click(screen.getByRole('tab', { name: '3. 证据与留痕' }))
    expect(await screen.findByText('命中口令字段')).toBeInTheDocument()
    expect(screen.queryByText(/策略级别/)).not.toBeInTheDocument()
    expect(screen.queryByText(/告警级别：/)).not.toBeInTheDocument()
    unmount()
    evidenceFor('策略级别：高危；告警级别：提示')
    renderDetail(make())
    fireEvent.click(screen.getByRole('tab', { name: '3. 证据与留痕' }))
    await screen.findByText('本次命中片段')
    expect(screen.queryByText(/策略级别|告警级别：/)).not.toBeInTheDocument()
  })
})
