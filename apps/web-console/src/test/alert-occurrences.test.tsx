import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { RECORD_MODE_PASS_LABEL } from '../utils/ws8ActionLabels'
import { Grid, message } from 'antd'
import { act, fireEvent, render, screen, waitFor, within, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ContentAudit from '../pages/ContentAudit'
import { AlertOccurrenceSummary } from '../components/AlertOccurrences'
import { alertOccurrencesApi, type AlertOccurrence, type AlertOccurrencePage, type AlertOperationalBreakdown } from '../services/alertOccurrences'
import { apiClient, auditDispositionApi, contentAuditApi, accessRetentionApi, contentSecurityApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { rawEvidenceApi } from '../services/rawEvidence'
import { RAW_EVIDENCE_OMITTED_TEXT } from '../utils/alertEvidence'

const occurrence = (overrides: Partial<AlertOccurrence> = {}): AlertOccurrence => ({
  id: 'email-occurrence', event_id: 'email-event', request_id: 'request-1', project_id: 'project-1',
  created_at: '2026-09-18T08:00:00Z', finding_index: 0, duplicate_count: 1, rule_ids: ['email-rule'],
  type: 'pii', category: 'pii_email', severity: 'low', rule_id: 'email-rule', rule_name: '邮箱地址',
  action_taken: 'audit', event_action_taken: 'block', suppressed: false, suppression_reason: '',
  review_state: 'review_pending', disposition_status: 'open', alert_group_id: '',
  message_index: 0, attachment_index: null, message_role: 'user', content_source: 'verified_user_input',
  stage: 'input', matched_location: 'message[0].content', location_status: 'available',
  reason: '本句出现邮箱地址', reason_status: 'available', evidence_kind: 'finding',
  redacted_evidence: '请联系 a***@example.com 获取说明', evidence_status: 'available', raw_evidence_status: 'not_requested',
  actor_user_id: 'user-1', actor_name: '张三', actor_department_id: 'dept-1', actor_department_name: '研发部',
  key_owner_user_id: 'owner-1', key_owner_name: '网关管理员', department_id: 'dept-owner', department_name: '运维部',
  agent_type: 'claude-code', credential_id: 'key-1', credential_name: '共享应用凭据', principal_key: '',
  identity_source: 'authenticated_user', identity_reliability: 'verified', source_ip: '192.0.2.10', access_direction: 'forward',
  conversation_key: 'conversation-1', conversation_id: 'conversation-1', session_id: 'session-1',
  conversation_source: 'content_session', conversation_reliability: 'recorded', ...overrides,
})

const page = (items: AlertOccurrence[], total = items.length): { data: AlertOccurrencePage } => ({
  data: { items, total, limit: 20, offset: 0, counts: { total, active: total, suppressed: 0, critical: 0, high: 0, medium: 0, low: total } },
})
const breakdown = (overrides: Partial<AlertOperationalBreakdown> = {}): AlertOperationalBreakdown => ({
  count_unit: 'security_events', event_count: 147394, last_24h_count: 1902, blocked_count: 831, latest_at: '2026-09-19T06:21:53Z',
  reasons: [
    { reason: 'inspection_invalid_json', event_count: 2349, last_24h_count: 831, blocked_count: 831 },
    { reason: 'judge_capacity_deferred', event_count: 631, last_24h_count: 617, blocked_count: 0 },
    { reason: 'judge_capacity_overflow', event_count: 22183, last_24h_count: 166, blocked_count: 0 },
  ],
  ...overrides,
})

describe('individual security alert occurrences', () => {
  let client: QueryClient
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { runtime: { status: 'pending', runtime_verified: false, components: [] } } } as any)
    client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    useAuthStore.setState({ token: 'test-token', user: { id: 'admin', username: 'admin', tenant_id: 'tenant-1', role: 'platform_admin' }, isAuthenticated: true })
    vi.spyOn(contentAuditApi, 'listUsers').mockResolvedValue({ data: { data: [], limit: 50, offset: 0, has_more: false } } as any)
    vi.spyOn(contentAuditApi, 'list').mockResolvedValue({ data: { data: [], total: 0 } } as any)
    vi.spyOn(contentAuditApi, 'getSession').mockResolvedValue({ data: { data: [], total: 0 } } as any)
    vi.spyOn(contentAuditApi, 'getSessionEvents').mockResolvedValue({ data: { data: [], total: 0 } } as any)
    vi.spyOn(accessRetentionApi, 'getContent').mockResolvedValue({ data: {} } as any)
    vi.spyOn(accessRetentionApi, 'list').mockResolvedValue({ data: { data: [], total: 0 } } as any)
    vi.spyOn(alertOccurrencesApi, 'list').mockResolvedValue(page([occurrence()]) as any)
    vi.spyOn(alertOccurrencesApi, 'listOperational').mockResolvedValue({ data: { items: [], total: 0, limit: 20, offset: 0, count_unit: 'security_events' } } as any)
    vi.spyOn(alertOccurrencesApi, 'summarizeOperational').mockResolvedValue({ data: breakdown() } as any)
    vi.spyOn(alertOccurrencesApi, 'getEvidence').mockImplementation(async (row) => ({ ...row, raw_evidence_status: 'missing' }))
    vi.spyOn(auditDispositionApi, 'upsert').mockResolvedValue({} as any)
  })
  afterEach(() => { message.destroy(); cleanup(); client.clear() })
  const renderPage = (entry = '/security/alerts') => render(
    <MemoryRouter initialEntries={[entry]}><QueryClientProvider client={client}><ContentAudit /></QueryClientProvider></MemoryRouter>,
  )
  const card = (id = 'email-occurrence') => screen.findByTestId(`alert-card-${id}`)
  it('shows only identity-matched endpoint evidence and keeps missing risk ungraded', () => {
    render(<MemoryRouter><AlertOccurrenceSummary occurrence={occurrence({
      agent_session_id: 'native-session-1',
      agent_endpoint_evidence: {
        status: 'matched', agent_event_id: 'agent-event-1', endpoint_id: 'ep-1', session_id: 'native-session-1',
        event_type: 'tool.pre', tool_use_id: 'tool-use-1', tool_name: 'Bash', tool_type: 'system',
        local_decision: { source: 'local', mode: 'block', effective_decision: 'block', policy_version: 8 },
      },
    })} /></MemoryRouter>)
    expect(screen.getByText('原生端点事件关联')).toBeInTheDocument()
    expect(screen.getByText('已按租户、端点、会话和工具事件身份核验')).toBeInTheDocument()
    expect(screen.getByText('ep-1 / tool.pre / agent-event-1')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'native-session-1' })).toHaveAttribute('href', '/agent/sessions/native-session-1')
    expect(screen.getByText('local / block')).toBeInTheDocument()
    expect(screen.getByText(/风险未记录/)).toBeInTheDocument()
  })

  it('does not expose a native session link when the alert event identity is unmatched', () => {
    render(<MemoryRouter><AlertOccurrenceSummary occurrence={occurrence({
      agent_session_id: 'unverified-session',
      agent_endpoint_evidence: { status: 'unmatched' },
    })} /></MemoryRouter>)
    expect(screen.getByText('未找到身份完整匹配的端点事件记录')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'unverified-session' })).not.toBeInTheDocument()
  })

  it('shows the folded development count and requests explicit inclusion', async () => {
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue({ data: { ...page([occurrence()]).data, folded_development_groups: 7 } } as any)
    renderPage(); await card()
    expect(screen.getByText(/已折叠 7 个开发作用域组/)).toBeInTheDocument()
    expect(vi.mocked(alertOccurrencesApi.list).mock.lastCall?.[0].include_dev).toBe(false)
    fireEvent.click(screen.getByRole('checkbox', { name: '显示开发作用域语义/运行告警' }))
    await waitFor(() => expect(vi.mocked(alertOccurrencesApi.list).mock.lastCall?.[0].include_dev).toBe(true))
    expect(await screen.findByText(/已显示 7 个开发作用域组/)).toBeInTheDocument()
  })

  it.each([
    '/security/alert-occurrences?event_id=history-event&request_id=history-request&window_hours=24',
    '/security/alert-occurrences?request_id=history-request',
  ])('shows a handled historical hit from the exact deep link %s', async (entry) => {
    vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
    const historical = occurrence({ id: 'history-hit', event_id: 'history-event', request_id: 'history-request', created_at: '2025-01-02T08:00:00Z', occurred_at: '2025-01-02T08:05:00Z', disposition_status: 'resolved', review_state: 'resolved', raw_evidence_status: 'missing' })
    vi.mocked(alertOccurrencesApi.list).mockImplementation(async params => page(params.disposition === 'all' && params.grouping === 'hits' && params.recent_limit === undefined && params.start_time === undefined && params.end_time === undefined ? [historical] : []) as any)
    vi.mocked(accessRetentionApi.getContent).mockResolvedValue({ data: { request_id: 'history-request', user_input: '历史阻断的本次请求正文', model_output: '' } } as any)
    renderPage(entry)
    const hit = await card('history-hit')
    expect(hit).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '全部告警' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByText(/按编号精确查询，共 1 条命中记录；包含所有处置状态/)).toBeInTheDocument()
    expect(screen.getByText('关联命中（1 条）')).toBeInTheDocument()
    expect(screen.getByText('共 1 条命中')).toBeInTheDocument()
    expect(screen.queryByText(/合并为/)).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: '告警时间范围' })).not.toBeInTheDocument()
    expect(screen.queryByText('最近 100 条')).not.toBeInTheDocument()
    expect(screen.getByText('编号精确查询，时间筛选不限制查询范围')).toBeInTheDocument()
    const calls = vi.mocked(alertOccurrencesApi.list).mock.calls
    expect(calls.every(([params]) => params.grouping === 'hits' && params.disposition === 'all' && params.request_id === 'history-request' && params.recent_limit === undefined && params.start_time === undefined && params.end_time === undefined)).toBe(true)
    if (entry.includes('event_id=')) expect(calls[0][0].event_id).toBe('history-event')
    await waitFor(() => expect(alertOccurrencesApi.getEvidence).toHaveBeenCalledWith(expect.objectContaining({ event_id: 'history-event', request_id: 'history-request' }), expect.objectContaining({ request_id: 'history-request', recent_limit: undefined, start_time: undefined, end_time: undefined })))
    const panel = await screen.findByRole('region', { name: '告警详情' })
    expect(await within(panel).findByText('历史阻断的本次请求正文')).toBeInTheDocument()
    await waitFor(() => expect(accessRetentionApi.getContent).toHaveBeenCalledWith('history-request', undefined, expect.objectContaining({ from: '2025-01-01T08:05:00.000Z', to: '2025-01-03T08:05:00.000Z' })))
  })

  it('keeps every dashboard category and its exact time range before pagination', async () => {
    renderPage('/security/alerts?window_hours=24&risk_category=config_file,env_file&start_time=2026-09-19T06:00:00Z&end_time=2026-09-20T06:00:00Z')
    await waitFor(() => expect(alertOccurrencesApi.list).toHaveBeenCalledWith(expect.objectContaining({category:'config_file,env_file',start_time:'2026-09-19T06:00:00Z',end_time:'2026-09-20T06:00:00Z',grouping:'cases',disposition:'pending'})))
  })

  it('defaults to the latest 100 cases, pages by 10 and exports the same bounded scope', async () => {
    vi.mocked(alertOccurrencesApi.list).mockImplementation(async () => page([occurrence()],100) as any)
    renderPage()
    await card()
    expect(screen.getByText('最近 100 条')).toBeInTheDocument()
    expect(vi.mocked(alertOccurrencesApi.list).mock.calls[0][0]).toMatchObject({grouping:'cases',recent_limit:100,limit:10,offset:0})
    expect(vi.mocked(alertOccurrencesApi.list).mock.calls[0][0].start_time).toBeUndefined()
    fireEvent.click(screen.getByTitle('2'))
    await waitFor(()=>expect(vi.mocked(alertOccurrencesApi.list).mock.calls.some(([p])=>p.offset===10 && p.recent_limit===100)).toBe(true))
    const originalCreate=URL.createObjectURL, originalRevoke=URL.revokeObjectURL
    URL.createObjectURL=vi.fn(()=> 'blob:recent-export'); URL.revokeObjectURL=vi.fn()
    try {
      await waitFor(()=>expect(screen.getByRole('button',{name:'导出告警'})).toBeEnabled())
      fireEvent.click(screen.getByRole('button',{name:'导出告警'}))
      await waitFor(()=>expect(vi.mocked(alertOccurrencesApi.list).mock.calls.some(([p])=>p.limit===100 && p.offset===0 && p.recent_limit===100)).toBe(true))
      await waitFor(()=>expect(URL.revokeObjectURL).toHaveBeenCalled(),{timeout:2000})
    } finally {URL.createObjectURL=originalCreate;URL.revokeObjectURL=originalRevoke}
  })

  it.each<[number,string]>([[24,'近 24 小时'],[168,'近 7 天'],[720,'近 30 天']])('switches to the complete %s-hour range and resets pagination', async (hours,label) => {
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence()],100) as any)
    renderPage(); await card()
    fireEvent.click(screen.getByTitle('2'))
    await waitFor(()=>expect(vi.mocked(alertOccurrencesApi.list).mock.calls.some(([p])=>p.offset===10)).toBe(true))
    fireEvent.mouseDown(screen.getByRole('combobox',{name:'告警时间范围'}))
    fireEvent.click(await screen.findByText(label))
    await waitFor(()=>expect(vi.mocked(alertOccurrencesApi.list).mock.lastCall?.[0].start_time).toBeTruthy())
    const p=vi.mocked(alertOccurrencesApi.list).mock.lastCall![0]
    expect(p.recent_limit).toBeUndefined();expect(p.offset).toBe(0);expect(p.limit).toBe(10)
    expect(Date.parse(p.end_time!)-Date.parse(p.start_time!)).toBe(Number(hours)*3600000)
  })

  describe('processing lanes', () => {
    const laneCounts = { lane_action: 4, lane_watch: 7, lane_eval: 62 }
    const lanePage = (items: AlertOccurrence[], total = items.length) => ({ data: { ...page(items, total).data, counts: { ...page(items, total).data.counts, ...laneCounts } } })
    const real = occurrence({ id: 'real', event_id: 'real-e', lane: 'action', category: 'code_leak_database_url', severity: 'critical', actor_name: '张三' })
    const sample = occurrence({ id: 'sample', event_id: 'sample-e', lane: 'eval', category: 'prompt_input_semantic_risk', severity: 'high', actor_name: '李四' })
    beforeEach(() => {
      vi.mocked(alertOccurrencesApi.list).mockImplementation(async (params) =>
        lanePage(params.lane === 'eval' ? [sample] : params.lane === 'watch' ? [] : [real], params.lane === 'eval' ? 62 : params.lane === 'watch' ? 7 : 4) as any)
    })

    it('opens on the action lane and shows every lane count so nothing is hidden silently', async () => {
      renderPage(); await card('real')
      expect(vi.mocked(alertOccurrencesApi.list).mock.calls[0][0]).toEqual(expect.objectContaining({ lane: 'action', grouping: 'cases' }))
      expect(screen.getByRole('tab', { name: /需行动\s*4/ })).toHaveAttribute('aria-selected', 'true')
      expect(screen.getByRole('tab', { name: /观察\s*7/ })).toBeInTheDocument()
      expect(screen.getByRole('tab', { name: /测评流量\s*62/ })).toBeInTheDocument()
    })

    it('requests the chosen lane from the server instead of filtering the page locally', async () => {
      renderPage(); await card('real')
      fireEvent.click(screen.getByRole('tab', { name: /测评流量/ }))
      await waitFor(() => expect(alertOccurrencesApi.list).toHaveBeenLastCalledWith(expect.objectContaining({ lane: 'eval', offset: 0 })))
      expect(await card('sample')).toBeInTheDocument()
      expect(screen.queryByTestId('alert-card-real')).not.toBeInTheDocument()
    })

    it('shows a loading state instead of the previous lane while the chosen lane loads', async () => {
      let release: () => void = () => {}
      vi.mocked(alertOccurrencesApi.list).mockImplementation((params) => params.lane === 'eval'
        ? new Promise((resolve) => { release = () => resolve(lanePage([sample], 62) as any) })
        : Promise.resolve(lanePage([real], 4) as any))
      renderPage(); await card('real')
      fireEvent.click(screen.getByRole('tab', { name: /测评流量/ }))
      await waitFor(() => expect(alertOccurrencesApi.list).toHaveBeenLastCalledWith(expect.objectContaining({ lane: 'eval' })))
      expect(screen.queryByTestId('alert-card-real')).not.toBeInTheDocument()
      expect(screen.getByText(/风险问题（加载中）/)).toBeInTheDocument()
      await act(async () => { release() })
      expect(await card('sample')).toBeInTheDocument()
    })

    it('explains in the eval lane that these are authorised test samples, not live attacks', async () => {
      renderPage('/security/alerts?lane=eval'); await card('sample')
      expect(screen.getByText(/管理员已将这些凭据标记为测评/)).toBeInTheDocument()
    })

    it('falls back to the action lane for an older backend that returns no lane field', async () => {
      const legacy = occurrence({ id: 'legacy', event_id: 'legacy-e' })
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([legacy]) as any)
      renderPage(); await card('legacy')
      expect(screen.queryByTestId('alert-lane-hidden-warning')).not.toBeInTheDocument()
    })

    it('keeps exact deep links on the unfiltered hit view', async () => {
      renderPage('/security/alert-occurrences?event_id=history-event&request_id=history-request')
      await waitFor(() => expect(alertOccurrencesApi.list).toHaveBeenCalled())
      expect(vi.mocked(alertOccurrencesApi.list).mock.calls.every(([params]) => params.lane === undefined)).toBe(true)
    })
  })

  describe('scannable alert cards', () => {
    const caseItem = (overrides: Partial<AlertOccurrence> = {}) => occurrence({
      id: 'case-1', event_id: 'case-e', case_id: 'ac1_' + '0'.repeat(32), hit_count: 288, request_count: 16, lane: 'action',
      category: 'code_leak_database_url', severity: 'critical', stage: 'input', content_source: 'user', rule_name: '',
      actor_name: '', key_owner_name: '', source_ip: '', credential_name: '', agent_type: 'claude-code', ...overrides,
    })

    it('leads with what happened and where, not with the missing identity', async () => {
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([caseItem()]) as any)
      renderPage()
      const c = await card('case-1')
      expect(within(c).getByTestId('alert-card-what')).toHaveTextContent('含凭据的连接串候选')
      expect(within(c).getByTestId('alert-card-where')).toHaveTextContent('用户输入')
      expect(within(c).getByTestId('alert-card-where')).toHaveTextContent('输入检测')
      expect(within(c).getByTestId('alert-card-who')).toHaveTextContent('Claude Code')
    })

    it('titles the card by the rule and says what matched, what happened and where', async () => {
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([caseItem({
        rule_name: '密钥相关', rule_name_count: 2, content_source: 'tool_result',
        redacted_evidence: 'PA****RD (sha256:0be64ae8)', event_action_taken: 'security_audit',
      })]) as any)
      renderPage()
      const c = await card('case-1')
      expect(within(c).getByTestId('alert-card-what')).toHaveTextContent('密钥相关 等 2 条')
      expect(within(c).getByTestId('alert-card-where')).toHaveTextContent('PA****RD (sha256:0be64ae8) · 仅记录 · 工具返回 · 输入检测')
      expect(within(c).getByTestId('alert-card-who')).toHaveTextContent('Claude Code')
    })

    it('translates destructive target summaries on the card', async () => {
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([caseItem({
        type: 'tool_destructive_intent', category: 'destructive_change', rule_name: 'Bash',
        content_source: 'assistant_tool_call', redacted_evidence: 'filesystem_overwrite:1-targets', event_action_taken: 'alert',
      })]) as any)
      renderPage()
      const where = within(await card('case-1')).getByTestId('alert-card-where')
      expect(where).toHaveTextContent('覆盖文件（1 个目标） · 告警放行 · 工具调用')
      expect(where).not.toHaveTextContent('filesystem_overwrite')
    })

    it('shows the single-dictionary action result and a translated reason code', async () => {
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([
        occurrence({ id: 'known', event_id: 'k-e', event_action_taken: 'alert', reason: 'explicit_block' }),
      ]) as any)
      renderPage()
      const known = await card('known')
      expect(within(known).getAllByText('告警放行')).toHaveLength(1)
      expect(within(known).queryByText('告警')).not.toBeInTheDocument()
      fireEvent.click(within(known).getByRole('button', { name: '查看告警' }))
      const detail = await screen.findByRole('dialog', { name: '告警详情' })
      fireEvent.click(within(detail).getByText('查看完整身份、检测理由与原始证据'))
      expect(within(detail).getByText('智能体行为策略要求阻断')).toBeInTheDocument()
      expect(within(detail).queryByText('explicit_block')).not.toBeInTheDocument()
    })

    it('hides the detection reason row for an unknown reason code', async () => {
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([
        occurrence({ id: 'unknown', event_id: 'u-e', reason: 'some_future_reason' }),
      ]) as any)
      renderPage()
      const row = await card('unknown')
      fireEvent.click(within(row).getByRole('button', { name: '查看告警' }))
      const detail = await screen.findByRole('dialog', { name: '告警详情' })
      fireEvent.click(within(detail).getByText('查看完整身份、检测理由与原始证据'))
      expect(within(detail).queryByText('some_future_reason')).not.toBeInTheDocument()
      expect(within(detail).queryByText('检测理由')).not.toBeInTheDocument()
    })

    it('hides the detection reason row when the reason is empty', async () => {
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence({ id: 'blank', event_id: 'b-e', reason: '' })]) as any)
      renderPage()
      fireEvent.click(within(await card('blank')).getByRole('button', { name: '查看告警' }))
      const detail = await screen.findByRole('dialog', { name: '告警详情' })
      fireEvent.click(within(detail).getByText('查看完整身份、检测理由与原始证据'))
      expect(within(detail).queryByText('检测理由')).not.toBeInTheDocument()
    })

    it('labels off-scale severities from the shared dictionary and everything else as ungraded', async () => {
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([
        occurrence({ id: 'sev-info', event_id: 'i-e', severity: 'info' }),
        occurrence({ id: 'sev-odd', event_id: 'o-e', severity: 'weird' }),
      ]) as any)
      renderPage()
      expect(within(await card('sev-info')).getByText('提示')).toBeInTheDocument()
      expect(within(await card('sev-odd')).getByText('未分级')).toBeInTheDocument()
    })

    it('leaves empty segments off a tool alert card instead of writing not-recorded', async () => {
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([
        caseItem({ id: 'tool', event_id: 't-e', redacted_evidence: '', content_source: '', stage: 'tool', matched_location: 'tool_call[0]', event_action_taken: 'alert' }),
        caseItem({ id: 'empty', event_id: 'e-e', redacted_evidence: '', content_source: '', message_role: '', stage: '', matched_location: '', event_action_taken: '' }),
        caseItem({ id: 'denied', event_id: 'd-e', evidence_status: 'restricted', redacted_evidence: '', content_source: 'user', stage: 'input', event_action_taken: 'block' }),
      ]) as any)
      renderPage()
      const where = within(await card('tool')).getByTestId('alert-card-where')
      expect(where).toHaveTextContent(/^告警放行 · 工具调用 · 工具检测$/)
      expect(within(await card('empty')).queryByTestId('alert-card-where')).not.toBeInTheDocument()
      expect(within(await card('denied')).getByTestId('alert-card-where')).toHaveTextContent(/^无权查看命中内容 · 已阻断 · 用户输入 · 输入检测$/)
    })

    it('shows how often the same problem repeated so a flood reads as one problem', async () => {
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([caseItem(), caseItem({ id: 'case-2', event_id: 'case-e2', hit_count: 1, request_count: 1 })]) as any)
      renderPage()
      expect(within(await card('case-1')).getByTestId('alert-card-repeat')).toHaveTextContent('288')
      expect(within(await card('case-2')).queryByTestId('alert-card-repeat')).not.toBeInTheDocument()
    })

    it('marks model-output and tool-result hits as coming from the model or a tool, not the user', async () => {
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([
        caseItem({ id: 'out', event_id: 'out-e', content_source: 'model_output', stage: 'output' }),
        caseItem({ id: 'tool', event_id: 'tool-e', content_source: 'tool_result' }),
      ]) as any)
      renderPage()
      expect(within(await card('out')).getByTestId('alert-card-where')).toHaveTextContent('模型输出')
      expect(within(await card('tool')).getByTestId('alert-card-where')).toHaveTextContent('工具返回')
    })

    it('titles the open case by the risk, not by the missing identity', async () => {
      vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([caseItem()]) as any)
      renderPage()
      const detail = await screen.findByRole('region', { name: '告警详情' })
      const heading = await within(detail).findByTestId('alert-case-title')
      expect(heading).toHaveTextContent('含凭据的连接串候选')
      expect(heading).not.toHaveTextContent('账户与来源 IP 未记录')
    })

    it('says where the traffic came from in one sentence instead of a wall of "未记录"', async () => {
      vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([caseItem({
        actor_name: '', key_owner_name: '', credential_name: '', credential_id: '', source_ip: '192.168.56.1',
        agent_type: 'openai-codex', access_direction: 'reverse', principal_key: 'caller_c676e83d6987', target_host: 'api.example-gateway.com',
      })]) as any)
      renderPage()
      const detail = await screen.findByRole('region', { name: '告警详情' })
      const origin = await within(detail).findByTestId('alert-origin-summary')
      expect(origin).toHaveTextContent('192.168.56.1')
      expect(origin).toHaveTextContent('OpenAI Codex')
      expect(origin).toHaveTextContent('反向代理')
      expect(origin).toHaveTextContent('api.example-gateway.com')
      expect(origin).not.toHaveTextContent('未记录')
    })

    it('tells the reviewer exactly what is unknown and what to do, only when something is really unknown', async () => {
      vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([caseItem({
        actor_name: '', key_owner_name: '', credential_name: '', credential_id: '', source_ip: '', agent_type: '', access_direction: '',
      })]) as any)
      renderPage()
      const detail = await screen.findByRole('region', { name: '告警详情' })
      const origin = await within(detail).findByTestId('alert-origin-summary')
      expect(origin).toHaveTextContent('来源 IP 未被记录')
      expect(origin).toHaveTextContent('请求编号')
    })

    it('explains a masked piece of evidence instead of leaving only a placeholder', async () => {
      vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
      const item = caseItem({ category: 'cloud_credential', type: 'secret', content_source: 'model_output', stage: 'output' })
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([item]) as any)
      vi.mocked(alertOccurrencesApi.getEvidence).mockResolvedValue({ ...item, raw_evidence_status: 'missing', redacted_evidence: 'cloud_credential:<MASKED>',
        evidence_context: 'export AWS_ACCESS_KEY_ID=<已打码 20 位> # deploy', matched_text_preview: 'AK****LE', reason: '匹配凭据格式' } as any)
      renderPage()
      fireEvent.click(await screen.findByRole('tab', { name: '3. 证据与留痕' }))
      expect(await screen.findByText(/export AWS_ACCESS_KEY_ID=/)).toBeInTheDocument()
      expect(screen.getByTestId('alert-evidence-guide')).toHaveTextContent('秘密本体已隐藏')
    })

    it('shows the masked-evidence guide for the new 已隐藏 marker', async () => {
      vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
      const item = caseItem({ category: 'cloud_credential', type: 'secret', content_source: 'model_output', stage: 'output' })
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([item]) as any)
      vi.mocked(alertOccurrencesApi.getEvidence).mockResolvedValue({ ...item, raw_evidence_status: 'missing', redacted_evidence: 'cloud_credential',
        evidence_context: 'export AWS_SECRET=<已隐藏 96 字> # deploy', matched_text_preview: 'AK****LE', reason: '匹配凭据格式' } as any)
      renderPage()
      fireEvent.click(await screen.findByRole('tab', { name: '3. 证据与留痕' }))
      expect(await screen.findByText(/export AWS_SECRET=/)).toBeInTheDocument()
      expect(screen.getByTestId('alert-evidence-guide')).toBeInTheDocument()
    })

    describe('原文留证入口', () => {
      const openEvidence = async (role: string, body = '') => {
        vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
        useAuthStore.setState({ user: { id: 'u', username: 'u', tenant_id: 'tenant-1', role } as any })
        const item = caseItem({ raw_evidence_count: 2 })
        vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([item]) as any)
        vi.mocked(accessRetentionApi.getContent).mockResolvedValue({ data: { request_id: 'request-1', user_input: body, model_output: '' } } as any)
        const list = vi.spyOn(rawEvidenceApi, 'list').mockResolvedValue({ data: { items: [], total: 0, enabled: true } } as any)
        const reveal = vi.spyOn(rawEvidenceApi, 'reveal')
        renderPage()
        fireEvent.click(await screen.findByRole('tab', { name: '3. 证据与留痕' }))
        await screen.findByLabelText('选中命中证据')
        return { list, reveal }
      }

      it('角色无权限时不出现查看原文', async () => {
        await openEvidence('auditor')
        expect(screen.queryByRole('button', { name: '查看原文' })).toBeNull()
      })

      it('有权限时出现查看原文，不点击就不请求', async () => {
        const { list, reveal } = await openEvidence('platform_admin')
        expect(await screen.findByRole('button', { name: '查看原文' })).toBeInTheDocument()
        expect(list).not.toHaveBeenCalled()
        expect(reveal).not.toHaveBeenCalled()
      })

      it('有原文留证且请求正文为空时不提示未读取到正文', async () => {
        await openEvidence('platform_admin')
        await screen.findByRole('button', { name: '查看原文' })
        await waitFor(() => expect(vi.mocked(accessRetentionApi.getContent)).toHaveBeenCalled())
        await waitFor(() => expect(screen.queryByText('正在读取该请求留存…')).toBeNull())
        expect(screen.queryByText(/未读取到该请求的正文/)).toBeNull()
      })
    })

    it('colours the severity edge but never relies on colour alone', async () => {
      vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([caseItem()]) as any)
      renderPage()
      const c = await card('case-1')
      expect(within(c).getByText('严重')).toBeInTheDocument()
      expect(c).toHaveAttribute('data-severity', 'critical')
    })
  })

  it('keeps desktop selection and exact evidence visible beside the list', async () => {
    vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence(), occurrence({ id: 'other-row', event_id: 'other-event', actor_name: '李四' })]) as any)
    renderPage()
    const panel = await screen.findByRole('region', { name: '告警详情' })
    expect(await within(panel).findByText('张三 · 研发部')).toBeInTheDocument()
    fireEvent.click(await card('other-row'))
    expect(await within(panel).findByText('李四 · 研发部')).toBeInTheDocument()
    expect((await card('other-row')).getAttribute('aria-pressed')).toBe('true')
    expect(screen.queryByRole('dialog', { name: '告警详情' })).not.toBeInTheDocument()
    expect(alertOccurrencesApi.getEvidence).toHaveBeenLastCalledWith(expect.objectContaining({ id: 'other-row' }), expect.anything())
  })

  it('requests each disposition tab from the server rather than filtering a page locally', async () => {
    renderPage(); await card()
    expect(alertOccurrencesApi.list).toHaveBeenCalledWith(expect.objectContaining({ disposition: 'pending', include_suppressed: true }))
    fireEvent.click(screen.getByRole('tab', { name: '误报' }))
    await waitFor(() => expect(alertOccurrencesApi.list).toHaveBeenLastCalledWith(expect.objectContaining({ disposition: 'false_positive', offset: 0 })))
    fireEvent.click(screen.getByRole('tab', { name: '已处置' }))
    await waitFor(() => expect(alertOccurrencesApi.list).toHaveBeenLastCalledWith(expect.objectContaining({ disposition: 'handled' })))
  })

  it('does not display healthy from a stale or incomplete runtime report', async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { runtime: { status: 'applied', runtime_verified: true, components: [{ component: 'security-engine', fresh: false, config_loaded: true, judge_required: true, judge_operational: true }] } } } as any)
    renderPage()
    await card()
    expect(screen.queryByRole('region', { name: '引擎健康' })).not.toBeInTheDocument()
  })

  it('adds a bounded project-and-rule exception only after a reason is supplied', async () => {
    vi.spyOn(contentSecurityApi, 'createException').mockResolvedValue({} as any)
    renderPage(); fireEvent.click(within(await card()).getByRole('button', { name: '查看告警' }))
    const detail = await screen.findByRole('dialog', { name: '告警详情' })
    fireEvent.click(within(detail).getByRole('button', { name: '加为例外' }))
    expect(contentSecurityApi.createException).not.toHaveBeenCalled()
    const modal = (await screen.findByText('添加策略例外')).closest('[role=dialog]') as HTMLElement
    expect(within(modal).getByRole('button', { name: '创建 24 小时审计例外' })).toBeDisabled()
    fireEvent.change(within(modal).getByLabelText('例外原因'), { target: { value: '已复核为测试邮箱' } })
    fireEvent.click(within(modal).getByRole('button', { name: '创建 24 小时审计例外' }))
    await waitFor(() => expect(contentSecurityApi.createException).toHaveBeenCalledWith(expect.objectContaining({ scope_type: 'project', scope_ref: 'project-1', rule_id: 'email-rule', decision: 'audit', reason: '已复核为测试邮箱', expires_at: expect.any(String) })))
  })

  it('没有项目的命中也能加例外，范围为全单位', async () => {
    vi.spyOn(contentSecurityApi, 'createException').mockResolvedValue({} as any)
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence({ project_id: '' })]) as any)
    renderPage(); fireEvent.click(within(await card()).getByRole('button', { name: '查看告警' }))
    const detail = await screen.findByRole('dialog', { name: '告警详情' })
    const add = within(detail).getByRole('button', { name: '加为例外' })
    await waitFor(() => expect(add).toBeEnabled())
    fireEvent.click(add)
    const modal = (await screen.findByText('添加策略例外')).closest('[role=dialog]') as HTMLElement
    fireEvent.change(within(modal).getByLabelText('例外原因'), { target: { value: '复核为测试数据' } })
    fireEvent.click(within(modal).getByRole('button', { name: '创建 24 小时审计例外' }))
    await waitFor(() => expect(contentSecurityApi.createException).toHaveBeenCalledWith(expect.objectContaining({ scope_type: 'tenant', scope_ref: '', rule_id: 'email-rule' })))
  })

  it('only exposes an agent session link for a verified agent session id', async () => {
    vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
    const ordinary = occurrence({session_id:'request-log-session',agent_session_id:''})
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([ordinary]) as any)
    renderPage(); fireEvent.click(within(await card()).getByRole('button',{name:'查看告警'}))
    const detail = await screen.findByRole('region',{name:'告警详情'})
    expect(within(detail).queryByRole('link',{name:'查看会话'})).not.toBeInTheDocument()
    expect(within(detail).getByRole('button',{name:'查看完整关联对话'})).toBeInTheDocument()
  })

  it('opens the endpoint session instead of the ordinary request-log session', async () => {
    vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
    const endpoint = occurrence({session_id:'request-log-session',agent_session_id:'agent-real/001'})
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([endpoint]) as any)
    renderPage(); fireEvent.click(within(await card()).getByRole('button',{name:'查看告警'}))
    const detail = await screen.findByRole('region',{name:'告警详情'})
    expect(within(detail).getByRole('link',{name:'查看会话'}).getAttribute('href')).toBe('/agent/sessions/agent-real%2F001')
  })

  it('centers the timeline on the exact request hit beyond the first eight rows', async () => {
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence({ message_index: 10 })]) as any)
    vi.mocked(contentAuditApi.getSession).mockResolvedValue({ data: { data: Array.from({ length: 15 }, (_, i) => ({ id: 'log-'+i, request_id: 'request-1', message_index: i, role: 'user', content: '上下文第'+i+'行' })) } } as any)
    renderPage(); fireEvent.click(within(await card()).getByRole('button', { name: '查看告警' }))
    const detail = await screen.findByRole('dialog', { name: '告警详情' })
    expect(await within(detail).findByText('上下文第10行')).toBeInTheDocument()
    expect(within(detail).getByText('⚑ 命中轮')).toBeInTheDocument()
    expect(within(detail).queryByText('上下文第0行')).not.toBeInTheDocument()
  })

  it('drills from a grouped problem to the selected hit and only that request retention', async () => {
    vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
    const grouped=occurrence({ case_id:'ac1_'+'1'.repeat(32), hit_count:50, request_count:20, blocked_count:0, first_seen:'2026-09-17T08:00:00Z',last_seen:'2026-09-19T08:00:00Z',last_detected_at:'2026-09-19T08:01:00Z',grouping_basis:'conversation',severity:'high' })
    const low=occurrence({id:'low-hit',event_id:'low-event',request_id:'request-two',severity:'low',raw_evidence:'exact-second-evidence',occurred_at:'2026-09-19T07:00:00Z'})
    vi.mocked(alertOccurrencesApi.list).mockImplementation(async p => p.grouping==='hits' ? page([low]) as any : {...page([grouped]),data:{...page([grouped]).data,count_unit:'triage_cases',counts:{...page([grouped]).data.counts,total:1,raw_hits:50,last_24h:0,delayed_24h:1}}} as any)
    vi.mocked(alertOccurrencesApi.getEvidence).mockResolvedValue({...low,raw_evidence_status:'available'})
    vi.mocked(accessRetentionApi.getContent).mockResolvedValue({data:{request_id:'request-two',user_input:'only second request body',model_output:'second response'}} as any)
    renderPage()
    const detail=await screen.findByRole('region',{name:'告警详情'})
    expect(await within(detail).findByText('查看 50 次命中明细')).toBeInTheDocument()
    expect(alertOccurrencesApi.getEvidence).not.toHaveBeenCalled()
    fireEvent.click(within(detail).getByRole('tab',{name:'2. 命中明细'}))
    fireEvent.click(await within(detail).findByRole('button',{name:'查看这条证据'}))
    expect(vi.mocked(alertOccurrencesApi.list).mock.calls.find(([p])=>p.grouping==='hits')?.[0].recent_limit).toBeUndefined()
    expect(await within(detail).findByText('only second request body')).toBeInTheDocument()
    // 命中明细页签和证据页签都显示这条命中的原文；这里核对证据页签里选中的那一条。
    expect(within(within(detail).getByRole('region',{name:'选中命中证据'})).getByText('exact-second-evidence')).toBeInTheDocument()
    expect(within(detail).getByText('邮箱地址 · 低危')).toBeInTheDocument()
    expect(accessRetentionApi.getContent).toHaveBeenCalledWith('request-two',undefined,expect.objectContaining({signal:expect.anything()}))
    expect(within(detail).getByRole('link',{name:/在请求留存页/}).getAttribute('href')).toContain('request_id=request-two')
    fireEvent.click(within(detail).getByRole('button',{name:'标为误报'}))
    await waitFor(()=>expect(auditDispositionApi.upsert).toHaveBeenCalledWith(expect.objectContaining({subject_type:'alert_case',subject_id:grouped.case_id,case_seen_through:grouped.last_detected_at})))
  })

  it('links only agent-endpoint case members to their real sessions', async () => {
    vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
    const grouped=occurrence({case_id:'ac1_'+'6'.repeat(32),hit_count:2,request_count:2})
    const ordinary=occurrence({id:'ordinary-hit',event_id:'ordinary-event',session_id:'ordinary-session',agent_session_id:''})
    const endpoint=occurrence({id:'endpoint-hit',event_id:'endpoint-event',session_id:'ordinary-session',agent_session_id:'agent-real/002'})
    vi.mocked(alertOccurrencesApi.list).mockImplementation(async p => p.grouping==='hits' ? page([ordinary,endpoint]) as any : page([grouped]) as any)
    renderPage()
    const detail=await screen.findByRole('region',{name:'告警详情'})
    fireEvent.click(await within(detail).findByRole('tab',{name:'2. 命中明细'}))
    await waitFor(()=>expect(within(detail).getAllByRole('button',{name:'查看这条证据'})).toHaveLength(2))
    const links=within(detail).getAllByRole('link',{name:'查看会话'})
    expect(links).toHaveLength(1)
    expect(links[0].getAttribute('href')).toBe('/agent/sessions/agent-real%2F002')
  })

  it('distinguishes missing tool evidence and judge failure from the current request summary', async () => {
    vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
    const item=occurrence({case_id:'ac1_'+'7'.repeat(32),hit_count:2,request_count:2,type:'catalog_policy',category:'illegal_weapon_trade',severity:'critical',content_source:'tool_result',message_role:'tool',message_index:310,redacted_evidence:''})
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue({...page([item]),data:{...page([item]).data,count_unit:'triage_cases'}} as any)
    vi.mocked(alertOccurrencesApi.getEvidence).mockResolvedValue({...item,raw_evidence_status:'missing',evidence_context:'<deterministic-catalog-match>',semantic_status:'incomplete',semantic_reason:'judge_timeout'})
    vi.mocked(accessRetentionApi.getContent).mockResolvedValue({data:{request_id:item.request_id,user_input:'继续',model_output:'SATA 可逆测试已完成'}} as any)
    renderPage()
    const detail=await screen.findByRole('region',{name:'告警详情'})
    fireEvent.click(await within(detail).findByRole('tab',{name:'3. 证据与留痕'}))
    expect(await within(detail).findByText(/语义复核未完成：裁判超时/)).toBeInTheDocument()
    expect(within(detail).getByText(/本条命中来自工具返回/)).toBeInTheDocument()
    expect(within(detail).queryByText('<deterministic-catalog-match>')).not.toBeInTheDocument()
    expect(within(detail).getByText(/未留存可核验的命中片段/)).toBeInTheDocument()
    expect(await within(detail).findByText('SATA 可逆测试已完成')).toBeInTheDocument()
  })

  it('does not reselect a stale pending case while disposition refresh is in flight', async () => {
    vi.spyOn(Grid,'useBreakpoint').mockReturnValue({lg:true})
    const grouped=occurrence({case_id:'ac1_'+'3'.repeat(32),hit_count:2,request_count:2,last_detected_at:'2026-09-19T08:01:00Z'})
    let refresh: ((value:any)=>void) | undefined
    vi.mocked(alertOccurrencesApi.list).mockResolvedValueOnce(page([grouped]) as any).mockImplementation(()=>new Promise(resolve=>{refresh=resolve}) as any)
    renderPage()
    const panel=await screen.findByRole('region',{name:'告警详情'})
    fireEvent.click(await within(panel).findByRole('button',{name:'标为误报'}))
    await waitFor(()=>expect(auditDispositionApi.upsert).toHaveBeenCalled())
    await waitFor(()=>expect(refresh).toBeDefined())
    expect(within(panel).queryByRole('button',{name:'标为已处理'})).not.toBeInTheDocument()
    await act(async()=>{refresh!(page([]))})
    expect(await screen.findByText('暂无安全告警')).toBeInTheDocument()
    expect(within(panel).queryByRole('button',{name:'标为已处理'})).not.toBeInTheDocument()
  })

  it('does not treat repeated hits or historic reinspection as newly occurring problems', async () => {
    const result=page([occurrence({case_id:'ac1_'+'2'.repeat(32),hit_count:100,request_count:60})])
    result.data.count_unit='triage_cases'
    result.data.counts={...result.data.counts,last_24h:0,pending:1,raw_hits:100,delayed_24h:1}
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(result as any)
    renderPage();await card()
    expect(screen.queryByRole('region',{name:'近24小时新增问题'})).not.toBeInTheDocument()
    expect(screen.queryByRole('region',{name:'历史请求补检'})).not.toBeInTheDocument()
    expect(screen.queryByText(/近 24 小时新增告警/)).not.toBeInTheDocument()
  })

  it('renders no KPI count cards above the alert list', async () => {
    const response = page([occurrence()], 30132)
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue({ data: { ...response.data,
      operational: { event_count: 147394, count_unit: 'security_events', list_url: '/admin/v1/security/alert-occurrences/operational' },
    } } as any)
    renderPage()
    await screen.findByText('请联系 a***@example.com 获取说明')
    // 任何范围总量、待办量、24 小时缺口量都不再成为首屏数字。
    expect(screen.queryByText('今日新增')).not.toBeInTheDocument()
    expect(screen.queryByText('今日高危')).not.toBeInTheDocument()
    expect(screen.queryByText(/未闭环且未抑制/)).not.toBeInTheDocument()
    expect(screen.queryByTestId('alert-kpi-operational')).not.toBeInTheDocument()
    expect(screen.queryByText('30,132')).not.toBeInTheDocument()
    expect(screen.queryByText('147,394')).not.toBeInTheDocument()
    // 卡片数字撤走后也不再发出额外统计请求（只有主列表一次）。
    expect(vi.mocked(alertOccurrencesApi.list).mock.calls.map(([params]) => params).filter((params) => params.limit === 1)).toHaveLength(0)
  })

  it('does not expose or fetch operational diagnostics from the customer alert page', async () => {
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue({data:{...page([]).data,operational:{count_known:false,event_count:100,count_unit:'security_events',list_url:'/admin/v1/security/alert-occurrences/operational'}}} as any)
    renderPage()
    await waitFor(()=>expect(alertOccurrencesApi.list).toHaveBeenCalled())
    expect(screen.queryByRole('button',{name:'检测覆盖缺口排查'})).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog',{name:'检测覆盖缺口 / 运行异常事件'})).not.toBeInTheDocument()
    expect(screen.queryByRole('link',{name:'运行健康'})).not.toBeInTheDocument()
    expect(alertOccurrencesApi.summarizeOperational).not.toHaveBeenCalled()
    expect(alertOccurrencesApi.listOperational).not.toHaveBeenCalled()
  })

  it('describes historical user evidence and audit outcomes in Chinese in the card and detail', async () => {
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence({ content_source: 'user_history', action_taken: 'security_audit', event_action_taken: 'security_audit_only' })]) as any)
    renderPage()
    const row = await card()
    expect(within(row).getByText('用户历史消息')).toBeInTheDocument()
    expect(within(row).queryByText(/规则建议/)).not.toBeInTheDocument()
    // W8 8.8：记录模式放行统一用执行模式名称（观察留痕），不再有「审计模式放行 / 审计放行」两种说法。
    expect(within(row).getByText(RECORD_MODE_PASS_LABEL)).toBeInTheDocument()
    fireEvent.click(within(row).getByRole('button', { name: '查看告警' }))
    const detail = await screen.findByRole('dialog', { name: '告警详情' })
    fireEvent.click(within(detail).getByText('查看完整身份、检测理由与原始证据'))
    expect(within(detail).getByText('用户 / 输入检测')).toBeInTheDocument()
    expect(within(detail).getAllByText('请求动作')[0].parentElement!.textContent).toContain(RECORD_MODE_PASS_LABEL)
    expect(detail).not.toHaveTextContent('user_history')
    expect(detail).not.toHaveTextContent('security_audit')
    expect(detail).not.toHaveTextContent('user / input')
  })

  it('defaults to one finding per row even across turns in the same conversation', async () => {
    const critical = occurrence({ id: 'critical-occurrence', event_id: 'critical-event', request_id: 'request-2', message_index: 4, category: 'secret', severity: 'critical', redacted_evidence: '另一轮的密钥证据', content_source: 'tool_result', message_role: 'tool' })
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence(), critical]) as any)
    renderPage()
    const emailRow = await card('email-occurrence')
    const criticalRow = await card('critical-occurrence')
    expect(emailRow).not.toBe(criticalRow)
    expect(within(emailRow).getByText('低危')).toBeInTheDocument()
    expect(within(emailRow).queryByText('严重')).not.toBeInTheDocument()
    expect(within(criticalRow).getByText('严重')).toBeInTheDocument()
    expect(within(emailRow).getByText(/张三 · 研发部/)).toBeInTheDocument()
    expect(contentAuditApi.list).not.toHaveBeenCalled()
    expect(contentAuditApi.getSessionEvents).not.toHaveBeenCalled()
    fireEvent.click(within(emailRow).getByRole('button', { name: '查看告警' }))
    const detail = await screen.findByRole('dialog', { name: '告警详情' })
    fireEvent.click(within(detail).getByText('查看完整身份、检测理由与原始证据'))
    expect(within(detail).getAllByText('低危')[0]).toBeInTheDocument()
    expect(within(detail).queryByText('严重')).not.toBeInTheDocument()
    expect(within(detail).queryByText('另一轮的密钥证据')).not.toBeInTheDocument()
    expect(within(detail).getByText(/消息索引 0/)).toBeInTheDocument()
    expect(within(detail).getByText('规则动作：仅记录')).toBeInTheDocument()
    expect(within(detail).getAllByText('已阻断')[0]).toBeInTheDocument()
  })

  it('uses independent event evidence when the retained conversation body is absent', async () => {
    vi.mocked(alertOccurrencesApi.getEvidence).mockResolvedValue(occurrence({ raw_evidence_status: 'available', raw_evidence: '本事件独立命中片段', evidence_context: '本事件保存的前后文' }))
    renderPage()
    fireEvent.click(within(await card()).getByRole('button', { name: '查看告警' }))
    const detail = await screen.findByRole('dialog', { name: '告警详情' })
    fireEvent.click(within(detail).getByText('查看完整身份、检测理由与原始证据'))
    expect(await within(detail).findByText('本事件保存的前后文')).toBeInTheDocument()
    // 命中规则卡片和完整证据里都显示原文。
    expect(within(detail).getByText('本次事件原始命中')).toBeInTheDocument()
    expect(within(detail).getAllByText('本事件独立命中片段')).toHaveLength(2)
    expect(within(detail).queryByText('该请求未留存正文')).not.toBeInTheDocument()
    expect(contentAuditApi.getSessionEvents).not.toHaveBeenCalled()
  })

  it('separates different findings in one event and never turns unknown location into message zero', async () => {
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([
      occurrence(),
      occurrence({ id: 'second-finding', finding_index: 1, severity: '', message_index: null, attachment_index: null, content_source: '', message_role: '', redacted_evidence: '另一条未定位命中' }),
    ]) as any)
    renderPage()
    const row = await card('second-finding')
    expect(within(row).getByText('未分级')).toBeInTheDocument()
    expect(within(row).getByText('消息位置未记录')).toBeInTheDocument()
    expect(within(row).getByText('未记录消息来源')).toBeInTheDocument()
    fireEvent.click(within(row).getByRole('button', { name: '查看告警' }))
    const detail = await screen.findByRole('dialog', { name: '告警详情' })
    fireEvent.click(within(detail).getByText('查看完整身份、检测理由与原始证据'))
    expect(within(detail).queryByText('请联系 a***@example.com 获取说明')).not.toBeInTheDocument()
    expect(within(detail).queryByText(/消息索引 0/)).not.toBeInTheDocument()
    expect(within(detail).getAllByText('未分级')[0]).toBeInTheDocument()
  })

  it.each([
    ['verified_final_output', '模型输出'],
    ['system_prompt', '内置上下文'],
    ['tool_result', '工具返回'],
    ['rag_context', 'RAG 检索内容'],
  ])('shows %s provenance without inferring it from the user message role', async (content_source, label) => {
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence({ content_source, message_role: 'user' })]) as any)
    renderPage()
    const row = await card()
    expect(within(row).getByText(label)).toBeInTheDocument()
    expect(within(row).queryByText('用户输入')).not.toBeInTheDocument()
  })

  it('labels rule block intent separately from an audit-only request outcome', async () => {
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence({ action_taken: 'block', event_action_taken: 'audit' })]) as any)
    renderPage()
    const row = await card()
    expect(within(row).getByText('规则建议：阻断')).toBeInTheDocument()
    expect(within(row).getByText('仅记录')).toBeInTheDocument()
    expect(within(row).queryByText('已阻断')).not.toBeInTheDocument()
    expect(within(row).queryByText(/请求动作/)).not.toBeInTheDocument()
    fireEvent.click(within(row).getByRole('button', { name: '查看告警' }))
    const detail = await screen.findByRole('dialog', { name: '告警详情' })
    fireEvent.click(within(detail).getByText('查看完整身份、检测理由与原始证据'))
    expect(within(detail).getByText('规则动作：阻断')).toBeInTheDocument()
    expect(within(detail).getAllByText('请求动作')[0].parentElement!.textContent).toContain('仅记录')
  })

  it('reads only one day either side of the selected hit from retention', async () => {
    const row = occurrence({ session_id: '', conversation_id: '', conversation_key: '', occurred_at: '2026-09-19T07:00:00Z' })
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([row]) as any)
    vi.mocked(alertOccurrencesApi.getEvidence).mockResolvedValue(row)
    renderPage()
    fireEvent.click(within(await card()).getByRole('button', { name: '查看告警' }))
    await waitFor(() => expect(accessRetentionApi.getContent).toHaveBeenCalledWith('request-1', undefined, expect.objectContaining({
      from: '2026-09-18T07:00:00.000Z', to: '2026-09-20T07:00:00.000Z',
    })))
  })

  it('refreshes only the current page after a disposition and leaves evidence and summaries for their next use', async () => {
    vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
    const row = occurrence()
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([row]) as any)
    vi.mocked(alertOccurrencesApi.getEvidence).mockResolvedValue(row)
    renderPage()
    const detail = await screen.findByRole('region', { name: '告警详情' })
    await waitFor(() => expect(alertOccurrencesApi.getEvidence).toHaveBeenCalledTimes(1))
    const before = vi.mocked(alertOccurrencesApi.list).mock.calls.length
    const current = { ...vi.mocked(alertOccurrencesApi.list).mock.calls[before - 1][0], signal: undefined }
    fireEvent.click(await within(detail).findByRole('button', { name: '标为已处理' }))
    await waitFor(() => expect(auditDispositionApi.upsert).toHaveBeenCalled())
    await waitFor(() => expect(vi.mocked(alertOccurrencesApi.list).mock.calls.length).toBe(before + 1))
    const again = { ...vi.mocked(alertOccurrencesApi.list).mock.calls[before][0], signal: undefined }
    expect(again).toEqual(current)
    // 处置本身不重取证据；刷新后宽屏自动重新选中第一条，才按需再取一次它的证据。
    await waitFor(() => expect(alertOccurrencesApi.getEvidence).toHaveBeenCalledTimes(2))
    await new Promise((resolve) => setTimeout(resolve, 100))
    expect(alertOccurrencesApi.getEvidence).toHaveBeenCalledTimes(2)
  })

  it('shows the stored original hit in the list for content readers and never substitutes the context or reason', async () => {
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence({ redacted_evidence: 'ra****ak', evidence_status: 'available', raw_evidence: 'raw-secret-original', evidence_context: 'raw-context-must-not-leak', reason: 'raw-reason-must-not-leak' })]) as any)
    renderPage()
    expect(await screen.findByText('raw-secret-original')).toBeInTheDocument()
    expect(screen.queryByText('ra****ak')).not.toBeInTheDocument()
    expect(screen.queryByText(/must-not-leak/)).not.toBeInTheDocument()
    expect(vi.mocked(alertOccurrencesApi.list).mock.calls.every(([call]) => call.include_raw === true)).toBe(true)
    expect(alertOccurrencesApi.getEvidence).not.toHaveBeenCalled()
  })

  it('follows the evidence permission the backend reports instead of the role name', async () => {
    const response = page([occurrence({ redacted_evidence: 'ra****ak', evidence_status: 'restricted' })])
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue({ ...response, data: { ...response.data, evidence_readable: false } } as any)
    renderPage()
    expect(await screen.findByText('无权查看命中片段')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '查看告警' })).not.toBeInTheDocument()
    expect(screen.getAllByText('仅元数据').length).toBeGreaterThan(0)
    expect(alertOccurrencesApi.getEvidence).not.toHaveBeenCalled()
  })

  it('keeps the list metadata-only for roles without content evidence access', async () => {
    useAuthStore.setState({ token: 'test-token', user: { id: 'viewer', username: 'viewer', tenant_id: 'tenant-1', role: 'tenant_viewer' }, isAuthenticated: true } as any)
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence({ redacted_evidence: 'ra****ak', evidence_status: 'restricted' })]) as any)
    renderPage()
    expect(await screen.findByText('无权查看命中片段')).toBeInTheDocument()
    expect(vi.mocked(alertOccurrencesApi.list).mock.calls.some(([call]) => call.include_raw === true)).toBe(false)
  })

  it('marks a truncated original hit', async () => {
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence({ raw_evidence: 'long-original', raw_evidence_truncated: true })]) as any)
    renderPage()
    expect(await screen.findByText('long-original（已截断）')).toBeInTheDocument()
  })

  it('says where to find an original that exceeded the per-event limit when it could not be recovered', async () => {
    const row = occurrence({ redacted_evidence: '', evidence_status: 'missing', raw_evidence_status: 'missing', raw_evidence_omitted: true })
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([row]) as any)
    vi.mocked(alertOccurrencesApi.getEvidence).mockResolvedValue(row)
    renderPage()
    expect(await within(await card()).findByText(RAW_EVIDENCE_OMITTED_TEXT)).toBeInTheDocument()
    expect(screen.queryByText('未记录命中片段')).not.toBeInTheDocument()
    fireEvent.click(within(await card()).getByRole('button', { name: '查看告警' }))
    const detail = await screen.findByRole('dialog', { name: '告警详情' })
    fireEvent.click(within(detail).getByText('查看完整身份、检测理由与原始证据'))
    expect((await within(detail).findAllByText(RAW_EVIDENCE_OMITTED_TEXT)).length).toBeGreaterThan(0)
  })

  it('shows a permission-checked historical preview without claiming it is a full raw window', async () => {
    const row = occurrence({ redacted_evidence: '', evidence_status: 'available', matched_text_preview: 'historical finding preview', raw_evidence_status: 'missing' })
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([row]) as any)
    vi.mocked(alertOccurrencesApi.getEvidence).mockResolvedValue(row)
    renderPage()
    await screen.findByText('未记录命中片段')
    expect(screen.queryByText('historical finding preview')).not.toBeInTheDocument()
    fireEvent.click(within(await card()).getByRole('button', { name: '查看告警' }))
    const detail = await screen.findByRole('dialog', { name: '告警详情' })
    fireEvent.click(within(detail).getByText('查看完整身份、检测理由与原始证据'))
    expect(await within(detail).findByText('historical finding preview')).toBeInTheDocument()
    expect(within(detail).getByText('历史命中预览（非完整原文）')).toBeInTheDocument()
    expect(within(detail).queryByText('本次事件原始命中')).not.toBeInTheDocument()
  })

  it.each([
    [{ credential_name: '共享应用凭据', credential_id: 'key-1' }, '192.0.2.10'],
    [{ credential_name: '', credential_id: 'key-1' }, '192.0.2.10'],
    [{ credential_name: '', credential_id: '', principal_key: 'upstream:credential:abc123' }, '192.0.2.10'],
    [{ credential_name: '', credential_id: '', principal_key: '' }, '192.0.2.10'],
  ])('uses source IP when no account name is available: %s', async (identity, label) => {
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence({ actor_user_id: '', actor_name: '', actor_department_name: '', identity_reliability: 'unknown', key_owner_name: '', ...identity })]) as any)
    renderPage()
    const row = await card()
    expect(within(row).getByText(new RegExp(label))).toBeInTheDocument()
    expect(within(row).queryByText(/未识别身份|身份未识别/)).not.toBeInTheDocument()
    expect(within(row).queryByText('网关管理员')).not.toBeInTheDocument()
    expect(within(row).getByText('来源 IP')).toBeInTheDocument()
  })

  it('shows the bound account on the case and separates connection, IP and credential in details', async () => {
    vi.spyOn(Grid, 'useBreakpoint').mockReturnValue({ lg: true })
    const item = occurrence({ case_id: 'ac1_'+'4'.repeat(32), hit_count: 2, request_count: 1, actor_name: '', actor_user_id: '', actor_department_name: '', key_owner_name: 'examplegw', identity_source: 'api_key', identity_reliability: 'credential', access_direction: 'chat_completion', credential_name: 'claude code mac' })
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([item]) as any)
    renderPage()
    const row = await card()
    // 卡片：风险名独占一行、账户在"谁"一行；凭据名绝不出现在卡片上（共享凭据不能当作操作者）。
    expect(within(row).getByTestId('alert-card-what')).toHaveTextContent('邮箱地址')
    expect(within(row).getByTestId('alert-card-who')).toHaveTextContent('examplegw')
    expect(within(row).queryByText(/claude code mac/)).not.toBeInTheDocument()
    const detail = await screen.findByRole('region', { name: '告警详情' })
    fireEvent.click(within(detail).getByText('examplegw'))
    expect(within(detail).getByText('API Key 接入')).toBeInTheDocument()
    expect(within(detail).getByText('claude code mac')).toBeInTheDocument()
    expect(within(detail).getByText('192.0.2.10')).toBeInTheDocument()
    expect(within(detail).queryByText('账户关联依据')).not.toBeInTheDocument()
  })

  it('uses a missing-record label only when all identity clues are absent', async () => {
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence({ actor_user_id: '', actor_name: '  ', key_owner_name: '', credential_name: '', credential_id: '', source_ip: '', principal_key: '', actor_department_name: '' })]) as any)
    renderPage()
    expect(within(await card()).getByText(/账户与来源 IP 未记录的流量/)).toBeInTheDocument()
  })

  it('saves a disposition for the exact security event and refreshes the list', async () => {
    renderPage()
    fireEvent.click(within(await card()).getByRole('button', { name: '查看告警' }))
    const detail = await screen.findByRole('dialog', { name: '告警详情' })
    fireEvent.click(within(detail).getByText('查看完整身份、检测理由与原始证据'))
    fireEvent.mouseDown(within(detail).getByRole('combobox', { name: '处置状态' }))
    fireEvent.click(await screen.findByText('误报', { selector: '.ant-select-item-option-content' }))
    fireEvent.change(within(detail).getByLabelText('处置批注'), { target: { value: '复核为正常文件' } })
    fireEvent.click(within(detail).getByRole('button', { name: '保存处置' }))
    await waitFor(() => expect(auditDispositionApi.upsert).toHaveBeenCalledWith({
      subject_type: 'security_event', subject_id: 'email-event', status: 'false_positive', note: '复核为正常文件',
    }))
    expect((await screen.findAllByText('处置状态已保存')).length).toBeGreaterThan(0)
  })

  it('shows the conversation timeline with the hit turn highlighted', async () => {
    vi.mocked(contentAuditApi.getSession).mockResolvedValue({ data: { data: [
      { id: 'm1', role: 'user', content: '帮我把客户信息整理成表格', created_at: '2026-09-18T07:59:00Z', message_index: 0 },
      { id: 'm2', role: 'assistant', content: '可以，请把信息发给我', created_at: '2026-09-18T07:59:10Z', message_index: 1 },
      { id: 'm3', role: 'user', content: '邮箱是 a***@example.com', created_at: '2026-09-18T08:00:00Z', message_index: 2 },
    ] } } as any)
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence({ message_index: 2 })]) as any)
    renderPage()
    fireEvent.click(within(await card()).getByRole('button', { name: '查看告警' }))
    const detail = await screen.findByRole('dialog', { name: '告警详情' })
    fireEvent.click(within(detail).getByText('查看完整身份、检测理由与原始证据'))
    expect(await within(detail).findByText('对话上下文')).toBeInTheDocument()
    expect(within(detail).getByText('帮我把客户信息整理成表格')).toBeInTheDocument()
    const hitBubble = (await within(detail).findByText('邮箱是 a***@example.com')).closest('div')!.parentElement!
    expect(within(hitBubble).getByText(/命中轮/)).toBeInTheDocument()
    expect(within(detail).getByRole('button', { name: '查看完整关联对话' })).toBeInTheDocument()
  })

  it('keeps exact request and project filters across pagination without hiding historical hits', async () => {
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence()], 41) as any)
    renderPage('/security/alerts?project_id=project-1&request_id=request-1&window_hours=24')
    await screen.findByText('请联系 a***@example.com 获取说明')
    const params = vi.mocked(alertOccurrencesApi.list).mock.calls.map(([call]) => call).filter((call) => call.limit === 10)[0]
    expect(params).toMatchObject({ limit: 10, offset: 0, project_id: 'project-1', request_id: 'request-1', include_raw: true, disposition: 'all', grouping: 'hits' })
    expect(params.start_time).toBeUndefined()
    expect(params.end_time).toBeUndefined()
    expect(params.recent_limit).toBeUndefined()
    fireEvent.click(screen.getByTitle('2'))
    // KPI 口径查询与列表共用同一接口，断言落在分页那一次调用上而不是"最后一次调用"。
    await waitFor(() => expect(vi.mocked(alertOccurrencesApi.list).mock.calls
      .some(([call]) => call.offset === 10 && call.project_id === 'project-1' && call.request_id === 'request-1')).toBe(true))
    expect(accessRetentionApi.list).not.toHaveBeenCalled()
  })

  it('keeps department readers on redacted metadata, including after a role change', async () => {
    renderPage()
    fireEvent.click(within(await card()).getByRole('button', { name: '查看告警' }))
    await screen.findByRole('dialog', { name: '告警详情' })
    const rawCalls = vi.mocked(alertOccurrencesApi.getEvidence).mock.calls.length
    act(() => useAuthStore.setState({ user: { id: 'manager', username: 'manager', tenant_id: 'tenant-1', role: 'dept_manager' } }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.queryByRole('button', { name: '查看告警' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '查看关联对话' })).not.toBeInTheDocument()
    expect(alertOccurrencesApi.getEvidence).toHaveBeenCalledTimes(rawCalls)
    expect(contentAuditApi.getSessionEvents).not.toHaveBeenCalled()
  })

  it('retains the selected finding before explicitly requested conversation context', async () => {
    vi.mocked(contentAuditApi.getSessionEvents).mockResolvedValue({ data: { data: [{ id: 'other-event', severity: 'critical', matched_summary: { findings: [{ severity: 'critical', category: 'secret', raw_evidence: 'unrelated-secret' }] } }] } } as any)
    renderPage()
    fireEvent.click(within(await card()).getByRole('button', { name: '查看关联对话' }))
    const detail = await screen.findByRole('dialog', { name: /关联对话/ })
    expect(within(detail).getAllByText('低危')[0]).toBeInTheDocument()
    expect(within(detail).queryByText('严重')).not.toBeInTheDocument()
    expect(within(detail).queryByText('unrelated-secret')).not.toBeInTheDocument()
    await waitFor(() => expect(contentAuditApi.getSession).toHaveBeenCalledWith('session-1', expect.objectContaining({ view: 'manager' })))
  })

  it('renders a fetch error with retry rather than claiming there are no alerts', async () => {
    // Production query defaults must not silently turn a 15s error into a
    // minute of repeated scans before showing the actionable retry button.
    client.setDefaultOptions({ queries: { retry: 3, retryDelay: 0 } })
    vi.mocked(alertOccurrencesApi.list).mockRejectedValue(new Error('unavailable'))
    renderPage()
    expect(await screen.findByText('告警加载失败')).toBeInTheDocument()
    // KPI 口径查询与列表共用同一接口；这里只数主列表（limit 20）本身未自动重试。
    const mainListCalls = () => vi.mocked(alertOccurrencesApi.list).mock.calls.map(([call]) => call).filter((call) => call.limit === 10)
    expect(mainListCalls()).toHaveLength(1)
    const params = mainListCalls()[0]
    expect(params.limit).toBe(10)
    expect(params.offset).toBe(0)
    expect(params.start_time).toBeUndefined()
    expect(params.recent_limit).toBe(100)
    expect(screen.queryByText('暂无安全告警')).not.toBeInTheDocument()
    vi.mocked(alertOccurrencesApi.list).mockResolvedValue(page([occurrence()]) as any)
    fireEvent.click(screen.getByRole('button', { name: '重试告警' }))
    expect(await screen.findByText('请联系 a***@example.com 获取说明')).toBeInTheDocument()
  })
})

describe('occurrence evidence boundary', () => {
  beforeEach(() => vi.restoreAllMocks())
  it('reads the provided operational route with authentication and preserves encoded scope', async () => {
    const get = vi.spyOn(apiClient, 'get').mockResolvedValue({ data: {} })
    const signal = new AbortController().signal
    await alertOccurrencesApi.listOperational('/admin/v1/security/alert-occurrences/operational?project_id=a%2Fb&request_id=request-1', { limit: 20, offset: 40, signal })
    expect(get).toHaveBeenCalledWith('/security/alert-occurrences/operational?project_id=a%2Fb&request_id=request-1', { params: { limit: 20, offset: 40 }, signal })
  })
  it('refuses operational URLs that would send admin credentials to another endpoint', async () => {
    const get = vi.spyOn(apiClient, 'get')
    await expect(alertOccurrencesApi.listOperational('https://example.invalid/admin/v1/security/alert-occurrences/operational')).rejects.toThrow('运行异常列表链接无效')
    await expect(alertOccurrencesApi.summarizeOperational('https://example.invalid/admin/v1/security/alert-occurrences/operational')).rejects.toThrow('运行异常列表链接无效')
    await expect(alertOccurrencesApi.listOperational('/admin/v1/security/alert-occurrences/operational/../../users?x=1')).rejects.toThrow('运行异常列表链接无效')
    expect(get).not.toHaveBeenCalled()
  })
  it('reads the scoped breakdown and reason drilldown on the same authenticated route', async () => {
    const get = vi.spyOn(apiClient, 'get').mockResolvedValue({ data: {} })
    const signal = new AbortController().signal
    await alertOccurrencesApi.summarizeOperational('/admin/v1/security/alert-occurrences/operational?project_id=a%2Fb&start_time=2026-09-18T00%3A00%3A00Z', { signal })
    expect(get).toHaveBeenCalledWith('/security/alert-occurrences/operational/summary?project_id=a%2Fb&start_time=2026-09-18T00%3A00%3A00Z', { signal })
    await alertOccurrencesApi.listOperational('/admin/v1/security/alert-occurrences/operational?project_id=a%2Fb', { limit: 20, offset: 0, reason: 'judge_capacity_deferred', signal })
    expect(get).toHaveBeenLastCalledWith('/security/alert-occurrences/operational?project_id=a%2Fb', { params: { limit: 20, offset: 0, reason: 'judge_capacity_deferred' }, signal })
  })
  it('selects the exact event/finding across pages and carries the original scope', async () => {
    const wrong = occurrence({ event_id: 'different-event', raw_evidence: 'wrong' })
    const selected = occurrence({ raw_evidence: 'correct', raw_evidence_status: 'available' })
    const get = vi.spyOn(apiClient, 'get').mockResolvedValueOnce(page([wrong], 101)).mockResolvedValueOnce(page([selected]))
    const signal = new AbortController().signal
    const result = await alertOccurrencesApi.getEvidence(occurrence(), { project_id: 'project-1', start_time: 'start', end_time: 'end', signal })
    expect(result?.raw_evidence).toBe('correct')
    expect(get).toHaveBeenLastCalledWith('/security/alert-occurrences', expect.objectContaining({ signal, params: expect.objectContaining({ project_id: 'project-1', event_id: 'email-event', grouping: 'hits', start_time: undefined, end_time: undefined, request_id: 'request-1', offset: 100, include_raw: true }) }))
  })
  it('does not substitute another finding or request when an occurrence disappears', async () => {
    vi.spyOn(apiClient, 'get').mockResolvedValue(page([occurrence({ finding_index: 1 }), occurrence({ request_id: 'other-request' })]))
    expect(await alertOccurrencesApi.getEvidence(occurrence(), {})).toBeNull()
  })
})
