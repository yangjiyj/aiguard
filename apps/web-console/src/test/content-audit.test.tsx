import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ContentAudit from '../pages/ContentAudit'
import * as api from '../services/api'
import { buildSensitiveRulePayload } from '../utils/sensitiveRulePayload'
import { useAuthStore } from '../stores/auth'
import { alertOccurrencesApi } from '../services/alertOccurrences'

// 「检测记录」页：展示治理配置和原始检测证据。
// 行业预置判断依据属于引擎内部能力，不在页面顶部作为客户可见配置展示。
describe('Content & data security page presentation', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    useAuthStore.setState({
      token: 'admin-token',
      user: { id: 'admin', username: 'admin', role: 'platform_admin', tenant_id: 'tenant-a' },
      isAuthenticated: true,
    })
    vi.restoreAllMocks()
    vi.spyOn(alertOccurrencesApi, 'list').mockResolvedValue({ data: { items: [], total: 0 } } as any)
    vi.spyOn(api.contentAuditApi, 'getSessionEvents').mockResolvedValue({
      data: { data: [], total: 0 },
    } as any)
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({
      data: { data: [], total: 0 },
    } as any)
    vi.spyOn(api.contentAuditApi, 'listUsers').mockResolvedValue({
      data: { data: [], limit: 50, offset: 0, has_more: false, next_cursor: '' },
    } as any)
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0 },
    } as any)
  })

  const renderPage = (entry = '/audit/content') =>
    render(
      <MemoryRouter initialEntries={[`${entry}${entry.includes('?') ? '&' : '?'}view=conversations`]}>
        <QueryClientProvider client={queryClient}>
          <ContentAudit />
        </QueryClientProvider>
      </MemoryRouter>,
    )

  it('uses the exact alert deep link with its native session instead of content audit', async () => {
    render(
      <MemoryRouter initialEntries={['/security/alerts?view=conversations&event_id=security-event-exact&session_id=native-session-exact']}>
        <QueryClientProvider client={queryClient}><ContentAudit /></QueryClientProvider>
      </MemoryRouter>,
    )
    await waitFor(() => expect(alertOccurrencesApi.list).toHaveBeenCalledWith(expect.objectContaining({
      event_id: 'security-event-exact', session_id: 'native-session-exact', recent_limit: undefined,
      start_time: undefined, end_time: undefined, include_raw: true,
    })))
    expect(api.contentAuditApi.list).not.toHaveBeenCalled()
  })

  it('shows occurrence query errors for an exact event deep link', async () => {
    vi.mocked(alertOccurrencesApi.list).mockRejectedValueOnce(new Error('fixture query failure'))
    render(
      <MemoryRouter initialEntries={['/security/alerts?event_id=security-event-error&session_id=native-session-error']}>
        <QueryClientProvider client={queryClient}><ContentAudit /></QueryClientProvider>
      </MemoryRouter>,
    )
    expect(await screen.findByText('告警加载失败')).toBeInTheDocument()
    expect(screen.queryByText('暂无安全告警')).not.toBeInTheDocument()
    expect(api.contentAuditApi.list).not.toHaveBeenCalled()
  })

  it('does not render the industry preset summary panel', async () => {
    vi.spyOn(api.contentSecurityApi, 'getIndustry').mockResolvedValue({
      data: {
        industry: 'medical_imaging',
        packs: [
          {
            rule_id: 'rule_pii_id_card',
            name: '身份证号',
            category: 'pii_id_card',
            rule_type: 'regex',
            data_level: 'L4',
            severity: 'high',
            action: 'audit',
          },
          {
            rule_id: 'rule_medical_record',
            name: '病历号/住院号/门诊号',
            category: 'medical_record_id',
            rule_type: 'regex',
            data_level: 'L4',
            severity: 'high',
            action: 'audit',
          },
        ],
      },
    } as any)

    renderPage()

    expect(await screen.findByText('安全告警记录')).toBeInTheDocument()
    expect(screen.queryByText('按行业挂载预置数据安全判断依据；内置规则不作为客户可配置项展示。')).not.toBeInTheDocument()
    expect(screen.queryByText('医疗影像')).not.toBeInTheDocument()
    expect(screen.queryByText('行业')).not.toBeInTheDocument()
    expect(screen.queryByText('已启用 2 条内置判断依据')).not.toBeInTheDocument()
    expect(screen.queryByText('客户自定义规则在治理配置中维护')).not.toBeInTheDocument()
    expect(screen.queryByText('内置规则仅用于引擎判断')).not.toBeInTheDocument()
    expect(screen.queryByText('身份证号')).not.toBeInTheDocument()
    expect(screen.queryByText('病历号/住院号/门诊号')).not.toBeInTheDocument()
  })

  it('does not expose the industry switcher as a page-level control', async () => {
    vi.spyOn(api.contentSecurityApi, 'getIndustry').mockResolvedValue({
      data: {
        industry: 'generic',
        packs: [
          {
            rule_id: 'rule_pii_id_card',
            name: '身份证号',
            category: 'pii_id_card',
            rule_type: 'regex',
            data_level: 'L4',
            severity: 'high',
            action: 'audit',
          },
        ],
      },
    } as any)
    const setIndustrySpy = vi
      .spyOn(api.contentSecurityApi, 'setIndustry')
      .mockResolvedValue({
        data: { industry: 'finance', packs: [] },
      } as any)

    renderPage()

    expect(await screen.findByText('安全告警记录')).toBeInTheDocument()
    expect(screen.queryByText('通用')).not.toBeInTheDocument()
    expect(screen.queryByText('金融')).not.toBeInTheDocument()
    expect(screen.queryByText('已启用 1 条内置判断依据')).not.toBeInTheDocument()
    expect(setIndustrySpy).not.toHaveBeenCalled()
  })

  it('does not put low-risk blocked records in the security alert table', async () => {
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({ data: { data: [{ session_id: 'low-blocked-noise', highest_severity: 'low', action_taken: 'block', actionable_alert_count: 1, risk_categories: ['system'] }], total: 0 } } as any)
    renderPage()
    expect(await screen.findByText('暂无安全告警')).toBeInTheDocument()
    expect(screen.queryByText('low-blocked-noise')).not.toBeInTheDocument()
    expect(screen.queryByText('研判状态')).not.toBeInTheDocument()
  })

  it('loads security alerts from one server-paged source and labels the responsibility column', async () => {
    vi.spyOn(api.contentSecurityApi, 'getIndustry').mockResolvedValue({
      data: { industry: 'generic', packs: [] },
    } as any)
    const alertRecord = {
      session_id: 'risk-001',
      start_time: '2026-06-14T12:00:00Z',
      source_ip: '172.26.0.9',
      user_id: 'user-sec',
      username: 'sec',
      client_name: '大模型评估，攻击',
      provider: 'openai',
      target_host: 'chatgpt.com',
      risk_categories: ['pii_email'],
      action_taken: 'audit',
      disposition_status: 'mixed',
      security_event_count: 1,
      actionable_alert_count: 1,
      matched_rule_count: 1,
    }
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({
      data: { data: [alertRecord], total: 41 },
    } as any)
    const retentionSpy = vi.spyOn(api.accessRetentionApi, 'list')

    renderPage()

    await waitFor(() => expect(api.contentAuditApi.list).toHaveBeenCalledWith(expect.objectContaining({
      limit: 20,
      offset: 0,
      alert_only: true,
    })))
    const sessionParams = (api.contentAuditApi.list as any).mock.calls.find(([params]: any[]) => params?.alert_only === true)?.[0]
    const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000
    expect(new Date(sessionParams.to).getTime() - new Date(sessionParams.from).getTime()).toBeGreaterThanOrEqual(NINETY_DAYS_MS - 60 * 1000)
    expect(new Date(sessionParams.to).getTime() - new Date(sessionParams.from).getTime()).toBeLessThanOrEqual(NINETY_DAYS_MS + 60 * 1000)
    expect(retentionSpy).not.toHaveBeenCalled()

    expect(await screen.findByText('安全告警')).toBeInTheDocument()
    expect(screen.getByText('安全告警明细')).toBeInTheDocument()
    expect(screen.queryByText('暂无安全告警')).not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Key 归属筛选' })).toBeInTheDocument()
    expect(screen.getByPlaceholderText('搜索告警留证正文')).toBeInTheDocument()
    expect(screen.queryByText('风险等级')).not.toBeInTheDocument()
    const advanced = screen.getByRole('button', { name: /高级筛选/ })
    expect(advanced).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(advanced)
    expect(screen.getByText('风险等级')).toBeInTheDocument()
    expect(screen.queryByText('处置状态')).not.toBeInTheDocument()
    expect(screen.queryByText('研判状态')).not.toBeInTheDocument()
    expect(screen.getAllByText('责任主体').length).toBeGreaterThan(0)
    expect(screen.getByText('risk-001')).toBeInTheDocument()
    expect(screen.getAllByText('sec').length).toBeGreaterThan(0)
    expect(screen.getAllByText('API Key：大模型评估，攻击 · 172.26.0.9').length).toBeGreaterThan(0)
    expect(screen.queryByText('部分处置')).not.toBeInTheDocument()
    expect(document.querySelector('.ant-spin-spinning')).not.toBeInTheDocument()
  })

  it('honors the dashboard 24-hour alert window in the URL', async () => {
    renderPage('/security/alerts?window_hours=24')

    await waitFor(() => expect(api.contentAuditApi.list).toHaveBeenCalledWith(expect.objectContaining({
      alert_only: true,
    })))
    const sessionParams = (api.contentAuditApi.list as any).mock.calls.find(([params]: any[]) => params?.alert_only === true)?.[0]
    const ONE_DAY_MS = 24 * 60 * 60 * 1000
    expect(new Date(sessionParams.to).getTime() - new Date(sessionParams.from).getTime()).toBeGreaterThanOrEqual(ONE_DAY_MS - 60 * 1000)
    expect(new Date(sessionParams.to).getTime() - new Date(sessionParams.from).getTime()).toBeLessThanOrEqual(ONE_DAY_MS + 60 * 1000)
  })

  it('requests the next alert page from the server', async () => {
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({
      data: { data: [{
        session_id: 'paged-alert-001',
        start_time: '2026-08-28T04:00:00Z',
        actionable_alert_count: 1,
      }], total: 41 },
    } as any)

    renderPage()
    expect(await screen.findByText('paged-alert-001')).toBeInTheDocument()
    fireEvent.click(screen.getByTitle('2'))

    await waitFor(() => expect(api.contentAuditApi.list).toHaveBeenCalledWith(expect.objectContaining({
      limit: 20,
      offset: 20,
      alert_only: true,
    })))
  })

  it('does not merge retained risk candidates into the server-paged alert list', async () => {
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({
      data: { data: [{
        session_id: 'content-risk-001',
        start_time: '2026-07-29T01:00:00Z',
        source_ip: '10.0.0.1',
        provider: 'internal',
        target_host: 'model.local',
        highest_severity: 'high',
        risk_categories: ['config_file'],
        security_event_count: 2,
        actionable_alert_count: 2,
        matched_rule_count: 1,
      }], total: 1 },
    } as any)
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [{
        request_id: 'retained-risk-001',
        created_at: '2026-07-29T00:00:00Z',
        risk_state: 'risk',
        actionable_alert_count: 1,
      }], total: 1 },
    } as any)

    renderPage()

    expect(await screen.findByText('content-risk-001')).toBeInTheDocument()
    expect(screen.queryByText('retained-risk-001')).not.toBeInTheDocument()
    expect(screen.getByText('2 次告警 · 1 条规则')).toBeInTheDocument()
  })

  it('keeps pure agent identification in behavior records instead of security alerts', async () => {
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({
      data: { data: [{
        session_id: 'content-older-high',
        start_time: '2026-08-06T01:20:31Z',
        source_ip: '172.19.0.1',
        provider: 'examplegw',
        target_host: 'gpt-5.5',
        highest_severity: 'high',
        risk_categories: ['other_risk'],
        security_event_count: 1,
        actionable_alert_count: 1,
        matched_rule_count: 1,
      }], total: 1 },
    } as any)
    vi.spyOn(api.accessRetentionApi, 'list').mockImplementation((params?: any) => Promise.resolve({
      data: { data: params?.risk_state === 'risk' ? [{
        request_id: 'retained-newer-low',
        created_at: '2026-08-06T01:24:02Z',
        source_ip: '172.19.0.1',
        target_host: 'gpt-5.5',
        provider: 'third_party',
        provider_cn: '第三方',
        access_type: 'llm',
        status: 'success',
        status_code: 200,
        response_bytes: 1024,
        tls_inspected: true,
        retention_level: 'content',
        content_retained: true,
        risk_state: 'risk',
        risk_reasons: ['agent_behavior'],
        action_taken: 'audit',
        security_event_count: 1,
        disposition_status: 'open',
      }] : [], total: params?.risk_state === 'risk' ? 1 : 0 },
    } as any))

    renderPage()

    expect(await screen.findByText('content-older-high')).toBeInTheDocument()
    expect(screen.queryByText('retained-newer-low')).not.toBeInTheDocument()
  })

  it('keeps audit-only security evidence out of security alerts even when severity is high', async () => {
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({
      data: { data: [{
        session_id: 'audit-only-high-001',
        start_time: '2026-08-28T04:00:00Z',
        highest_severity: 'high',
        risk_categories: ['code_ssrf_generation', 'agent_openai_codex'],
        security_event_count: 22,
        actionable_alert_count: 0,
        matched_rule_count: 22,
      }], total: 1 },
    } as any)

    renderPage('/security/alerts')

    expect(await screen.findByText('暂无安全告警')).toBeInTheDocument()
    expect(screen.queryByText('audit-only-high-001')).not.toBeInTheDocument()
  })

  it('does not resurrect a pure agent behavior from retained access data', async () => {
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({ data: { data: [], total: 0 } } as any)
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [{
        request_id: 'agent-policy-alert-001',
        created_at: '2026-08-06T01:24:02Z',
        risk_state: 'risk',
        risk_reasons: ['agent_behavior'],
        action_taken: 'audit',
        security_event_count: 1,
        actionable_alert_count: 1,
      }], total: 1 },
    } as any)

    renderPage()

    expect(await screen.findByText('暂无安全告警')).toBeInTheDocument()
    expect(screen.queryByText('agent-po...t-001')).not.toBeInTheDocument()
  })

  it('searches alert retained evidence only after the keyword is submitted', async () => {
    renderPage()
    await screen.findByText('安全告警记录')

    const input = screen.getByPlaceholderText('搜索告警留证正文')
    fireEvent.change(input, { target: { value: '  登录失败  ' } })
    const keywordCallsBeforeSubmit = (api.contentAuditApi.list as any).mock.calls.filter(([params]: any[]) => params?.keyword)
    expect(keywordCallsBeforeSubmit).toHaveLength(0)
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter', charCode: 13 })

    await waitFor(() => expect(api.contentAuditApi.list).toHaveBeenCalledWith(expect.objectContaining({
      alert_only: true,
      keyword: '登录失败',
      limit: 20,
      offset: 0,
    })))
  })

  it('renders only the active session mode result while the alert list is cached', async () => {
    vi.mocked(api.contentAuditApi.list).mockImplementation(async (params: any) => ({
      data: {
        data: params.session_id
          ? [{ id: 'session-row', role: 'user', content: '当前会话结果', created_at: '2026-09-08T00:01:00Z' }]
          : [{ session_id: 'cached-alert', start_time: '2026-09-08T00:00:00Z', actionable_alert_count: 1 }],
        total: 1,
      },
    } as any))

    renderPage()
    expect(await screen.findByText('cached-alert')).toBeInTheDocument()
    const mode = screen.getByRole('combobox', { name: '告警视图' })
    fireEvent.mouseDown(mode!)
    fireEvent.click(await screen.findByText('指定请求/会话ID'))
    const sessionInput = screen.getByPlaceholderText('输入请求或会话 ID')
    fireEvent.change(sessionInput, { target: { value: 'session-current' } })
    fireEvent.keyDown(sessionInput, { key: 'Enter', code: 'Enter', charCode: 13 })

    expect(await screen.findByText('当前会话结果')).toBeInTheDocument()
    expect(screen.queryByText('cached-alert')).not.toBeInTheDocument()
  })

  it('submits a session identifier explicitly and forwards the query abort signal', async () => {
    renderPage()
    const mode = screen.getByRole('combobox', { name: '告警视图' })
    fireEvent.mouseDown(mode!)
    fireEvent.click(await screen.findByText('指定请求/会话ID'))
    const sessionInput = screen.getByPlaceholderText('输入请求或会话 ID')
    fireEvent.change(sessionInput, { target: { value: '  session-stable  ' } })

    expect(vi.mocked(api.contentAuditApi.list).mock.calls.filter(([params]: any[]) => params?.session_id)).toHaveLength(0)
    fireEvent.keyDown(sessionInput, { key: 'Enter', code: 'Enter', charCode: 13 })

    await waitFor(() => {
      const sessionCall = vi.mocked(api.contentAuditApi.list).mock.calls.find(([params]: any[]) => params?.session_id)
      expect(sessionCall?.[0]).toEqual(expect.objectContaining({
        session_id: 'session-stable',
        signal: expect.any(AbortSignal),
      }))
    })
  })

  it('loads the scoped user selector remotely and combines committed alert filters', async () => {
    const selectorSpy = vi.spyOn(api.contentAuditApi, 'listUsers').mockResolvedValue({
      data: {
        data: [{ id: 'user-remote', username: '张三', identity_kind: 'key_owner', department_id: 'dept-a', department_name: '研发部' }],
        limit: 50,
        offset: 0,
        has_more: false,
        next_cursor: '',
      },
    } as any)
    const globalUsersSpy = vi.spyOn(api.userApi, 'list')

    renderPage('/security/alerts?risk_category=prompt_injection')
    const userSelector = await screen.findByRole('combobox', { name: 'Key 归属筛选' })
    fireEvent.change(userSelector, { target: { value: '张' } })
    await new Promise((resolve) => window.setTimeout(resolve, 350))
    expect(selectorSpy.mock.calls.filter(([params]: any[]) => params?.q)).toHaveLength(0)
    fireEvent.keyDown(userSelector, { key: 'Enter', code: 'Enter', isComposing: true })
    expect(selectorSpy.mock.calls.filter(([params]: any[]) => params?.q)).toHaveLength(0)
    fireEvent.keyDown(userSelector, { key: 'Enter', code: 'Enter', charCode: 13 })

    await waitFor(() => expect(selectorSpy).toHaveBeenCalledWith(expect.objectContaining({
      q: '张',
      limit: 50,
      signal: expect.any(AbortSignal),
    })), { timeout: 1000 })
    expect(globalUsersSpy).not.toHaveBeenCalled()

    fireEvent.click(await screen.findByText('张三 · 研发部'))
    const keywordInput = screen.getByPlaceholderText('搜索告警留证正文')
    fireEvent.change(keywordInput, { target: { value: '凭据外发' } })
    fireEvent.keyDown(keywordInput, { key: 'Enter', code: 'Enter', charCode: 13 })

    const advanced = screen.getByRole('button', { name: /高级筛选/ })
    fireEvent.click(advanced)
    const severityPlaceholder = await screen.findByText('风险等级')
    fireEvent.mouseDown(severityPlaceholder.closest('.ant-select-selector')!)
    fireEvent.click(await screen.findByText('高危'))


    await waitFor(() => expect(api.contentAuditApi.list).toHaveBeenCalledWith(expect.objectContaining({
      alert_only: true,
      user_id: 'user-remote',
      keyword: '凭据外发',
      category: 'prompt_injection',
      severity: 'high',
      offset: 0,
      signal: expect.any(AbortSignal),
    })))
  })

  it('exports with the exact frozen window used by the visible alert list', async () => {
    vi.mocked(api.contentAuditApi.list).mockResolvedValue({
      data: {
        data: [{ session_id: 'session-export', start_time: '2026-09-08T00:00:00Z', actionable_alert_count: 1 }],
        total: 1,
      },
    } as any)
    const exportSpy = vi.spyOn(api.contentAuditApi, 'export').mockResolvedValue({ data: '{}' } as any)

    renderPage('/security/alerts?window_hours=4320')
    await screen.findByText('session-export')
    const listWindow = vi.mocked(api.contentAuditApi.list).mock.calls.find(([params]) => params.alert_only)?.[0]
    fireEvent.click(screen.getByRole('button', { name: /导出/ }))

    await waitFor(() => expect(exportSpy).toHaveBeenCalledWith('session-export', 'json', {
      from: listWindow?.from,
      to: listWindow?.to,
    }))
  })

  it('marks narrow-screen controls with responsive layout hooks', async () => {
    renderPage()
    await screen.findByText('安全告警明细')
    expect(screen.getByPlaceholderText('搜索告警留证正文').closest('.content-audit-keyword-search')).not.toBeNull()
  })

  it('keeps content searches and detail actions unavailable to department managers', async () => {
    useAuthStore.setState({
      token: 'dept-token',
      user: { id: 'manager-a', username: 'manager', role: 'dept_manager', tenant_id: 'tenant-a' },
      isAuthenticated: true,
    })
    vi.mocked(api.contentAuditApi.list).mockResolvedValue({
      data: {
        data: [{ session_id: 'dept-alert', start_time: '2026-09-08T00:00:00Z', actionable_alert_count: 1 }],
        total: 1,
        has_more: false,
      },
    } as any)
    const detailSpy = vi.spyOn(api.contentAuditApi, 'getSession').mockResolvedValue({
      data: { data: [], total: 0, limit: 20, offset: 0, has_more: false },
    } as any)

    renderPage()
    await waitFor(() => expect(alertOccurrencesApi.list).toHaveBeenCalled())
    expect(screen.getByRole('combobox', { name: '用户筛选' })).toBeInTheDocument()
    expect(screen.queryByPlaceholderText('搜索告警留证正文')).not.toBeInTheDocument()
    expect(screen.queryByText('指定请求/会话ID')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /查看/ })).not.toBeInTheDocument()
    expect(detailSpy).not.toHaveBeenCalled()
  })

  it('allows auditors to search authorized retained content', async () => {
    useAuthStore.setState({
      token: 'auditor-token',
      user: { id: 'auditor-a', username: 'auditor', role: 'auditor', tenant_id: 'tenant-a' },
      isAuthenticated: true,
    })

    renderPage()

    expect(await screen.findByPlaceholderText('搜索告警留证正文')).toBeInTheDocument()
    expect(screen.getByText('关联会话视图')).toBeInTheDocument()
  })

  // N3：安全员（security_officer）负责处置告警并复核证据（docs/design/ws4-rbac-matrix.md §1：
  // "Security policy, alert handling, evidence review"；evidence 类对安全员 Allow，后端 canReadFullTenantContentEvidence
  // 也含 security_officer）。前端原先手写的 canReadContent 白名单漏了它，安全员被挡在证据之外，
  // 页面还提示「当前权限仅可查看告警元数据」。
  it('lets security officers open alert evidence like the backend allows', async () => {
    useAuthStore.setState({
      token: 'officer-token',
      user: { id: 'officer-a', username: 'officer', role: 'security_officer', tenant_id: 'tenant-a' },
      isAuthenticated: true,
    })

    renderPage()

    expect(await screen.findByPlaceholderText('搜索告警留证正文')).toBeInTheDocument()
    expect(screen.getByText('关联会话视图')).toBeInTheDocument()
  })

  it('keeps evidence unavailable to roles the backend does not grant it to', async () => {
    for (const role of ['dept_manager', 'developer', 'viewer']) {
      useAuthStore.setState({
        token: `${role}-token`,
        user: { id: `${role}-a`, username: role, role, tenant_id: 'tenant-a' },
        isAuthenticated: true,
      })
      const { unmount } = renderPage()
      await waitFor(() => expect(alertOccurrencesApi.list).toHaveBeenCalled())
      expect(screen.queryByPlaceholderText('搜索告警留证正文')).not.toBeInTheDocument()
      unmount()
    }
  })

  it('按链接传入的风险类型筛选记录，并显示同步统计', async () => {
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({
      data: { data: [
        { session_id: 'prompt-risk-001', start_time: '2026-07-29T01:00:00Z', risk_categories: ['prompt_injection'], security_event_count: 2, actionable_alert_count: 2, matched_rule_count: 3 },
        { session_id: 'data-risk-001', start_time: '2026-07-29T00:00:00Z', risk_categories: ['pii_email'], security_event_count: 1, actionable_alert_count: 1, matched_rule_count: 1 },
      ], total: 2 },
    } as any)

    renderPage('/security/alerts?risk_category=prompt_injection')

    expect(await screen.findByText('已按 Prompt 注入 筛选')).toBeInTheDocument()
    await waitFor(() => expect(api.contentAuditApi.list).toHaveBeenCalledWith(expect.objectContaining({
      alert_only: true,
      category: 'prompt_injection',
    })))
    expect(screen.getByTestId('content-audit-filtered-stats')).toHaveTextContent('筛选已在服务端分页前应用')
  })

  it('builds keyword-only customer sensitive rule payload by default', () => {
    const payload = buildSensitiveRulePayload({
      match_mode: 'keyword',
      name: '客户项目代号',
      keywords: '星河计划\nAlpha-7, 内部报价',
      category: 'customer_sensitive_data',
      severity: 'high',
    })

    expect(payload).toEqual({
      name: '客户项目代号',
      keywords: ['星河计划', 'Alpha-7', '内部报价'],
      field_names: [],
      category: 'customer_sensitive_data',
      severity: 'high',
      action: 'audit',
    })
    expect(payload).not.toHaveProperty('regex')
  })

  it('builds field-name and regex payloads for customer sensitive rules', () => {
    expect(buildSensitiveRulePayload({
      match_mode: 'field_name',
      name: '客户合同字段',
      field_names: 'contract_amount\ncustomer_name',
      severity: 'medium',
    })).toEqual({
      name: '客户合同字段',
      keywords: [],
      field_names: ['contract_amount', 'customer_name'],
      category: 'customer_sensitive_data',
      severity: 'medium',
      action: 'audit',
    })

    expect(buildSensitiveRulePayload({
      match_mode: 'regex',
      name: '合同编号',
      regex: 'HT-2026-[0-9]{6}',
      action: 'block',
    })).toEqual({
      name: '合同编号',
      regex: 'HT-2026-[0-9]{6}',
      keywords: [],
      field_names: [],
      category: 'customer_sensitive_data',
      severity: 'high',
      action: 'block',
    })
  })
})
