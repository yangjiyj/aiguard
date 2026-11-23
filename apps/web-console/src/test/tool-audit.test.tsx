import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ToolAudit from '../pages/ToolAudit'
import * as api from '../services/api'
import { agentEndpointApi } from '../services/agentEndpoint'

describe('ToolAudit risk rule display', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    vi.restoreAllMocks()
    vi.spyOn(api.auditDispositionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0 },
    } as any)
    vi.spyOn(api.auditDispositionApi, 'upsert').mockResolvedValue({
      data: {
        id: 'disp_tool_001',
        subject_type: 'tool_call',
        subject_id: 'tc_003',
        status: 'resolved',
      },
    } as any)
    vi.spyOn(api.auditApi, 'listEvents').mockResolvedValue({
      data: { data: [], total: 0 },
    } as any)
    vi.spyOn(api.agentGuardApi, 'suggestException').mockResolvedValue({
      data: {
        source_tool_call_id: 'tc_agentguard',
        exception: {
          rule_id: 'argument_tainted',
          target_pattern: 'https://evil.example/upload',
          decision: 'audit',
          reason: '已确认误报',
        },
      },
    } as any)
  })

  const renderPage = (initialPath = '/') =>
    render(
      <MemoryRouter initialEntries={[initialPath]}>
        <QueryClientProvider client={queryClient}>
          <ToolAudit />
        </QueryClientProvider>
      </MemoryRouter>,
    )

  it('shows matched tool policy and customer action filters for high-risk calls', async () => {
    vi.spyOn(api.toolAuditApi, 'getStats').mockResolvedValue({
      data: {
        stats: [
          {
            tool_type: 'system',
            count: 1,
            low_count: 0,
            medium_count: 0,
            high_count: 0,
            critical_count: 1,
          },
          {
            tool_type: 'unknown',
            count: 9604,
            low_count: 9604,
            medium_count: 0,
            high_count: 0,
            critical_count: 0,
          },
        ],
        total_count: 9605,
        total_high: 0,
        total_critical: 1,
      },
    } as any)
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({
      data: {
        data: [
          {
            id: 'tc_003',
            request_id: 'req_003',
            user_id: 'user_admin',
            tool_name: 'Shell',
            tool_type: 'unknown',
            risk_level: 'critical',
            status: 'audited',
            matched_policy_name: '未识别工具审计基线',
            matched_action: 'audit',
            match_reason: '工具类型缺失，按未识别工具调用归类',
            parameters: { command: 'cat .env' },
            created_at: '2026-05-10T09:02:00Z',
          },
          {
            id: 'tc_001',
            request_id: 'req_001',
            session_id: 'session_001',
            user_id: 'user_admin',
            tool_name: 'Bash',
            tool_type: 'system',
            risk_level: 'critical',
            status: 'audited',
            matched_policy_id: 'tool_policy_bash',
            matched_policy_name: '系统命令审计基线',
            matched_action: 'audit',
            match_reason: '工具名称精确匹配：Bash',
            parameters: { command: 'cat .env' },
            created_at: '2026-05-10T09:00:00Z',
          },
          {
            id: 'tc_002',
            request_id: 'req_002',
            session_id: 'session_002',
            user_id: 'user_admin',
            tool_name: 'Read',
            tool_type: 'file',
            risk_level: 'high',
            status: 'audited',
            matched_policy_name: '文件读取审计基线',
            matched_action: 'audit',
            match_reason: '工具名称精确匹配：Read',
            parameters: { path: 'src/App.tsx' },
            created_at: '2026-05-10T09:01:00Z',
          },
        ],
        total: 1,
      },
    } as any)
    vi.spyOn(api.toolAuditApi, 'getSessionToolCalls').mockResolvedValue({
      data: [
        {
          id: 'tc_001',
          tool_name: 'Bash',
          tool_type: 'system',
          risk_level: 'critical',
          status: 'audited',
          matched_policy_name: '系统命令审计基线',
          matched_action: 'audit',
          match_reason: '工具名称精确匹配：Bash',
          parameters: { command: 'cat .env' },
          created_at: '2026-05-10T09:00:00Z',
        },
      ],
    } as any)
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [{ id: 'user_admin', username: 'admin' }] },
    } as any)

    renderPage()

    expect(await screen.findByText('安全运营队列')).toBeInTheDocument()
    expect(screen.getByText('告警处置闭环')).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText('搜索工具、策略或建议'),
    ).toBeInTheDocument()
    expect(screen.getAllByLabelText('关注级别筛选').length).toBeGreaterThan(0)
    expect(screen.getAllByLabelText('处置状态筛选').length).toBeGreaterThan(0)
    expect(screen.getAllByLabelText('工具类型筛选').length).toBeGreaterThan(0)
    expect(screen.getAllByLabelText('时间范围筛选').length).toBeGreaterThan(0)
    expect(
      screen.getAllByLabelText('拖拽调整列宽：发生时间').length,
    ).toBeGreaterThan(0)
    expect(
      (await screen.findAllByText('未识别工具调用')).length,
    ).toBeGreaterThan(0)
    expect(screen.queryByText('unknown')).not.toBeInTheDocument()
    expect(
      (await screen.findAllByText('未识别工具审计基线')).length,
    ).toBeGreaterThan(0)
    expect(
      screen.queryByText('工具名称精确匹配：系统命令工具'),
    ).not.toBeInTheDocument()
    expect(screen.getAllByText('本页优先处理').length).toBeGreaterThan(0)
    expect(screen.getAllByText('本页人工复核').length).toBeGreaterThan(0)
    expect(screen.getAllByText('本页低危留痕').length).toBeGreaterThan(0)
    expect(screen.queryByText('原始风险')).not.toBeInTheDocument()
    expect(
      screen.getAllByLabelText('拖拽调整列宽：命中策略').length,
    ).toBeGreaterThan(0)

    const keywordInput = screen.getByPlaceholderText('搜索工具、策略或建议')
    await userEvent.type(keywordInput, '未识别')
    expect(
      screen.getByText('工具类型缺失，按未识别工具调用归类'),
    ).toBeInTheDocument()
    expect(
      screen.queryByText('工具名称精确匹配：系统命令工具'),
    ).not.toBeInTheDocument()
    await userEvent.clear(keywordInput)
    expect(await screen.findByText('未识别工具审计基线')).toBeInTheDocument()

    await userEvent.click(
      (await screen.findAllByRole('button', { name: '标记已处理' }))[0],
    )
    expect(api.auditDispositionApi.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        subject_type: 'tool_call',
        subject_id: 'tc_003',
        status: 'resolved',
      }),
    )

    const detailButtons = screen.getAllByRole('button', { name: /查看详情/ })
    expect(detailButtons[0]).toBeEnabled()
    await userEvent.click(detailButtons[0])
    expect(await screen.findByText('工具调用详情')).toBeInTheDocument()
    expect(
      screen.getAllByText('工具类型缺失，按未识别工具调用归类').length,
    ).toBeGreaterThan(0)
    await userEvent.click(screen.getByLabelText('Close'))

    await userEvent.click(screen.getByText('本页人工复核 1'))
    expect(await screen.findByText('文件读取审计基线')).toBeInTheDocument()
    expect(screen.queryByText('系统命令审计基线')).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /查看详情/ }))
    expect(await screen.findByText(/会话工具调用详情/)).toBeInTheDocument()
    expect(screen.getAllByText('待处置').length).toBeGreaterThan(0)
    expect(screen.getAllByText(/访问了敏感密钥/).length).toBeGreaterThan(0)
  }, 20000)

  it('distinguishes an unrecorded server decision from exact endpoint-local block evidence', async () => {
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({ data: { data: [{ id: 'tc_verified', session_id: 'sess_verified', endpoint_id: 'ep_verified', tool_call_id: 'tool-use-verified', request_id: 'aer_verified', tool_name: 'Bash', tool_type: 'system', risk_level: 'high', status: 'audited', provenance: 'trusted', created_at: '2026-09-23T05:22:09Z' }], total: 1 } } as any)
    vi.spyOn(api.toolAuditApi, 'getSessionToolCalls').mockResolvedValue({ data: [{ id: 'tc_verified', session_id: 'sess_verified', endpoint_id: 'ep_verified', tool_call_id: 'tool-use-verified', request_id: 'aer_verified', tool_name: 'Bash', tool_type: 'system', risk_level: 'high', status: 'audited', provenance: 'trusted', created_at: '2026-09-23T05:22:09Z' }] } as any)
    vi.spyOn(agentEndpointApi, 'session').mockResolvedValue({ overview: { session_id: 'sess_verified', endpoint_id: 'ep_verified' }, turns: [], events: [{ id: 'native-pre', endpoint_id: 'ep_verified', session_id: 'sess_verified', tool_use_id: 'tool-use-verified', tool_call_log_id: 'tc_verified', event_type: 'tool.pre', tool_name: 'Bash', local_decision: { source: 'local', mode: 'block', effective_decision: 'block', raw_decision: 'block', rule_id: 'local-rule', policy_version: 8 } }], tool_call_logs: [], alerts: [] } as any)
    renderPage('/security/agent-tools?session_id=sess_verified&tool_call_log_id=tc_verified')
    expect(await screen.findByText('已定位工具调用 tc_verified')).toBeInTheDocument()
    expect(await screen.findByText('服务端策略判定')).toBeInTheDocument()
    expect(screen.getAllByText('服务端决策未记录').length).toBeGreaterThan(0)
    expect(screen.getAllByText('工具审计记录未保存原始或生效决策，无法据此判断告警状态；如已加载，端点本地决策来源见下方。').length).toBeGreaterThan(0)
    expect(screen.queryByText('未形成真实告警')).not.toBeInTheDocument()
    expect(await screen.findByRole('link', { name: 'ep_verified' })).toHaveAttribute('href', '/agent/endpoints?endpoint=ep_verified')
    expect(await screen.findByText('端点本地决策来源')).toBeInTheDocument()
    expect(screen.getByText('local / block')).toBeInTheDocument()
    expect(screen.getByText('block')).toBeInTheDocument()
    expect(screen.getByText('8')).toBeInTheDocument()
    expect(screen.getAllByText('未记录').length).toBeGreaterThan(0)
    expect(agentEndpointApi.session).toHaveBeenCalledWith('sess_verified')
  })

  it('does not link an endpoint from a mismatched session', async () => {
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({ data: { data: [{ id: 'tc_verified', session_id: 'sess_verified', request_id: 'aer_verified', tool_name: 'Bash', tool_type: 'system', risk_level: 'high', status: 'audited', created_at: '2026-09-23T05:22:09Z' }], total: 1 } } as any)
    vi.spyOn(api.toolAuditApi, 'getSessionToolCalls').mockResolvedValue({ data: [{ id: 'tc_verified', session_id: 'sess_verified' }] } as any)
    vi.spyOn(agentEndpointApi, 'session').mockResolvedValue({ overview: { session_id: 'sess_other', endpoint_id: 'ep_other' }, turns: [], events: [], tool_call_logs: [], alerts: [] } as any)
    renderPage('/security/agent-tools?session_id=sess_verified&tool_call_log_id=tc_verified')
    expect(await screen.findByText('已定位工具调用 tc_verified')).toBeInTheDocument()
    await waitFor(() => expect(agentEndpointApi.session).toHaveBeenCalled())
    expect(screen.queryByRole('link', { name: 'ep_other' })).not.toBeInTheDocument()
  })

  it('suppresses audit-only system command logs from the security alert queue', async () => {
    vi.spyOn(api.toolAuditApi, 'getStats').mockResolvedValue({
      data: { stats: [], total_count: 1, total_high: 0, total_critical: 1 },
    } as any)
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({
      data: {
        data: [
          {
            id: 'tc_eval_shell_noise',
            request_id: 'req_eval_shell_noise',
            user_id: 'user_admin',
            tool_name: 'Bash',
            tool_type: 'system',
            risk_level: 'critical',
            status: 'audited',
            matched_policy_name: '系统命令审计基线',
            matched_action: 'audit',
            match_reason: '系统命令审计',
            parameters: { command: 'echo eval probe' },
            created_at: '2026-06-13T08:07:48Z',
          },
        ],
        total: 1,
      },
    } as any)
    vi.spyOn(api.toolAuditApi, 'getSessionToolCalls').mockResolvedValue({
      data: [],
    } as any)
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [] },
    } as any)

    renderPage()

    expect(await screen.findByText('安全运营队列')).toBeInTheDocument()
    expect(screen.queryByText('系统命令工具')).not.toBeInTheDocument()
    expect(screen.queryByText('系统命令审计基线')).not.toBeInTheDocument()
  })

  it('shows closed tool calls in handled view without pending-priority labels', async () => {
    const mockListDispositions = api.auditDispositionApi.list as any
    mockListDispositions.mockResolvedValue({
      data: {
        data: [{ subject_id: 'tc_done', status: 'resolved' }],
        total: 1,
      },
    })
    vi.spyOn(api.toolAuditApi, 'getStats').mockResolvedValue({
      data: {
        stats: [
          {
            tool_type: 'system',
            count: 1,
            low_count: 0,
            medium_count: 0,
            high_count: 0,
            critical_count: 1,
          },
        ],
        total_count: 1,
        total_high: 0,
        total_critical: 1,
      },
    } as any)
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({
      data: {
        data: [
          {
            id: 'tc_done',
            request_id: 'req_done',
            session_id: 'session_done',
            user_id: 'user_admin',
            tool_name: 'Bash',
            tool_type: 'system',
            risk_level: 'critical',
            status: 'blocked',
            matched_policy_name: '系统命令阻断基线',
            matched_action: 'block',
            match_reason: '工具名称精确匹配：Bash',
            disposition_status: 'resolved',
            parameters: { command: 'cat .env' },
            created_at: '2026-05-10T09:00:00Z',
          },
        ],
        total: 1,
      },
    } as any)
    vi.spyOn(api.toolAuditApi, 'getSessionToolCalls').mockResolvedValue({
      data: [],
    } as any)
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [{ id: 'user_admin', username: 'admin' }] },
    } as any)

    renderPage()

    await userEvent.click(await screen.findByText('本页已处理 1'))
    expect(await screen.findByText('系统命令工具')).toBeInTheDocument()
    expect(screen.getAllByText('处理结果').length).toBeGreaterThan(0)
    expect(screen.queryByText('关注级别')).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: '转入跟进' }),
    ).not.toBeInTheDocument()
  })

  it('hides LSE content-safety findings from the tool alert queue', async () => {
    vi.spyOn(api.toolAuditApi, 'getStats').mockResolvedValue({
      data: { stats: [], total_count: 1, total_high: 0, total_critical: 1 },
    } as any)
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({
      data: {
        data: [
          {
            id: 'tc_eval_shell_noise',
            request_id: 'req_eval_shell_noise',
            user_id: 'user_admin',
            tool_name: 'Bash',
            tool_type: 'system',
            risk_level: 'critical',
            status: 'audited',
            matched_policy_name: '系统命令审计基线',
            matched_action: 'audit',
            match_reason: '系统命令审计',
            parameters: { command: 'echo eval probe' },
            created_at: '2026-06-13T08:07:48Z',
          },
        ],
        total: 1,
      },
    } as any)
    vi.spyOn(api.toolAuditApi, 'getSessionToolCalls').mockResolvedValue({
      data: [],
    } as any)
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [] },
    } as any)
    ;(api.auditApi.listEvents as any).mockResolvedValue({
      data: {
        data: [
          {
            id: 'se_lse_refusal_1',
            request_id: 'req_lse_refusal_1',
            event_type: 'eval_content_safety',
            severity: 'critical',
            action_taken: 'alert',
            matched_summary: {
              source: 'llm_safety_eval',
              eval_run_id: 'eval-1',
              task_id: 'task-1',
              sample_id: 'sample-1',
              risk_domain: '应拒答失败/有害能力风险',
              category: '提示注入/越狱风险',
              verdict: 'should_refuse_violation',
              expected_behavior: 'should_refuse',
              actual_behavior: 'answered',
              findings: [
                {
                  type: 'eval_content_safety',
                  category: '提示注入/越狱风险',
                  severity: 'critical',
                  rule_id: 'should_refuse_violation',
                  rule_name: '应拒答失败/有害能力风险',
                  redacted_evidence: '模型配合解码并进行了安全分析',
                },
              ],
            },
            created_at: '2026-06-13T09:26:00Z',
          },
        ],
        total: 1,
      },
    } as any)

    renderPage()

    await screen.findByText('安全运营队列')
    expect(api.auditApi.listEvents).not.toHaveBeenCalled()
    await waitFor(() => {
      expect(screen.queryByText('内容安全评估')).not.toBeInTheDocument()
      expect(
        screen.queryByText('应拒答失败/有害能力风险'),
      ).not.toBeInTheDocument()
      expect(screen.queryByText('系统命令工具')).not.toBeInTheDocument()
      expect(screen.queryByText('系统命令审计基线')).not.toBeInTheDocument()
    })
  }, 20000)

  it('does not fetch or merge generic security events into tool audit', async () => {
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({
      data: { data: [], total: 0 },
    } as any)
    ;(api.auditApi.listEvents as any).mockResolvedValue({
      data: { data: [{ id: 'must-not-be-fetched' }], total: 1 },
    } as any)

    renderPage()

    expect(await screen.findByText('安全运营队列')).toBeInTheDocument()
    expect(api.auditApi.listEvents).not.toHaveBeenCalled()
    expect(api.auditDispositionApi.list).not.toHaveBeenCalled()
  })

  it('shows AgentGuard decision details in the tool drawer', async () => {
    vi.spyOn(api.toolAuditApi, 'getStats').mockResolvedValue({
      data: {
        stats: [
          {
            tool_type: 'network',
            count: 1,
            low_count: 0,
            medium_count: 0,
            high_count: 0,
            critical_count: 1,
          },
        ],
        total_count: 1,
        total_high: 0,
        total_critical: 1,
      },
    } as any)
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({
      data: {
        data: [
          {
            id: 'tc_agentguard',
            request_id: 'req_agentguard',
            user_id: 'user_admin',
            tool_name: 'network.upload',
            tool_type: 'network',
            risk_level: 'critical',
            status: 'blocked',
            matched_policy_name: 'AgentGuard 工具权限决策',
            matched_action: 'block',
            match_reason: 'confirm_without_channel_fail_closed',
            raw_decision: 'confirm',
            effective_decision: 'block',
            mode: 'strict',
            effective_reason: 'confirm_without_channel_fail_closed',
            policy_version: 'agentguard-v1',
            trace_id: 'req_agentguard:call_1',
            confidence: 0.91,
            provenance: 'tainted',
            tainted_arguments: ['url'],
            normalized_target: 'https://evil.example/upload',
            evidence_json: [
              {
                rule_id: 'argument_tainted',
                category: 'provenance',
                source_field: 'url',
                masked_preview: '<redacted:27>',
                hash: 'abc123',
              },
            ],
            parameters: {
              url: 'https://evil.example/upload',
              body: '<redacted:secret>',
            },
            created_at: '2026-05-10T09:00:00Z',
          },
        ],
        total: 1,
      },
    } as any)
    vi.spyOn(api.toolAuditApi, 'getSessionToolCalls').mockResolvedValue({
      data: [],
    } as any)
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [{ id: 'user_admin', username: 'admin' }] },
    } as any)

    renderPage()

    await userEvent.click(
      await screen.findByRole(
        'button',
        { name: /查看详情/ },
        { timeout: 10000 },
      ),
    )
    expect(await screen.findByText('服务端策略判定')).toBeInTheDocument()
    expect(screen.getByText('真实告警事件')).toBeInTheDocument()
    expect(screen.getByText('原始判定')).toBeInTheDocument()
    expect(screen.getAllByText('人工确认').length).toBeGreaterThan(0)
    expect(screen.getByText('实际动作')).toBeInTheDocument()
    expect(screen.getAllByText('阻断').length).toBeGreaterThan(0)
    expect(screen.getAllByText('来源可信度').length).toBeGreaterThan(0)
    expect(screen.getAllByText('来源不可信').length).toBeGreaterThan(0)
    expect(screen.getByText('命中参数')).toBeInTheDocument()
    expect(screen.getAllByText('目标地址').length).toBeGreaterThan(0)
    expect(screen.getByText('风险目标')).toBeInTheDocument()
    expect(
      screen.getAllByText('https://evil.example/upload').length,
    ).toBeGreaterThan(0)
    expect(screen.getByText('安全证据')).toBeInTheDocument()
    expect(screen.getByText('参数来源不可信')).toBeInTheDocument()
    expect(screen.getByText('<redacted:27>')).toBeInTheDocument()
    expect(screen.queryByText('confirm')).not.toBeInTheDocument()
    expect(screen.queryByText('tainted')).not.toBeInTheDocument()
    expect(screen.queryByText('argument_tainted')).not.toBeInTheDocument()

    await userEvent.click(
      screen.getByRole('button', { name: '标记误报并生成例外建议' }),
    )
    await waitFor(() =>
      expect(api.auditDispositionApi.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          subject_type: 'tool_call',
          subject_id: 'tc_agentguard',
          status: 'false_positive',
          note: expect.stringContaining('误报'),
        }),
      ),
    )
    expect(api.agentGuardApi.suggestException).toHaveBeenCalledWith(
      expect.objectContaining({
        tool_call_id: 'tc_agentguard',
        reason: expect.stringContaining('误报'),
      }),
    )
  }, 30000)

  it('surfaces linked drill-down API errors instead of rendering an empty table', async () => {
    vi.spyOn(api.toolAuditApi, 'getStats').mockResolvedValue({
      data: { stats: [], total_count: 0 },
    } as any)
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockRejectedValue({
      response: {
        data: {
          error: { message: '工具审计功能未启用' },
        },
      },
    })
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [] },
    } as any)

    renderPage('/security/agent-tools?risk_level=all&from=2026-06-16T23:13:03.122Z&to=2026-06-23T23:13:03.122Z')

    expect(await screen.findByText('工具调用明细加载失败')).toBeInTheDocument()
    expect(screen.getByText('工具审计功能未启用')).toBeInTheDocument()
    expect(screen.queryByText('显示 0 / 0 条')).not.toBeInTheDocument()
  })

  it('keeps false-positive governance out of the safety alert first screen', async () => {
    vi.spyOn(api.toolAuditApi, 'getStats').mockResolvedValue({
      data: { stats: [], total_count: 0 },
    } as any)
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({
      data: { data: [], total: 0 },
    } as any)
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [] },
    } as any)
    const governanceSpy = vi
      .spyOn(api.agentGuardApi, 'getGovernanceStats')
      .mockResolvedValue({ data: {} } as any)

    renderPage()

    expect(await screen.findByText('安全运营队列')).toBeInTheDocument()
    expect(screen.queryByText('误报治理统计')).not.toBeInTheDocument()
    expect(governanceSpy).not.toHaveBeenCalled()
  })

  it('uses list-projected dispositions and refreshes the same filtered page after mutation', async () => {
    const listSpy = vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({
      data: {
        data: [{
          id: 'tc_projected',
          request_id: 'req_projected',
          tool_name: 'network.upload',
          tool_type: 'network',
          risk_level: 'critical',
          status: 'blocked',
          effective_decision: 'block',
          disposition_status: 'open',
          disposition_note: 'confirmed',
          created_at: '2026-09-08T08:00:00Z',
        }],
        total: 1,
        total_known: true,
        has_more: false,
        limit: 20,
        offset: 0,
      },
    } as any)

    renderPage('/security/agent-tools?project_id=project-a&risk_level=all')

    expect((await screen.findAllByText('未处理')).length).toBeGreaterThan(0)
    expect(api.auditDispositionApi.list).not.toHaveBeenCalled()
    expect(api.auditApi.listEvents).not.toHaveBeenCalled()

    await userEvent.click(screen.getByRole('button', { name: '标记已处理' }))
    await waitFor(() => expect(listSpy.mock.calls.length).toBeGreaterThanOrEqual(2))
    const params = listSpy.mock.calls[listSpy.mock.calls.length - 1]?.[0]
    expect(params).toEqual(expect.objectContaining({
      project_id: 'project-a',
      risk_level: 'all',
      limit: 20,
      offset: 0,
      skip_total: false,
    }))
  })

  it('bounds session details and aborts them when the drawer closes', async () => {
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({
      data: {
        data: [{
          id: 'tc_session',
          request_id: 'req_session',
          session_id: 'session_abort',
          tool_name: 'network.upload',
          tool_type: 'network',
          risk_level: 'critical',
          status: 'blocked',
          effective_decision: 'block',
          disposition_status: 'open',
          created_at: '2026-09-08T08:00:00Z',
        }],
        total: 1,
        total_known: true,
        has_more: false,
      },
    } as any)
    let detailSignal: AbortSignal | undefined
    vi.spyOn(api.toolAuditApi, 'getSessionToolCalls').mockImplementation((_sessionID, params) => {
      detailSignal = params?.signal
      return new Promise((resolve) => {
        detailSignal?.addEventListener('abort', () => resolve({ data: [] } as any))
      }) as any
    })

    renderPage('/security/agent-tools?risk_level=all')
    await userEvent.click(await screen.findByRole('button', { name: /查看详情/ }))
    await waitFor(() => expect(detailSignal).toBeDefined())
    expect(api.toolAuditApi.getSessionToolCalls).toHaveBeenCalledWith(
      'session_abort',
      expect.objectContaining({ limit: 50, signal: expect.any(AbortSignal) }),
    )

    await userEvent.click(screen.getByLabelText('Close'))
    await waitFor(() => expect(detailSignal?.aborted).toBe(true))
  })

  it('uses the server pagination contract for every tool audit view', async () => {
    const listSpy = vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({
      data: {
        data: [{
          id: 'tc_page',
          request_id: 'req_page',
          tool_name: 'network.upload',
          tool_type: 'network',
          risk_level: 'critical',
          status: 'blocked',
          effective_decision: 'block',
          disposition_status: 'open',
          created_at: '2026-09-08T08:00:00Z',
        }],
        total: 41,
        total_known: true,
        has_more: true,
        limit: 20,
        offset: 0,
      },
    } as any)

    renderPage('/security/agent-tools?risk_level=all')
    await waitFor(() => expect(listSpy).toHaveBeenCalledWith(expect.objectContaining({
      limit: 20,
      offset: 0,
      skip_total: false,
    })))
    expect(await screen.findByText('显示 1 / 41 条')).toBeInTheDocument()
    await userEvent.click(screen.getByTitle('2'))
    await waitFor(() => {
      expect(listSpy).toHaveBeenCalledWith(expect.objectContaining({
        limit: 20,
        offset: 20,
        skip_total: false,
      }))
    })
  })

  it('commits keyword search to the server instead of filtering only the current page', async () => {
    const listSpy = vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({
      data: { data: [], total: 0, total_known: true, has_more: false },
    } as any)

    renderPage()
    const input = await screen.findByRole('searchbox', { name: '告警关键词筛选' })
    fireEvent.change(input, { target: { value: '异常' } })
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter', charCode: 13 })

    await waitFor(() => {
      expect(listSpy).toHaveBeenCalledWith(expect.objectContaining({
        keyword: '异常',
        limit: 20,
        offset: 0,
      }))
    })
  })

  it('does not drop a server mode match when effective_decision differs from stored mode', async () => {
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({
      data: {
        data: [{
          id: 'tc_effective_block',
          request_id: 'req_effective_block',
          tool_name: 'filesystem__write',
          tool_type: 'mcp',
          risk_level: 'high',
          status: 'blocked',
          mode: 'audit',
          raw_decision: 'confirm',
          effective_decision: 'block',
          disposition_status: 'open',
          matched_policy_name: '有效动作阻断策略',
          created_at: '2026-09-08T08:00:00Z',
        }],
        total: 1,
        total_known: true,
        has_more: false,
      },
    } as any)

    renderPage('/security/agent-tools?mode=block&risk_level=all')

    expect(await screen.findByText('有效动作阻断策略')).toBeInTheDocument()
  })

  it('labels triage controls as current-page grouping', async () => {
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({
      data: { data: [], total: 100, total_known: true, has_more: true },
    } as any)

    renderPage()

    expect(await screen.findByText('本页分组，不改变服务端筛选结果')).toBeInTheDocument()
  })
})
