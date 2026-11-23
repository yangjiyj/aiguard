import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom'
import AccessRetention from '../pages/AccessRetention'
import * as api from '../services/api'

vi.mock('antd', async () => {
  const actual = await vi.importActual('antd')
  return {
    ...actual,
    message: {
      success: vi.fn(),
      warning: vi.fn(),
      error: vi.fn(),
    },
  }
})

function LocationProbe() {
  const location = useLocation()
  const navigate = useNavigate()
  return (
    <>
      <span data-testid="location-search">{location.search}</span>
      <button type="button" onClick={() => navigate(-1)}>测试浏览器后退</button>
    </>
  )
}

describe('AccessRetention page', () => {
  let queryClient: QueryClient
  let summarySpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    vi.clearAllMocks()
    summarySpy = vi.fn().mockResolvedValue({ data: {} })
    ;(api.accessRetentionApi as any).getSummary = summarySpy
    ;(api.accessRetentionApi as any).getArtifact = vi.fn().mockRejectedValue(new Error('artifact mock not configured'))
    vi.spyOn(api.contentAuditApi, 'listUsers').mockResolvedValue({
      data: {
        data: [{ id: 'user_42', username: '张三', department_name: '研发部' }],
        limit: 50,
        offset: 0,
        has_more: false,
      },
    } as any)
  })

  const renderPage = (initialPath = '/?view=requests') =>
    render(
      <MemoryRouter initialEntries={[initialPath]}>
        <QueryClientProvider client={queryClient}>
          <AccessRetention />
        </QueryClientProvider>
        <LocationProbe />
      </MemoryRouter>,
    )

  const openFirstDetail = async () => {
    const detailButton = await waitFor(
      () => screen.getByRole('button', { name: /详情/ }),
      { timeout: 10000 },
    )
    fireEvent.click(detailButton)
  }

  const mockCatalog = () => vi.spyOn(api.llmProviderCatalogApi, 'list').mockResolvedValue({
    data: {
      data: [
        { id: 'openai_chatgpt', provider: 'openai', provider_cn: 'OpenAI', product: 'chatgpt', product_cn: 'ChatGPT', category: 'chat', domains: ['chatgpt.com'], retain_level: 'content' },
        { id: 'deepseek_api', provider: 'deepseek', provider_cn: 'DeepSeek', product: 'deepseek_api', product_cn: 'DeepSeek API', category: 'api', domains: ['api.deepseek.com'], retain_level: 'content' },
        { id: 'doubao', provider: 'bytedance', provider_cn: '字节跳动', product: 'doubao', product_cn: '豆包', category: 'chat', domains: ['www.doubao.com'], retain_level: 'content' },
        { id: 'kimi', provider: 'moonshot', provider_cn: '月之暗面', product: 'kimi', product_cn: 'Kimi', category: 'chat', domains: ['www.kimi.com'], retain_level: 'content' },
        { id: 'yuanbao', provider: 'tencent', provider_cn: '腾讯', product: 'yuanbao', product_cn: '腾讯元宝', category: 'chat', domains: ['yuanbao.tencent.com'], retain_level: 'content' },
      ],
      providers: [
        { value: 'openai', label: 'OpenAI', count: 1 },
        { value: 'deepseek', label: 'DeepSeek', count: 1 },
        { value: 'bytedance', label: '字节跳动', count: 1 },
        { value: 'moonshot', label: '月之暗面', count: 1 },
        { value: 'tencent', label: '腾讯', count: 1 },
      ],
    },
    status: 200,
    statusText: 'OK',
    headers: {},
    config: {},
  } as any)

  const openAgentTaskWithAssistantMessages = async (
    contents: string[],
    userContent: string | string[] = '请给出 XML 示例',
    runTitle = '检查模型输出清洗',
  ) => {
    const userContents = Array.isArray(userContent) ? userContent : [userContent]
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'listRuns').mockResolvedValue({
      data: { data: [{
        run_id: 'evr-fenced-xml', kind: 'agent_task', correlation_source: 'content_hash_chain',
        correlation_confidence: 'derived', representative_request_id: 'req-fenced-xml', member_request_ids: ['req-fenced-xml'],
        title: runTitle, started_at: '2026-08-05T04:00:00Z', ended_at: '2026-08-05T04:01:00Z', duration_ms: 60000,
        agent_type: 'openai-codex', agent_label: 'OpenAI Codex', models: ['gpt-5.6-sol'], access_directions: ['chat_completion'],
        request_count: 1, tool_event_count: 0, input_artifact_count: 0, output_artifact_count: 0,
        evidence_status: 'complete', risk_state: 'normal',
      }], total: 1 }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req-fenced-xml', user_input: '', model_output: '', evidence_status: 'complete', artifacts: [], file_metadata: [],
        messages: [
          ...userContents.map((content, index) => ({
            id: `fenced-user-${index}`, request_id: 'req-fenced-xml', sequence: index + 1,
            role: 'user', kind: 'user_input', content,
          })),
          ...contents.map((content, index) => ({
            id: `fenced-assistant-${index}`, request_id: 'req-fenced-xml', sequence: userContents.length + index + 1,
            role: 'assistant', kind: 'model_output', content,
          })),
        ],
      }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getTimeline').mockResolvedValue({
      data: { data: [] }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)

    renderPage('/?view=agent_tasks')
    fireEvent.click(await screen.findByRole('button', { name: /查看任务/ }, { timeout: 10000 }))
    return screen.findAllByTestId('retained-message-assistant', {}, { timeout: 10000 })
  }

  const emptySummary = {
    total: 0,
    normal_count: 0,
    risk_count: 0,
    blocked_count: 0,
    llm_count: 0,
    ai_ide_count: 0,
    normal_public_count: 0,
    retained_content_count: 0,
    forward_count: 0,
    reverse_count: 0,
    device_count: 0,
    agent_request_count: 0,
    identified_agent_count: 0,
    unidentified_agent_count: 0,
    unique_model_count: 0,
    evidence_quality: {
      complete_count: 0,
      request_only_count: 0,
      response_only_count: 0,
      metadata_only_count: 0,
    },
    timeline: [],
    top_risk_categories: [],
    top_providers: [],
    top_targets: [],
    top_agents: [],
  }

  const expectDefaultListWindow = (params: any, days = 1, skipTotal = true) => {
    expect(params).toEqual(expect.objectContaining({
      limit: 20,
      offset: 0,
      skip_summary: true,
      skip_total: skipTotal,
    }))
    expect(typeof params.from).toBe('string')
    expect(typeof params.to).toBe('string')
    const fromTime = Date.parse(params.from)
    const toTime = Date.parse(params.to)
    expect(Number.isNaN(fromTime)).toBe(false)
    expect(Number.isNaN(toTime)).toBe(false)
    expect(toTime - fromTime).toBe(days * 24 * 60 * 60 * 1000)
  }

  const expectDetailWindow = (value: any, days = 1) => {
    expect(value).toEqual(expect.objectContaining({ from: expect.any(String), to: expect.any(String), signal: expect.any(AbortSignal) }))
    const fromTime = Date.parse(value.from)
    const toTime = Date.parse(value.to)
    expect(Number.isNaN(fromTime)).toBe(false)
    expect(Number.isNaN(toTime)).toBe(false)
    expect(toTime - fromTime).toBe(days * 24 * 60 * 60 * 1000)
  }

  it('shows LLM access retention records, catalog and SOC actions', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_forward_001',
            created_at: '2026-06-06T09:30:00Z',
            source_ip: '10.10.10.8',
            target_host: 'api.deepseek.com',
            target_path: '/v1/chat/completions',
            method: 'POST',
            provider: 'deepseek',
            provider_cn: 'DeepSeek',
            product: 'deepseek_api',
            product_cn: 'DeepSeek API',
            access_type: 'llm',
            endpoint_kind: 'api',
            path_template: '/v1/chat/completions',
            status: 'success',
            status_code: 200,
            response_bytes: 4096,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'risk',
            risk_reasons: ['bank_card_cn'],
            action_taken: 'audit',
            security_event_count: 1,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, risk_count: 1, llm_count: 1, retained_content_count: 1, data_fresh_until: '2026-06-18T13:00:00Z', top_providers: [{ name: 'deepseek', count: 1, risk_count: 1 }], top_targets: [{ name: 'api.deepseek.com', count: 1, risk_count: 1 }] },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.auditDispositionApi, 'upsert').mockResolvedValue({ data: { status: 'escalated' }, status: 200, statusText: 'OK', headers: {}, config: {} } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_forward_001',
        request_content:
          '[ref_file_ids] file-238c74b9-c8ed-4a86-8563-07b9b5fe656b\nb5415133-5636-432e-8fed-2441555982d8\ndefault\n咋说\n6d4f6f78-ab74-4cd0-8b33-ca2d9840f68f',
        response_content:
          'default\nASSISTANT\nWIP\nTHINK\n嗯，用户问“咋说”，这个问题非常简短，可能是在询问某个特定词语或句子的不同表达方式。\n回复应该友好，有帮助，并且以提问结束，请用户给出具体内容。\nSET RESPONSE “咋说”的意思是“怎么说”。\n\n可以这样表达：\n1. **询问表达方式**：这句话该怎么说？\n2. **反问或质疑**：他那样做还有理了？\nDEFAULT\nresponse/fragments/-1/content\nAPPEND',
        retention_until: '2026-09-01T00:00:00+08:00',
        file_metadata: [
          { source: 'json_file_reference', field_name: 'ref_file_ids', reference_id: 'file-238c74b9-c8ed-4a86-8563-07b9b5fe656b' },
          { source: 'multipart', field_name: 'file', file_name: 'patient-report.pdf', content_type: 'application/pdf', size: 2048, sha256: 'sha256-demo', text_preview: '患者报告正文预览：病历号 MR-2026-0001', findings: [{ category: 'custom_medical_record', rule_name: '病历号识别', action: 'alert' }] },
        ],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()

    await waitFor(() => {
      expect(screen.getByText('内容留证')).toBeInTheDocument()
      expect(screen.getByText('留证内容')).toBeInTheDocument()
      expect(screen.getAllByText('大模型访问').length).toBeGreaterThan(0)
      // 本页仅聚焦大模型流量：普通公网访问标签/分页已移除，不应再出现。
      expect(screen.queryByText('普通公网访问')).not.toBeInTheDocument()
      expect(screen.getAllByText('DeepSeek API').length).toBeGreaterThan(0)
      expect(screen.getAllByText('已留证内容').length).toBeGreaterThan(0)
      expect(screen.getAllByText(/正文内容/).length).toBeGreaterThan(0)
      expect(screen.getByText(/数据更新至/)).toBeInTheDocument()
      expect(screen.queryByText(/rollup/i)).not.toBeInTheDocument()
      expect(screen.queryByText(/bucket/i)).not.toBeInTheDocument()
      expect(screen.getByText(/本页聚焦解密后可审计的客户内容、模型响应、文件引用与审计处置证据/)).toBeInTheDocument()
      expect(screen.getByText('审计线索：银行卡号')).toBeInTheDocument()
      expect(screen.queryByText('大模型与 AI 工具目录')).not.toBeInTheDocument()
      expect(screen.queryByText('服务商与目标聚合')).not.toBeInTheDocument()
      expect(screen.queryByText('全部访问')).not.toBeInTheDocument()
    })

    await openFirstDetail()

    await waitFor(() => {
      expect(screen.getByText('用户提问')).toBeInTheDocument()
      expect(screen.getByText('模型回答')).toBeInTheDocument()
      expect(screen.getByText('咋说')).toBeInTheDocument()
      expect(screen.queryByText('default')).not.toBeInTheDocument()
      expect(screen.queryByText('b5415133-5636-432e-8fed-2441555982d8')).not.toBeInTheDocument()
      const answerText = screen.getByTestId('retained-text-response').textContent || ''
      expect(answerText).toContain('“咋说”的意思是“怎么说”。')
      expect(answerText).toContain('1. 询问表达方式')
      expect(screen.getByText('询问表达方式', {selector:'strong'})).toBeInTheDocument()
      expect(answerText).not.toContain('用户问“咋说”')
      expect(answerText).not.toContain('回复应该友好')
      expect(answerText).not.toContain('SET RESPONSE')
      expect(screen.queryByText('我们需要')).not.toBeInTheDocument()
      expect(screen.queryByText('6d4f6f78-ab74-4cd0-8b33-ca2d9840f68f')).not.toBeInTheDocument()
      expect(screen.queryByText('response/fragments/-1/content')).not.toBeInTheDocument()
      expect(screen.getByText(/内容保留至/)).toBeInTheDocument()
      expect(screen.getByText('引用文件')).toBeInTheDocument()
      expect(screen.getByText('file-238c74b9-c8ed-4a86-8563-07b9b5fe656b')).toBeInTheDocument()
      expect(screen.getAllByText('上传文件').length).toBeGreaterThan(0)
      expect(screen.getByText('patient-report.pdf')).toBeInTheDocument()
      expect(screen.getByText('文件正文预览')).toBeInTheDocument()
      expect(screen.getByText(/病历号 MR-2026-0001/)).toBeInTheDocument()
      expect(screen.getByText('命中规则')).toBeInTheDocument()
      expect(screen.getByText('病历号识别')).toBeInTheDocument()
      expect(screen.queryByText(/本次问答由 4 条请求合并/)).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '合并展示' })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: /第 1 次/ })).not.toBeInTheDocument()
    })

    expect(api.accessRetentionApi.getContent).toHaveBeenCalledWith(
      'req_forward_001',
      undefined,
      expect.objectContaining({ from: expect.any(String), to: expect.any(String) }),
    )
    expectDetailWindow((api.accessRetentionApi.getContent as any).mock.calls[0][2])

    fireEvent.click(screen.getAllByRole('button', { name: '升级事件' })[0])

    await waitFor(() => {
      expect(api.auditDispositionApi.upsert).toHaveBeenCalledWith({
        subject_type: 'request',
        subject_id: 'req_forward_001',
        status: 'escalated',
        note: '内容留证风险访问已升级为安全事件',
      })
    })

    expect(document.querySelector('.ant-drawer-open')).not.toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => {
      expect(document.querySelector('.ant-drawer-open')).toBeNull()
    })
    expect(screen.getByTestId('location-search').textContent).toBe('?view=requests')
  }, 30000)

  it('shows one aggregated conversation row and its conversation detail', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [{
          request_id: 'req_conversation_latest',
          created_at: '2026-08-24T00:20:00Z',
          target_host: 'api.openai.com',
          target_path: '/v1/responses',
          method: 'POST',
          provider: 'openai',
          product: 'chatgpt',
          product_cn: 'ChatGPT',
          access_type: 'llm',
          status: 'success',
          status_code: 200,
          response_bytes: 2048,
          tls_inspected: true,
          retention_level: 'content',
          content_retained: true,
          risk_state: 'normal',
          action_taken: 'allow',
          security_event_count: 0,
          disposition_status: 'open',
          turn_count: 2,
          member_count: 3,
          member_request_ids: ['req_turn1_a', 'req_turn1_b', 'req_conversation_latest'],
        }],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_conversation_latest',
        request_content: '【第 1/2 轮】\n问题一\n\n【第 2/2 轮】\n问题二',
        response_content: '【第 1/2 轮】\n回答一\n\n【第 2/2 轮】\n回答二',
        file_metadata: [],
      },
    } as any)

    renderPage()

    expect(await screen.findByText('2 轮对话')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /详情/ })).toHaveLength(1)
    await openFirstDetail()

    expect(await screen.findByText(/2 轮对话，3 次模型调用/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '完整会话' })).toBeInTheDocument()
    await waitFor(() => expect(api.accessRetentionApi.getContent).toHaveBeenCalledWith(
      'req_conversation_latest',
      ['req_turn1_a', 'req_turn1_b', 'req_conversation_latest'],
      expect.objectContaining({ from: expect.any(String), to: expect.any(String) }),
    ))
    expect(await screen.findByTestId('retained-text-request')).toHaveTextContent('问题一')
    expect(screen.getByText(/回答二/)).toBeInTheDocument()
  }, 30000)

  it('shows the Chat account and labels a normal portal conversation as non-agent traffic', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_chat_portal_001',
            created_at: '2026-07-19T02:12:52Z',
            client_id: 'key_c4def315',
            client_name: 'yanfa.demo@jjdguard.invalid',
            target_host: 'gpt-5.6',
            access_type: 'llm',
            status: 'success',
            status_code: 200,
            response_bytes: 1024,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
            access_direction: 'chat_completion',
            provider: 'examplegw',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    expect(await screen.findByText(/yanfa\.demo@jjdguard\.invalid/)).toBeInTheDocument()
    expect(screen.getByText('普通对话（非智能体）')).toBeInTheDocument()
    expect(screen.queryByText(/第三方（无智能体特征）/)).not.toBeInTheDocument()
    expect(screen.queryByText('key_c4def315')).not.toBeInTheDocument()
  })

  it('shows upload/download traffic and duration for an uninspected tunnel', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_tunnel_001',
            created_at: '2026-10-11T02:12:52Z',
            source_ip: '10.10.10.9',
            target_host: 'files.blob.core.windows.net:443',
            method: 'CONNECT',
            access_type: 'normal_public',
            status: 'success',
            status_code: 200,
            request_bytes: 2 * 1024 * 1024,
            response_bytes: 3 * 1024,
            tunnel_duration_ms: 125000,
            tls_inspected: false,
            retention_level: 'summary',
            content_retained: false,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
            access_direction: 'forward',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, normal_public_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    expect(await screen.findByText('上行 2.0 MB')).toBeInTheDocument()
    expect(screen.getByText('下行 3.0 KB')).toBeInTheDocument()
    expect(screen.getByText('时长 2 分 5 秒')).toBeInTheDocument()
    expect(screen.getAllByText('流量 / 时长').length).toBeGreaterThan(0)
    expect(screen.queryByText(/tunnel_duration_ms|request_bytes/)).not.toBeInTheDocument()
  })

  it('keeps empty summary customer-safe', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0, summary: {} },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    const runsSpy = vi.spyOn(api.accessRetentionApi, 'listRuns').mockResolvedValue({
      data: { data: [], total: 0 },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage('/audit/access-retention')

    await waitFor(() => {
      expect(screen.getByRole('tab', { name: '概览' })).toHaveAttribute('aria-selected', 'true')
      expect(screen.getByRole('tab', { name: '留证明细' })).toBeInTheDocument()
      expect(screen.getByText('内容留证概览')).toBeInTheDocument()
      expect(screen.getByText('留证请求')).toBeInTheDocument()
      expect(screen.getByText('证据完整率')).toBeInTheDocument()
      expect(screen.getByText('暂无趋势数据')).toBeInTheDocument()
      expect(screen.getByText('暂无模型或外部服务统计')).toBeInTheDocument()
      expect(screen.getByText('暂无规则命中统计')).toBeInTheDocument()
      expect(screen.getByText('暂无智能体归因统计')).toBeInTheDocument()
    })
    // 概览只发一次完整汇总，计数也从中取。
    expect(summarySpy).not.toHaveBeenCalledWith(expect.objectContaining({ summary_detail: 'counts' }))
    expect(summarySpy).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('留证内容')).not.toBeInTheDocument()
    expect(listSpy).not.toHaveBeenCalled()
    expect(runsSpy).not.toHaveBeenCalled()
  })

  it('keeps the details entry available when overview aggregation fails', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0, summary: emptySummary, summary_error: 'summary_unavailable' },
    } as any)
    const runsSpy = vi.spyOn(api.accessRetentionApi, 'listRuns').mockResolvedValue({
      data: { data: [], total: 0 }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    summarySpy.mockResolvedValue({
      data: { data: [], total: 0, summary: emptySummary, summary_error: 'summary_unavailable' },
    })

    renderPage('/audit/access-retention')

    expect(await screen.findByText('留证概览统计加载失败，留证明细仍可使用')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '留证明细' })).toBeInTheDocument()
    expect(screen.queryByText('内容留证概览')).not.toBeInTheDocument()
    expect(listSpy).not.toHaveBeenCalled()
    expect(runsSpy).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('tab', { name: '留证明细' }))

    expect(await screen.findByText('留证内容')).toBeInTheDocument()
    await waitFor(() => expect(runsSpy).toHaveBeenCalledTimes(1))
    expect(listSpy).not.toHaveBeenCalled()
  })

  it('applies linked agent type filters from the URL', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [],
        total: 0,
        summary: emptySummary,
      },
    } as any)

    renderPage('/audit/access-retention?view=requests&agent_type=workbuddy&content_only=true&from=2026-06-16T15:17:42.000Z&to=2026-06-23T15:17:42.000Z')

    await waitFor(() => {
      expect(api.accessRetentionApi.list).toHaveBeenCalledWith(expect.objectContaining({
        agent_type: 'workbuddy',
        content_only: true,
        skip_total: true,
        from: '2026-06-16T15:17:42.000Z',
        to: '2026-06-23T15:17:42.000Z',
      }))
    })
    const advanced = screen.getByRole('button', { name: /高级筛选（已启用 1）/ })
    expect(advanced).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(advanced)
    expect(await screen.findByText('WorkBuddy')).toBeInTheDocument()
  })

  it('presents a balanced retention overview and drills charts into the record filters', async () => {
    mockCatalog()
    const runsSpy = vi.spyOn(api.accessRetentionApi, 'listRuns').mockResolvedValue({
      data: { data: [], total: 0 }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [{
          request_id: 'req_agent_model_1',
          created_at: '2026-07-11T06:26:52Z',
          source_ip: '100.67.114.59',
          target_host: 'GPT-5.5',
          target_path: '/v1/messages?beta=true',
          provider: 'third-party',
          access_type: 'llm',
          status: 'success',
          status_code: 200,
          response_bytes: 1024,
          tls_inspected: true,
          retention_level: 'content',
          content_retained: true,
          risk_state: 'normal',
          action_taken: 'allow',
          security_event_count: 0,
          disposition_status: 'open',
          access_direction: 'chat_completion',
          agent_type: 'claude-code',
          agent_label: 'Claude Code',
        }],
        total: 1,
        summary: {
          ...emptySummary,
          total: 10,
          normal_count: 5,
          risk_count: 3,
          blocked_count: 2,
          retained_content_count: 10,
          unique_model_count: 3,
          evidence_quality: {
            complete_count: 6,
            request_only_count: 2,
            response_only_count: 1,
            metadata_only_count: 1,
          },
          timeline: [
            { bucket: '2026-07-11T05:00:00Z', total_count: 4, normal_count: 3, risk_count: 1, blocked_count: 0 },
            { bucket: '2026-07-11T06:00:00Z', total_count: 6, normal_count: 2, risk_count: 2, blocked_count: 2 },
          ],
          top_risk_categories: [
            { name: 'config_file', count: 4 },
            { name: 'ssrf_metadata_instruction', count: 2 },
          ],
          top_targets: [
            { name: 'gpt-5.6-sol', count: 6, risk_count: 4 },
            { name: 'claude-opus-4-8', count: 4, risk_count: 1 },
          ],
          agent_request_count: 8,
          identified_agent_count: 6,
          unidentified_agent_count: 2,
          data_fresh_until: '2026-07-11T06:30:00Z',
          top_agents: [
            { name: 'claude-code', label: 'Claude Code', count: 5, risk_count: 2 },
            { name: 'agent-tool-call', label: '待识别智能体请求', count: 2, risk_count: 1 },
          ],
        },
      },
    } as any)
    const overviewResponse = await (listSpy.getMockImplementation() as any)()
    summarySpy.mockResolvedValue({ data: { summary: overviewResponse.data.summary } })

    renderPage('/audit/access-retention')

    expect((await screen.findAllByText('60%')).length).toBeGreaterThan(0)
    expect(screen.getByText('留证请求')).toBeInTheDocument()
    expect(screen.getByText('证据完整率')).toBeInTheDocument()
    expect(screen.getAllByText('60%').length).toBeGreaterThan(0)
    expect(screen.getByText('需关注记录')).toBeInTheDocument()
    expect(screen.getAllByText('拒绝记录').length).toBeGreaterThan(0)
    expect(screen.getAllByText('75%').length).toBeGreaterThan(0)
    expect(screen.getByText('留证与处置趋势')).toBeInTheDocument()
    expect(screen.getByText('证据完整性')).toBeInTheDocument()
    expect(screen.getByText('请求与响应完整')).toBeInTheDocument()
    expect(screen.getByText('审计与处置结构')).toBeInTheDocument()
    expect(screen.getByText('模型 / 外部服务需关注记录')).toBeInTheDocument()
    expect(screen.getByText('规则命中 TOP')).toBeInTheDocument()
    expect(screen.getByText('线索 / 阻断')).toBeInTheDocument()
    expect(screen.getAllByText(/需关注占比 \d+%/).length).toBeGreaterThan(0)
    expect(screen.queryByText(/风险率 \d+%/)).not.toBeInTheDocument()
    expect(screen.getByText('同一请求可命中多类')).toBeInTheDocument()
    expect(screen.getByText('配置文件风险')).toBeInTheDocument()
    expect(screen.getByText('SSRF 元数据探测指令')).toBeInTheDocument()
    expect(screen.getByText('智能体归因')).toBeInTheDocument()
    expect(screen.queryByText('智能体归因概览')).not.toBeInTheDocument()
    expect(screen.queryByText('访问目标 TOP（按风险数）')).not.toBeInTheDocument()
    expect(screen.queryByText('model_b54760f3')).not.toBeInTheDocument()
    expect(screen.getByText('数据更新至 2026/7/11 14:30:00')).toBeInTheDocument()
    expect(screen.queryByText('GPT-5.5')).not.toBeInTheDocument()

    const reviewStatusButton = await screen.findByRole('button', { name: /筛选处置状态 审计线索/ })
    expect(reviewStatusButton).toHaveClass('retention-risk-status-tile')
    expect(reviewStatusButton.querySelector('.retention-risk-status-label')).toHaveTextContent('审计线索')
    expect(reviewStatusButton.querySelector('.retention-risk-status-metrics')).toHaveTextContent('3')

    expect(listSpy).not.toHaveBeenCalled()
    expect(runsSpy).not.toHaveBeenCalled()

    fireEvent.click(await screen.findByRole('button', { name: /筛选模型 gpt-5.6-sol/ }))
    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({ target_host: 'gpt-5.6-sol' })))
    expect(runsSpy).not.toHaveBeenCalled()
    expect(screen.getByRole('tab', { name: '留证明细' })).toHaveAttribute('aria-selected', 'true')
    const drillParams = new URLSearchParams(screen.getByTestId('location-search').textContent || '')
    expect(drillParams.get('tab')).toBe('details')
    expect(drillParams.get('view')).toBe('requests')
  })

  it('loads the overview independently after a detail keyword search', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0, summary: emptySummary },
      status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    summarySpy.mockResolvedValue({
      data: { summary: { ...emptySummary, total: 9, normal_count: 9, retained_content_count: 9 } },
    })

    renderPage('/audit/access-retention?view=requests')
    await waitFor(() => expect(listSpy).toHaveBeenCalledTimes(1))

    const keywordInput = screen.getByPlaceholderText('搜索留证正文 / 文件名')
    fireEvent.change(keywordInput, { target: { value: '密钥' } })
    fireEvent.keyDown(keywordInput, { key: 'Enter', code: 'Enter', charCode: 13 })
    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({ keyword: '密钥' })))

    fireEvent.click(screen.getByRole('tab', { name: '概览' }))

    await waitFor(() => expect(summarySpy).toHaveBeenCalledWith(expect.objectContaining({
      keyword: undefined,
    })))
    expect(summarySpy).not.toHaveBeenCalledWith(expect.objectContaining({ summary_detail: 'counts' }))
    const metric = (await screen.findByText('留证请求')).closest('.enterprise-metric-card')
    expect(metric).not.toBeNull()
    expect(within(metric as HTMLElement).getByText('9')).toBeInTheDocument()
    const params = new URLSearchParams(screen.getByTestId('location-search').textContent || '')
    expect(params.get('tab')).toBeNull()
    expect(params.get('view')).toBeNull()
  })

  it('keeps tab and detail-view state consistent through browser history', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0, summary: emptySummary },
      status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'listRuns').mockResolvedValue({
      data: { data: [], total: 0 }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)

    renderPage('/audit/access-retention?view=requests')
    expect(await screen.findByRole('tab', { name: '留证明细' })).toHaveAttribute('aria-selected', 'true')

    fireEvent.click(screen.getByRole('tab', { name: '概览' }))
    await waitFor(() => expect(screen.getByRole('tab', { name: '概览' })).toHaveAttribute('aria-selected', 'true'))
    let params = new URLSearchParams(screen.getByTestId('location-search').textContent || '')
    expect(params.get('tab')).toBeNull()
    expect(params.get('view')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: '测试浏览器后退' }))
    await waitFor(() => expect(screen.getByRole('tab', { name: '留证明细' })).toHaveAttribute('aria-selected', 'true'))
    params = new URLSearchParams(screen.getByTestId('location-search').textContent || '')
    expect(params.get('view')).toBe('requests')

    fireEvent.click(screen.getByRole('button', { name: '智能体任务' }))
    await waitFor(() => {
      const next = new URLSearchParams(screen.getByTestId('location-search').textContent || '')
      expect(next.get('tab')).toBe('details')
      expect(next.get('view')).toBeNull()
      expect(screen.getByRole('tab', { name: '留证明细' })).toHaveAttribute('aria-selected', 'true')
    })
  })

  it('opens only the exact call for a member request_id deep link', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_demo_rep',
            created_at: '2026-06-12T03:20:00Z',
            source_ip: '192.168.31.108',
            target_host: 'api.deepseek.com',
            target_path: '/v1/chat/completions',
            method: 'POST',
            provider: 'deepseek',
            provider_cn: 'DeepSeek',
            product: 'deepseek_api',
            product_cn: 'DeepSeek API',
            access_type: 'llm',
            endpoint_kind: 'api',
            path_template: '/v1/chat/completions',
            status: 'success',
            status_code: 200,
            response_bytes: 4096,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'risk',
            action_taken: 'audit',
            security_event_count: 1,
            disposition_status: 'open',
            member_count: 2,
            member_request_ids: ['req_demo_1', 'req_demo_rep'],
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, risk_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_demo_1',
        request_content: '你好',
        response_content: '你好，有什么可以帮你？',
        retention_until: '2026-09-01T00:00:00+08:00',
        file_metadata: [],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage('/audit/access-retention?request_id=req_demo_1&agent_type=workbuddy&from=2026-06-16T15:17:42.000Z&to=2026-06-23T15:17:42.000Z')

    await waitFor(() => {
      // 深链定位须同时解除 content_only（否则 has_retained_content=true 硬过滤会命不中目标告警行、抽屉静默不开）
      expect(listSpy).toHaveBeenCalledWith(expect.objectContaining({ request_id: 'req_demo_1', content_only: undefined }))
    })
    // 命中即自动打开详情抽屉（无需人工点"详情"）
    expect(await screen.findAllByText('对话留证')).toBeTruthy()
    await waitFor(() => {
      expect(api.accessRetentionApi.getContent).toHaveBeenCalledWith('req_demo_1', undefined, expect.objectContaining({
        from: '2026-06-16T15:17:42.000Z',
        to: '2026-06-23T15:17:42.000Z',
      }))
    })

    expect(vi.mocked(api.accessRetentionApi.getContent).mock.calls.every(([id, members]) => id === 'req_demo_1' && members === undefined)).toBe(true)
    expect(screen.getByRole('button', { name: '调用 1' })).toHaveClass('ant-btn-primary')
    expect(screen.getByRole('button', { name: '完整会话' })).not.toHaveClass('ant-btn-primary')
    expect(document.querySelector('.ant-drawer-open')).not.toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => {
      expect(document.querySelector('.ant-drawer-open')).toBeNull()
      const params = new URLSearchParams(screen.getByTestId('location-search').textContent || '')
      expect(params.get('request_id')).toBeNull()
      expect(params.get('agent_type')).toBe('workbuddy')
      expect(params.get('from')).toBe('2026-06-16T15:17:42.000Z')
      expect(params.get('to')).toBe('2026-06-23T15:17:42.000Z')
      expect(params.get('tab')).toBe('details')
      expect(params.get('view')).toBe('requests')
      expect(Array.from(params.keys()).sort()).toEqual(['agent_type', 'from', 'tab', 'to', 'view'])
    })
  }, 30000)

  it('keeps uploaded file bodies out of prompts, lays out code fences, and downloads retained file text', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_uploaded_html',
            created_at: '2026-06-12T03:20:00Z',
            source_ip: '192.168.31.108',
            target_host: 'chat.deepseek.com',
            target_path: '/api/v0/chat/completion',
            method: 'POST',
            provider: 'deepseek',
            provider_cn: 'DeepSeek',
            product: 'deepseek_chat',
            product_cn: 'DeepSeek Chat',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/api/v0/chat/completion',
            status: 'success',
            status_code: 200,
            response_bytes: 16384,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_uploaded_html',
        request_content:
          '[field:prompt] 帮我 review 这个上传的 HTML，顺手优化排版\n[file:客户BAgent安全解决方案.html type=text/html size=94 sha256=htmlsha123]\n<!DOCTYPE html>\n<html lang="zh-CN">\n<body>FILE ONLY 上传文件正文</body>\n</html>',
        response_content:
          'SET RESPONSE 以下是优化后的版本：\n\n```html\n<!DOCTYPE html>\n<html lang="zh-CN">\n<head><title>客户B智能体安全全周期安全解决方案</title></head>\n</html>\n```\n\n以上代码保持原页面结构。',
        retention_until: '2026-09-10T12:15:49+08:00',
        file_metadata: [
          { source: 'multipart', field_name: 'file', file_name: '客户BAgent安全解决方案.html', content_type: 'text/html', size: 94, sha256: 'htmlsha123', text_preview: 'FILE ONLY 上传文件正文' },
        ],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.auditDispositionApi, 'upsert').mockResolvedValue({ data: { status: 'ok' }, status: 200, statusText: 'OK', headers: {}, config: {} } as any)
    const createObjectURL = vi.fn((blobArg: Blob) => {
      void blobArg
      return 'blob:file-download'
    })
    const revokeObjectURL = vi.fn()
    const prevCreateObjectURL = (globalThis.URL as any).createObjectURL
    const prevRevokeObjectURL = (globalThis.URL as any).revokeObjectURL
    ;(globalThis.URL as any).createObjectURL = createObjectURL
    ;(globalThis.URL as any).revokeObjectURL = revokeObjectURL
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    try {
      renderPage()

      await openFirstDetail()

      const promptPanel = await screen.findByTestId('retained-text-request')
      await waitFor(() => expect(promptPanel).toHaveTextContent('帮我 review 这个上传的 HTML，顺手优化排版'))
      expect(promptPanel).not.toHaveTextContent('FILE ONLY 上传文件正文')

      const answerPanel = await screen.findByTestId('retained-text-response')
      await waitFor(() => expect(answerPanel).toHaveTextContent('以下是优化后的版本：'))
      expect(screen.getByText('html')).toBeInTheDocument()
      expect(screen.getByTestId('retained-code-block')).toHaveTextContent('<!DOCTYPE html>')
      expect(answerPanel).toHaveTextContent('以上代码保持原页面结构。')

      expect(screen.getByText('客户BAgent安全解决方案.html')).toBeInTheDocument()
      expect(screen.getByText(/FILE ONLY 上传文件正文/)).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: /下载留存副本/ }))

      await waitFor(() => expect(createObjectURL).toHaveBeenCalledWith(expect.any(Blob)))
      const blob = createObjectURL.mock.calls[0][0]
      await expect(blob.text()).resolves.toContain('FILE ONLY 上传文件正文')
      expect(blob.type).toContain('text/html')
      expect(clickSpy).toHaveBeenCalled()
    } finally {
      (globalThis.URL as any).createObjectURL = prevCreateObjectURL
      ;(globalThis.URL as any).revokeObjectURL = prevRevokeObjectURL
      clickSpy.mockRestore()
    }
  }, 30000)



  it('shows uploaded image files as visible previews and downloadable retained copies', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_uploaded_image',
            created_at: '2026-06-12T10:20:00Z',
            source_ip: '192.168.31.108',
            target_host: 'chat.deepseek.com',
            target_path: '/api/v0/file/upload',
            method: 'POST',
            provider: 'deepseek',
            provider_cn: 'DeepSeek',
            product: 'deepseek_chat',
            product_cn: 'DeepSeek Chat',
            access_type: 'llm',
            endpoint_kind: 'file',
            path_template: '/api/v0/file/upload',
            status: 'success',
            status_code: 200,
            response_bytes: 1024,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_uploaded_image',
        request_content: '[field:prompt] 看下这个截图\n[file:sketch.png type=image/png size=5 sha256=imgup]',
        response_content: '已收到图片',
        retention_until: '2026-09-10T16:40:53+08:00',
        file_metadata: [
          { source: 'multipart', stage: 'request', field_name: 'file', file_name: 'sketch.png', content_type: 'image/png', size: 5, sha256: 'imgup', data_base64: 'aGVsbG8=' },
        ],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    const createObjectURL = vi.fn((blobArg: Blob) => {
      void blobArg
      return 'blob:uploaded-image'
    })
    const revokeObjectURL = vi.fn()
    const prevCreateObjectURL = (globalThis.URL as any).createObjectURL
    const prevRevokeObjectURL = (globalThis.URL as any).revokeObjectURL
    ;(globalThis.URL as any).createObjectURL = createObjectURL
    ;(globalThis.URL as any).revokeObjectURL = revokeObjectURL
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    try {
      renderPage()
      await openFirstDetail()

      expect(await screen.findByText('用户上传文件')).toBeInTheDocument()
      const preview = await screen.findByAltText('用户上传图片 1')
      expect(preview).toHaveAttribute('src', 'data:image/png;base64,aGVsbG8=')
      expect(screen.getByText('sketch.png')).toBeInTheDocument()
      expect(screen.getByText(/SHA256 imgup/)).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: /下载留存副本/ }))

      await waitFor(() => expect(createObjectURL).toHaveBeenCalledWith(expect.any(Blob)))
      const blob = createObjectURL.mock.calls[0][0]
      expect(blob.type).toBe('image/png')
      expect(clickSpy).toHaveBeenCalled()
    } finally {
      (globalThis.URL as any).createObjectURL = prevCreateObjectURL
      ;(globalThis.URL as any).revokeObjectURL = prevRevokeObjectURL
      clickSpy.mockRestore()
    }
  }, 30000)


  it('renders model-returned images as previews instead of answer text noise', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_model_image_response',
            created_at: '2026-06-12T09:10:00Z',
            source_ip: '192.168.31.108',
            target_host: 'www.doubao.com',
            target_path: '/chat/completion?aid=497858',
            method: 'POST',
            provider: 'bytedance',
            provider_cn: '字节跳动',
            product: 'doubao',
            product_cn: '豆包',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/chat/completion',
            status: 'success',
            status_code: 200,
            response_bytes: 5120,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_model_image_response',
        request_content: '画一张测试图',
        response_content: '已生成图片\n[embedded:content.image type=image/png size=5 sha256=imgsha]',
        retention_until: '2026-09-10T16:40:53+08:00',
        file_metadata: [
          { source: 'json_data_url', stage: 'response', field_name: 'content.image', content_type: 'image/png', size: 5, sha256: 'imgsha', data_base64: 'aGVsbG8=' },
        ],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    const answerPanel = await screen.findByTestId('retained-text-response')
    await waitFor(() => expect(answerPanel).toHaveTextContent('已生成图片'))
    expect(answerPanel).not.toHaveTextContent('embedded:content.image')
    expect(await screen.findByText('模型返回图片')).toBeInTheDocument()
    const preview = await screen.findByAltText('模型返回图片 1')
    expect(preview).toHaveAttribute('src', 'data:image/png;base64,aGVsbG8=')
    expect(screen.getByText('image/png')).toBeInTheDocument()
    expect(screen.getByText(/SHA256 imgsha/)).toBeInTheDocument()
  }, 30000)

  it('renders Kimi referenced image URLs as model-returned images and cleans URL noise', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_kimi_image_refs',
            created_at: '2026-06-12T10:17:36Z',
            source_ip: '192.168.31.108',
            target_host: 'www.kimi.com',
            target_path: '/apiv2/kimi.gateway.chat.v1.ChatService/Chat',
            method: 'POST',
            provider: 'moonshot',
            provider_cn: '月之暗面',
            product: 'kimi',
            product_cn: 'Kimi',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/apiv2/kimi.gateway.chat.v1.ChatService/Chat',
            status: 'success',
            status_code: 200,
            response_bytes: 17920,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'risk',
            action_taken: 'audit',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, risk_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_kimi_image_refs',
        request_content: '来点老虎的图',
        response_content:
          '世界经济论坛 [message.refs.images.originUrl] https://kimi-web-img.moonshot.cn/img/assets.weforum.org/tiger-one.png [message.refs.images.thumbnailUrl] https://kimi-web-img.moonshot.cn/img/assets.weforum.org/tiger-one.png?x-oss-process=image/resize,w_546 [message.refs.images.sourceSiteUrl] https://cn.weforum.org/stories/2022/02/tiger-story/ 虎虎生威？全球野生老虎不到4000只。\n[message.references.items.image.url] https://assets.weforum.org/article/image/tiger-two.jpg 第二张是一只站立的老虎全身照，背景是自然的野外环境。',
        retention_until: '2026-09-10T18:17:36+08:00',
        file_metadata: [],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    const answerPanel = await screen.findByTestId('retained-text-response')
    await waitFor(() => expect(answerPanel).toHaveTextContent('虎虎生威？全球野生老虎不到4000只。'))
    expect(answerPanel).toHaveTextContent('第二张是一只站立的老虎全身照')
    expect(answerPanel).not.toHaveTextContent('message.refs.images')
    expect(answerPanel).not.toHaveTextContent('message.references.items.image.url')
    expect(answerPanel).not.toHaveTextContent('https://kimi-web-img.moonshot.cn')

    expect(await screen.findByText('模型返回图片')).toBeInTheDocument()
    const previews = await screen.findAllByAltText(/模型返回图片/)
    expect(previews).toHaveLength(2)
    expect(previews[0]).toHaveAttribute('src', `/admin/v1/audit/access-retention/req_kimi_image_refs/image-proxy?url=${encodeURIComponent('https://kimi-web-img.moonshot.cn/img/assets.weforum.org/tiger-one.png')}`)
    expect(previews[1]).toHaveAttribute('src', `/admin/v1/audit/access-retention/req_kimi_image_refs/image-proxy?url=${encodeURIComponent('https://assets.weforum.org/article/image/tiger-two.jpg')}`)
    expect(screen.queryByText('本次请求未直接上传文件')).not.toBeInTheDocument()
  }, 30000)


  it('classifies Kimi chat file image references as user uploads, not model-returned images', async () => {
    mockCatalog()
    const fileURL = 'https://www.kimi.com/apiv2-files/sign-obj/kimi-fs%2Ffiles%2Fblob%2F16030a988c74e252db56f0a8cc0459251731481f311971a6732c14edb231d9f0?filename=image.png&t=o'
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_kimi_uploaded_image',
            created_at: '2026-06-12T12:25:36Z',
            source_ip: '192.168.31.108',
            target_host: 'www.kimi.com',
            target_path: '/apiv2/kimi.gateway.chat.v1.ChatService/Chat',
            method: 'POST',
            provider: 'moonshot',
            provider_cn: '月之暗面',
            product: 'kimi',
            product_cn: 'Kimi',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/apiv2/kimi.gateway.chat.v1.ChatService/Chat',
            status: 'success',
            status_code: 200,
            response_bytes: 543,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_kimi_uploaded_image',
        request_content: '这是什么',
        response_content: '这是 Kimi 的界面截图。',
        retention_until: '2026-09-10T20:25:42+08:00',
        file_metadata: [
          {
            source: 'json_file_url',
            stage: 'response',
            field_name: 'chat.files.blob.signUrl',
            file_name: 'image.png',
            reference_id: 'kimi-fs/files/blob/16030a988c74e252db56f0a8cc0459251731481f311971a6732c14edb231d9f0',
            content_type: 'image/png',
            size: 0,
            sha256: '',
            download_url: fileURL,
          },
        ],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    expect(await screen.findByText('用户上传文件')).toBeInTheDocument()
    expect(screen.getByText('image.png')).toBeInTheDocument()
    expect(screen.queryByText('模型返回图片')).not.toBeInTheDocument()
  }, 30000)

  it('renders Doubao inline image URLs as model-returned images and removes JSON noise', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_doubao_inline_image',
            created_at: '2026-06-12T10:25:00Z',
            source_ip: '192.168.31.108',
            target_host: 'www.doubao.com',
            target_path: '/chat/completion?aid=497858',
            method: 'POST',
            provider: 'bytedance',
            provider_cn: '字节跳动',
            product: 'doubao',
            product_cn: '豆包',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/chat/completion',
            status: 'success',
            status_code: 200,
            response_bytes: 6144,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_doubao_inline_image',
        request_content: '给我画一只老虎',
        response_content:
          '已生成图片。\n{"event":"message","content":{"image":{"url":"https://p3-flow-imagex-sign.byteimg.com/ocean-cloud-tos/tiger-doubao.png~tplv-a9rns2rl98-image-qvalue.png?x-expires=1783834240"},"text":"老虎图片"}}\n这是一只老虎的图片，橙黑条纹清晰。',
        retention_until: '2026-09-10T18:25:00+08:00',
        file_metadata: [],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    const answerPanel = await screen.findByTestId('retained-text-response')
    await waitFor(() => expect(answerPanel).toHaveTextContent('已生成图片。'))
    expect(answerPanel).toHaveTextContent('这是一只老虎的图片')
    expect(answerPanel).not.toHaveTextContent('byteimg.com')
    expect(answerPanel).not.toHaveTextContent('"event"')
    expect(await screen.findByText('模型返回图片')).toBeInTheDocument()
    const preview = await screen.findByAltText('模型返回图片 1')
    expect(preview).toHaveAttribute('src', `/admin/v1/audit/access-retention/req_doubao_inline_image/image-proxy?url=${encodeURIComponent('https://p3-flow-imagex-sign.byteimg.com/ocean-cloud-tos/tiger-doubao.png~tplv-a9rns2rl98-image-qvalue.png?x-expires=1783834240')}`)
  }, 30000)


  it.each([
    {
      name: 'Qwen',
      requestId: 'req_qwen_inline_image',
      host: 'chat.qwen.ai',
      path: '/api/chat/completions',
      provider: 'alibaba',
      providerCN: '阿里云',
      product: 'qwen_chat',
      productCN: '通义千问',
      prompt: '生成一张山水图',
      response:
        '已生成图片。\n{"data":{"images":[{"url":"https://dashscope-result-sh.oss-cn-shanghai.aliyuncs.com/qwen/mountain.webp?Expires=1783834240"}]}}\n山水图包含远山和湖面。',
      visibleText: '山水图包含远山和湖面。',
      hiddenText: 'dashscope-result-sh.oss-cn-shanghai.aliyuncs.com',
      imageURL: 'https://dashscope-result-sh.oss-cn-shanghai.aliyuncs.com/qwen/mountain.webp?Expires=1783834240',
    },
    {
      name: 'ChatGPT',
      requestId: 'req_chatgpt_inline_image',
      host: 'chatgpt.com',
      path: '/backend-api/conversation',
      provider: 'openai',
      providerCN: 'OpenAI',
      product: 'chatgpt',
      productCN: 'ChatGPT',
      prompt: '生成一张海报',
      response:
        'Here is the image.\n[image_url] https://oaidalleapiprodscus.blob.core.windows.net/private/org/poster-image.png?se=2026-06-12T18%3A30%3A00Z\n海报已生成，主体是蓝色科技风。',
      visibleText: '海报已生成，主体是蓝色科技风。',
      hiddenText: 'oaidalleapiprodscus.blob.core.windows.net',
      imageURL: 'https://oaidalleapiprodscus.blob.core.windows.net/private/org/poster-image.png?se=2026-06-12T18%3A30%3A00Z',
    },
    {
      name: 'Claude',
      requestId: 'req_claude_inline_image',
      host: 'claude.ai',
      path: '/api/organizations/org/chat_conversations',
      provider: 'anthropic',
      providerCN: 'Anthropic',
      product: 'claude',
      productCN: 'Claude',
      prompt: '给我一张架构图',
      response:
        'I created the diagram.\n{"artifact":{"type":"image","source":{"url":"https://claudeusercontent.com/assets/architecture-diagram.jpeg?token=retained"}}}\n架构图包含网关、控制面和审计存储。',
      visibleText: '架构图包含网关、控制面和审计存储。',
      hiddenText: 'claudeusercontent.com',
      imageURL: 'https://claudeusercontent.com/assets/architecture-diagram.jpeg?token=retained',
    },
    {
      name: 'Gemini',
      requestId: 'req_gemini_inline_image',
      host: 'gemini.google.com',
      path: '/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate',
      provider: 'google',
      providerCN: 'Google',
      product: 'gemini',
      productCN: 'Gemini',
      prompt: '生成一张办公室图',
      response:
        '已生成图片。\n{"candidates":[{"content":{"parts":[{"image_url":"https://lh3.googleusercontent.com/gemini/generated-office-image=s2048"}]}}]}\n办公室图包含会议桌和屏幕。',
      visibleText: '办公室图包含会议桌和屏幕。',
      hiddenText: 'lh3.googleusercontent.com',
      imageURL: 'https://lh3.googleusercontent.com/gemini/generated-office-image=s2048',
    },
    {
      name: 'Yuanbao',
      requestId: 'req_yuanbao_inline_image',
      host: 'yuanbao.tencent.com',
      path: '/api/chat/completions',
      provider: 'tencent',
      providerCN: '腾讯',
      product: 'yuanbao',
      productCN: '腾讯元宝',
      prompt: '生成一张产品图',
      response:
        '图片生成完成。\n{"image":{"url":"https://hunyuan-prod-1258344707.cos.ap-guangzhou.myqcloud.com/yuanbao/generated-product-image?sign=abc"}}\n产品图是白底实物风格。',
      visibleText: '产品图是白底实物风格。',
      hiddenText: 'myqcloud.com',
      imageURL: 'https://hunyuan-prod-1258344707.cos.ap-guangzhou.myqcloud.com/yuanbao/generated-product-image?sign=abc',
    },
    {
      name: 'Grok',
      requestId: 'req_grok_inline_image',
      host: 'grok.com',
      path: '/rest/app-chat/conversations/new',
      provider: 'xai',
      providerCN: 'xAI',
      product: 'grok',
      productCN: 'Grok',
      prompt: '生成一张机器人图',
      response:
        'Generated image: https://assets.grok.com/users/abc/generated-robot-image.jpg?token=xyz\n机器人图有金属外壳和蓝色灯光。',
      visibleText: '机器人图有金属外壳和蓝色灯光。',
      hiddenText: 'assets.grok.com',
      imageURL: 'https://assets.grok.com/users/abc/generated-robot-image.jpg?token=xyz',
    },
    {
      name: 'Perplexity',
      requestId: 'req_perplexity_inline_image',
      host: 'www.perplexity.ai',
      path: '/rest/thread',
      provider: 'perplexity',
      providerCN: 'Perplexity',
      product: 'perplexity',
      productCN: 'Perplexity',
      prompt: '找一张资料图',
      response:
        '参考图片 [image] https://pplx-res.cloudinary.com/image/upload/v1783834240/search-result-chart.webp 资料图展示了趋势曲线。',
      visibleText: '资料图展示了趋势曲线。',
      hiddenText: 'pplx-res.cloudinary.com',
      imageURL: 'https://pplx-res.cloudinary.com/image/upload/v1783834240/search-result-chart.webp',
    },
    {
      name: 'DeepSeek',
      requestId: 'req_deepseek_inline_image',
      host: 'chat.deepseek.com',
      path: '/api/v0/chat/completion',
      provider: 'deepseek',
      providerCN: 'DeepSeek',
      product: 'deepseek_chat',
      productCN: 'DeepSeek Chat',
      prompt: '解释这张图',
      response:
        '图像引用：https://cdn.deepseek.com/chat/files/analysis-preview.png?token=retained\n这张图展示了调用链路。',
      visibleText: '这张图展示了调用链路。',
      hiddenText: 'cdn.deepseek.com',
      imageURL: 'https://cdn.deepseek.com/chat/files/analysis-preview.png?token=retained',
    },
  ])('renders $name inline image URLs through the generic model image extractor', async (sample) => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: sample.requestId,
            created_at: '2026-06-12T10:30:00Z',
            source_ip: '192.168.31.108',
            target_host: sample.host,
            target_path: sample.path,
            method: 'POST',
            provider: sample.provider,
            provider_cn: sample.providerCN,
            product: sample.product,
            product_cn: sample.productCN,
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: sample.path,
            status: 'success',
            status_code: 200,
            response_bytes: 8192,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: sample.requestId,
        request_content: sample.prompt,
        response_content: sample.response,
        retention_until: '2026-09-10T18:30:00+08:00',
        file_metadata: [],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    const answerPanel = await screen.findByTestId('retained-text-response')
    await waitFor(() => expect(answerPanel).toHaveTextContent(sample.visibleText))
    expect(answerPanel).not.toHaveTextContent(sample.hiddenText)
    expect(await screen.findByText('模型返回图片')).toBeInTheDocument()
    const preview = await screen.findByAltText('模型返回图片 1')
    expect(preview).toHaveAttribute('src', `/admin/v1/audit/access-retention/${sample.requestId}/image-proxy?url=${encodeURIComponent(sample.imageURL)}`)
  }, 30000)


  it('cleans Kimi web protocol noise from retained prompt and answer', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_kimi_web_dirty',
            created_at: '2026-06-12T05:31:17Z',
            source_ip: '192.168.31.108',
            target_host: 'www.kimi.com',
            target_path: '/apiv2/kimi.gateway.chat.v1.ChatService/Chat',
            method: 'POST',
            provider: 'moonshot',
            provider_cn: '月之暗面',
            product: 'kimi',
            product_cn: 'Kimi',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/apiv2/kimi.gateway.chat.v1.ChatService/Chat',
            status: 'success',
            status_code: 200,
            response_bytes: 3215,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_kimi_web_dirty',
        request_content: 'SCENARIO_K2D5\nTOOL_TYPE_SEARCH\nuser\n怎么样\nSCENARIO_K2D5',
        response_content: 'set 2026-06-12T05:31:18.033698701Z 19eba503-04c2-8402-8000-09eec6438f14 未命名会话 TOOL_TYPE_SEARCH SCENARIO_K2D5 set chat.lastRequest set MESSAGE_STATUS_COMPLETED SCENARIO_K2D5 chat.name 怎么样 set block.text block.text.content! 1 block.text.content 你 1 block.text.content 好！ 1 block.text.content 之前 1 block.text.content 问的是 1 block.text.content “怎么样”。 1 set',
        retention_until: '2026-09-10T12:15:49+08:00',
        file_metadata: [],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    const promptPanel = await screen.findByTestId('retained-text-request')
    await waitFor(() => expect(promptPanel).toHaveTextContent('怎么样'))
    expect(promptPanel).not.toHaveTextContent('SCENARIO_K2D5')
    expect(promptPanel).not.toHaveTextContent('TOOL_TYPE_SEARCH')

    const answerPanel = await screen.findByTestId('retained-text-response')
    await waitFor(() => expect(answerPanel).toHaveTextContent('你好！之前问的是“怎么样”。'))
    expect(answerPanel).not.toHaveTextContent('block.text.content')
    expect(answerPanel).not.toHaveTextContent('SCENARIO_K2D5')
    expect(answerPanel).not.toHaveTextContent('MESSAGE_STATUS_COMPLETED')
    expect(answerPanel).not.toHaveTextContent('19eba503')
  }, 30000)

  it('shows DeepSeek reasoning separately and keeps final answers readable', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_deepseek_reasoning_fragments',
            created_at: '2026-06-12T13:19:56Z',
            source_ip: '192.168.31.108',
            target_host: 'chat.deepseek.com',
            target_path: '/api/v0/chat/completion',
            method: 'POST',
            provider: 'deepseek',
            provider_cn: 'DeepSeek',
            product: 'deepseek_chat',
            product_cn: 'DeepSeek Chat',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/api/v0/chat/completion',
            status: 'success',
            status_code: 200,
            response_bytes: 1065,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_deepseek_reasoning_fragments',
        request_content: '你这个市什么',
        response_content: [
          '嗯',
          '用户',
          '问',
          '你这个',
          '市',
          '什么',
          '看起来',
          '可能是',
          '打字',
          '错误',
          '或者',
          '表达',
          '不',
          '完整',
          '我应该',
          '理解',
          '这个',
          '意图',
          '不要',
          '直接',
          '指出',
          '错误',
          '而是',
          '友好',
          '地',
          '纠正',
          '并',
          '自我介绍',
          '哎呀',
          '我',
          '猜',
          '你',
          '可能是',
          '想问',
          '你',
          '是什么',
          '吧',
          '我是',
          '一个',
          '由',
          '深度',
          '求',
          '索',
          '公司',
          '创造的',
          '助手',
          '我可以',
          '帮你',
          '回答问题',
          '提供',
          '建议',
        ].join('\n'),
        retention_until: '2026-09-10T21:20:01+08:00',
        file_metadata: [],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    expect(screen.queryByTestId('retained-text-reasoning')).not.toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', {name:/查看过程/}))
    const reasoningPanel = await screen.findByTestId('retained-text-reasoning')
    await waitFor(() => expect(reasoningPanel).toHaveTextContent('嗯用户问你这个市什么看起来可能是打字错误'))
    expect(reasoningPanel).toHaveTextContent('我应该理解这个意图')

    const answerPanel = await screen.findByTestId('retained-text-response')
    await waitFor(() => expect(answerPanel).toHaveTextContent('哎呀我猜你可能是想问你是什么吧'))
    expect(answerPanel).toHaveTextContent('我是一个由深度求索公司创造的助手')
    expect(answerPanel).not.toHaveTextContent('用户问你这个市什么')
    expect(answerPanel).not.toHaveTextContent('我应该理解这个意图')
    expect(answerPanel.querySelector('.retention-rich-text')).not.toBeNull()
  }, 30000)


  it('splits reasoning into its own panel for non-DeepSeek providers carrying [reasoning] markers', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_codebuddy_reasoning_markers',
            created_at: '2026-06-14T10:00:00Z',
            source_ip: '192.168.31.120',
            target_host: 'copilot.tencent.com',
            target_path: '/v2/chat/completions',
            method: 'POST',
            provider: 'tencent',
            provider_cn: '\u817e\u8baf',
            product: 'codebuddy',
            product_cn: '\u817e\u8baf CodeBuddy / WorkBuddy',
            access_type: 'llm',
            endpoint_kind: 'ai_ide_agent',
            path_template: '/v2/chat/completions',
            status: 'success',
            status_code: 200,
            response_bytes: 1115,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_codebuddy_reasoning_markers',
        request_content: '\u5e2e\u6211\u770b\u4e0b\u8fd9\u4e2a\u4ed3\u5e93',
        response_content: [
          '[reasoning] The user is asking me to look at the repository.',
          '[reasoning] I should read BOOTSTRAP.md and SOUL.md before answering.',
          '[reasoning] USER.md says to reply in Chinese, so I will respond in Chinese.',
          '\u4f60\u597d\uff0c\u6211\u662f CodeBuddy \u52a9\u624b\u3002',
          '\u6211\u5df2\u7ecf\u8bfb\u53d6\u4e86\u4ed3\u5e93\u7ed3\u6784\uff0c\u6709\u4ec0\u4e48\u9700\u8981\u6211\u534f\u52a9\u7684\u5417\uff1f',
        ].join('\n'),
        retention_until: '2026-09-12T10:00:00+08:00',
        file_metadata: [],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    expect(screen.queryByTestId('retained-text-reasoning')).not.toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', {name:/查看过程/}))
    const reasoningPanel = await screen.findByTestId('retained-text-reasoning')
    await waitFor(() => expect(reasoningPanel).toHaveTextContent('I should read BOOTSTRAP.md and SOUL.md before answering.'))
    expect(reasoningPanel).toHaveTextContent('The user is asking me to look at the repository.')

    const answerPanel = await screen.findByTestId('retained-text-response')
    await waitFor(() => expect(answerPanel).toHaveTextContent('\u4f60\u597d\uff0c\u6211\u662f CodeBuddy \u52a9\u624b\u3002'))
    expect(answerPanel).toHaveTextContent('\u6211\u5df2\u7ecf\u8bfb\u53d6\u4e86\u4ed3\u5e93\u7ed3\u6784')
    expect(answerPanel).not.toHaveTextContent('BOOTSTRAP.md')
    expect(answerPanel).not.toHaveTextContent('The user is asking me to look at the repository.')
  }, 30000)

  it('splits single-line DeepSeek reasoning history from the final answer', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_deepseek_reasoning_single_line',
            created_at: '2026-06-12T13:20:01Z',
            source_ip: '192.168.31.108',
            target_host: 'chat.deepseek.com',
            target_path: '/api/v0/chat/completion',
            method: 'POST',
            provider: 'deepseek',
            provider_cn: 'DeepSeek',
            product: 'deepseek_chat',
            product_cn: 'DeepSeek Chat',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/api/v0/chat/completion',
            status: 'success',
            status_code: 200,
            response_bytes: 1065,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_deepseek_reasoning_single_line',
        request_content: '你这个市什么',
        response_content: '嗯用户问你这个市什么看起来可能是打字错误或者表达不完整结合常见的提问方式用户可能是想问我是什么我应该理解这个意图不要直接指出错误而是友好地纠正并自我介绍哎呀我猜你可能是想问你是什么吧我是一个由深度求索公司创造的助手我可以帮你回答问题提供建议',
        retention_until: '2026-09-10T21:20:01+08:00',
        file_metadata: [],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    expect(screen.queryByTestId('retained-text-reasoning')).not.toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', {name:/查看过程/}))
    const reasoningPanel = await screen.findByTestId('retained-text-reasoning')
    await waitFor(() => expect(reasoningPanel).toHaveTextContent('嗯用户问你这个市什么看起来可能是打字错误'))

    const answerPanel = await screen.findByTestId('retained-text-response')
    await waitFor(() => expect(answerPanel).toHaveTextContent('哎呀我猜你可能是想问你是什么吧'))
    expect(answerPanel).not.toHaveTextContent('用户问你这个市什么')
  }, 30000)

  it('shows Kimi Word file references as downloadable files and reflows fragmented answer text', async () => {
    mockCatalog()
    const fileURL = 'https://www.kimi.com/apiv2-files/sign-obj/kimi-fs%2Ffiles%2Fblob%2Fa4d8112c7ab15f661211e7b5de645562383d4e75348d8f3dd844355fe4ed2298?filename=QAgent+%E9%85%8D%E7%BD%AE%E8%93%9D%E4%BF%A1%E9%80%9A%E9%81%93%E6%93%8D%E4%BD%9C%E6%96%87%E6%A1%A3_V1.1.docx&demo=1&t=o'
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_kimi_word_upload',
            created_at: '2026-06-12T11:44:35Z',
            source_ip: '192.168.31.108',
            target_host: 'www.kimi.com',
            target_path: '/apiv2/kimi.gateway.chat.v1.ChatService/Chat',
            method: 'POST',
            provider: 'moonshot',
            provider_cn: '月之暗面',
            product: 'kimi',
            product_cn: 'Kimi',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/apiv2/kimi.gateway.chat.v1.ChatService/Chat',
            status: 'success',
            status_code: 200,
            response_bytes: 81715,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_kimi_word_upload',
        request_content: '这个咋样',
        response_content:
          `[chat.files.meta.type] FILE_TYPE_DOCUMENT\n[chat.files.blob.signUrl] ${fileURL}\n[chat.files.blob.previewUrl] https://www.kimi.com/apiv2-files/sign-obj/kimi-fs%2Ffiles%2Fblob%2Fa4d8112c7ab15f661211e7b5de645562383d4e75348d8f3dd844355fe4ed2298?filename=a4d811.docx&preview=1&t=o\n这是\n**\nQ\nAgent\n配置\n蓝信\n通道\n操作\n文档\n**\n，\n整体\n建议\n补充\n：\n\`\`\`text\n#\n示例\n命令\ngrep\n"\n_id\n"\n/var\n/log\n/qagent\n/sso.log\n\`\`\`\nappend\nblock.text.content`,
        retention_until: '2026-09-10T19:44:35+08:00',
        file_metadata: [],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    let clickedHref = ''
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function mockClick(this: HTMLAnchorElement) {
      clickedHref = this.getAttribute('href') || this.href
    })

    try {
      renderPage()
      await openFirstDetail()

      expect(await screen.findByText('用户上传文件')).toBeInTheDocument()
      expect(screen.getByText('QAgent 配置蓝信通道操作文档_V1.1.docx')).toBeInTheDocument()
      const answerPanel = await screen.findByTestId('retained-text-response')
      await waitFor(() => expect(answerPanel).toHaveTextContent('这是 Q Agent 配置蓝信通道操作文档，整体建议补充：'))
      expect(answerPanel).toHaveTextContent('# 示例命令 grep "_id" /var/log/qagent/sso.log')
      expect(answerPanel).not.toHaveTextContent('FILE_TYPE_DOCUMENT')
      expect(answerPanel).not.toHaveTextContent('signUrl')
      expect(answerPanel).not.toHaveTextContent('block.text.content')
      fireEvent.click(screen.getByRole('button', { name: /下载留存副本/ }))
      expect(clickSpy).toHaveBeenCalled()
      expect(clickedHref).toBe(fileURL)
    } finally {
      clickSpy.mockRestore()
    }
  }, 30000)


  it('shows model generated files in a separate downloadable section', async () => {
    mockCatalog()
    const fileURL = 'https://files.example.com/generated/audit-report.docx?download=1'
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_model_generated_file',
            created_at: '2026-06-12T12:00:00Z',
            source_ip: '192.168.31.108',
            target_host: 'chatgpt.com',
            target_path: '/backend-api/f/conversation',
            method: 'POST',
            provider: 'openai',
            provider_cn: 'OpenAI',
            product: 'chatgpt',
            product_cn: 'ChatGPT',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/backend-api/f/conversation',
            status: 'success',
            status_code: 200,
            response_bytes: 2048,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_model_generated_file',
        request_content: '生成一份审计报告',
        response_content: '已生成审计报告。',
        retention_until: '2026-09-10T20:00:00+08:00',
        file_metadata: [
          {
            source: 'json_file_url',
            stage: 'response',
            field_name: 'artifacts.download_url',
            file_name: 'audit-report.docx',
            content_type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            size: 4096,
            sha256: '',
            download_url: fileURL,
          },
        ],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    let clickedHref = ''
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function mockClick(this: HTMLAnchorElement) {
      clickedHref = this.getAttribute('href') || this.href
    })

    try {
      renderPage()
      await openFirstDetail()

      expect(await screen.findByText('模型生成文件')).toBeInTheDocument()
      expect(screen.getByText('audit-report.docx')).toBeInTheDocument()
      expect(screen.queryByText('用户上传文件')).not.toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: /下载留存副本/ }))
      expect(clickSpy).toHaveBeenCalled()
      expect(clickedHref).toBe(fileURL)
    } finally {
      clickSpy.mockRestore()
    }
  }, 30000)

  it('cleans Doubao web JSON protocol blocks and reflows duplicated fragments', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_doubao_web_dirty',
            created_at: '2026-06-12T06:10:00Z',
            source_ip: '192.168.31.108',
            target_host: 'www.doubao.com',
            target_path: '/chat/completion?aid=497858',
            method: 'POST',
            provider: 'bytedance',
            provider_cn: '字节跳动',
            product: 'doubao',
            product_cn: '豆包',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/chat/completion',
            status: 'success',
            status_code: 200,
            response_bytes: 5243,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_doubao_web_dirty',
        request_content: '小众服装品牌的质量有保障吗？',
        response_content:
          '小众服装品牌的质量有保障吗？\n[{"block_type":10000,"block_id":"5c1856a4-7722-49c1-bc9a-a39ad3bd058d","content":{"text_block":{"text":" 小众服装品牌的质量有保障吗？"}}}]\n小众\n小众\n{"ack_cost_time":"15","agent_id":"19457456070409730","agent_name":"豆包","first_packet_cost_time":"15","llm_intention":"seed_main","llm_intention_detail":"knowledge"}\n{"plugin_intention":"","plugin_generalize_intention":"无","branch_intention":"Branch-Knowledge","intention_ori_score":"{"AgentECommerceRawValue":0.7025300573952054,"SearchRawValue":0.879146767509}"}\n{"bot_id":"7338286299411103781","bot_name":"豆包","agent_name":"豆包","agent_id":"19457456070409730","intent_agent_name":"Agent-Knowledge"}\n品牌\n品牌\n**\n质量\n质量\n不能\n不能\n一概\n一概\n而论\n而论\n**\n，整体分梯队、看\n，整体分梯队、看\n类型，结合品类、定价\n类型，结合品类、定价\n、产地就能快速判断。\n、产地就能快速判断。',
        retention_until: '2026-09-10T16:40:53+08:00',
        file_metadata: [],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    const answerPanel = await screen.findByTestId('retained-text-response')
    await waitFor(() => expect(answerPanel).toHaveTextContent('品牌质量不能一概而论，整体分梯队、看类型，结合品类、定价、产地就能快速判断。'))
    const answerText = answerPanel.textContent || ''
    expect(answerText).not.toContain('block_type')
    expect(answerText).not.toContain('ack_cost_time')
    expect(answerText).not.toContain('agent_id')
    expect(answerText).not.toContain('intention_ori_score')
    expect(answerText).not.toContain('AgentECommerceRawValue')
  }, 30000)

  it('reflows fragmented DeepSeek web answers into readable paragraphs', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_deepseek_fragmented',
            created_at: '2026-06-12T08:40:53Z',
            source_ip: '192.168.31.108',
            target_host: 'chat.deepseek.com',
            target_path: '/api/v0/chat/completion',
            method: 'POST',
            provider: 'deepseek',
            provider_cn: 'DeepSeek',
            product: 'deepseek_chat',
            product_cn: 'DeepSeek Chat',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/api/v0/chat/completion',
            status: 'success',
            status_code: 200,
            response_bytes: 2072,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_deepseek_fragmented',
        request_content: '怎么样',
        response_content: '我们需要\n评估\n用户\n问\n怎么样\n是指\n对\n前\n文\n生成的\n智能\n体\n安全\n白\n皮书\n文章\n的评价\n。\n整体\n结构\n清晰\n，\n但\n可以\n更\n聚焦\n。',
        retention_until: '2026-09-10T16:40:53+08:00',
        file_metadata: [],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    const answerPanel = await screen.findByTestId('retained-text-response')
    await waitFor(() => expect(answerPanel).toHaveTextContent('我们需要评估用户问怎么样是指对前文生成的智能体安全白皮书文章的评价。整体结构清晰，但可以更聚焦。'))
    expect(answerPanel.textContent || '').not.toContain('我们需要\n评估')
  }, 30000)

  it('shows AI development tool traffic with clear TLS visibility', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_cursor_agent',
            created_at: '2026-06-10T09:00:00Z',
            source_ip: '10.10.10.18',
            target_host: 'api5.cursor.sh',
            target_path: '/aiserver.v1.AgentService/StreamBidi',
            method: 'POST',
            provider: 'cursor',
            provider_cn: 'Cursor',
            product: 'cursor_agent',
            product_cn: 'Cursor Agent',
            access_type: 'ai_ide',
            endpoint_kind: 'coding',
            path_template: '/aiserver.v1.AgentService/StreamBidi',
            status: 'success',
            status_code: 200,
            response_bytes: 8192,
            tls_inspected: false,
            retention_level: 'summary',
            content_retained: false,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
            access_direction: 'forward',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, ai_ide_count: 1, forward_count: 1, top_providers: [{ name: 'cursor', count: 1, risk_count: 0 }], top_targets: [{ name: 'api5.cursor.sh', count: 1, risk_count: 0 }] },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()

    // 标签页已移除：大模型口径默认包含 AI 开发工具流量（access_type=undefined → 后端取 llm+ai_ide），无需再切 tab。
    await waitFor(() => {
      expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({ access_type: undefined, provider: undefined, risk_state: undefined, target_host: undefined, direction: undefined, content_only: true, skip_total: true }))
      expect(screen.getAllByText('AI 开发工具访问').length).toBeGreaterThan(0)
      expect(screen.getByText('Cursor Agent')).toBeInTheDocument()
      expect(screen.getAllByText('api5.cursor.sh').length).toBeGreaterThan(0)
    })

    // HTTPS 审计列已移除；TLS 可见性说明仍保留在访问详情抽屉中。
    await openFirstDetail()

    await waitFor(() => {
      expect(screen.getByText(/仅元数据可见，无法检测 prompt、代码片段或文件内容/)).toBeInTheDocument()
    })
  }, 30000)

  it('defaults to decrypted content evidence rather than full request logs', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({ data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {} } as any)
    renderPage()
    await waitFor(() => expect(listSpy).toHaveBeenCalledWith(expect.objectContaining({ access_type: undefined, provider: undefined, risk_state: undefined, target_host: undefined, direction: undefined, content_only: true, skip_total: true })))
    expectDefaultListWindow(listSpy.mock.calls[0][0])
    fireEvent.click(screen.getByRole('button', { name: /高级筛选/ }))
    // 风险筛选改为统一「风险状态」下拉，不再是独立标签页；content_only 固定为 true。
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '风险状态' }))
    fireEvent.click(screen.getByText('风险'))
    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({ access_type: undefined, provider: undefined, risk_state: 'risk', target_host: undefined, direction: undefined, content_only: true, skip_total: true })))
  })

  it('keeps metadata-only CONNECT records out of the default content evidence list', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_codex_retained',
            created_at: '2026-06-15T11:30:00Z',
            source_ip: '172.26.0.1',
            target_host: 'api.openai.com',
            target_path: '/v1/responses',
            method: 'POST',
            provider: 'openai',
            provider_cn: 'OpenAI',
            product: 'codex',
            product_cn: 'Codex',
            access_type: 'ai_ide',
            endpoint_kind: 'chat',
            path_template: '/v1/responses',
            status: 'success',
            status_code: 200,
            response_bytes: 8192,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
            access_direction: 'forward',
            agent_type: 'openai-codex',
            agent_label: 'OpenAI Codex',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, ai_ide_count: 1, retained_content_count: 1, forward_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()

    await waitFor(() =>
      expect(listSpy).toHaveBeenCalledWith(expect.objectContaining({ access_type: undefined, provider: undefined, risk_state: undefined, target_host: undefined, direction: undefined, content_only: true, skip_total: true })),
    )
    expect(await screen.findByText('Codex')).toBeInTheDocument()
    expect(screen.getByText('OpenAI Codex')).toBeInTheDocument()
    expect(screen.queryByText('model_local_qwen25_7b')).not.toBeInTheDocument()
    expect(screen.getByText(/本页聚焦解密后可审计的客户内容、模型响应、文件引用与审计处置证据/)).toBeInTheDocument()
  })

  it('filters content evidence by responsibility without changing other default filters', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({ data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {} } as any)

    renderPage()

    await waitFor(() => expect(listSpy).toHaveBeenCalledWith(expect.objectContaining({ access_type: undefined, provider: undefined, risk_state: undefined, target_host: undefined, direction: undefined, content_only: true, skip_total: true })))
    expect(screen.getByPlaceholderText('搜索模型 / 域名')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('搜索来源 IP / 应用 / 入口')).toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: '风险状态' })).not.toBeInTheDocument()
    const advanced = screen.getByRole('button', { name: /高级筛选/ })
    expect(advanced).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(advanced)
    expect(screen.getByRole('combobox', { name: '风险状态' })).toBeInTheDocument()
    fireEvent.change(screen.getByPlaceholderText('搜索来源 IP / 应用 / 入口'), { target: { value: '研发入口' } })

    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({ source_ip: '研发入口' })))
  })

  it('uses a separate abortable user selector and preserves the frozen time window', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({ data: { data: [], total: 0, has_more: false, total_known: true, summary: emptySummary } } as any)
    const usersSpy = api.contentAuditApi.listUsers as ReturnType<typeof vi.fn>

    renderPage()
    await waitFor(() => expect(listSpy).toHaveBeenCalled())
    const initial = listSpy.mock.calls[0][0]!
    await waitFor(() => expect(usersSpy).toHaveBeenCalledWith(expect.objectContaining({
      limit: 50,
      signal: expect.any(AbortSignal),
    })))

    fireEvent.mouseDown(screen.getByRole('combobox', { name: '人员筛选' }))
    fireEvent.click(await screen.findByText('张三 · 研发部'))

    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({
      user_id: 'user_42',
      from: initial.from,
      to: initial.to,
    })))
    expect(screen.getByPlaceholderText('搜索来源 IP / 应用 / 入口')).toBeInTheDocument()
  })

  it('searches retained request, response and file evidence by submitted keyword', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({ data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {} } as any)

    renderPage()
    await waitFor(() => expect(listSpy).toHaveBeenCalled())
    const input = screen.getByPlaceholderText('搜索留证正文 / 文件名')
    fireEvent.change(input, { target: { value: '  登录失败  ' } })
    expect(listSpy).not.toHaveBeenLastCalledWith(expect.objectContaining({ keyword: '登录失败' }))
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter', charCode: 13 })

    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({ keyword: '登录失败' })))
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '正文搜索范围' }))
    fireEvent.click(await screen.findByText('仅模型输出'))
    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({ keyword: '登录失败', keyword_scope: 'response', offset: 0 })))
    expect(screen.getByText('已搜索：模型输出「登录失败」')).toBeInTheDocument()

  })

  it('paginates keyword matches past the first 100 rows and resets filters before querying', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockImplementation(async (params: any) => ({
      data: {
        data: [{ request_id: `req_${params?.offset || 0}`, created_at: '2026-08-15T00:00:00Z', target_host: 'api.example.com', access_type: 'llm', status: 'success', risk_state: 'normal', content_retained: true, disposition_status: 'open' }],
        total: (params?.offset || 0) + 21,
        has_more: true,
        total_known: false,
        summary: emptySummary,
      },
    } as any))

    renderPage()
    await waitFor(() => expect(listSpy).toHaveBeenCalled())
    const keywordInput = screen.getByPlaceholderText('搜索留证正文 / 文件名')
    fireEvent.change(keywordInput, { target: { value: '登录失败' } })
    fireEvent.keyDown(keywordInput, { key: 'Enter', code: 'Enter', charCode: 13 })

    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({
      keyword: '登录失败',
      limit: 20,
      offset: 0,
      skip_total: true,
      signal: expect.any(AbortSignal),
    })))
    fireEvent.click(screen.getByTitle(/Next Page|\u4e0b\u4e00\u9875/))
    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({
      keyword: '登录失败',
      limit: 20,
      offset: 20,
    })))

    const callsBeforeFilter = listSpy.mock.calls.length
    fireEvent.change(screen.getByPlaceholderText('搜索来源 IP / 应用 / 入口'), { target: { value: '研发入口' } })
    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({
      keyword: '登录失败',
      source_ip: '研发入口',
      offset: 0,
    })))
    const callsAfterFilter = listSpy.mock.calls.slice(callsBeforeFilter)
    expect(callsAfterFilter.every(([params]) => params?.offset === 0)).toBe(true)
  })

  it('does not render redundant traffic-direction metric tiles', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [],
        total: 0,
        summary: { ...emptySummary, forward_count: 3, reverse_count: 2, device_count: 0 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()

    await waitFor(() => {
      expect(screen.queryByText('反向代理流量')).not.toBeInTheDocument()
      expect(screen.queryByText('正向代理流量')).not.toBeInTheDocument()
      expect(screen.queryByText('经过设备的流量')).not.toBeInTheDocument()
    })
  })

  it('uses filtered summary top_providers for provider option counts', async () => {
    vi.spyOn(api.llmProviderCatalogApi, 'list').mockResolvedValue({
      data: {
        data: [],
        providers: [
          { value: 'deepseek', label: 'DeepSeek', count: 99 },
          { value: 'openai', label: 'OpenAI', count: 88 },
        ],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [],
        total: 2,
        summary: { ...emptySummary, total: 2, top_providers: [{ name: 'deepseek', count: 2, risk_count: 0 }] },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()

    await waitFor(() => expect(api.accessRetentionApi.list).toHaveBeenCalled())
    fireEvent.click(screen.getByRole('button', { name: /高级筛选/ }))
    fireEvent.mouseDown(await screen.findByRole('combobox', { name: '服务商' }))

    await waitFor(() => {
      expect(screen.getByText('DeepSeek (2)')).toBeInTheDocument()
      expect(screen.queryByText('DeepSeek (99)')).not.toBeInTheDocument()
      expect(screen.queryByText('OpenAI (88)')).not.toBeInTheDocument()
    })
  })

  it('renders a traffic-direction column with a Tag', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_reverse_001',
            created_at: '2026-06-06T10:00:00Z',
            source_ip: '10.10.10.9',
            target_host: 'api.internal',
            target_path: '/v1/chat/completions',
            method: 'POST',
            provider: 'deepseek',
            provider_cn: 'DeepSeek',
            product: 'deepseek_api',
            product_cn: 'DeepSeek API',
            access_type: 'llm',
            endpoint_kind: 'api',
            path_template: '/v1/chat/completions',
            status: 'success',
            status_code: 200,
            response_bytes: 2048,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'none',
            security_event_count: 0,
            disposition_status: 'open',
            access_direction: 'reverse',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, reverse_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()

    await waitFor(() => {
      expect(screen.getAllByText('流量方向').length).toBeGreaterThan(0)
      expect(screen.getAllByText('反向代理').length).toBeGreaterThan(0)
    })
  })

  it('queries direction=device and shows honest empty state for 经过设备', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({ data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {} } as any)
    renderPage()

    await waitFor(() => expect(listSpy).toHaveBeenCalled())
    fireEvent.click(screen.getByRole('button', { name: /高级筛选/ }))

    // 方向从 Segmented 标签改为统一「访问方向」下拉。
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '访问方向' }))
    fireEvent.click(screen.getByText('经过设备'))

    await waitFor(() =>
      expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({ access_type: undefined, provider: undefined, risk_state: undefined, target_host: undefined, direction: 'device', content_only: true, skip_total: true })),
    )
    await waitFor(() => expect(screen.getByText('暂无经过设备的流量接入')).toBeInTheDocument())
  })

  it('sends skip_total and a configurable bounded time window for list requests', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({ data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {} } as any)

    renderPage()

    await waitFor(() => expect(listSpy).toHaveBeenCalled())
    expectDefaultListWindow(listSpy.mock.calls[0][0], 1)
    expect(screen.getByText('近 24h')).toBeInTheDocument()

    // 时间窗从 Segmented 标签改为统一「时间范围」下拉（第 4 个 combobox）。
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '时间范围' }))
    fireEvent.click(screen.getByText('近 30 天'))

    await waitFor(() => {
      const latestParams = listSpy.mock.calls[listSpy.mock.calls.length - 1]?.[0]
      expectDefaultListWindow(latestParams, 30)
    })
  })

  it('uses server-side pagination and resets to the first page when filters change', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [{ request_id: 'req_page_1', created_at: '2026-06-06T00:00:00Z', target_host: 'page.example', access_type: 'llm', status: 'success', risk_state: 'normal', content_retained: true, disposition_status: 'open' }], total: 125 },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()

    await waitFor(() => expect(listSpy).toHaveBeenCalled())
    await screen.findByText('page.example')
    expectDefaultListWindow(listSpy.mock.calls[0][0], 1, true)
    fireEvent.click(screen.getByTitle(/Next Page|\u4e0b\u4e00\u9875/))

    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({
      limit: 20,
      offset: 20,
      skip_summary: true,
      skip_total: true,
    })))

    fireEvent.click(screen.getByRole('button', { name: /\u9ad8\u7ea7\u7b5b\u9009/ }))
    fireEvent.change(screen.getByPlaceholderText(/IP/), { target: { value: '10.0.0.1' } })

    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(expect.objectContaining({
      limit: 20,
      offset: 0,
      source_ip: '10.0.0.1',
      skip_summary: true,
      skip_total: true,
    })))
  })

  it('keeps the detail list independent from the overview aggregation', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 7, summary: emptySummary },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    summarySpy.mockResolvedValue({
      data: { total: 0, summary: { ...emptySummary, total: 0 }, summary_error: 'summary_unavailable' },
    })

    renderPage('/audit/access-retention?view=requests')

    await waitFor(() => expect(screen.getByText('\u5171 7 \u6761')).toBeInTheDocument())
    expect(summarySpy).not.toHaveBeenCalled()
  })
  it('exports current filtered records when clicking 导出留证', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({ data: { data: [{ request_id: 'req_page_1', created_at: '2026-06-06T00:00:00Z', target_host: 'page.example', access_type: 'llm', status: 'success', risk_state: 'normal', content_retained: true, disposition_status: 'open' }], total: 125 }, status: 200, statusText: 'OK', headers: {}, config: {} } as any)
    const exportSpy = vi.spyOn(api.accessRetentionApi, 'export').mockResolvedValue({ data: new Blob(['\ufeff请求ID\n'], { type: 'text/csv' }), status: 200, statusText: 'OK', headers: {}, config: {} } as any)
    const createObjectURL = vi.fn(() => 'blob:mock-url')
    const revokeObjectURL = vi.fn()
    const prevCreateObjectURL = (globalThis.URL as any).createObjectURL
    const prevRevokeObjectURL = (globalThis.URL as any).revokeObjectURL
    ;(globalThis.URL as any).createObjectURL = createObjectURL
    ;(globalThis.URL as any).revokeObjectURL = revokeObjectURL
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const originalCreateElement = document.createElement.bind(document)
    let exportedDownload = ''
    const createElementSpy = vi.spyOn(document, 'createElement').mockImplementation((tagName: string, options?: ElementCreationOptions) => {
      const element = originalCreateElement(tagName, options)
      if (tagName.toLowerCase() === 'a') {
        Object.defineProperty(element, 'download', {
          configurable: true,
          get: () => exportedDownload,
          set: (value: string) => {
            exportedDownload = value
          },
        })
      }
      return element
    })

    try {
      renderPage()
      await waitFor(() => expect(api.accessRetentionApi.list).toHaveBeenCalled())
      await screen.findByText('page.example')
      fireEvent.click(screen.getByTitle(/Next Page|\u4e0b\u4e00\u9875/))
      await waitFor(() => expect(api.accessRetentionApi.list).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 20 })))

      fireEvent.click(screen.getByRole('button', { name: /导出留证/ }))

      await waitFor(() =>
        expect(exportSpy).toHaveBeenCalledWith(expect.objectContaining({
          access_type: undefined,
          provider: undefined,
          risk_state: undefined,
          target_host: undefined,
          direction: undefined,
          content_only: true,
          limit: 100000,
          offset: 0,
        })),
      )
      expect(exportSpy.mock.calls[0][0]).not.toEqual(expect.objectContaining({ limit: 20, offset: 20 }))
      await waitFor(() => expect(createObjectURL).toHaveBeenCalled())
      expect(clickSpy).toHaveBeenCalled()
      expect(exportedDownload).toMatch(/^内容留证-\d{4}-\d{2}-\d{2}\.csv$/)
    } finally {
      (globalThis.URL as any).createObjectURL = prevCreateObjectURL
      ;(globalThis.URL as any).revokeObjectURL = prevRevokeObjectURL
      clickSpy.mockRestore()
      createElementSpy.mockRestore()
    }
  })

  it('classifies ChatGPT json_file_object input_message echo as a user upload, not a model-returned image', async () => {
    // ChatGPT 网页版发「图片 + 文字」时，SSE 流里会把用户那条 input_message 原样回放一遍，
    // 于是对话行的 file_metadata 同一张上传图片出现两次：
    //   Entry1 stage=request  field=messages.metadata.attachments     —— 真正的用户上传
    //   Entry2 stage=response field=input_message.metadata.attachments —— 流里回放的同一条，仍是用户上传
    // 两条 source 都是 json_file_object、同一 reference_id、均无 data_base64（像素未留存）。
    // 修复前 Entry2 因 stage=response 被误判进「模型返回图片」。本测试钉死：两条都归入
    // 「用户上传文件」，去重后只剩一张卡片，且绝不出现「模型返回图片」面板。
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_chatgpt_uploaded_image',
            created_at: '2026-06-12T13:09:45Z',
            source_ip: '192.168.31.108',
            target_host: 'chatgpt.com',
            target_path: '/backend-api/conversation',
            method: 'POST',
            provider: 'openai',
            provider_cn: 'OpenAI',
            product: 'chatgpt',
            product_cn: 'ChatGPT',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/backend-api/conversation',
            status: 'success',
            status_code: 200,
            response_bytes: 1024,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_chatgpt_uploaded_image',
        request_content: '',
        response_content: '',
        retention_until: '2026-09-12T21:09:45+08:00',
        file_metadata: [
          {
            source: 'json_file_object',
            stage: 'request',
            field_name: 'messages.metadata.attachments',
            file_name: '测试图片.jpg',
            reference_id: 'file_testchatgptimage0001',
            content_type: 'image/jpeg',
            size: 2012314,
            sha256: '',
          },
          {
            source: 'json_file_object',
            stage: 'response',
            field_name: 'input_message.metadata.attachments',
            file_name: '测试图片.jpg',
            reference_id: 'file_testchatgptimage0001',
            content_type: 'image/jpeg',
            size: 2012314,
            sha256: '',
          },
        ],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    expect(await screen.findByText('用户上传文件')).toBeInTheDocument()
    expect(screen.getAllByText('测试图片.jpg').length).toBeGreaterThan(0)
    expect(screen.queryByText('模型返回图片')).not.toBeInTheDocument()
  }, 30000)

  it('does not classify Claude Code documentation URLs as uploaded images when tool text mentions images', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [{
          request_id: 'req_claude_code_tool_urls', created_at: '2026-07-26T01:00:00Z', source_ip: '192.168.31.108',
          target_host: 'api.anthropic.com', target_path: '/v1/messages', method: 'POST', provider: 'anthropic',
          provider_cn: 'Anthropic', product: 'claude_code', product_cn: 'Claude Code', access_type: 'ai_ide',
          endpoint_kind: 'chat', path_template: '/v1/messages', status: 'success', status_code: 200,
          response_bytes: 1024, tls_inspected: true, retention_level: 'content', content_retained: true,
          risk_state: 'normal', action_taken: 'allow', security_event_count: 0, disposition_status: 'open',
        }],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, ai_ide_count: 1, retained_content_count: 1 },
      },
      status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_claude_code_tool_urls',
        request_content: [
          'The image tool can inspect screenshots.',
          '{"url":"https://docs.example.com/mcp"}',
          '{"url":"https://github.com/example/repo%20(required)"}',
          '{"url":"https://docs.example.com/sse"}',
          '帮我检查当前项目。',
        ].join('\n'),
        response_content: '可以。', retention_until: '2026-10-26T09:00:00+08:00', file_metadata: [],
      },
      status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    expect(await screen.findByText('用户提问')).toBeInTheDocument()
    expect(screen.queryByText('用户上传文件')).not.toBeInTheDocument()
    expect(screen.queryByAltText(/用户上传图片/)).not.toBeInTheDocument()
  }, 30000)

  it('renders Doubao pure attachment request fallback text from file metadata', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            request_id: 'req_doubao_attachment_only',
            created_at: '2026-06-21T09:15:00Z',
            source_ip: '192.168.31.28',
            target_host: 'www.doubao.com',
            target_path: '/chat/completion',
            method: 'POST',
            provider: 'bytedance',
            provider_cn: '字节跳动',
            product: 'doubao',
            product_cn: '豆包',
            access_type: 'llm',
            endpoint_kind: 'chat',
            path_template: '/chat/completion',
            status: 'success',
            status_code: 200,
            response_bytes: 2048,
            tls_inspected: true,
            retention_level: 'content',
            content_retained: true,
            risk_state: 'normal',
            action_taken: 'allow',
            security_event_count: 0,
            disposition_status: 'open',
            access_direction: 'forward',
          },
        ],
        total: 1,
        summary: { ...emptySummary, total: 1, normal_count: 1, llm_count: 1, retained_content_count: 1 },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req_doubao_attachment_only',
        request_content: '',
        response_content: '已收到附件。',
        file_metadata: [
          {
            source: 'json_file_object',
            stage: 'request',
            field_name: 'messages.content_block.content.attachment_block.attachments.file',
            file_name: '需求说明.docx',
            reference_id: 'file_doubao_docx_000001',
            content_type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            size: 12345,
          },
          {
            source: 'json_file_object',
            stage: 'request',
            field_name: 'messages.content_block.content.attachment_block.attachments.image',
            reference_id: 'file_doubao_image_000001',
            content_type: 'image/png',
            size: 23456,
          },
        ],
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    } as any)

    renderPage()
    await openFirstDetail()

    const requestPanel = await screen.findByTestId('retained-text-request')
    await waitFor(() => {
      expect(requestPanel).toHaveTextContent('[附件] 需求说明.docx')
      expect(requestPanel).toHaveTextContent('[图片]')
      expect(requestPanel).not.toHaveTextContent('暂无可展示的请求正文')
    })
  }, 30000)

  it('shows a retryable list error and hides overview metrics', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list')
      .mockRejectedValueOnce(new Error('500 list unavailable'))
      .mockResolvedValueOnce({
        data: { data: [], total: 0, summary: emptySummary },
        status: 200, statusText: 'OK', headers: {}, config: {},
      } as any)

    renderPage('/?view=requests')

    expect(await screen.findByText('留证列表加载失败')).toBeInTheDocument()
    expect(screen.getByText('暂时无法读取内容留证，不会将同步或查询失败显示为 0 条。请检查服务状态后重试。')).toBeInTheDocument()
    expect(screen.queryByText('留证请求')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /重\s*试/ }))
    await waitFor(() => expect(listSpy).toHaveBeenCalledTimes(2))
  })

  it('does not let a cached detail-list failure suppress a healthy overview', async () => {
    mockCatalog()
    const listSpy = vi.spyOn(api.accessRetentionApi, 'list').mockRejectedValue(new Error('500 list unavailable'))
    summarySpy.mockResolvedValue({
      data: { summary: { ...emptySummary, total: 9, normal_count: 9, retained_content_count: 9 } },
    })

    renderPage('/?view=requests')
    expect(await screen.findByText('留证列表加载失败')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('tab', { name: '概览' }))

    const metric = (await screen.findByText('留证请求')).closest('.enterprise-metric-card')
    expect(metric).not.toBeNull()
    await waitFor(() => expect(within(metric as HTMLElement).getByText('9')).toBeInTheDocument())
    expect(screen.queryByText('留证列表加载失败')).not.toBeInTheDocument()
    expect(listSpy).toHaveBeenCalledTimes(1)
  })

  it('shows an explicit AI conversation error without rendering task wording', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'listRuns').mockRejectedValue(new Error('conversation runs unavailable'))

    renderPage('/?view=ai_conversations')

    expect(await screen.findByText('AI 对话视图加载失败')).toBeInTheDocument()
    expect(screen.getByText('AI 对话聚合接口暂不可用，请稍后重试；不会退回原始请求视图。')).toBeInTheDocument()
    expect(screen.queryByText('任务聚合接口暂不可用，请稍后重试；不会退回原始请求视图。')).not.toBeInTheDocument()
  })

  it('does not silently fall back to raw requests when the task view fails', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'listRuns').mockRejectedValue(new Error('runs unavailable'))

    renderPage('/?view=agent_tasks')

    expect(await screen.findByText('智能体任务视图加载失败')).toBeInTheDocument()
    expect(screen.getByText('任务聚合接口暂不可用，请稍后重试；不会退回原始请求视图。')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '任务 / 时间' })).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: '模型 / 外部服务' })).not.toBeInTheDocument()
  })

  it('loads only the aggregate endpoint for the default task table and fetches details on demand', async () => {
    mockCatalog()
    const list = vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    const listRuns = vi.spyOn(api.accessRetentionApi, 'listRuns').mockResolvedValue({
      data: { data: [{
        run_id: 'evr-workbuddy', kind: 'agent_task', correlation_source: 'workbuddy_workspace',
        correlation_confidence: 'exact', representative_request_id: 'req-workbuddy-2',
        member_request_ids: ['req-workbuddy-1', 'req-workbuddy-2'], title: '修复内容留证聚合',
        started_at: '2026-08-24T14:46:00Z', ended_at: '2026-08-24T14:52:00Z', duration_ms: 360000,
        agent_type: 'workbuddy', agent_label: 'WorkBuddy', models: ['gpt-5.6-sol'], access_directions: ['chat_completion'],
        request_count: 2, tool_event_count: 1, input_artifact_count: 1, output_artifact_count: 0,
        evidence_status: 'complete', risk_state: 'normal',
      }], total: 1 }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    const getContent = vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: { request_id: 'req-workbuddy-2', user_input: '修复内容留证聚合', model_output: '已完成', messages: [], artifacts: [], file_metadata: [] },
      status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getTimeline').mockResolvedValue({
      data: { data: [] }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)

    renderPage('/?view=agent_tasks')

    expect(await screen.findByText('修复内容留证聚合')).toBeInTheDocument()
    expect(listRuns).toHaveBeenCalledTimes(1)
    expect(list).not.toHaveBeenCalled()
    expect(getContent).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: /查看任务/ }))
    await waitFor(() => expect(getContent).toHaveBeenCalledWith(
      'req-workbuddy-2',
      ['req-workbuddy-1', 'req-workbuddy-2'],
      expect.objectContaining({ from: expect.any(String), to: expect.any(String) }),
    ))
  })

  it('shows a Codex task as one evidence chain with runtime secondary and timeline details', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    const listRuns = vi.spyOn(api.accessRetentionApi, 'listRuns').mockResolvedValue({
      data: { data: [{
        run_id: 'evr_codex', kind: 'agent_task', correlation_source: 'responses_prompt_cache_key',
        correlation_confidence: 'exact', representative_request_id: 'req-2', member_request_ids: ['req-1', 'req-2'],
        title: '制作政企版安全网关 PPT', started_at: '2026-08-05T02:40:00Z', ended_at: '2026-08-05T02:50:00Z', duration_ms: 600000,
        agent_type: 'openai-codex', agent_label: 'OpenAI Codex', agent_runtime: 'vscode',
        agent_detection_source: 'content', agent_detection_confidence: 0.98,
        models: ['gpt-5.6-sol', 'gpt-5.6-luna'], access_directions: ['chat_completion'],
        request_count: 12, tool_event_count: 4, input_artifact_count: 2, output_artifact_count: 1,
        evidence_status: 'complete', risk_state: 'normal',
      }], total: 1 }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    const getContent = vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req-2', request_content: '', response_content: '',
        user_input: '请制作政企版安全网关 PPT', model_output: 'PPT 已生成', evidence_status: 'complete',
        artifacts: [{ id: 'art-1', direction: 'output', kind: 'file', display_name: '安全网关.pptx', media_type: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', byte_size: 4096, sha256: 'abc', retention_status: 'retained', has_preview: false }],
        messages: [
          { id: 'msg-1', request_id: 'req-1', sequence: 1, role: 'user', kind: 'user_input', content: '请制作政企版安全网关 PPT', created_at: '2026-08-05T02:40:00Z' },
          { id: 'msg-2', request_id: 'req-1', sequence: 2, role: 'assistant', kind: 'model_output', content: '正在整理安全能力材料', created_at: '2026-08-05T02:42:00Z' },
          { id: 'msg-3', request_id: 'req-2', sequence: 3, role: 'assistant', kind: 'model_output', content: 'PPT 已生成', created_at: '2026-08-05T02:50:00Z' },
          { id: 'msg-runtime', request_id: 'req-2', sequence: 4, role: 'user', kind: 'user_input', content: 'Analyze this rollout and produce JSON with `raw_memory`.\n\nrollout_context:\n- rollout_path: /Users/example/.codex/sessions/private.jsonl', created_at: '2026-08-05T02:51:00Z' },
        ],
        file_metadata: [],
      }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getTimeline').mockResolvedValue({
      data: { data: [
        { id: 'model-1', type: 'model_calls', title: '模型交互 12 次', detail: 'gpt-5.6-sol、gpt-5.6-luna', status: 'success', timestamp: '2026-08-05T02:40:00Z', count: 12 },
        { id: 'model-2', type: 'model_calls', title: '模型交互 1 次', detail: 'gpt-5.6-sol', status: 'failed', timestamp: '2026-08-05T02:41:00Z', count: 1 },
        { id: 'tool-1', type: 'tool_action', title: 'shell_command', detail: 'npm test', status: 'success', event_kind: 'execution_forwarded', fact_label: '已转发执行', timestamp: '2026-08-05T02:45:00Z', count: 1 },
        { id: 'tool-2', type: 'tool_action', title: 'exec', detail: 'npm run build', status: 'success', event_kind: 'invocation_proposed', fact_label: '调用请求', timestamp: '2026-08-05T02:46:00Z', count: 3 },
        { id: 'tool-inventory', type: 'tool_inventory', title: '可用工具', detail: 'Bash、Read、exec', status: 'recorded', event_kind: 'definition_exposed', timestamp: '2026-08-05T02:44:00Z', count: 3 },
      ] }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)

    renderPage('/?view=agent_tasks')
    await waitFor(() => {
      expect(screen.getByText('制作政企版安全网关 PPT')).toBeInTheDocument()
      expect(screen.getAllByText('OpenAI Codex').length).toBeGreaterThan(0)
      expect(screen.getByText('运行环境：VS Code')).toBeInTheDocument()
      expect(screen.queryByText(/^VS Code$/)).not.toBeInTheDocument()
      expect(screen.getByText('12 次模型交互')).toBeInTheDocument()
      expect(screen.getByText('工具与附件明细点击任务后加载')).toBeInTheDocument()
      expect(screen.getByText('精确关联')).toBeInTheDocument()
    })
    expect(listRuns).toHaveBeenCalledWith(expect.objectContaining({ view: 'agent_tasks' }))

    fireEvent.click(screen.getByRole('button', { name: /查看任务/ }))
    await waitFor(() => {
      expect(screen.getByText('对话留证')).toBeInTheDocument()
      expect(screen.getByTestId('retained-text-request')).toHaveTextContent('请制作政企版安全网关 PPT')
      expect(screen.getByText('PPT 已生成')).toBeInTheDocument()
      expect(screen.getAllByTestId('retained-message-user')).toHaveLength(1)
      expect(screen.getAllByTestId('retained-message-assistant')).toHaveLength(1)
      expect(screen.queryByText('正在整理安全能力材料')).not.toBeInTheDocument()
      expect(screen.queryByText('任务行为摘要')).not.toBeInTheDocument()
      expect(screen.getByText('安全网关.pptx')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button',{name:/查看过程/}))
    expect(await screen.findByText('正在整理安全能力材料')).toBeInTheDocument()
    expect(await screen.findByText('调用请求')).toBeInTheDocument()
    expect(screen.getByText('执行未确认')).toBeInTheDocument()
    expect(screen.getByText('已转发执行')).toBeInTheDocument()
    expect(screen.queryByText('可用工具')).not.toBeInTheDocument()
    expect(screen.getAllByText('成功')).toHaveLength(2)
    expect(screen.getByText('失败')).toBeInTheDocument()
    expect(screen.queryByText(/Analyze this rollout|rollout_path/)).not.toBeInTheDocument()
    expect(getContent).toHaveBeenCalledWith(
      'req-2',
      ['req-1', 'req-2'],
      expect.objectContaining({ from: expect.any(String), to: expect.any(String) }),
    )
    expectDetailWindow((getContent as any).mock.calls[0][2])
  })

  it('hides Codex memory consolidation even if a legacy server returns it', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    const listRuns = vi.spyOn(api.accessRetentionApi, 'listRuns').mockResolvedValue({
      data: { data: [{
        run_id: 'evr-memory', kind: 'agent_task', task_class: 'codex_background_memory',
        correlation_source: 'content_hash_chain', correlation_confidence: 'derived',
        representative_request_id: 'req-memory', member_request_ids: ['req-memory'],
        title: 'Analyze this rollout and extract durable memory.', started_at: '2026-08-05T02:40:00Z',
        ended_at: '2026-08-05T02:41:00Z', duration_ms: 60000, agent_type: 'openai-codex',
        agent_label: 'OpenAI Codex', models: ['gpt-5.6-sol'], access_directions: ['chat_completion'],
        request_count: 1, tool_event_count: 0, input_artifact_count: 0, output_artifact_count: 0,
        evidence_status: 'complete', risk_state: 'normal',
      }], total: 1 }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)

    renderPage('/?view=agent_tasks')

    await waitFor(() => expect(listRuns).toHaveBeenCalled())
    expect(screen.queryByText('Codex 后台记忆整理')).not.toBeInTheDocument()
    expect(screen.queryByText('后台任务')).not.toBeInTheDocument()
    expect(screen.queryByText('Analyze this rollout and extract durable memory.')).not.toBeInTheDocument()
  })

  it('labels fingerprint groups as inferred rather than exact or single requests', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'listRuns').mockResolvedValue({
      data: { data: [{
        run_id: 'evr-inferred', kind: 'agent_task', correlation_source: 'content_fingerprint',
        correlation_confidence: 'inferred', representative_request_id: 'req-inferred', member_request_ids: ['req-inferred'],
        title: '验证会话归并', started_at: '2026-08-05T02:40:00Z', ended_at: '2026-08-05T02:41:00Z',
        duration_ms: 60000, agent_type: 'openai-codex', agent_label: 'OpenAI Codex',
        models: ['test-model'], access_directions: ['reverse_proxy'], request_count: 92,
        evidence_status: 'complete', risk_state: 'normal',
      }], total: 1 }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    renderPage('/?view=agent_tasks')
    expect(await screen.findByText('推断关联')).toBeInTheDocument()
    expect(screen.queryByText('精确关联')).not.toBeInTheDocument()
    expect(screen.queryByText('单次请求留证')).not.toBeInTheDocument()
  })

  it('loads retained image previews through authorized blob requests', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'listRuns').mockResolvedValue({
      data: { data: [{
        run_id: 'evr-image', kind: 'agent_task', correlation_source: 'content_hash_chain',
        correlation_confidence: 'derived', representative_request_id: 'req-image', member_request_ids: ['req-image'],
        title: '检查架构图', started_at: '2026-08-05T02:40:00Z', ended_at: '2026-08-05T02:41:00Z',
        duration_ms: 60000, agent_type: 'openai-codex', agent_label: 'OpenAI Codex',
        models: ['gpt-5.6-sol'], access_directions: ['chat_completion'], request_count: 1,
        tool_event_count: 0, input_artifact_count: 1, output_artifact_count: 0,
        evidence_status: 'complete', risk_state: 'normal',
      }], total: 1 }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req-image', request_content: '', response_content: '', user_input: '检查架构图',
        model_output: '已检查', evidence_status: 'complete', file_metadata: [],
        messages: [
          { id: 'msg-other', request_id: 'req-other', sequence: 1, role: 'user', kind: 'user_input', content: '先做准备' },
          { id: 'msg-answer', request_id: 'req-image', sequence: 2, role: 'assistant', kind: 'model_output', content: '已检查' },
        ],
        artifacts: [{
          id: 'art-image', request_id: 'req-image', direction: 'input', kind: 'image',
          display_name: 'architecture.png', media_type: 'image/png', byte_size: 128,
          sha256: 'image-sha', retention_status: 'retained', has_preview: true, reference_count: 2,
        }],
      }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getTimeline').mockResolvedValue({
      data: { data: [] }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    const getArtifact = vi.fn().mockResolvedValue({
      data: new Blob(['image'], { type: 'image/png' }), status: 200, statusText: 'OK', headers: {}, config: {},
    })
    ;(api.accessRetentionApi as any).getArtifact = getArtifact
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: vi.fn(() => 'blob:retained-preview') })
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() })

    renderPage('/?view=agent_tasks')
    fireEvent.click(await screen.findByRole('button', { name: /查看任务/ }))

    const preview = await screen.findByAltText('输入附件 architecture.png')
    expect(getArtifact).toHaveBeenCalledWith(
      'req-image',
      'art-image',
      'preview',
      expect.objectContaining({ from: expect.any(String), to: expect.any(String) }),
    )
    expectDetailWindow((getArtifact as any).mock.calls[0][3])
    expect(preview).toHaveAttribute('src', 'blob:retained-preview')
    expect(screen.getByText('引用 2 次')).toBeInTheDocument()
    const userMessage = preview.closest('[data-testid="retained-message-user"]')
    expect(userMessage).not.toBeNull()
    expect(within(userMessage as HTMLElement).queryByText('先做准备')).not.toBeInTheDocument()
    expect(screen.getByText('先做准备')).toBeInTheDocument()
    expect(screen.getAllByText('architecture.png')).toHaveLength(1)
    expect(screen.getAllByTestId('retained-message-user')).toHaveLength(2)
    expect(screen.getByAltText('输入附件 architecture.png')).toBeInTheDocument()

  })

  it('keeps ordinary AI conversations distinct from agent tasks', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({
      data: { data: [], total: 0, summary: emptySummary }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    const listRuns = vi.spyOn(api.accessRetentionApi, 'listRuns').mockResolvedValue({
      data: { data: [{
        run_id: 'conversation-web-1', kind: 'ai_conversation', correlation_source: 'conversation_id',
        correlation_confidence: 'exact', representative_request_id: 'req-web-2', member_request_ids: ['req-web-1', 'req-web-2'],
        title: '网页 AI 客服对话', started_at: '2026-08-05T03:00:00Z', ended_at: '2026-08-05T03:02:00Z', duration_ms: 120000,
        username: '张三', client_name: '企业 AI 门户', source_ip: '192.168.1.10',
        models: ['gpt-5.6-sol'], access_directions: ['reverse'],
        request_count: 6, tool_event_count: 99, input_artifact_count: 1, output_artifact_count: 0,
        evidence_status: 'complete', risk_state: 'normal',
      }], total: 1 }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    const getTimeline = vi.spyOn(api.accessRetentionApi, 'getTimeline').mockResolvedValue({
      data: { data: [{ id: 'tool-hidden', type: 'tool_action', title: '不应展示的工具行为', timestamp: '2026-08-05T03:01:00Z' }] },
      status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req-web-2', request_content: '', response_content: '',
        user_input: '帮我查询订单状态', model_output: '订单正在配送中', evidence_status: 'complete',
        artifacts: [], file_metadata: [],
      }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)

    renderPage('/?view=ai_conversations')

    expect(await screen.findByRole('columnheader', { name: '对话主体' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '对话概览' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '内容证据' })).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: '智能体身份' })).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: '智能体行为' })).not.toBeInTheDocument()
    expect(await screen.findByText('普通 AI 对话（非智能体）')).toBeInTheDocument()
    expect(await screen.findByText('6 个对话片段')).toBeInTheDocument()
    expect(screen.queryByText('99 次工具调用请求')).not.toBeInTheDocument()
    expect(listRuns).toHaveBeenCalledWith(expect.objectContaining({ view: 'ai_conversations' }))

    fireEvent.click(screen.getByRole('button', { name: /查看对话/ }))
    await waitFor(() => {
      expect(screen.getByText('AI 对话留证')).toBeInTheDocument()
      expect(screen.getByText('对话留证')).toBeInTheDocument()
      expect(screen.getByTestId('retained-text-request')).toHaveTextContent('帮我查询订单状态')
      expect(screen.getByText('订单正在配送中')).toBeInTheDocument()
    })
    expect(screen.queryByText('行为时间线')).not.toBeInTheDocument()
    expect(screen.queryByRole('complementary', {name:'智能体行为'})).not.toBeInTheDocument()
    expect(getTimeline).toHaveBeenCalled()
  })

  it('projects legacy task messages to human input and model-visible output', async () => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'listRuns').mockResolvedValue({
      data: { data: [{
        run_id: 'evr-noise', kind: 'agent_task', correlation_source: 'content_hash_chain',
        correlation_confidence: 'derived', representative_request_id: 'req-noise', member_request_ids: ['req-noise'],
        title: '清理留证', started_at: '2026-08-05T04:00:00Z', ended_at: '2026-08-05T04:01:00Z', duration_ms: 60000,
        agent_type: 'openai-codex', agent_label: 'OpenAI Codex', models: ['gpt-5.6-sol'], access_directions: ['chat_completion'],
        request_count: 1, tool_event_count: 1, input_artifact_count: 0, output_artifact_count: 0,
        evidence_status: 'complete', risk_state: 'normal',
      }], total: 1 }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: {
        request_id: 'req-noise', user_input: '', model_output: '', evidence_status: 'complete', artifacts: [], file_metadata: [],
        messages: [
          {
            id: 'noise-user', request_id: 'req-noise', sequence: 1, role: 'user', kind: 'user_input',
            content: '# Files pasted by the user:\n\n## screenshot.png: C:/Users/test/AppData/Local/Temp/screenshot.png\n\n## My request:\n请清理留证',
          },
          {
            id: 'noise-assistant', request_id: 'req-noise', sequence: 2, role: 'assistant', kind: 'model_output',
            content: '已清理。\n<oai-mem-citation><rollout_ids>private</rollout_ids></oai-mem-citation>',
          },
        ],
      }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getTimeline').mockResolvedValue({
      data: { data: [] }, status: 200, statusText: 'OK', headers: {}, config: {},
    } as any)

    renderPage('/?view=agent_tasks')
    fireEvent.click(await screen.findByRole('button', { name: /查看任务/ }, { timeout: 10000 }))

    await waitFor(() => {
      expect(screen.getByText('请清理留证')).toBeInTheDocument()
      expect(screen.getByText(/已清理/)).toBeInTheDocument()
      expect(screen.queryByText(/Files pasted by the user/)).not.toBeInTheDocument()
      expect(screen.queryByText(/AppData\\Local\\Temp/)).not.toBeInTheDocument()
      expect(screen.queryByText(/oai-mem-citation/)).not.toBeInTheDocument()
      expect(screen.getAllByTestId('retained-message-user')).toHaveLength(1)
      expect(screen.getAllByTestId('retained-message-assistant')).toHaveLength(1)
    }, { timeout: 10000 })
  })

  it('preserves literal private-tag XML inside a complete fenced response', async () => {
    const [assistantMessage] = await openAgentTaskWithAssistantMessages([
      '```xml\n<tool_call name="demo">VISIBLE_FENCED_CALL</tool_call>\n<tool_result>VISIBLE_FENCED_RESULT</tool_result>\n<memory>VISIBLE_FENCED_MEMORY</memory>\n```',
    ])

    const codeBlock = within(assistantMessage).getByTestId('retained-code-block')
    expect(codeBlock).toHaveTextContent('<tool_call name="demo">VISIBLE_FENCED_CALL</tool_call>')
    expect(codeBlock).toHaveTextContent('<tool_result>VISIBLE_FENCED_RESULT</tool_result>')
    expect(codeBlock).toHaveTextContent('<memory>VISIBLE_FENCED_MEMORY</memory>')
  })

  it('preserves a fenced XML example while hiding a real tool block outside it', async () => {
    const [assistantMessage] = await openAgentTaskWithAssistantMessages([
      '示例：\n```xml\n<function_call name="demo">VISIBLE_FENCED_FUNCTION</function_call>\n[tool_use:demo] VISIBLE_FENCED_LINE\n```\n<tool_use name="shell">PRIVATE_OUTSIDE_TOOL</tool_use>\n[tool_use:Bash] PRIVATE_OUTSIDE_LINE\n[tool_result:read_file] PRIVATE_OUTSIDE_RESULT\n公开结尾',
    ])

    const codeBlock = within(assistantMessage).getByTestId('retained-code-block')
    expect(codeBlock).toHaveTextContent('<function_call name="demo">VISIBLE_FENCED_FUNCTION</function_call>')
    expect(codeBlock).toHaveTextContent('[tool_use:demo] VISIBLE_FENCED_LINE')
    expect(within(assistantMessage).queryByText(/PRIVATE_OUTSIDE_TOOL/)).not.toBeInTheDocument()
    expect(within(assistantMessage).queryByText(/PRIVATE_OUTSIDE_LINE|PRIVATE_OUTSIDE_RESULT/)).not.toBeInTheDocument()
    expect(within(assistantMessage).getByText('公开结尾')).toBeInTheDocument()
  })

  it('does not treat an unterminated fence as a privacy boundary', async () => {
    const [assistantMessage] = await openAgentTaskWithAssistantMessages([
      '公开前缀\n```xml\n<tool_call>PRIVATE_UNTERMINATED_FENCE',
    ])

    expect(within(assistantMessage).getByText('公开前缀')).toBeInTheDocument()
    expect(within(assistantMessage).queryByText(/PRIVATE_UNTERMINATED_FENCE/)).not.toBeInTheDocument()
  })

  it('does not protect fence variants that the drawer does not render as code', async () => {
    const assistantMessages = await openAgentTaskWithAssistantMessages([
      '~~~xml\n<tool_call>PRIVATE_TILDE_FENCE</tool_call>\n~~~\n公开波浪结尾',
      '````xml\n<tool_result>PRIVATE_FOUR_BACKTICKS</tool_result>\n````\n公开四反引号结尾',
      ' ```xml\n<function_call>PRIVATE_INDENTED_FENCE</function_call>\n ```\n公开缩进结尾',
    ])

    expect(assistantMessages).toHaveLength(1)
    expect(within(assistantMessages[0]).getByText(/公开缩进结尾/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button',{name:/查看过程/}))
    expect(screen.getByText(/公开波浪结尾/)).toBeInTheDocument()
    expect(screen.getByText(/公开四反引号结尾/)).toBeInTheDocument()
    expect(screen.queryByText(/PRIVATE_TILDE_FENCE|PRIVATE_FOUR_BACKTICKS|PRIVATE_INDENTED_FENCE/)).not.toBeInTheDocument()

  })

  it('hides VS Code runtime notices and CodeBuddy local image paths from legacy messages', async () => {
    await openAgentTaskWithAssistantMessages(
      ['处理完成'],
      '<current_datetime>2026-09-03T04:51:10.219+08:00</current_datetime>\n继续处理\n' +
      '<system_reminder><sql_tables>Available tables: todos</sql_tables></system_reminder>\n' +
      '<tools_changed_notice>Tools no longer available: grep</tools_changed_notice>\n' +
      '@image:C:\\Users\\test\\AppData\\Local\\Temp\\image.private.png\n你在干嘛\n' +
      'Image file at path C:\\Users\\test\\agentSessionData\\private\\Pasted Image.png',
      '继续 你在干嘛 <tools_changed_notice>\nTools no longer available: grep\nImportant: truncated transport',
    )

    expect(screen.getByTestId('retained-text-request')).toHaveTextContent(/继续处理\s*你在干嘛/)
    expect(screen.queryByText(/current_datetime|system_reminder|tools_changed_notice|AppData|@image:|Image file at path|agentSessionData/)).not.toBeInTheDocument()
    expect(screen.getAllByText('继续 你在干嘛').length).toBeGreaterThanOrEqual(2)
    expect(screen.queryByText(/grep, read_file/)).not.toBeInTheDocument()
  })

  it('drops a WorkBuddy loop transport message without deleting ordinary text or fenced JSON arrays', async () => {
    const loopNotice = '[\n' +
      'Loop detected: the tool "Skill" has been called 4 consecutive times with identical arguments.\n\n' +
      'STOP calling tools immediately. Do NOT make any more tool calls.\n' +
      'Instead, tell the user what happened and suggest they switch models or modify their prompt to retry.\n' +
      ']\n\n' +
      '[LOOP_DETECTED]'
    await openAgentTaskWithAssistantMessages(
      ['正常回复'],
      [
        loopNotice,
        loopNotice.replace('"Skill"', "'Read'"),
        '真实问题：请解释 Loop detected 和 Tools no longer available 这两句话。\n```text\n' + loopNotice +
          '\n```\n```json\n["[LOOP_DETECTED]", {"xml":"<tools_changed_notice>Tools no longer available: demo</tools_changed_notice>"}]\n```',
      ],
      'WorkBuddy 留证检查',
    )

    const userMessages = screen.getAllByTestId('retained-message-user')
    expect(userMessages).toHaveLength(1)
    expect(screen.getAllByTestId('retained-message-user')).toHaveLength(1)
    expect(within(userMessages[0]).getByText('真实问题：请解释 Loop detected 和 Tools no longer available 这两句话。')).toBeInTheDocument()
    const codeBlocks = within(userMessages[0]).getAllByTestId('retained-code-block')
    expect(codeBlocks).toHaveLength(2)
    expect(codeBlocks[0]).toHaveTextContent('has been called 4 consecutive times with identical arguments')
    expect(codeBlocks[0]).toHaveTextContent('STOP calling tools immediately')
    expect(codeBlocks[1]).toHaveTextContent('["[LOOP_DETECTED]", {"xml":"<tools_changed_notice>Tools no longer available: demo</tools_changed_notice>"}]')
  })

  it.each(['forward', 'reverse', 'chat_completion'])('uses the collapsed question/answer view for %s request details', async (direction) => {
    mockCatalog()
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({ data: { data: [{
      request_id: 'r2', created_at: '2026-09-10T00:00:00Z', target_host: 'api.example.com',
      access_type: 'llm', status: 'success', status_code: 200, response_bytes: 100,
      tls_inspected: true, retention_level: 'content', content_retained: true,
      risk_state: 'blocked', action_taken: 'blocked', security_event_count: 1,
      disposition_status: 'open', access_direction: direction, agent_type: 'custom-agent',
    }], total: 1, summary: emptySummary } } as any)
    const content = vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({ data: {
      turn_view_version: 1, request_id: 'r2', artifacts: [], turns: [{
        id: 'turn-ingress', index: 1, user_input: '检查三种入口', request_ids: ['r2'],
        request_count: 1, process_count: 1, status: 'unconfirmed',
        finality_source: 'last_observed_response', correlation_source: 'ingress_context', evidence_status: 'complete',
        answer: { id: 'answer', request_id: 'r2', sequence: 1, role: 'assistant', kind: 'answer_candidate', content: '入口检查结果' },
      }],
    } } as any)
    const process = vi.spyOn(api.accessRetentionApi, 'getTurnProcess').mockResolvedValue({ data: {
      data: [{ id: 'progress', request_id: 'r1', sequence: 1, role: 'assistant', kind: 'assistant_progress', content: '正在检查入口' }],
      total: 1, offset: 0, limit: 50, has_more: false,
    } } as any)
    const timeline = vi.spyOn(api.accessRetentionApi, 'getTimeline').mockResolvedValue({ data: { data: [] } } as any)
    renderPage()
    await openFirstDetail()
    expect(await screen.findByText('入口检查结果')).toBeInTheDocument()
    expect(screen.getByText('检查三种入口')).toBeInTheDocument()
    expect(screen.getByText(/此任务包含请求拒绝或安全回复记录/)).toBeInTheDocument()
    expect(process).not.toHaveBeenCalled()
    expect(timeline).toHaveBeenCalled()
    expect(content).toHaveBeenCalledWith('r2', undefined, expect.objectContaining({ view: 'turns' }))
    fireEvent.click(screen.getByRole('button', { name: /查看过程/ }))
    expect(await screen.findByText('正在检查入口')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /收起过程/ }))
    expect(screen.queryByText('正在检查入口')).not.toBeInTheDocument()
    expect(screen.getByText('入口检查结果')).toBeInTheDocument()
  })
})
