import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import BlockRecords from '../pages/BlockRecords'
import * as api from '../services/api'
import { useAuthStore } from '../stores/auth'
import { DEFAULT_BLOCK_NOTICE_TEMPLATE, blockRecordSearchQuery, renderBlockNotice, validateBlockNoticeTemplate } from '../services/blockNotice'
import { securityModeLabel } from '../services/securityExecutionMode'
import * as reportExport from '../utils/reportExport'

// 现场问题（2026-09-23）：被阻断后页面看不到阻断记录、哪条规则、哪条明细；
// 智能体给出的操作编号在后台查不到。

const inputBlock: api.SecurityBlockRecord = {
  block_id: 'evt_input',
  created_at: '2026-09-23T03:00:07Z',
  request_id: 'req-input',
  trace_id: 'f53bc1b9',
  project_name: '研发一部',
  user_name: 'zhangsan',
  model: 'custom-local.glm-5.2',
  agent_type: 'codebuddy',
  source: 'gateway',
  event_type: 'security_check',
  action_taken: 'security_blocked',
  severity: 'critical',
  layer: 'input_content',
  reason: '输入内容命中安全规则',
  rule_id: 'rule_525f3078',
  rule_name: '密码明文检测',
  detail: 'pass****i996',
  basis: '规则「密码明文检测」的处置动作为阻断',
}

const toolBlock: api.SecurityBlockRecord = {
  ...inputBlock,
  block_id: 'evt_tool',
  request_id: 'req-tool',
  operation_id: 'op_5f1b100aea3d3d597ee318442e7f628c',
  action_taken: 'tool_attempt_blocked',
  layer: 'destructive_operation',
  reason: '模型准备调用删除或破坏性工具（删除文件）',
  rule_id: 'destructive_operation',
  rule_name: '删除与破坏',
  detail: 'Bash · filesystem_delete:1-targets',
  basis: '策略中心「智能体行为 → 删除与破坏」动作为阻断',
}

const trace: api.SecurityBlockTrace = {
  block: inputBlock,
  alerts_status: 'available',
  alerts: { items: [{ id: 'occurrence-exact', event_id: inputBlock.block_id, request_id: inputBlock.request_id,
    rule_name: '密码明文检测', severity: 'critical', event_action_taken: 'block', created_at: inputBlock.created_at,
    redacted_evidence: 'pass****i996', reason: '输入含敏感密码' } as any], total: 1, limit: 50, offset: 0, counts: {} as any },
  audit: {
    request_id: inputBlock.request_id,
    status: 'available', content_count: 1, tool_count: 0,
    request: { record_id: 'audit-exact', request_id: inputBlock.request_id, created_at: inputBlock.created_at, status: 'security_blocked', input_tokens: 20, output_tokens: 0 },
    security_events: [{ id: inputBlock.block_id, request_id: inputBlock.request_id, event_type: 'security_check', severity: 'critical', rule_name: '密码明文检测', action_taken: 'block', created_at: inputBlock.created_at }],
    content_records: [{ id: 'content-exact', role: 'user', tokens: 20, created_at: inputBlock.created_at }],
    tool_records: [],
    content_evidence: { status: 'available', reason_code: 'content_available', summary: '已保存本次请求的内容留痕', can_view: true },
    detail_url: '/security/alerts?request_id=req-input',
    retention_url: '/audit/access-retention?request_id=req-input&from=2026-09-22T03%3A00%3A07Z&to=2026-09-24T03%3A00%3A07Z',
  },
}

describe('BlockRecords page', () => {
  let queryClient: QueryClient
  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.restoreAllMocks()
    useAuthStore.setState({ user: { id: 'admin', username: 'admin', role: 'platform_admin', tenant_id: 't1' } as any, isAuthenticated: true } as any)
    vi.spyOn(api.statsApi, 'getOverview').mockResolvedValue({ data: { timezone: 'Asia/Shanghai', execution_mode: { effective_mode: 'protect' } } } as any)
    vi.spyOn(api.blockRecordsApi, 'trace').mockResolvedValue({ data: trace } as any)
  })

  const renderPage = (path = '/security/blocks') =>
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[path]}>
          <BlockRecords />
        </MemoryRouter>
      </QueryClientProvider>,
    )

  it('shows the rule, matched detail, basis and numbers of every block', async () => {
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [toolBlock, inputBlock], total: 2, limit: 20, offset: 0 } } as any)
    vi.spyOn(api.blockRecordsApi, 'getNoticeSettings').mockResolvedValue({ security_block_response_mode: 'error' })
    renderPage()
    expect(await screen.findByText('密码明文检测')).toBeInTheDocument()
    expect(screen.getByText('pass****i996')).toBeInTheDocument()
    expect(screen.getByText('规则「密码明文检测」的处置动作为阻断')).toBeInTheDocument()
    expect(screen.getByText('Bash · 删除文件（1 个目标）')).toBeInTheDocument()
    expect(screen.getByText('op_5f1b100aea3d3d597ee318442e7f628c')).toBeInTheDocument()
    expect(screen.getAllByText('删除与破坏').length).toBeGreaterThan(0)
    expect(screen.queryByText(/rule_525f3078|destructive_operation|filesystem_delete/)).not.toBeInTheDocument()
  })

  it('searches by any identifier pasted from an agent screenshot', async () => {
    const list = vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [], total: 0, limit: 20, offset: 0 } } as any)
    vi.spyOn(api.blockRecordsApi, 'getNoticeSettings').mockResolvedValue({})
    renderPage()
    const box = await screen.findByLabelText('检索阻断记录')
    fireEvent.change(box, { target: { value: 'op_5f1b100aea3d3d597ee318442e7f628c18' } })
    fireEvent.keyDown(box, { key: 'Enter', code: 'Enter', keyCode: 13 })
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ q: 'op_5f1b100aea3d3d597ee318442e7f628c18' })))
  })

  it('lets a platform admin choose how agents receive the notice and previews it', async () => {
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [], total: 0, limit: 20, offset: 0 } } as any)
    vi.spyOn(api.blockRecordsApi, 'getNoticeSettings').mockResolvedValue({ security_block_response_mode: 'message', security_block_notice_template: '已拦截：{rule}，编号 {block_id}' })
    const save = vi.spyOn(api.blockRecordsApi, 'saveNoticeSettings').mockResolvedValue({} as any)
    renderPage()
    fireEvent.click(screen.getByText('客户阻断提示设置（模板与返回方式）'))
    await waitFor(() => expect(screen.getByTestId('block-notice-preview').textContent).toContain('已拦截：密码明文检测（rule_525f3078），编号 evt_9bc36fc530b040eebe56e669'))
    expect(screen.getByTestId('block-notice-preview').textContent).toContain('请求 ID：f53bc1b9-0c1e-4a57-9d5e-3b0f7f0e1a2d')
    expect(screen.getByText('模板预览（示例数据，不是真实阻断记录）')).toBeInTheDocument()
    fireEvent.click(screen.getByText('保存阻断提示'))
    await waitFor(() => expect(save).toHaveBeenCalledWith({ mode: 'message', template: '已拦截：{rule}，编号 {block_id}' }))
  })

  it('hides notice settings from non platform admins', async () => {
    useAuthStore.setState({ user: { id: 'auditor', username: 'auditor', role: 'auditor', tenant_id: 't1' } as any } as any)
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [], total: 0, limit: 20, offset: 0 } } as any)
    renderPage()
    await screen.findByText('阻断明细')
    expect(screen.queryByText('智能体收到的阻断提示')).not.toBeInTheDocument()
  })

  it('W8 8.3: states the current execution mode pill in record mode', async () => {
    vi.spyOn(api.statsApi, 'getOverview').mockResolvedValue({ data: { timezone: 'Asia/Tokyo', execution_mode: { effective_mode: 'record' } } } as any)
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [inputBlock], total: 1, limit: 20, offset: 0 } } as any)
    vi.spyOn(api.blockRecordsApi, 'getNoticeSettings').mockResolvedValue({})
    renderPage()
    await screen.findByText('阻断明细')
    await waitFor(() => expect(screen.getByText(/当前执行模式/).textContent).toContain(securityModeLabel('record')))
    expect(screen.queryByText(/观察留痕模式/)).not.toBeInTheDocument()
    // 03:00:07Z 在东京时区为 12:00:07（W8 8.9）。
    expect(await screen.findByText('2026-09-23 12:00:07')).toBeInTheDocument()
  })

  it('W8 8.7: exports on the server with the same search conditions as the list', async () => {
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [inputBlock], total: 1, limit: 20, offset: 0 } } as any)
    vi.spyOn(api.blockRecordsApi, 'getNoticeSettings').mockResolvedValue({})
    const exp = vi.spyOn(api.ws8BlockRecordsApi, 'export').mockResolvedValue({ data: new Blob(['x']) } as any)
    vi.spyOn(reportExport, 'downloadBlob').mockImplementation(() => undefined)
    renderPage('/security/blocks?q=req-input')
    await screen.findByText('pass****i996')
    fireEvent.click(screen.getByRole('button', { name: /CSV/ }))
    await waitFor(() => expect(exp).toHaveBeenCalledWith('csv', expect.objectContaining({ q: 'req-input' })))
  })

  it('finds the real block when an administrator pastes the entire customer notice', async () => {
    const list = vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [], total: 0 } } as any)
    renderPage()
    const box = await screen.findByLabelText('检索阻断记录')
    fireEvent.change(box, { target: { value: '【JJDGuard 安全网关】本次请求已阻断。\n阻断编号：evt_actual12345678\n请求 ID：req-another' } })
    fireEvent.click(screen.getByRole('button', { name: '搜索阻断记录' }))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ q: 'evt_actual12345678' })))
    expect(box).toHaveValue('evt_actual12345678')
    expect(screen.queryByTestId('block-notice-preview')).not.toBeInTheDocument()
  })

  it('opens alert evidence and retained audit metadata for the same blocked request', async () => {
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [inputBlock], total: 1 } } as any)
    renderPage('/security/blocks?q=evt_input')
    fireEvent.click(await screen.findByRole('button', { name: '查看告警与留痕' }))
    expect(await screen.findByText('occurrence-exact')).toBeInTheDocument()
    expect(screen.getByText('audit-exact')).toBeInTheDocument()
    expect(screen.getByText('告警原因：输入含敏感密码')).toBeInTheDocument()
    expect(screen.getByText('本次阻断')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '查看完整调用留痕' })).toHaveAttribute('href', trace.audit.retention_url)
    expect(api.blockRecordsApi.trace).toHaveBeenCalledWith('evt_input', expect.any(AbortSignal))
  })

  it('shows the original hit from the trace and marks truncation', async () => {
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [inputBlock], total: 1 } } as any)
    vi.spyOn(api.blockRecordsApi, 'trace').mockResolvedValue({ data: { ...trace, block: { ...inputBlock,
      raw_evidence: 'password=RAWHIT', raw_evidence_truncated: true, evidence_context: 'ctx before password=RAWHIT after' } } } as any)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '查看告警与留痕' }))
    expect(await screen.findByText('password=RAWHIT（已截断）')).toBeInTheDocument()
    expect(screen.getByText('ctx before password=RAWHIT after')).toBeInTheDocument()
  })

  it('says where to find an original that exceeded the per-event limit', async () => {
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [inputBlock], total: 1 } } as any)
    vi.spyOn(api.blockRecordsApi, 'trace').mockResolvedValue({ data: { ...trace, block: { ...inputBlock, raw_evidence_omitted: true } } } as any)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '查看告警与留痕' }))
    expect(await screen.findByText('命中原文超出单个事件的保存上限，未随事件保存，请在内容留存中查看。')).toBeInTheDocument()
  })

  it('does not display evidence belonging to a different request', async () => {
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [inputBlock], total: 1 } } as any)
    vi.spyOn(api.blockRecordsApi, 'trace').mockResolvedValue({ data: { ...trace, audit: { ...trace.audit, request_id: 'req-other' } } } as any)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '查看告警与留痕' }))
    expect(await screen.findByText('关联编号不一致，未展示告警与留痕')).toBeInTheDocument()
    expect(screen.queryByText('audit-exact')).not.toBeInTheDocument()
    expect(screen.queryByText('occurrence-exact')).not.toBeInTheDocument()
  })

  it('reports unavailable data separately from absent or expired retained evidence', async () => {
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [inputBlock], total: 1 } } as any)
    vi.spyOn(api.blockRecordsApi, 'trace').mockResolvedValue({ data: { ...trace, alerts: null, alerts_status: 'unavailable', audit: { ...trace.audit,
      content_evidence: { status: 'expired', can_view: false, summary: '内容留痕已超过保存期限' } } } } as any)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '查看告警与留痕' }))
    expect(await screen.findByText('关联告警暂不可用')).toBeInTheDocument()
    expect(screen.getByText('内容留痕：已过期')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '查看完整调用留痕' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: '按请求 ID 查询留痕' })).toHaveAttribute('href', trace.audit.retention_url)
  })

  it('distinguishes a failed trace read from a missing record', async () => {
    vi.spyOn(api.blockRecordsApi, 'list').mockResolvedValue({ data: { items: [inputBlock], total: 1 } } as any)
    vi.spyOn(api.blockRecordsApi, 'trace').mockRejectedValue(new Error('service unavailable'))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '查看告警与留痕' }))
    expect(await screen.findByText('告警与留痕读取失败')).toBeInTheDocument()
    expect(screen.queryByText('当前未找到本次请求的关联告警')).not.toBeInTheDocument()
  })
})

describe('block notice rendering', () => {
  it('drops lines whose placeholders have no value', () => {
    const text = renderBlockNotice(DEFAULT_BLOCK_NOTICE_TEMPLATE, { reason: '输入内容命中安全规则', block_id: 'evt_1' })
    expect(text).toContain('阻断编号：evt_1')
    expect(text).not.toContain('操作编号')
    expect(text).not.toContain('命中规则')
  })

  it('rejects unknown placeholders and falls back to the default template', () => {
    expect(validateBlockNoticeTemplate('{password}')).toContain('{password}')
    expect(renderBlockNotice('{password}', { block_id: 'evt_2' })).toContain('evt_2')
  })

  it('keeps custom wording while preserving searchable identifiers exactly once', () => {
    const values = { block_id: 'evt-real', request_id: 'req-real' }
    expect(renderBlockNotice('请联系管理员', values)).toBe('请联系管理员\n阻断编号：evt-real\n请求 ID：req-real')
    expect(renderBlockNotice('编号 {block_id}\n请求 {request_id}', values)).toBe('编号 evt-real\n请求 req-real')
  })

  it('updates the previously saved default menu while preserving edited custom templates', () => {
    const oldDefault = DEFAULT_BLOCK_NOTICE_TEMPLATE
      .replace('请求 ID：{request_id}\n', '')
      .replace('如需核查，请联系管理员并提供阻断编号或请求 ID（管理后台「风险处理 → 阻断记录」可查）。', '如需放行，请联系管理员并提供阻断编号（管理后台「安全护栏 → 阻断记录」可查）。')
    const values = { block_id: 'evt-actual', request_id: 'req-actual' }
    expect(renderBlockNotice(oldDefault, values)).toContain('风险处理 → 阻断记录')
    expect(renderBlockNotice('自定义说明\n' + oldDefault, values)).toContain('自定义说明')
    expect(renderBlockNotice('自定义说明\n' + oldDefault, values)).toContain('安全护栏 → 阻断记录')
  })

  it('preserves explicit screenshot truncation and accepts request-only notices', () => {
    expect(blockRecordSearchQuery('阻断编号：evt_1234567890…\n命中规则：测试')).toBe('evt_1234567890…')
    expect(blockRecordSearchQuery('请求 ID：req-actual\n联系管理员')).toBe('req-actual')
    expect(blockRecordSearchQuery('密码检测')).toBe('密码检测')
  })
})
