import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, useLocation } from 'react-router-dom'
import DiagnosisBot from '../components/diagnosis/DiagnosisBot'
import DiagnosisCard from '../components/diagnosis/DiagnosisCard'
import { message } from 'antd'
import DiagnosisSettings from '../components/diagnosis/DiagnosisSettings'
import { diagnosticsApi, type DiagnosisReport } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { useDiagnosisContext } from '../stores/diagnosisContext'

const report: DiagnosisReport = {
  id: 'diag-1', tier: 'L2', ok_count: 3, started_at: '', finished_at: '',
  steps: [{ tool: 'get_request', args: {}, summary: '已查询请求' }],
  findings: [{ check_id: 'timeout', severity: 'error', level: 'confirmed', title: '上游请求超时', impact: '影响一个请求', advice: [{ text: '查看模型', link: '/model-operations' }], excluded: ['网关限流'], evidence: [{ kind: 'request', ref: 'req-123', summary: '请求超时' }] }],
}
const response = <T,>(data: T) => ({ data }) as any
function Location() { const location = useLocation(); return <output aria-label="当前路由">{location.pathname + location.search}</output> }
const renderBot = (entry = '/') => render(<MemoryRouter initialEntries={[entry]}><DiagnosisBot /><Location /></MemoryRouter>)
const settle = () => act(async () => { await Promise.resolve() })

describe('诊断助手', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: { id: 'employee', username: '员工', role: 'developer' } })
    useDiagnosisContext.getState().clear()
    localStorage.removeItem('diag_ai_notice_seen')
    vi.spyOn(diagnosticsApi, 'getBadge').mockResolvedValue(response({ has_issue: false }))
    vi.spyOn(diagnosticsApi, 'listSessions').mockResolvedValue(response([]))
    vi.spyOn(diagnosticsApi, 'createSession').mockResolvedValue(response({ session_id: 'diag-1' }))
    vi.spyOn(diagnosticsApi, 'getSession').mockResolvedValue(response({ status: 'done', steps: [], report }))
  })
  afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks() })

  it.each(['developer', 'platform_admin', 'tenant_admin'])('%s 的设置和导出权限正确', async (role) => {
    useAuthStore.setState({ user: { id: role, username: role, role } })
    renderBot()
    fireEvent.click(screen.getByRole('button', { name: '诊断助手' }))
    fireEvent.click(screen.getByRole('button', { name: '一键体检' }))
    await screen.findByText('上游请求超时')
    expect(!!screen.queryByRole('button', { name: '诊断设置' })).toBe(role !== 'developer')
    expect(!!screen.queryByRole('button', { name: '导出诊断包' })).toBe(role !== 'developer')
  })

  it('每秒轮询，完成后显示结论并停止，追问继续轮询', async () => {
    vi.useFakeTimers()
    vi.spyOn(diagnosticsApi, 'sendMessage').mockResolvedValue(response({ session_id: 'diag-1' }))
    vi.mocked(diagnosticsApi.getSession)
      .mockResolvedValueOnce(response({ status: 'running', steps: [{ tool: 'get_request', summary: '正在查询请求' }] }))
      .mockResolvedValueOnce(response({ status: 'done', steps: [], report }))
    renderBot()
    fireEvent.click(screen.getByRole('button', { name: '诊断助手' }))
    const input = screen.getByPlaceholderText('粘贴报错、请求编号，或直接描述问题')
    fireEvent.change(input, { target: { value: '请求失败' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await settle()
    expect(screen.getByText('正在查询请求')).toBeInTheDocument()
    expect(screen.queryByText('上游请求超时')).not.toBeInTheDocument()
    await act(async () => { await vi.advanceTimersByTimeAsync(1000) })
    expect(screen.getByText('上游请求超时')).toBeInTheDocument()
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(diagnosticsApi.getSession).toHaveBeenCalledTimes(2)
    fireEvent.change(screen.getByLabelText('追问'), { target: { value: '如何处理' } })
    fireEvent.keyDown(screen.getByLabelText('追问'), { key: 'Enter' })
    await settle()
    expect(diagnosticsApi.sendMessage).toHaveBeenCalledWith('diag-1', '如何处理')
  })

  it('合并正常项，显示降级提示和中文级别，证据默认折叠', () => {
    render(<MemoryRouter><DiagnosisCard report={{ ...report, degraded: '系统繁忙，已降级为轻量诊断', findings: [...report.findings, { ...report.findings[0], severity: 'ok', title: '正常项不展开' }, { ...report.findings[0], level: 'suspected', title: '疑似问题' }, { ...report.findings[0], level: 'unknown', title: '证据不足' }] }} onOpenRequest={vi.fn()} /></MemoryRouter>)
    for (const text of ['另有 3 项正常', '系统繁忙，已降级为轻量诊断', '确定', '疑似', '无法判断']) expect(screen.getByText(text)).toBeInTheDocument()
    expect(screen.queryByText('正常项不展开')).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'req-123' })).not.toBeInTheDocument()
  })

  it('点击证据请求编号调用回调', () => {
    const onOpenRequest = vi.fn()
    render(<MemoryRouter><DiagnosisCard report={report} onOpenRequest={onOpenRequest} /></MemoryRouter>)
    fireEvent.click(screen.getByText('证据'))
    fireEvent.click(screen.getByRole('link', { name: 'req-123' }))
    expect(onOpenRequest).toHaveBeenCalledWith('req-123')
  })

  it('证据跳转到调用明细', async () => {
    renderBot()
    fireEvent.click(screen.getByRole('button', { name: '诊断助手' }))
    fireEvent.click(screen.getByRole('button', { name: '一键体检' }))
    await screen.findByText('上游请求超时')
    fireEvent.click(screen.getByText('证据'))
    fireEvent.click(screen.getByRole('link', { name: 'req-123' }))
    expect(screen.getByLabelText('当前路由')).toHaveTextContent('/cost/records?request_id=req-123')
  })

  it('选中请求上下文优先于路由参数，读取后清理', () => {
    useDiagnosisContext.getState().setContext({ requestId: 'req-selected' })
    renderBot('/model-operations?model=模型一&request_id=req-url')
    fireEvent.click(screen.getByRole('button', { name: '诊断助手' }))
    expect(screen.getByPlaceholderText('粘贴报错、请求编号，或直接描述问题')).toHaveValue('req-selected')
    expect(useDiagnosisContext.getState().context).toBeNull()
  })

  it('卸载后停止会话和红点轮询', async () => {
    vi.useFakeTimers()
    vi.mocked(diagnosticsApi.getSession).mockResolvedValue(response({ status: 'running', steps: [] }))
    const view = renderBot()
    fireEvent.click(screen.getByRole('button', { name: '诊断助手' }))
    fireEvent.click(screen.getByRole('button', { name: '一键体检' }))
    await settle()
    view.unmount()
    const count = vi.mocked(diagnosticsApi.getSession).mock.calls.length
    await act(async () => { await vi.advanceTimersByTimeAsync(65000) })
    expect(diagnosticsApi.getSession).toHaveBeenCalledTimes(count)
    expect(diagnosticsApi.getBadge).toHaveBeenCalledTimes(1)
  })

  it('红点每 60 秒刷新，失败时保持静默', async () => {
    vi.useFakeTimers()
    vi.mocked(diagnosticsApi.getBadge).mockRejectedValueOnce(new Error('网络异常'))
    const notice = vi.spyOn(message, 'error')
    renderBot()
    await settle()
    await act(async () => { await vi.advanceTimersByTimeAsync(60000) })
    expect(diagnosticsApi.getBadge).toHaveBeenCalledTimes(2)
    expect(notice).not.toHaveBeenCalled()
  })

  it('诊断失败后停止轮询并允许重新体检', async () => {
    vi.useFakeTimers()
    vi.mocked(diagnosticsApi.getSession).mockResolvedValue(response({ status: 'failed', steps: [] }))
    renderBot()
    fireEvent.click(screen.getByRole('button', { name: '诊断助手' }))
    fireEvent.click(screen.getByRole('button', { name: '一键体检' }))
    await settle()
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(diagnosticsApi.getSession).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('button', { name: '一键体检' })).toBeEnabled()
    expect(screen.getByText('诊断失败，请重试或重新开始诊断')).toBeInTheDocument()
  })

  it('首次 L3 解读只提示一次并写入浏览器存储', async () => {
    const info = vi.spyOn(message, 'info').mockImplementation(() => (() => {}) as any)
    vi.mocked(diagnosticsApi.getSession).mockResolvedValue(response({ status: 'done', steps: [], report: { ...report, tier: 'L3', model: '本地模型' } }))
    renderBot()
    fireEvent.click(screen.getByRole('button', { name: '诊断助手' }))
    fireEvent.click(screen.getByRole('button', { name: '一键体检' }))
    await screen.findByText('上游请求超时')
    expect(info).toHaveBeenCalledWith('本次使用模型 本地模型 解读，数据不出本环境')
    expect(localStorage.getItem('diag_ai_notice_seen')).toBe('1')
    fireEvent.click(screen.getByRole('button', { name: '一键体检' }))
    await settle()
    expect(info).toHaveBeenCalledTimes(1)
  })

  it('关闭抽屉后保留会话，历史最多显示五条', async () => {
    vi.mocked(diagnosticsApi.listSessions).mockResolvedValue(response(Array.from({ length: 7 }, (_, i) => ({ id: String(i), input: { text: `历史问题${i}` }, status: 'done' }))))
    renderBot()
    fireEvent.click(screen.getByRole('button', { name: '诊断助手' }))
    await screen.findByText('历史问题4')
    expect(screen.queryByText('历史问题5')).not.toBeInTheDocument()
    fireEvent.click(screen.getByText('历史问题0'))
    await screen.findByText('上游请求超时')
    expect(diagnosticsApi.getSession).toHaveBeenCalledWith('0')
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    fireEvent.click(screen.getByRole('button', { name: '诊断助手' }))
    expect(screen.getByText('上游请求超时')).toBeInTheDocument()
  })

  it('Shift+Enter 和中文输入法确认不会发送', () => {
    renderBot()
    fireEvent.click(screen.getByRole('button', { name: '诊断助手' }))
    const input = screen.getByLabelText('诊断问题')
    fireEvent.change(input, { target: { value: '错误信息' } })
    fireEvent.keyDown(input, { key: 'Enter', shiftKey: true })
    fireEvent.keyDown(input, { key: 'Enter', isComposing: true })
    expect(diagnosticsApi.createSession).not.toHaveBeenCalled()
  })

  it('门户用户不显示机器人，也不请求诊断接口', () => {
    useAuthStore.setState({ user: { id: 'portal', username: '门户', role: 'chat_user' } })
    renderBot()
    expect(screen.queryByRole('button', { name: '诊断助手' })).not.toBeInTheDocument()
    expect(diagnosticsApi.getBadge).not.toHaveBeenCalled()
  })

  it('设置读取模型、自检和采集器状态，保存仅提交两个配置字段', async () => {
    vi.spyOn(diagnosticsApi, 'getSettings').mockResolvedValue(response({ ai_enabled: false, model_id: 'model-1', model_name: '本地模型', models: [{ id: 'model-1', name: '本地模型' }], selfcheck: { passed: true, score: 4, tested_at: '2026-10-24T01:00:00Z' }, agent_installed: true, agent_last_seen: '2026-10-24T02:00:00Z' }))
    vi.spyOn(diagnosticsApi, 'putSettings').mockResolvedValue(response({}))
    const close = vi.fn()
    render(<DiagnosisSettings open onClose={close} />)
    await screen.findByText(/通过 · 4\/5/)
    expect(screen.getByText('已安装')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('switch', { name: 'AI 解读' }))
    fireEvent.click(screen.getByRole('button', { name: '保 存' }))
    await settle()
    expect(diagnosticsApi.putSettings).toHaveBeenCalledWith({ ai_enabled: true, model_id: 'model-1' })
    expect(close).toHaveBeenCalledTimes(1)
  })

  it('自动选择时提示当前实际使用的模型', async () => {
    vi.spyOn(diagnosticsApi, 'getSettings').mockResolvedValue(response({ ai_enabled: true, model_id: null, model_name: '', effective_model_name: 'gpt-6-luna', models: [{ id: 'model-1', name: 'gpt-6-luna' }], selfcheck: null, agent_installed: true, agent_last_seen: null }))
    render(<DiagnosisSettings open onClose={vi.fn()} />)
    expect(await screen.findByText('自动选择（当前：gpt-6-luna）')).toBeInTheDocument()
  })


  it('红点亮着时打开抽屉直接展示最近一次体检结果', async () => {
    vi.mocked(diagnosticsApi.getBadge).mockResolvedValue(response({ has_issue: true }))
    vi.mocked(diagnosticsApi.listSessions).mockResolvedValue(response([
      { id: 'q-1', status: 'done', input: { kind: 'question', text: '问个问题', ref: '', window_hours: 1 }, created_at: '2026-10-25T01:00:00Z' },
      { id: 'h-1', status: 'done', input: { kind: 'health', text: '', ref: '', window_hours: 1 }, created_at: '2026-10-25T00:50:00Z' },
    ]))
    renderBot()
    await settle()
    fireEvent.click(screen.getByRole('button', { name: '诊断助手' }))
    await screen.findByText('上游请求超时')
    expect(diagnosticsApi.getSession).toHaveBeenCalledWith('h-1')
  })
})
