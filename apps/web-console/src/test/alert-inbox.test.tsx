import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AlertInbox from '../pages/AlertInbox'
import * as api from '../services/api'
import * as reportExport from '../utils/reportExport'
import { severityLabel } from '../utils/alertInboxDisplay'
import { RECORD_MODE_PASS_LABEL } from '../utils/ws8ActionLabels'

// 消息中心是客户直接可见的页面：所有新枚举（含日聚合卡）必须有中文文案，绝不露原始英文。

const dailySummaryItem = {
  id: 'inbox_daily_1',
  severity: 'medium',
  type: 'security_event_daily_summary',
  // 即使后端标题残留英文枚举，前端也要用 body 重建中文摘要卡
  title: 'security_event_daily_summary: regex_bank_card_cn',
  // 契约字段对齐 secevent_bridge 日聚合实现：daily_count/dimension(维度取值,可能是规则 id)/date
  body_json: {
    rule_name: '国内银行卡号',
    event_type: 'security_check',
    dimension: 'regex_bank_card_cn',
    daily_count: 37,
    date: '2026-07-01',
  },
  created_at: '2026-07-02T01:00:00Z',
  read_at: '',
}

const foldedEventItem = {
  id: 'inbox_event_1',
  severity: 'high',
  type: 'security_event',
  title: '安全事件【高危】数据安全 · 处置：审计',
  body_json: {
    event_type: 'data_security',
    severity: 'high',
    action: 'security_blocked',
    rule_name: '客户敏感词',
    occurrence_count: 5,
    distinct_occurrences: 2,
    affected_users: 1,
    first_seen_at: '2026-07-01T01:00:00Z',
    last_seen_at: '2026-07-02T01:00:00Z',
  },
  created_at: '2026-07-02T01:00:00Z',
  read_at: '',
}

describe('AlertInbox page', () => {
  let queryClient: QueryClient
  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.clearAllMocks()
    // 页面下方的告警组积压处置区块有独立测试（alert-group-backlog.test.tsx），这里只给空列表。
    vi.spyOn(api.alertGroupApi, 'list').mockResolvedValue({ data: { items: [], total: 0, limit: 50, offset: 0 } } as any)
    // 页面默认是「按天折叠」视图，会先请求折叠接口；这里只给空结果，避免渲染瞬间发出真实 HTTP 请求。
    vi.spyOn(api.ws8AlertInboxApi, 'folded').mockResolvedValue({ data: { groups: [], total_groups: 0, total_items: 0, unread_count: 0 } } as any)
  })

  // 消息中心默认进入「按天折叠」视图；本文件覆盖的是「逐条明细」（原有行为），渲染后先切过去以保持用例原语义。
  // 折叠视图另见 alert-inbox-fold.test.tsx。
  const renderPage = () => {
    const view = render(
      <QueryClientProvider client={queryClient}><AlertInbox /></QueryClientProvider>,
    )
    fireEvent.click(within(screen.getByRole('radiogroup', { name: '消息展示方式' })).getByText('逐条明细'))
    return view
  }

  it('renders daily-summary cards in Chinese without leaking raw enums', async () => {
    vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [dailySummaryItem] } } as any)

    renderPage()

    await waitFor(() => expect(screen.getByText(/规则日聚合/)).toBeInTheDocument())
    expect(screen.getByText(/国内银行卡号/)).toBeInTheDocument()
    expect(screen.getByText(/当日累计 37 条/)).toBeInTheDocument()
    expect(screen.getByText(/2026-07-01/)).toBeInTheDocument()
    // 来源列走中文映射表
    expect(screen.getByText('安全事件日聚合')).toBeInTheDocument()
    // 原始英文枚举与技术 id 一律不露出
    expect(screen.queryByText(/security_event_daily_summary/)).not.toBeInTheDocument()
    expect(screen.queryByText(/regex_bank_card_cn/)).not.toBeInTheDocument()
  })

  it('shows folded occurrence bookkeeping for deduped security events', async () => {
    vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [foldedEventItem] } } as any)

    renderPage()

    await waitFor(() => expect(screen.getByText(/数据安全/)).toBeInTheDocument())
    expect(screen.getByText(/处置：已阻断/)).toBeInTheDocument()
    expect(screen.getByText(/命中记录 5 条 · 独立事发\/会话 2 · 涉及主体 1/)).toBeInTheDocument()
  })
  it('labels runtime failures and access governance separately from attacks', async () => {
    vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [
      { id: 'fault', type: 'runtime_fault', severity: 'low', body_json: { action: 'audit', semantic_reason: 'tier1_timeout' } },
      { id: 'access', type: 'governor.alert', severity: 'warning', body_json: { reason: 'model not allowed for team', alert_only: true } },
      { id: 'route', type: 'model_route_degraded', severity: 'warning', title: '模型线路退化' },
    ] } } as any)
    renderPage()
    await waitFor(() => expect(screen.getAllByText('运行故障')).toHaveLength(2))
    // 「访问治理」同时出现在风险域 Segmented 选项与来源 Tag 中。
    expect(screen.getAllByText('访问治理').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('初筛超时')).toBeInTheDocument()
    expect(screen.getByText('当前团队模型策略仅告警，未阻断请求')).toBeInTheDocument()
    expect(screen.queryByText(/语义攻击/)).not.toBeInTheDocument()
  })

  it('shows tool failure loops as their own title with the evidence text, not as a detection fault', async () => {
    vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [
      { id: 'loop', type: 'runtime_fault', severity: 'low', body_json: { action: 'audit', matched: { findings: [{ type: 'tool_failure_loop', category: 'agent_tool_failure_loop', evidence_kind: 'runtime', rule_name: 'Bash', redacted_evidence: 'Bash 在窗口内失败 5 次' }] } } },
    ] } } as any)
    renderPage()
    expect(await screen.findByText(/智能体工具连续失败/)).toBeInTheDocument()
    expect(screen.getByText('Bash 在窗口内失败 5 次')).toBeInTheDocument()
    expect(screen.queryByText(/检测运行故障/)).not.toBeInTheDocument()
    expect(screen.queryByText('检测未完成，请查看运行状态')).not.toBeInTheDocument()
  })

  it('reads the tool failure loop from the top-level category or primary finding', async () => {
    vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [
      { id: 'cat', type: 'runtime_fault', severity: 'low', body_json: { action: 'audit', category: 'agent_tool_failure_loop', primary_finding: { category: 'agent_tool_failure_loop', redacted_evidence: 'Read 在窗口内失败 3 次' } } },
    ] } } as any)
    renderPage()
    expect(await screen.findByText('Read 在窗口内失败 3 次')).toBeInTheDocument()
    expect(screen.queryByText(/检测运行故障/)).not.toBeInTheDocument()
  })

  it('calls the warning severity 提醒, same as the rest of the console', () => {
    expect(severityLabel('warning')).toBe('提醒')
    expect(severityLabel('info')).toBe('提示')
  })

  it('计费类运维告警显示中文类型与处置建议，不露英文枚举', async () => {
    vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [
      { id: 'ops', type: 'billing_finalize_failed', severity: 'high', title: '计费结算失败 · 模型 gpt-x',
        body_json: { ops_alert: true, alert_type: 'billing_finalize_failed', count: 3, suggestion: '网关结算重试后仍失败，费用暂未入账。', domain: 'system', scope_key: 'model:gpt-x' } },
    ] } } as any)
    renderPage()
    expect(await screen.findByText('计费结算失败 · 模型 gpt-x')).toBeInTheDocument()
    expect(screen.getByText('本次 3 次 · 网关结算重试后仍失败，费用暂未入账。')).toBeInTheDocument()
    expect(screen.getAllByText('计费结算失败').length).toBeGreaterThanOrEqual(1)
    expect(screen.queryByText(/billing_finalize_failed|model:gpt-x/)).not.toBeInTheDocument()
  })

  it.each([false, true])('explains request capacity without claiming a dangerous file (nested=%s)', async (nested) => {
    vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [
      { id: 'capacity', type: 'runtime_fault', severity: 'low', body_json: { action: 'audit', ...(nested ? { matched: { semantic_reason: 'request_body_limit_exceeded' } } : { semantic_reason: 'request_body_limit_exceeded' }) } },
    ] } } as any)
    renderPage()
    expect(await screen.findByText('请求体超过检测容量限制，检测未完成')).toBeInTheDocument()
    expect(screen.queryByText('文件安全')).not.toBeInTheDocument()
    expect(screen.queryByText('高危')).not.toBeInTheDocument()
  })

  it('W8 8.8: labels record-mode passes as observation pass, not a block', async () => {
    vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [
      { ...foldedEventItem, id: 'rec', body_json: { ...foldedEventItem.body_json, action: 'security_audit_only' } },
    ] } } as any)
    renderPage()
    expect(await screen.findByText(new RegExp(`处置：${RECORD_MODE_PASS_LABEL}`))).toBeInTheDocument()
    expect(screen.queryByText(/处置：已阻断/)).not.toBeInTheDocument()
  })

  it('W8 8.7/8.9: server-side severity filter shows server total, tenant-timezone time and exports the same filters', async () => {
    vi.spyOn(api.statsApi, 'getOverview').mockResolvedValue({ data: { timezone: 'Asia/Tokyo' } } as any)
    const legacy = vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [] } } as any)
    const list = vi.spyOn(api.ws8AlertInboxApi, 'list').mockResolvedValue({ data: { items: [foldedEventItem], total: 42 } } as any)
    const exp = vi.spyOn(api.ws8AlertInboxApi, 'export').mockResolvedValue({ data: new Blob(['x']) } as any)
    vi.spyOn(reportExport, 'downloadBlob').mockImplementation(() => undefined)

    renderPage()
    await waitFor(() => expect(legacy).toHaveBeenCalled())

    fireEvent.mouseDown(screen.getByRole('combobox', { name: '按严重度筛选' }))
    // 选项顺序取自 SEVERITY_CONFIG：critical、high、…；取第 2 项（high），避免手打中文标签。
    const option = await waitFor(() => {
      const el = document.querySelectorAll('.ant-select-item-option')[1]
      expect(el).toBeTruthy()
      return el as HTMLElement
    })
    fireEvent.click(option)

    await waitFor(() => expect(list).toHaveBeenLastCalledWith({ severity: 'high', unread: true, limit: 20, offset: 0 }))
    expect(await screen.findByText(/共 42 条未读消息/)).toBeInTheDocument()
    // 01:00Z 在东京时区为 10:00。
    expect(screen.getByText('2026-07-02 10:00:00')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Excel/ }))
    await waitFor(() => expect(exp).toHaveBeenCalledWith('xlsx', { severity: 'high', unread: true }))
  })

  it('renders risk-domain tags and filters rows through the segmented control', async () => {
    vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [
      { id: 'd-content', type: 'security_event', severity: 'high', body_json: { event_type: 'data_security', action: 'security_blocked' } },
      { id: 'd-tool', type: 'security_event', severity: 'high', body_json: { event_type: 'tool_attempt_blocked', action: 'block', tool_name: 'exec' } },
      { id: 'd-skill', type: 'security_event', severity: 'low', body_json: { event_type: 'skill_invocation_risk', action: 'audit', domain: 'skill', skill_name: 'demo-skill' } },
      { id: 'd-mcp', type: 'security_event', severity: 'high', body_json: { event_type: 'tool_execution_risk', action: 'allow', source: 'gateway_mcp' } },
      { id: 'd-access', type: 'security_event', severity: 'medium', body_json: { event_type: 'model_policy', action: 'block' } },
      { id: 'd-system', type: 'runtime_fault', severity: 'low', body_json: { action: 'audit' } },
    ] } } as any)

    renderPage()

    await waitFor(() => expect(screen.getByText('工具尝试已阻断')).toBeInTheDocument())
    // 各风险域标签都出现（Segmented 选项与同文案的 Tag 共存，用 getAllByText）；
    // mcp 域的 event_type 是 tool_ 前缀，靠 source=gateway_mcp 归域。
    expect(screen.getAllByText('内容安全').length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('Skill').length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('MCP').length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('访问治理').length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('系统').length).toBeGreaterThanOrEqual(2)

    // 点 Skill 域后只剩该域的行。
    const skillOption = screen.getAllByText('Skill')
      .map((el) => el.closest('.ant-segmented-item'))
      .find(Boolean) as HTMLElement
    fireEvent.click(skillOption)
    await waitFor(() => expect(screen.queryByText('工具尝试已阻断')).not.toBeInTheDocument())
    expect(screen.getByText('Skill 调用风险')).toBeInTheDocument()

    // 回到全部。
    fireEvent.click(screen.getByText('全部'))
    await waitFor(() => expect(screen.getByText('工具尝试已阻断')).toBeInTheDocument())
  })

  it('places the alert-group backlog block below the inbox list', async () => {
    vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({ data: { items: [foldedEventItem] } } as any)
    renderPage()
    const block = await screen.findByLabelText('告警组积压处置')
    expect(block).toBeInTheDocument()
    expect(await screen.findByText('没有符合条件的告警组')).toBeInTheDocument()
  })
})
