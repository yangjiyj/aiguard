import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ContentAudit from '../pages/ContentAudit'
import * as api from '../services/api'
import { useAuthStore } from '../stores/auth'

// Task 3 责任主体：四行归属 + 工具调用块。文案与页面常量同源，页面改文案这里会一起红。
const USER_LABEL = '用户'
const UNLINKED_USER = '未关联用户'
const DEPARTMENT_PREFIX = '部门：'
const AGENT_LABEL = '智能体'
const CREDENTIAL_LABEL = '凭据 / 上游账号'
const CONVERSATION_LABEL = '对话 ID'
const VIEW_RETENTION = '查看留存'
const SOURCE_IP_PREFIX = '来源 IP '
const TOOL_CALLS_TITLE = '工具调用'
const NAT_NOTE = '（经 NAT，不能定位到人）'
const DEPARTMENT_FIXTURE = '研发部'
const ATTRIBUTION_CARD = '责任与证据链'
const ALERT_DETAIL_TITLE = '安全告警明细'
const RETENTION_DETAIL_TITLE = '留存详情'
const VIEW_LABEL = '查看'

const UPSTREAM_ACCOUNT_KEY = 'upstream:openai_account:7f3a91c0deadbeef'
const UPSTREAM_ACCOUNT_LABEL = '上游账号 openai:7f3a91c0'
const REQUEST_ID = 'req-upstream'
const NAT_IP = '192.168.56.1'

describe('Content audit responsibility attribution', () => {
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
    vi.spyOn(api.contentAuditApi, 'getSessionEvents').mockResolvedValue({ data: { data: [], total: 0 } } as any)
    vi.spyOn(api.contentAuditApi, 'listUsers').mockResolvedValue({
      data: { data: [], limit: 50, offset: 0, has_more: false, next_cursor: '' },
    } as any)
    vi.spyOn(api.contentSecurityApi, 'getIndustry').mockResolvedValue({ data: { industry: 'generic', packs: [] } } as any)
    vi.spyOn(api.accessRetentionApi, 'list').mockResolvedValue({ data: { data: [], total: 0 } } as any)
    vi.spyOn(api.accessRetentionApi, 'getContent').mockResolvedValue({
      data: { request_id: '', request_content: '', response_content: '', file_metadata: [] },
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getRawContent').mockResolvedValue({
      data: { request_id: '', sections: [], tool_calls: [], evidence_fallback: [] },
    } as any)
    vi.spyOn(api.auditApi, 'getRequestDetail').mockResolvedValue({ data: { security_events: [], content_logs: [] } } as any)
  })

  const renderPage = (entry = '/audit/content') =>
    render(
      <MemoryRouter initialEntries={[`${entry}${entry.includes('?') ? '&' : '?'}view=conversations`]}>
        <QueryClientProvider client={queryClient}>
          <ContentAudit />
        </QueryClientProvider>
      </MemoryRouter>,
    )

  // 一条代理流量会话：没有用户，只留下网关出口地址，主体应落到上游账号上。
  const proxiedSession = {
    session_id: REQUEST_ID,
    request_id: REQUEST_ID,
    start_time: '2026-09-17T02:00:00Z',
    source_ip: NAT_IP,
    client_ip: NAT_IP,
    user_id: '',
    username: '',
    client_name: '',
    provider: 'openai',
    target_host: 'api.openai.com',
    agent_type: 'cursor',
    department_id: 'dept-risk',
    department_name: DEPARTMENT_FIXTURE,
    conversation_id: 'conv-upstream-1',
    principal_key: UPSTREAM_ACCOUNT_KEY,
    principal_proxy_nat: true,
    risk_categories: ['credential_leak'],
    security_event_count: 1,
    actionable_alert_count: 1,
    matched_rule_count: 1,
    highest_severity: 'high',
    action_taken: 'audit',
  }

  const openDrawer = async () => {
    renderPage()
    expect(await screen.findByText(ALERT_DETAIL_TITLE)).toBeInTheDocument()
    // 反向代理/正向会话的抽屉标题是「会话详情」，只有访问留存记录才叫「留存详情」，
    // 所以这里以抽屉内容（责任与证据链）出现作为打开信号。
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(VIEW_LABEL + '$') }))
  }

  const findAttributionCard = async () => {
    const title = await screen.findByText(ATTRIBUTION_CARD)
    const card = title.closest('.ant-card')
    if (!card) throw new Error('attribution card container not found')
    return within(card as HTMLElement)
  }

  it('names the upstream account in the responsibility column and keeps the NAT caveat', async () => {
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({ data: { data: [proxiedSession], total: 1 } } as any)

    renderPage()

    // 主体是上游账号，不是网关出口地址。
    expect(await screen.findByText(UPSTREAM_ACCOUNT_LABEL)).toBeInTheDocument()
    // 列表列把出口地址连同 NAT 说明一起放在次要行，避免被当成真实客户端。
    expect(screen.getByText(NAT_IP + NAT_NOTE)).toBeInTheDocument()
    expect(screen.queryByText(NAT_IP)).not.toBeInTheDocument()
  })

  it('renders the four attribution rows with department, agent, upstream label and conversation jump', async () => {
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({ data: { data: [proxiedSession], total: 1 } } as any)

    await openDrawer()
    const card = await findAttributionCard()

    // 行一：用户（无关联用户）+ 部门。
    expect(card.getByText(USER_LABEL)).toBeInTheDocument()
    expect(card.getByText(UNLINKED_USER)).toBeInTheDocument()
    expect(card.getByText(DEPARTMENT_PREFIX + DEPARTMENT_FIXTURE)).toBeInTheDocument()
    // 行二：智能体。
    expect(card.getByText(AGENT_LABEL)).toBeInTheDocument()
    expect(card.getByText('Cursor')).toBeInTheDocument()
    // 行三：凭据 / 上游账号 + 来源 IP（带 NAT 说明）。
    expect(card.getByText(CREDENTIAL_LABEL)).toBeInTheDocument()
    expect(card.getByText(UPSTREAM_ACCOUNT_LABEL)).toBeInTheDocument()
    // 抽屉里带上"来源 IP"前缀，与列表列的次要行区分开。
    expect(card.getByText(SOURCE_IP_PREFIX + NAT_IP + NAT_NOTE)).toBeInTheDocument()
    // 行四：对话 ID 可复制，并能跳到访问留存。
    expect(card.getByText(CONVERSATION_LABEL)).toBeInTheDocument()
    expect(card.getByText(proxiedSession.conversation_id)).toBeInTheDocument()
    expect(card.getByRole('button', { name: VIEW_RETENTION })).toBeInTheDocument()
  })

  it('surfaces tool calls inside the drawer without switching to the raw view', async () => {
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({ data: { data: [], total: 0 } } as any)
    vi.mocked(api.accessRetentionApi.list).mockResolvedValue({
      data: {
        data: [{
          request_id: REQUEST_ID,
          created_at: '2026-09-17T02:00:00Z',
          source_ip: '10.0.0.7',
          provider: 'openai',
          target_host: 'api.openai.com',
          risk_state: 'risk',
          risk_reasons: ['credential_leak'],
          security_event_count: 1,
          action_taken: 'audit',
          agent_type: 'cursor',
        }],
        total: 1,
      },
    } as any)
    vi.mocked(api.accessRetentionApi.getRawContent).mockResolvedValue({
      data: {
        request_id: REQUEST_ID,
        sections: [],
        tool_calls: [{ id: 'tool-1', name: 'ReadFile', kind: 'invocation_proposed', stage: 'request', arguments_preview: '{"path":"/etc/hosts"}' }],
        evidence_fallback: [],
      },
    } as any)

    renderPage('/security/alerts?request_id=' + REQUEST_ID)

    expect(await screen.findByText(RETENTION_DETAIL_TITLE + ': ' + REQUEST_ID)).toBeInTheDocument()
    // 元数据在 manager 视图就该取：责任主体块要用它，不能等切「全部原文」。
    await waitFor(() => expect(api.accessRetentionApi.getRawContent).toHaveBeenCalled())
    expect(await screen.findByText(TOOL_CALLS_TITLE)).toBeInTheDocument()
    expect(screen.getByText('ReadFile')).toBeInTheDocument()
    expect(screen.getByText('{"path":"/etc/hosts"}')).toBeInTheDocument()
  })
})
