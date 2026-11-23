import { describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import type { AgentEndpoint } from '../services/agentEndpoint.types'
import AgentEndpoints from '../pages/agent/AgentEndpoints'
import { ControlBoundaryPanel } from '../pages/agent/ControlBoundary'
import { controlBoundaryRows, notReportedText, readControlBoundary, triggerLabels } from '../pages/agent/controlBoundaryReport'
// Captured from a real hookd (client 49facc1e) heartbeat via TestT04HookdProcessToEventsHandler.
import realHealth from './fixtures/hookd-heartbeat-health-control-boundary.json'

const reported = realHealth.control_boundary
const endpoint = (overrides: Partial<AgentEndpoint>): AgentEndpoint => ({
  id: 'ep-1', machine_id: 'm', hostname: 'host-1', os: 'linux', os_version: '6', arch: 'amd64', os_user: 'u',
  product: 'openclaw', agent_version: '1', adapter_name: 'openclaw', adapter_version: '1', hookd_version: '0.1.0',
  capabilities: [], token_prefix: 'p', mode: null, capture_level: 'metadata', status: 'active',
  last_heartbeat_at: new Date().toISOString(), last_event_at: null, last_policy_version: 7, last_config_version: 1,
  health: { queue_events: 1 }, created_at: '2026-09-28T00:00:00Z', updated_at: '2026-09-28T00:00:00Z',
  ...overrides,
})
const rows: AgentEndpoint[] = [
  endpoint({ id: 'ep-reporting', hostname: 'reporting-host', health: realHealth as unknown as AgentEndpoint['health'], control_boundary: reported }),
  endpoint({ id: 'ep-legacy', hostname: 'legacy-host', control_boundary: null }),
  endpoint({ id: 'ep-old-api', hostname: 'old-api-host' }),
]
vi.mock('../services/agentEndpoint', async (importOriginal) => {
  const source = await importOriginal<typeof import('../services/agentEndpoint')>()
  return { ...source, agentEndpointApi: { ...source.agentEndpointApi,
    endpoints: vi.fn(async () => ({ items: rows, page: 1, page_size: 20, total: rows.length })),
    endpoint: vi.fn(async (id: string) => rows.find(row => row.id === id)!),
    assets: vi.fn(async () => ({ items: [], page: 1, page_size: 100, total: 0 })),
    sessions: vi.fn(async () => ({ items: [], page: 1, page_size: 5, total: 0 })),
  } }
})
const renderPage = (path: string) => render(<MemoryRouter initialEntries={[path]}><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><AgentEndpoints /></QueryClientProvider></MemoryRouter>)

describe('控制边界展示', () => {
  it('只接受 v1 对象，缺省与异常值一律视为未上报', () => {
    expect(readControlBoundary(reported)?.schema).toBe('jjdguard-control-boundary/v1')
    for (const value of [null, undefined, 'fail_open', [reported], { schema: 'other/v2' }]) expect(readControlBoundary(value)).toBeNull()
  })

  it('真实 hookd 上报的每个触发条件都有中文说明', () => {
    const triggers = controlBoundaryRows(readControlBoundary(reported)!).map(row => row.trigger)
    expect(triggers.length).toBeGreaterThan(0)
    expect(triggers.filter(trigger => !triggerLabels[trigger])).toEqual([])
  })

  it('旧 hookd（null 或字段缺失）显示未上报与失效行为未知', () => {
    for (const value of [null, undefined]) {
      const { unmount } = render(<ControlBoundaryPanel value={value} />)
      expect(screen.getByTestId('control-boundary-missing')).toHaveTextContent(notReportedText)
      expect(screen.queryByText('失效放行')).toBeNull()
      unmount()
    }
  })

  it('OpenClaw 握手前失效阻断、握手后非严格失效放行，按宿主逐条展示', () => {
    render(<ControlBoundaryPanel value={reported} />)
    const panel = screen.getByTestId('control-boundary')
    const handshake = within(panel).getByText('模式握手失败或超时').closest('tr')!
    expect(within(handshake).getByText('失效阻断')).toBeInTheDocument()
    expect(within(handshake).getByText('3000 毫秒')).toBeInTheDocument()
    const afterHandshake = within(panel).getByText('握手后调用失败（非严格）').closest('tr')!
    expect(within(afterHandshake).getByText('失效放行')).toBeInTheDocument()
    expect(within(panel).getAllByText('仅观测').length).toBe(2)
    expect(within(panel).getByText('Shell 子进程')).toBeInTheDocument()
    expect(within(panel).getByText('要求可信授权').closest('tr')).toHaveTextContent('要求可信授权否')
  })

  it('配置不可用时明确提示前置钩子全部阻断', () => {
    render(<ControlBoundaryPanel value={{ schema: 'jjdguard-control-boundary/v1', approval_required_actions: [], config_error: 'config unreadable' }} />)
    expect(screen.getByText('hookd 无法加载钩子配置，前置钩子将全部阻断')).toBeInTheDocument()
  })

  it('端点列表区分已上报与未上报', async () => {
    renderPage('/agent/endpoints')
    const reportingRow = (await screen.findByText('reporting-host')).closest('tr')!
    expect(within(reportingRow).getByText('已上报')).toBeInTheDocument()
    expect(within(screen.getByText('legacy-host').closest('tr')!).getByText('未上报')).toBeInTheDocument()
    expect(within(screen.getByText('old-api-host').closest('tr')!).getByText('未上报')).toBeInTheDocument()
  })

  it('详情抽屉展示控制边界，采集健康不把对象渲染成文本', async () => {
    renderPage('/agent/endpoints?endpoint=ep-reporting')
    expect(await screen.findByTestId('control-boundary')).toBeInTheDocument()
    expect(screen.queryByText('[object Object]')).toBeNull()
    expect(screen.getByText('积压事件')).toBeInTheDocument()
  })

  it('旧 hookd 端点详情显示未上报', async () => {
    renderPage('/agent/endpoints?endpoint=ep-old-api')
    expect(await screen.findByTestId('control-boundary-missing')).toHaveTextContent(notReportedText)
  })
})
