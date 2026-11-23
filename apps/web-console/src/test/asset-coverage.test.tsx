import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AgentAssetCoverage from '../pages/agent/AgentAssetCoverage'
import { coverageGaps, endpointHealth } from '../pages/agent/assetCoverage'
import { unifiedAssetKeys, type UnifiedAsset } from '../services/unifiedAssets'
import type { AgentEndpoint } from '../services/agentEndpoint.types'
const mocks = vi.hoisted(() => ({ list: vi.fn(), history: vi.fn(), endpoint: vi.fn(), sessions: vi.fn() }))
vi.mock('../services/unifiedAssets', async importOriginal => ({ ...await importOriginal<typeof import('../services/unifiedAssets')>(), unifiedAssetsApi: { list: mocks.list, history: mocks.history } }))
vi.mock('../services/agentEndpoint', () => ({ agentEndpointApi: { endpoint: mocks.endpoint, sessions: mocks.sessions } }))
const asset: UnifiedAsset = { id:'asset-a', name:'demo-skill', asset_type:'skill', owner_user_id:'', business_unit:'', business_service:'', catalog_status:'expired', catalog_reason:'review', first_seen:'2026-01-01T00:00:00Z', last_seen:'2026-01-02T00:00:00Z', instance_count:1, managed_instance_count:1, observed_instance_count:1, control_evidence_count:0, discovered:true, managed:true, observed:true, controlled:false, control_state:'not_evidenced' }
function mount() { return render(<MemoryRouter><QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><AgentAssetCoverage /></QueryClientProvider></MemoryRouter>) }
beforeEach(() => {
  vi.clearAllMocks()
  mocks.list.mockImplementation(async ({page}) => ({items:[{...asset,id:'asset-'+page,name:'demo-skill-'+page}],page,page_size:20,total:41}))
  mocks.history.mockImplementation(async (id,page) => ({ items:[{ id:id+'-h'+page,source_type:'agent_endpoint', source_namespace:'ep/a', source_event_id:'event-'+page, version:'1',hash:'sha-safe',present:true,scan_status:'clean',scan_decision:'allow',source_occurred_at:'2026-01-01T00:00:00Z',received_at:'2026-01-01T00:00:01Z', evidence:{secret:'do-not-render'} }],page,page_size:20,total:21 }))
  mocks.endpoint.mockResolvedValue({id:'ep/a',status:'active',last_heartbeat_at:'2020-01-01T00:00:00Z',last_event_at:null,health:{queue_events:4,dropped_events:2}})
  mocks.sessions.mockResolvedValue({items:[{id:'s-row',session_id:'session/a',blocked_count:1,would_block_count:2,last_request_at:null}],page:1,page_size:5,total:1})
})
describe('资产覆盖口径与调查', () => {
  it('扫描存在与接入不推导运行时控制，统计明确当前页', async () => {
    mount()
    await screen.findByText('demo-skill-1')
    expect(screen.getByText('当前页覆盖')).toBeInTheDocument()
    expect(screen.getByText('未知：无资产级运行时证据')).toBeInTheDocument()
    expect(screen.getByText('未知：无控制生效证据')).toBeInTheDocument()
    expect(mocks.endpoint).not.toHaveBeenCalled()
    expect(coverageGaps(asset)).toContain('目录例外已过期')
    expect(coverageGaps({...asset, controlled:true,control_evidence_count:1,control_state:'not_evidenced'})).toContain('缺少控制生效证据')
  })
  it('列表与历史独立分页，翻页后清理详情；来源可下钻真实端点会话', async () => {
    mount()
    fireEvent.click(await screen.findByText('demo-skill-1'))
    await screen.findByText('event-1')
    expect(screen.queryByText(/do-not-render/)).not.toBeInTheDocument()
    fireEvent.click(document.querySelector('.ant-drawer .ant-pagination-next') as HTMLElement)
    await screen.findByText('event-2')
    expect(mocks.history).toHaveBeenCalledWith('asset-1',2)
    fireEvent.click(screen.getByRole('button',{name:'检查端点 ep/a'}))
    expect(await screen.findByRole('link',{name:'session/a'})).toHaveAttribute('href','/agent/sessions/session%2Fa')
    expect(screen.getByRole('link',{name:'端点详情：ep/a'})).toHaveAttribute('href','/agent/endpoints?endpoint=ep%2Fa')
    expect(screen.getByText(/失联 · 最近心跳超过/)).toBeInTheDocument()
    expect(mocks.sessions).toHaveBeenCalledWith({endpoint_id:'ep/a',page:1,page_size:5})
    fireEvent.click(within(document.querySelector('.ant-drawer') as HTMLElement).getByRole('button',{name:'Close'}))
    fireEvent.click(document.querySelector('.enterprise-page > .ant-table-wrapper .ant-pagination-next') as HTMLElement)
    expect(await screen.findByText('demo-skill-2')).toBeInTheDocument()
    fireEvent.click(screen.getByText('demo-skill-2'))
    await waitFor(() => expect(mocks.history).toHaveBeenCalledWith('asset-2',1))
    expect(screen.queryByRole('link',{name:'session/a'})).not.toBeInTheDocument()
  })
  it.each([402,403,500])('列表错误 %s 不显示虚假空集或覆盖计数', async status => {
    mocks.list.mockRejectedValue({response:{status}})
    mount()
    await screen.findByRole('alert')
    expect(screen.queryByText('暂无符合条件的资产；尚未发现不代表环境中不存在资产')).not.toBeInTheDocument()
    expect(screen.getAllByText('—').length).toBeGreaterThan(0)
  })
  it('历史失败保留错误并禁止显示旧历史', async () => {
    mocks.history.mockRejectedValue({response:{status:403}})
    mount(); fireEvent.click(await screen.findByText('demo-skill-1'))
    expect(await screen.findByText('无权查看当前资产数据（403）')).toBeInTheDocument()
    expect(screen.queryByText('event-1')).not.toBeInTheDocument()
  })
  it('查询键隔离用户租户、资产和页码', () => {
    expect(unifiedAssetKeys.history('tenant-a','a',1)).not.toEqual(unifiedAssetKeys.history('tenant-b','a',1))
    expect(unifiedAssetKeys.history('tenant-a','a',1)).not.toEqual(unifiedAssetKeys.history('tenant-a','b',1))
    expect(unifiedAssetKeys.history('tenant-a','a',1)).not.toEqual(unifiedAssetKeys.history('tenant-a','a',2))
  })
  it('在线必须有有效近期心跳，未来时间和缺心跳显示原因', () => {
    const now = Date.parse('2026-01-01T00:00:00Z')
    const ep = {status:'active',last_heartbeat_at:'2026-01-01T00:00:00Z'} as AgentEndpoint
    expect(endpointHealth(ep,now).label).toBe('在线')
    expect(endpointHealth({...ep,last_heartbeat_at:null},now).label).toBe('未知')
    expect(endpointHealth({...ep,last_heartbeat_at:'2027-01-01T00:00:00Z'},now).label).toBe('未知')
    expect(endpointHealth({...ep,status:'revoked'},now).label).toBe('已吊销')
    expect(endpointHealth({...ep,status:'stale'},now).label).toBe('失联')
  })
})
