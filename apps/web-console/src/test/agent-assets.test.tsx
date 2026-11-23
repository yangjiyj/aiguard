import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import AgentEndpoints from '../pages/agent/AgentEndpoints'
import { agentKeys } from '../services/agentEndpoint'

const mocks = vi.hoisted(() => ({ endpoints: vi.fn(), endpoint: vi.fn(), assets: vi.fn(), sessions: vi.fn() }))
vi.mock('../services/agentEndpoint', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../services/agentEndpoint')>()
  return { ...actual, agentEndpointApi: { ...actual.agentEndpointApi, endpoints: mocks.endpoints, endpoint: mocks.endpoint, assets: mocks.assets, sessions: mocks.sessions } }
})
const assetPage = (endpoint_id: string, page: number) => ({items:[{id:`${endpoint_id}-${page}`,endpoint_id,asset_type:'skill',name:`asset-${endpoint_id}-${page}`,present:true,version:'1.2',source:'hook',scan_status:'clean',scan_decision:'allow',first_seen:'2026-01-01T00:00:00Z',last_seen:'2026-01-02T00:00:00Z'}],page,page_size:100,total:205})
function mount() {
  const client = new QueryClient({defaultOptions:{queries:{retry:false}}})
  return render(<MemoryRouter><QueryClientProvider client={client}><AgentEndpoints/></QueryClientProvider></MemoryRouter>)
}
beforeEach(() => {
  vi.clearAllMocks()
  mocks.endpoints.mockResolvedValue({items:[{id:'ep-a',product:'claude-code',agent_version:'1',hostname:'host-a',os_user:'user',os:'linux',status:'active',last_heartbeat_at:new Date().toISOString(),mode:'monitor',capture_level:'metadata',last_policy_version:1,health:{},capabilities:[]}],page:1,page_size:20,total:1})
  mocks.endpoint.mockResolvedValue({id:'ep-a',product:'claude-code',hostname:'host-a',os_user:'user',os:'linux',os_version:'1',mode:'monitor',capture_level:'metadata',last_heartbeat_at:null,last_policy_version:1,health:{},capabilities:[]})
  mocks.assets.mockImplementation(async (id:string,page:number)=>assetPage(id,page))
  mocks.sessions.mockResolvedValue({items:[],total:0,page:1,page_size:5})
})
describe('端点资产契约', () => {
  it('API 和 Query Key 按 endpoint 与 page 隔离，并支持翻过 100 项', async () => {
    expect(agentKeys.assets('ep-a',2)).not.toEqual(agentKeys.assets('ep-a',1))
    expect(agentKeys.assets('ep-a',1)).not.toEqual(agentKeys.assets('ep-b',1))
    mount()
    fireEvent.click((await screen.findAllByRole('button',{name:'详情'}))[0])
    expect(await screen.findByText('asset-ep-a-1')).toBeInTheDocument()
    fireEvent.click(document.querySelector('.ant-drawer .ant-pagination-next') as HTMLElement)
    expect(await screen.findByText('asset-ep-a-2')).toBeInTheDocument()
    expect(mocks.assets).toHaveBeenCalledWith('ep-a',2,100)
  })
  it('切换端点重置页码且不展示先前端点数据', async () => {
    mocks.endpoints.mockResolvedValue({items:[{id:'ep-a',product:'claude-code',agent_version:'1',hostname:'host-a',os_user:'u',os:'linux',status:'active',last_heartbeat_at:new Date().toISOString(),mode:'monitor',capture_level:'metadata',last_policy_version:1,health:{},capabilities:[]},{id:'ep-b',product:'codex',agent_version:'2',hostname:'host-b',os_user:'u',os:'linux',status:'active',last_heartbeat_at:new Date().toISOString(),mode:'monitor',capture_level:'metadata',last_policy_version:1,health:{},capabilities:[]}],page:1,page_size:20,total:2})
    mount()
    fireEvent.click((await screen.findAllByRole('button',{name:'详情'}))[0])
    await screen.findByText('asset-ep-a-1')
    fireEvent.click(document.querySelector('.ant-drawer .ant-pagination-next') as HTMLElement)
    await screen.findByText('asset-ep-a-2')
    fireEvent.click(screen.getAllByRole('button',{name:'详情'})[1])
    expect(await screen.findByText('asset-ep-b-1')).toBeInTheDocument()
    expect(screen.queryByText('asset-ep-a-2')).not.toBeInTheDocument()
    expect(mocks.assets).toHaveBeenCalledWith('ep-b',1,100)
  })
  it.each([[403,'无权查看此端点资产（403）'],[402,'当前服务额度不足，无法查看端点资产（402）'],[500,'端点资产加载失败']])('区分资产接口错误 %i', async (status,message) => {
    mocks.assets.mockRejectedValue({response:{status}})
    mount()
    fireEvent.click((await screen.findAllByRole('button',{name:'详情'}))[0])
    await waitFor(() => expect(screen.getAllByRole('alert').some(alert => alert.textContent?.includes(message))).toBe(true))
  })
  it('缺少可选字段时显示占位，不暴露 evidence', async () => {
    mocks.assets.mockResolvedValue({items:[{id:'e',endpoint_id:'ep-a',asset_type:'skill',name:'safe-name',present:false,evidence:{secret:'private'}}],page:1,page_size:100,total:1})
    mount()
    fireEvent.click((await screen.findAllByRole('button',{name:'详情'}))[0])
    expect(await screen.findByText('safe-name')).toBeInTheDocument()
    expect(screen.getAllByText('未记录').length).toBeGreaterThan(0)
    expect(screen.queryByText(/private/)).not.toBeInTheDocument()
  })
})
