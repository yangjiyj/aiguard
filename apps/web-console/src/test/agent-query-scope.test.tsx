import { act, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AuditQueryIdentityBoundary from '../components/AuditQueryIdentityBoundary'
import AgentSessionDetail from '../pages/agent/AgentSessionDetail'
import AgentEndpoints from '../pages/agent/AgentEndpoints'
import { agentEndpointApi, agentKeys } from '../services/agentEndpoint'
import { useAuthStore } from '../stores/auth'

beforeEach(() => {
  vi.restoreAllMocks()
  useAuthStore.setState({ user: { id:'user-a',username:'A',role:'auditor',tenant_id:'tenant-a' },isAuthenticated:true,token:'secret-not-in-query-key' })
})
const switchIdentity = () => act(() => useAuthStore.getState().setUser({ id:'user-b',username:'B',role:'auditor',tenant_id:'tenant-b' }))
describe('资产调查目标页的身份隔离', () => {
  it('相同原生 session ID 在切换租户时立即丢弃旧会话详情', async () => {
    vi.spyOn(agentEndpointApi,'session').mockImplementation(() => new Promise(() => {}))
    const client = new QueryClient({defaultOptions:{queries:{retry:false,staleTime:Infinity}}})
    const oldKey = agentKeys.session('same-session')
    client.setQueryData(oldKey,{ overview:{id:'r',session_id:'same-session',product:'codex',project_label:'tenant-a-private-project',status:'ended',source:'endpoint',turn_count:0,event_count:0,blocked_count:0,would_block_count:0},events:[],turns:[],alerts:[],tool_call_logs:[] })
    render(<QueryClientProvider client={client}><AuditQueryIdentityBoundary><MemoryRouter initialEntries={['/agent/sessions/same-session']}><Routes><Route path="/agent/sessions/:id" element={<AgentSessionDetail />} /></Routes></MemoryRouter></AuditQueryIdentityBoundary></QueryClientProvider>)
    expect(await screen.findByText('tenant-a-private-project')).toBeInTheDocument()
    switchIdentity()
    expect(screen.queryByText('tenant-a-private-project')).not.toBeInTheDocument()
    expect(client.getQueryData(oldKey)).toBeUndefined()
    expect(agentKeys.session('same-session')).not.toEqual(oldKey)
    expect(JSON.stringify(agentKeys.session('same-session'))).not.toContain('secret-not-in-query-key')
  })
  it('同名端点详情不会从另一租户缓存恢复', async () => {
    vi.spyOn(agentEndpointApi,'endpoints').mockImplementation(() => new Promise(() => {}))
    vi.spyOn(agentEndpointApi,'endpoint').mockImplementation(() => new Promise(() => {}))
    vi.spyOn(agentEndpointApi,'assets').mockImplementation(() => new Promise(() => {}))
    vi.spyOn(agentEndpointApi,'sessions').mockImplementation(() => new Promise(() => {}))
    const client = new QueryClient({defaultOptions:{queries:{retry:false,staleTime:Infinity}}})
    const oldKey = agentKeys.endpoint('same-endpoint')
    client.setQueryData(oldKey,{id:'same-endpoint',hostname:'tenant-a-private-host',product:'codex',os:'linux',os_user:'user',status:'active',last_heartbeat_at:null,health:{},capabilities:[]})
    render(<QueryClientProvider client={client}><AuditQueryIdentityBoundary><MemoryRouter initialEntries={['/agent/endpoints?endpoint=same-endpoint']}><AgentEndpoints /></MemoryRouter></AuditQueryIdentityBoundary></QueryClientProvider>)
    expect(await screen.findByText('tenant-a-private-host')).toBeInTheDocument()
    switchIdentity()
    expect(screen.queryByText('tenant-a-private-host')).not.toBeInTheDocument()
    expect(client.getQueryData(oldKey)).toBeUndefined()
  })
  it('列表、历史、注册、事件和首页查询随身份与角色分离', () => {
    const collect = () => [agentKeys.scope,agentKeys.overview,agentKeys.endpoints({page:1,page_size:20}),agentKeys.endpoint('e'),agentKeys.assets('e',1),agentKeys.enrollment(1),agentKeys.sessions({page:1,page_size:20}),agentKeys.session('s'),agentKeys.events('s',1)]
    const old=collect()
    switchIdentity()
    collect().forEach((key,i) => expect(key).not.toEqual(old[i]))
    const current=collect()
    act(() => useAuthStore.getState().setUser({id:'user-b',username:'B',role:'tenant_admin',tenant_id:'tenant-b'}))
    collect().forEach((key,i) => expect(key).not.toEqual(current[i]))
  })
})
