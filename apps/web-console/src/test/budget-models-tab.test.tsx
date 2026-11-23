import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { BudgetModelsTab } from '../components/team-tabs/BudgetModelsTab'
import * as api from '../services/api'

describe('BudgetModelsTab 保存提示', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.clearAllMocks()
    vi.spyOn(api.orgApi, 'getEffective').mockResolvedValue({ data: { team: {}, models: [], projects: [] } } as any)
    vi.spyOn(api.policyApi, 'getQuota').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.modelApi, 'list').mockResolvedValue({ data: { data: [{ id: 'model_1', model_name: 'glm-5.2' }] } } as any)
  })

  const renderTab = () => render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <BudgetModelsTab teamId="t1" />
      </QueryClientProvider>
    </MemoryRouter>,
  )

  it('只读展示部门预算与限流，并跳转到预算与额度页配置，不渲染编辑表单', async () => {
    vi.spyOn(api.policyApi, 'getQuota').mockResolvedValue({ data: { monthly_budget_micros: 300_000_000, rpm_limit: 60, tpm_limit: null, concurrency_limit: 0 } } as any)
    const setQuota = vi.spyOn(api.policyApi, 'setQuota')
    renderTab()
    const linkText = await screen.findByRole('link', { name: /去配置$/ })
    expect(await screen.findByText('300 元')).toBeInTheDocument()
    expect(screen.getByText('60')).toBeInTheDocument()
    expect(screen.queryByRole('spinbutton')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /保存配置/ })).not.toBeInTheDocument()
    expect(setQuota).not.toHaveBeenCalled()
    expect(screen.queryByText('\u9884\u7b97\u914d\u7f6e')).not.toBeInTheDocument()
    expect(linkText.closest('a')).toHaveAttribute(
      'href',
      '/cost/budgets?scope_type=team&scope_id=t1',
    )
    expect(screen.queryByText(/日度预算/)).not.toBeInTheDocument()
    expect(screen.queryByText(/保存预算/)).not.toBeInTheDocument()
  })

  it('未挂应用时保存提示去挂应用', async () => {
    const spy = vi.spyOn(api.orgApi, 'updateModels').mockResolvedValue({
      data: { updated: 0, propagated_project_ids: [], warning: '该部门未挂应用，模型授权不会对 chat 生效，请先在『应用』tab 挂应用' },
    } as any)
    renderTab()
    fireEvent.click(await screen.findByText('保存模型白名单'))
    await waitFor(() => expect(spy).toHaveBeenCalled())
    expect(await screen.findByText(/未挂应用/)).toBeInTheDocument()
  })

  it('写穿成功时提示已更新', async () => {
    const spy = vi.spyOn(api.orgApi, 'updateModels').mockResolvedValue({
      data: { updated: 1, propagated_project_ids: ['proj_1'] },
    } as any)
    renderTab()
    fireEvent.click(await screen.findByText('保存模型白名单'))
    await waitFor(() => expect(spy).toHaveBeenCalled())
    expect(await screen.findByText(/模型白名单已更新/)).toBeInTheDocument()
  })
})


describe('部门模型默认开放',()=>{
 it('默认模式把模型放在右侧，新增模型自动跟随；切换明确全禁后可保存',async()=>{
  vi.spyOn(api.orgApi,'getEffective').mockResolvedValue({data:{team:{},model_access_mode:'all_active',model_access_configured:false,models:[],projects:[]}} as unknown as Awaited<ReturnType<typeof api.orgApi.getEffective>>)
  vi.spyOn(api.modelApi,'list').mockResolvedValue({data:{data:[{id:'ma',model_name:'模型甲',status:'active',callable:true},{id:'mb',model_name:'模型乙',status:'active',callable:true}]}} as unknown as Awaited<ReturnType<typeof api.modelApi.list>>)
  vi.spyOn(api.policyApi,'getQuota').mockResolvedValue({data:{}} as unknown as Awaited<ReturnType<typeof api.policyApi.getQuota>>)
  const save=vi.spyOn(api.orgApi,'updateModels').mockResolvedValue({data:{updated:0,propagated_project_ids:[]}} as unknown as Awaited<ReturnType<typeof api.orgApi.updateModels>>)
  render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><BudgetModelsTab teamId="default-team"/></QueryClientProvider>)
  await waitFor(()=>expect(screen.getByLabelText('默认开放全部模型')).toBeChecked())
  await waitFor(()=>{const list=screen.getByText('模型甲').closest('.ant-transfer-list');expect(list?.textContent).toContain('已授权模型');expect(list?.textContent).toContain('模型乙')})
  fireEvent.click(screen.getByLabelText('禁止全部模型'))
  fireEvent.click(screen.getByRole('button',{name:'保存模型白名单'}))
  await waitFor(()=>expect(save).toHaveBeenCalledWith('default-team',{mode:'deny_all',models:[]}))
 })
})


describe('部门选择仅使用已部署可调用模型', () => {
  it('请求可调用目录，并与全量管理目录缓存隔离', async () => {
    const full = { data: { data: [
      { id: 'ready', model_name: '已部署模型', status: 'active', callable: true },
      { id: 'pending', model_name: '未部署目录候选', status: 'pending', callable: false },
    ] } }
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    client.setQueryData(['models'], full)
    vi.spyOn(api.orgApi, 'getEffective').mockResolvedValue({ data: { team: {}, model_access_mode: 'all_active', models: [], projects: [] } } as any)
    vi.spyOn(api.policyApi, 'getQuota').mockResolvedValue({ data: {} } as any)
    const list = vi.spyOn(api.modelApi, 'list').mockResolvedValue({ data: { data: [full.data.data[0]] } } as any)
    render(<QueryClientProvider client={client}><BudgetModelsTab teamId="selection-team" /></QueryClientProvider>)
    await waitFor(() => expect(screen.getByText('已部署模型')).toBeInTheDocument())
    expect(screen.queryByText('未部署目录候选')).not.toBeInTheDocument()
    expect(list).toHaveBeenCalledWith({ available_only: true })
    expect(client.getQueryData(['models'])).toEqual(full)
  })
})
