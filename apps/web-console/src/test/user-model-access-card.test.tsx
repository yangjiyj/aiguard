import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { UserModelAccessCard } from '../components/ai-permissions/UserModelAccessCard'
import { userModelAccessApi } from '../services/userModelAccess'
import { modelApi } from '../services/api'

const initial = { mode: 'allowlist' as const, model_names: [], department_models: ['model-a', 'model-b'], effective_models: [], version: 2, user_id: 'u1', department_id: 'dept', department_name: '研发部', department_version: 1, chat_allowed: true }
function show() {
 return render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><UserModelAccessCard userId="u1" canEdit /></QueryClientProvider>)
}
beforeEach(() => {
 vi.restoreAllMocks()
 vi.spyOn(userModelAccessApi, 'get').mockResolvedValue({data:{data:initial}} as any)
 vi.spyOn(userModelAccessApi, 'set').mockResolvedValue({data:{data:initial}} as any)
 vi.spyOn(modelApi,'list').mockResolvedValue({data:{data:[{id:'ma',model_name:'model-a',model_label:'模型 A'},{id:'mb',model_name:'model-b',model_label:'模型 B'},{id:'mc',model_name:'model-c',model_label:'部门外模型 C'}]}} as any)
})
describe('用户个人模型授权', () => {
 it('显式空名单禁止所有模型，并以当前版本保存', async () => {
  show()
  await waitFor(() => expect(screen.getByText('当前未授权任何模型')).toBeInTheDocument())
  expect(screen.getByText('单独指定模型')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button',{name:'保存模型权限'}))
  await waitFor(()=>expect(userModelAccessApi.set).toHaveBeenCalledWith('u1',{mode:'allowlist',model_names:[],version:2}))
 })
 it('切换继承不会把旧个人名单作为新授权提交', async () => {
  vi.spyOn(userModelAccessApi,'get').mockResolvedValue({data:{data:{...initial,model_names:['model-a'],effective_models:['model-a']}}} as any)
  show();await screen.findByRole('button',{name:'保存模型权限'})
  await userEvent.click(screen.getByLabelText('继承部门权限'))
  await userEvent.click(screen.getByRole('button',{name:'保存模型权限'}))
  await waitFor(()=>expect(userModelAccessApi.set).toHaveBeenCalledWith('u1',{mode:'inherit',model_names:[],version:2}))
 })
 it('只能选择部门上限以内的模型', async () => {
  show();await screen.findByRole('button',{name:'保存模型权限'})
  await userEvent.click(screen.getByRole('combobox',{name:'个人可用模型'}))
  expect(await screen.findByText('模型 A')).toBeInTheDocument()
  expect(screen.getByText('模型 B')).toBeInTheDocument()
  expect(screen.queryByText('部门外模型 C')).not.toBeInTheDocument()
 })
 it('读取失败不展示可编辑的空权限，也不回显内部异常', async () => {
  vi.spyOn(userModelAccessApi,'get').mockRejectedValue(new Error('postgresql://sensitive-storage'))
  show();expect(await screen.findByText('模型权限读取失败')).toBeInTheDocument()
  expect(screen.queryByRole('button',{name:'保存模型权限'})).not.toBeInTheDocument()
  expect(screen.queryByText(/sensitive-storage/)).not.toBeInTheDocument()
 })
})

it('模型名称与其他模型内部 ID 同字时，名称标签优先', async () => {
 vi.spyOn(userModelAccessApi,'get').mockResolvedValue({data:{data:{...initial,department_models:['model-a'],model_names:['model-a'],effective_models:['model-a']}}} as any)
 vi.spyOn(modelApi,'list').mockResolvedValue({data:{data:[{id:'id-b',model_name:'model-a',model_label:'模型 B'},{id:'model-a',model_name:'model-z',model_label:'模型 A'}]}} as any)
 show()
 await waitFor(()=>expect(screen.getAllByText('模型 B').length).toBeGreaterThan(0))
 expect(screen.queryByText('模型 A')).not.toBeInTheDocument()
})
it('合法的 __proto__ 模型名按普通文本标签展示', async () => {
 vi.spyOn(userModelAccessApi,'get').mockResolvedValue({data:{data:{...initial,department_models:['__proto__'],model_names:['__proto__'],effective_models:['__proto__']}}} as any)
 vi.spyOn(modelApi,'list').mockResolvedValue({data:{data:[{id:'safe-model-id',model_name:'__proto__',model_label:'模型 原型名称'}]}} as any)
 show()
 await waitFor(()=>expect(screen.getAllByText('模型 原型名称').length).toBeGreaterThan(0))
})


it('展示三类来源、陈旧项与额外授权撤销入口', async () => {
 vi.spyOn(userModelAccessApi,'get').mockResolvedValue({data:{data:{...initial,
  model_names:['model-a','old-model'],effective_models:['model-a','model-b','model-c'],
  model_sources:{'model-a':'personal_narrowed','model-b':'department','model-c':'personal_extra'},
  stale_models:['old-model'],extra_grants:[{id:'grant-c',model:'model-c',reason:'独立业务',created_by:'admin',created_at:'2026-10-12T00:00:00Z',expires_at:null,revoked_at:null}]
 }}} as unknown as Awaited<ReturnType<typeof userModelAccessApi.get>>)
 show()
 await waitFor(()=>expect(screen.getByText('个人已收窄')).toBeInTheDocument())
 expect(screen.getByText('部门授权')).toBeInTheDocument()
 expect(screen.getByText('个人额外授权')).toBeInTheDocument()
 expect(screen.getByText(/old-model.*已不在当前部门范围/)).toBeInTheDocument()
 expect(screen.getByText('独立业务')).toBeInTheDocument()
 expect(screen.getByRole('button',{name:'撤销额外授权'})).toBeInTheDocument()
 expect(screen.getByRole('button',{name:'新增个人额外授权'})).toBeInTheDocument()
})
