import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { message } from 'antd'
import Providers from '../pages/Providers'
import { providerApi } from '../services/api'

const fixture = vi.hoisted(() => ({ failures: 1 }))
vi.mock('../components/providers/ModelCatalogSyncModal', () => ({ default: ({ open, onSynced }: { open: boolean; onSynced: (result: unknown) => void }) => open ? <button onClick={() => onSynced({created:0,updated:45,verified:0,deactivated:0,verification_failed:fixture.failures,skipped:0})}>返回同步回执</button> : null }))
afterEach(() => { cleanup(); vi.restoreAllMocks() })
it.each([1, 0])('uses an honest notification when verification failures are %s', async (failures) => {
 fixture.failures = failures
 vi.spyOn(providerApi, 'list').mockResolvedValue({data:{data:[{id:'p1',name:'测试渠道',provider_type:'anthropic',status:'active',has_credential:true}],total:1}} as never)
 vi.spyOn(providerApi, 'deleted').mockResolvedValue({data:{items:[]}} as never)
 vi.spyOn(providerApi, 'metrics').mockResolvedValue({data:{data:[]}} as never)
 const success=vi.spyOn(message,'success').mockImplementation(vi.fn())
 const warning=vi.spyOn(message,'warning').mockImplementation(vi.fn())
 const client=new QueryClient({defaultOptions:{queries:{retry:false,gcTime:0}}})
 render(<MemoryRouter><QueryClientProvider client={client}><Providers /></QueryClientProvider></MemoryRouter>)
 await userEvent.click(await screen.findByRole('button',{name:/同步模型/}))
 await userEvent.click(await screen.findByRole('button',{name:'返回同步回执'}))
 if(failures){expect(warning).toHaveBeenCalledWith(expect.stringContaining('部分模型验证失败'));expect(success).not.toHaveBeenCalled()}
 else{expect(success).toHaveBeenCalledWith(expect.stringContaining('同步完成'));expect(warning).not.toHaveBeenCalled()}
 client.clear()
})
