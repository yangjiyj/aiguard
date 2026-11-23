import {beforeEach,it,expect,vi} from 'vitest'
import {render,screen,waitFor,fireEvent} from '@testing-library/react'
import {QueryClient,QueryClientProvider} from '@tanstack/react-query'
import {UserAccountMergeCard} from '../components/UserAccountMergeCard'
import {userAccountMergeApi} from '../services/userAccountMerge'
import {userApi} from '../services/api'
beforeEach(()=>{vi.restoreAllMocks()})
it('先预览，所有冲突选择后才允许确认合并，中文展示且不露枚举',async()=>{
 vi.spyOn(userApi,'list').mockResolvedValue({data:{data:[{id:'source',username:'源账号',role:'chat_user',status:'active'},{id:'target',username:'目标账号',role:'chat_user',status:'active'}]}} as unknown as Awaited<ReturnType<typeof userApi.list>>)
 vi.spyOn(userAccountMergeApi,'preview').mockResolvedValue({data:{data:{source_user_id:'source',target_user_id:'target',source:{username:'源账号'},target:{username:'目标账号'},preview_version:'v1',required_choices:['department','personal_policy'],source_identity_count:1,source_key_count:0,billing_history:'只追加历史归属标注',session_history:'源账号登录失效'}}} as unknown as Awaited<ReturnType<typeof userAccountMergeApi.preview>>)
 render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><UserAccountMergeCard userId="target"/></QueryClientProvider>)
 fireEvent.mouseDown(await screen.findByRole('combobox',{name:'待合并账号'}))
 fireEvent.click(await screen.findByText('源账号'))
 fireEvent.click(screen.getByRole('button',{name:'预览合并'}))
 await waitFor(()=>expect(screen.getByRole('button',{name:'确认合并账号'})).toBeDisabled())
 expect(screen.getByText('所属部门')).toBeInTheDocument()
 expect(screen.getByText('个人模型策略')).toBeInTheDocument()
 expect(screen.queryByText('personal_policy')).not.toBeInTheDocument()
})
