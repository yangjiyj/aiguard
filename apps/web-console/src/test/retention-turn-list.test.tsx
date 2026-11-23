import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import RetentionTurnList from '../components/RetentionTurnList'
import { accessRetentionApi, type AccessRetentionTurn, type AccessRetentionSearchHit } from '../services/api'

const turn: AccessRetentionTurn = {
 id: 'turn-a', index: 1, user_input: '请检查代码',
 answer: { id: 'answer-r2', request_id: 'r2', sequence: 2, role: 'assistant', kind: 'answer_candidate', content: '检查结果原文' },
 request_ids: ['r1', 'r2'], request_count: 2, process_count: 1,
 status: 'unconfirmed', finality_source: 'last_observed_response', correlation_source: 'history_occurrence',
 evidence_status: 'complete', observed_duration_ms: 12000,
}
function show(turns = [turn], identity = 'user-a', search?: { keyword: string; hits: AccessRetentionSearchHit[] }) {
 const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
 return render(<QueryClientProvider client={client}><RetentionTurnList
   turns={turns} requestId="r2" members={['r1', 'r2']} identity={identity}
   window={{ from: '2026-09-01T00:00:00Z', to: '2026-09-11T00:00:00Z' }}
   riskState="risk" agentLabel="WorkBuddy" artifacts={[]} searchKeyword={search?.keyword} searchHits={search?.hits}
   renderText={(text) => <div>{text}</div>} renderArtifacts={() => null}
 /></QueryClientProvider>)
}
beforeEach(() => vi.spyOn(accessRetentionApi, 'getTimeline').mockResolvedValue({ data: { data: [] } } as any))
afterEach(() => vi.restoreAllMocks())
describe('retention question and answer view', () => {
 it('shows durable inspection progress without declaring an incomplete scan safe', async () => {
  vi.spyOn(accessRetentionApi, 'getTurnProcess').mockResolvedValue({ data: { data: [], total: 0, has_more: false } } as any)
  vi.spyOn(accessRetentionApi, 'getTimeline').mockResolvedValue({ data: { data: [
   { id: 'inspection:r1', request_id: 'r1', type: 'inspection_progress', title: '安全检测排队补检', detail: '已完成 3/7 个检测部分。未完成部分将自动重试，服务重启后继续。', status: 'in_progress', timestamp: '2026-09-10T01:00:00Z' },
  ] } } as any)
  show()
  fireEvent.click(screen.getByRole('button', { name: /查看过程/ }))
  expect(await screen.findByText('安全检测排队补检')).toBeInTheDocument()
  expect(screen.getByText(/已完成 3\/7 个检测部分/)).toBeInTheDocument()
  expect(screen.getByText('补检中')).toBeInTheDocument()
  expect(screen.queryByText('安全检测已完成')).not.toBeInTheDocument()
 })
 it('shows tool names in the summary and keeps intermediate text and details collapsed', async () => {
  const process = vi.spyOn(accessRetentionApi, 'getTurnProcess').mockResolvedValue({ data: { data: [
   { id: 'progress-r1', request_id: 'r1', sequence: 1, role: 'assistant', kind: 'assistant_progress', content: '我先读取文件' },
  ], total: 1, offset: 0, limit: 50, has_more: false } } as any)
  const timeline = vi.spyOn(accessRetentionApi, 'getTimeline').mockResolvedValue({ data: { data: [
   { id: 'tool-1', type: 'tool_action', title: '读取文件', event_kind: 'invocation_proposed', timestamp: '' },
  ] } } as any)
  show()
  expect(screen.getByText('请检查代码')).toBeInTheDocument()
  expect(screen.getByText('检查结果原文')).toBeInTheDocument()
  expect(screen.queryByText('结束状态待确认')).not.toBeInTheDocument()
  expect(screen.getByText(/包含风险记录/)).toBeInTheDocument()
  expect(screen.queryByText('我先读取文件')).not.toBeInTheDocument()
  expect(process).not.toHaveBeenCalled()
  expect(timeline).toHaveBeenCalled()
  expect(screen.queryByRole('complementary', { name: '智能体行为' })).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: /查看过程/ }))
  expect(await screen.findByText('我先读取文件')).toBeInTheDocument()
  expect(await screen.findByText('读取文件')).toBeInTheDocument()
  expect(timeline).toHaveBeenCalledWith('r1', ['r1', 'r2'], expect.objectContaining({signal: expect.anything()}))
  expect(await screen.findByText('执行未确认')).toBeInTheDocument()
  expect(process).toHaveBeenCalledWith('r2', ['r1', 'r2'], 'turn-a', 0, expect.objectContaining({ from: '2026-09-01T00:00:00Z', signal: expect.anything() }))
  fireEvent.click(screen.getByRole('button', { name: /收起过程/ }))
  expect(screen.queryByText('我先读取文件')).not.toBeInTheDocument()
  expect(screen.getByText('检查结果原文')).toBeInTheDocument()
 })
 it('keeps real submissions as consecutive question/answer pairs without a selector', () => {
  show([{ ...turn, user_input: '继续' }, { ...turn, id: 'turn-b', index: 2, user_input: '继续', answer: undefined, status: 'response_unavailable' }])
  expect(screen.getAllByTestId('retained-message-user')).toHaveLength(2)
  expect(screen.getAllByTestId('retained-message-assistant')).toHaveLength(2)
  expect(screen.getByText('尚未观察到可展示的答复')).toBeInTheDocument()
  expect(screen.getByText('检查结果原文')).toBeInTheDocument()
  expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
  expect(screen.queryByText('已完成')).not.toBeInTheDocument()
 })
 it('keeps the answer visible when process loading fails and supports retry', async () => {
  vi.spyOn(accessRetentionApi, 'getTurnProcess').mockRejectedValue(new Error('offline'))
  vi.spyOn(accessRetentionApi, 'getTimeline').mockResolvedValue({ data: { data: [] } } as any)
  show()
  fireEvent.click(screen.getByRole('button', { name: /查看过程/ }))
  await waitFor(() => expect(screen.getByText('过程回复加载失败')).toBeInTheDocument())
  expect(screen.getByText('检查结果原文')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '重试过程回复' })).toBeInTheDocument()
 })

 it('keeps an interrupted call visible while the process remains collapsed', () => {
  show([{ ...turn, status: 'interrupted', finality_source: 'request_outcome' }])
  expect(screen.getByText('最近一次调用已中断')).toBeInTheDocument()
  expect(screen.getByText('检查结果原文')).toBeInTheDocument()
  expect(screen.queryByText('已完成')).not.toBeInTheDocument()
 })
 it('allows long inputs to expand without hiding the model answer', () => {
  show([{ ...turn, user_input: '长输入'.repeat(400) }])
  const expand = screen.getByRole('button', { name: '展开完整输入' })
  expect(expand).toHaveAttribute('aria-expanded', 'false')
  expect(screen.getByText('检查结果原文')).toBeInTheDocument()
  fireEvent.click(expand)
  expect(screen.getByRole('button', { name: '收起输入' })).toHaveAttribute('aria-expanded', 'true')
 })

 it('shows historical keyword excerpts even when the current question and answer do not match', () => {
  show([turn], 'user-a', { keyword: '继续', hits: [
   {request_id:'r2',kind:'request_context',role:'user',snippet:'继续',message_index:14},
   {request_id:'r2',kind:'request_context',role:'assistant',snippet:'会继续检查',message_index:15},
  ]})
  expect(screen.getByText('请求携带的历史对话')).toBeInTheDocument()
  expect(screen.getByText(/本次输入和最新回答未命中/)).toBeInTheDocument()
  expect(screen.getByText('继续', {selector:'mark'})).toBeInTheDocument()
  expect(screen.queryByRole('button',{name:'定位到问答'})).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button',{name:'下一处'}))
  expect(screen.getByText(/消息序号 15/)).toBeInTheDocument()
 })
 it('locates a process hit and opens its collapsed replies', async () => {
  vi.spyOn(accessRetentionApi,'getTurnProcess').mockResolvedValue({data:{data:[{id:'p',content:'继续检查文件'}],has_more:false}} as any)
  show([turn], 'user-a', {keyword:'继续',hits:[{request_id:'r1',turn_id:'turn-a',kind:'process',role:'assistant',snippet:'继续检查文件'}]})
  fireEvent.click(screen.getByRole('button',{name:'定位到问答'}))
  await waitFor(()=>expect(screen.getByRole('button',{name:/收起过程/})).toHaveAttribute('aria-expanded','true'))
  expect(await screen.findByText('继续检查文件')).toBeInTheDocument()
 })

 it('loads earlier conversation in batches and locates a search hit without replacing later pairs', () => {
  const many = Array.from({length:40}, (_, i) => ({...turn,id:`turn-${i}`,index:i+1,user_input:`问题 ${i}`,answer:{...turn.answer!,content:`答案 ${i}`}}))
  show(many, 'user-a', {keyword:'问题',hits:[{request_id:'r1',turn_id:'turn-0',kind:'user_input',role:'user',snippet:'问题 0'}]})
  expect(screen.getAllByTestId('retained-message-user')).toHaveLength(30)
  expect(screen.getByText('答案 39')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', {name:'定位到问答'}))
  expect(screen.getByText('答案 0')).toBeInTheDocument()
  expect(screen.getByText('答案 39')).toBeInTheDocument()
  expect(screen.getAllByTestId('retained-message-user')).toHaveLength(40)
 })
 it('keeps protocol tool summaries visible when no separate tool audit exists', async () => {
  vi.spyOn(accessRetentionApi,'getTurnProcess').mockResolvedValue({data:{data:[],has_more:false}} as any)
  show([{...turn,tools:[{id:'call',name:'execute_command',kind:'result_observed',request_id:'r1'}]}])
  expect(screen.getByText(/execute_command · 1 次工具调用/)).toBeInTheDocument()
  expect(screen.queryByRole('complementary',{name:'协议工具记录'})).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button',{name:/查看过程/}))
  expect(await screen.findByText('已观察结果')).toBeInTheDocument()
  expect(screen.getByText('检查结果原文')).toBeInTheDocument()
 })
 it('does not show a risk warning for missing or normal status', () => {
  // Unknown metadata must not manufacture a risk finding.
  const client = new QueryClient()
  render(<QueryClientProvider client={client}><RetentionTurnList turns={[turn]} requestId="r2" members={[]} identity="u" window={{from:"2026-09-01T00:00:00Z",to:"2026-09-12T00:00:00Z"}} riskState="" agentLabel="AI" artifacts={[]} renderText={(text)=>text} renderArtifacts={()=>null} /></QueryClientProvider>)
  expect(screen.queryByText(/包含风险记录/)).not.toBeInTheDocument()
 })

 it('uses one expansion control for structured answers instead of nesting a second answer preview', () => {
  show([{...turn,answer:{...turn.answer!,content:JSON.stringify({rows:Array.from({length:80},(_,i)=>({index:i,text:'完整记录'}))})}}])
  expect(screen.queryByRole('button',{name:'展开完整回答'})).not.toBeInTheDocument()
  expect(screen.getAllByTestId('retained-message-assistant')).toHaveLength(1)
 })

 it('loads later process pages to the actual searched request', async () => {
  const process = vi.spyOn(accessRetentionApi,'getTurnProcess')
   .mockResolvedValueOnce({data:{data:[{id:'p1',request_id:'r1',content:'早期过程'}],offset:0,limit:50,has_more:true}} as any)
   .mockResolvedValueOnce({data:{data:[{id:'p2',request_id:'later',content:'继续核对目标结果'}],offset:50,limit:50,has_more:false}} as any)
  show([turn],'user-a',{keyword:'继续',hits:[{request_id:'later',turn_id:'turn-a',kind:'process',role:'assistant',snippet:'继续核对目标结果'}]})
  fireEvent.click(screen.getByRole('button',{name:'定位到问答'}))
  expect(await screen.findByText('继续核对目标结果', {}, {timeout:5000})).toBeInTheDocument()
  expect(process).toHaveBeenCalledWith('r2',['r1','r2'],'turn-a',50,expect.objectContaining({signal:expect.anything()}))
 })

})

it('keeps audit evidence collapsed below the question and answer', async () => {
 vi.mocked(accessRetentionApi.getTimeline).mockResolvedValue({data:{data:[
  {id:'outcome:r1',request_id:'r1',type:'request_outcome',title:'请求被拒绝（具体原因未留存）',detail:'返回码 403；不能据此认定内容策略阻断。',timestamp:'2026-09-10T00:00:00Z'},
  {id:'security:s1',request_id:'r1',type:'security_event',title:'安全检测未完成',detail:'实际动作：审计记录；未执行内容拦截。',timestamp:'2026-09-10T00:00:00Z'},
 ]}} as any)
 show([{...turn,answer:undefined}])
 await screen.findByRole('button', {name: '查看审计明细'})
 expect(screen.queryByText('请求被拒绝（具体原因未留存）')).not.toBeInTheDocument()
 expect(screen.getByTestId('retained-message-user').compareDocumentPosition(screen.getByRole('button', {name: '查看审计明细'})) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
 expect(screen.getByTestId('retained-message-assistant').compareDocumentPosition(screen.getByRole('button', {name: '查看审计明细'})) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
 fireEvent.click(screen.getByRole('button', {name: '查看审计明细'}))
 expect(screen.getByText('请求被拒绝（具体原因未留存）')).toBeInTheDocument()
 expect(screen.getByText('安全检测未完成')).toBeInTheDocument()
 expect(screen.getAllByText(/来源请求：r1/)).toHaveLength(2)
 expect(screen.getByText(/未留存可展示的模型正文/)).toBeInTheDocument()
 expect(screen.getByRole('button',{name:/查看过程/})).toHaveAttribute('aria-expanded','false')
})

it('collapses 25 repeated audit events into one group instead of a log wall', async () => {
 vi.mocked(accessRetentionApi.getTimeline).mockResolvedValue({data:{data:Array.from({length:25},(_,i)=>({
 id:`s${i}`,request_id:`r${i}`,type:'security_event',title:'安全检测未完成',status:'audit',detail:'本条安全事件仅作审计记录，未执行拦截。',timestamp:'2026-09-13T08:50:00Z'
 }))}} as any)
 show()
 expect(await screen.findByText('25 次检测未完成')).toBeInTheDocument()
 expect(screen.queryByText('安全检测未完成')).not.toBeInTheDocument()
 expect(screen.queryByText(/来源请求：/)).not.toBeInTheDocument()
 fireEvent.click(screen.getByRole('button',{name:'查看审计明细'}))
 expect(screen.getAllByText('安全检测未完成')).toHaveLength(1)
 expect(screen.getByText('25 条')).toBeInTheDocument()
 expect(screen.getByText('查看时间与请求编号').parentElement).not.toHaveAttribute('open')
 fireEvent.click(screen.getByRole('button',{name:'收起审计明细'}))
 expect(screen.queryByText('安全检测未完成')).not.toBeInTheDocument()
})
