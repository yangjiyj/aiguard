import { type ReactNode, useEffect, useRef, useState } from 'react'
import { Alert, Button, Empty, Space, Tag, Typography } from 'antd'
import { DownOutlined, RightOutlined, MessageOutlined, RobotOutlined, ExclamationCircleOutlined } from '@ant-design/icons'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { accessRetentionApi, type AccessRetentionMessage, type AccessRetentionSearchHit, type AccessRetentionArtifact, type AccessRetentionTurn, type AccessRetentionWindow } from '../services/api'
import RetentionKeywordText from './RetentionKeywordText'
import './RetentionTurnList.css'

type Props = {
 searchKeyword?: string
 searchHits?: AccessRetentionSearchHit[]
 searchHitsTruncated?: boolean
 activeSearchHit?: AccessRetentionSearchHit
 turns: AccessRetentionTurn[]
 requestId: string
 members: string[]
 identity: unknown
 window: AccessRetentionWindow
 agentLabel: string
 riskState: string
 artifacts: AccessRetentionArtifact[]
 processMessages?: Record<string, AccessRetentionMessage[]>
 renderText: (content: string, kind: 'request' | 'response') => ReactNode
 renderArtifacts: (artifacts: AccessRetentionArtifact[], direction: 'input' | 'output') => ReactNode
 supplementaryArtifacts?: ReactNode
 // 传了就表示当前角色能看原文留证；被阻断的输入气泡据此给出“查看原文”。
 onViewRawEvidence?: (requestId: string) => void
}
const { Text } = Typography
const timeLabel = (time?: string) => time ? new Date(time).toLocaleString('zh-CN', { hour12: false }) : ''
function MessageHeader({ user, label, time }: { user?: boolean; label: string; time?: string }) {
 return <div className="retention-message-heading"><strong>{user ? '用户提问' : '模型回答'}</strong><span>{label}</span><time>{timeLabel(time)}</time></div>
}

function Turn({ turn, ...props }: Omit<Props, 'turns'> & { turn: AccessRetentionTurn }) {
 const section = useRef<HTMLElement>(null)
 const [expanded, setExpanded] = useState(false)
 const [auditExpanded, setAuditExpanded] = useState(false)
 const [inputExpanded, setInputExpanded] = useState(false)
 const [answerExpanded, setAnswerExpanded] = useState(false)
 useEffect(() => {
  if (props.activeSearchHit?.turn_id !== turn.id) return
  if (props.activeSearchHit.kind === 'process') setExpanded(true)
  if (props.activeSearchHit.kind === 'user_input') setInputExpanded(true)
  if (props.activeSearchHit.kind === 'model_output') setAnswerExpanded(true)
 }, [props.activeSearchHit, turn.id])
 const behavior = useQuery({
  queryKey: ['retention-visible-behavior', props.identity, turn.request_ids[0] || props.requestId, turn.request_ids, props.window],
  queryFn: ({ signal }) => accessRetentionApi.getTimeline(turn.request_ids[0] || props.requestId, turn.request_ids, { ...props.window, signal }),
  enabled: !!props.requestId,
  refetchInterval: (query) => query.state.data?.data?.data?.some((event) => event.type === 'inspection_progress' && event.status === 'in_progress') ? 5000 : false,
 })
 const callOutcomes = (behavior.data?.data?.data || []).filter((event) => event.type === 'model_calls')
 const outcomeEvidence = (behavior.data?.data?.data || []).filter((event) => event.type === 'request_outcome' || event.type === 'security_event').sort((a, b) => Number(b.type === 'request_outcome') - Number(a.type === 'request_outcome'))
 const evidenceGroups = Array.from(outcomeEvidence.reduce((groups, event) => {
  const key = JSON.stringify([event.type, event.title, event.status, event.detail])
  const group = groups.get(key) || { key, event, records: [] as typeof outcomeEvidence }
  group.records.push(event)
  groups.set(key, group)
  return groups
 }, new Map<string, { key: string; event: (typeof outcomeEvidence)[number]; records: typeof outcomeEvidence }>()).values())
 const incompleteCount = outcomeEvidence.filter((event) => event.type === 'security_event' && event.title === '安全检测未完成').reduce((sum, event) => sum + (event.count || 1), 0)
 const callSummary = callOutcomes.map((event) => `${({ success: '成功', failed: '失败或被拒绝', in_progress: '结果待确认', unknown: '结果未知' } as Record<string, string>)[event.status || 'unknown'] || '结果未知'} ${event.count || 1} 次`).join(' · ')
 const tools = (behavior.data?.data?.data || []).filter((event) => event.type === 'tool_action')
 const protocolTools = turn.tools || []
 const toolNames = [...new Set([...tools.map((event) => event.title), ...protocolTools.map((tool) => tool.name || '工具结果')])]
 const toolCount = Math.max(protocolTools.length, tools.reduce((count, event) => count + (event.count || 1), 0))
 const blockedInputEvidenceId = turn.blocked_input_evidence_request_ids?.[0]
 const longInput = (turn.user_input?.length || 0) > 500 || (turn.user_input?.split('\n').length || 0) > 8
 const answerContent = turn.answer?.content || ''
 let structuredAnswer = answerContent.includes('```')
 if (!structuredAnswer && /^[{[]/.test(answerContent.trimStart())) {
  try { JSON.parse(answerContent); structuredAnswer = true } catch { /* Non-JSON answers use the normal text preview. */ }
 }
 const longAnswer = !structuredAnswer && (answerContent.length > 1200 || answerContent.split('\n').length > 18)
 const process = useInfiniteQuery({
  queryKey: ['retention-turn-process', props.identity, props.requestId, props.members, turn.id, props.window],
  queryFn: ({ pageParam, signal }) => accessRetentionApi.getTurnProcess(props.requestId, props.members, turn.id, pageParam, { ...props.window, signal }),
  initialPageParam: 0,
  getNextPageParam: (last) => last.data.has_more ? last.data.offset + last.data.limit : undefined,
  enabled: expanded && !props.processMessages,
 })
 const messages = props.processMessages?.[turn.id] || process.data?.pages.flatMap((page) => page.data.data) || []
 // A search hit can be beyond the first process page. Load up to its
 // actual source request, then scroll to that message rather than the question.
 const { data: processData, hasNextPage, isFetchingNextPage, isFetchNextPageError, fetchNextPage } = process
 const processHit = props.activeSearchHit?.turn_id === turn.id && props.activeSearchHit.kind === 'process' ? props.activeSearchHit : undefined
 const matchedProcess = processHit && messages.find((message) => message.request_id === processHit.request_id && (!props.searchKeyword || message.content.toLocaleLowerCase().includes(props.searchKeyword.toLocaleLowerCase())))
 useEffect(() => {
  if (expanded && processHit && !matchedProcess && !props.processMessages && processData && hasNextPage && !isFetchingNextPage && !isFetchNextPageError) void fetchNextPage()
 }, [expanded, processHit, matchedProcess, props.processMessages, processData, hasNextPage, isFetchingNextPage, isFetchNextPageError, fetchNextPage])
 useEffect(() => {
  if (matchedProcess) requestAnimationFrame(() => {
   const target = Array.from(section.current?.querySelectorAll<HTMLElement>('[data-retention-message]') || []).find((node) => node.dataset.retentionMessage === matchedProcess.id)
   target?.scrollIntoView?.({ behavior: 'smooth', block: 'center' })
  })
 }, [matchedProcess])
 const artifacts = props.artifacts.filter((artifact) => artifact.request_id && turn.request_ids.includes(artifact.request_id))
 const confirmed = turn.status === 'completed' && turn.finality_source === 'client_completion'
 const outcomeLabel = ({ interrupted: '最近一次调用已中断', request_failed: '最近一次调用失败', blocked: '最近一次调用被拒绝或返回安全回复' } as Record<string, string>)[turn.status]
 const panelId = 'retention-process-' + turn.id
 return <section ref={section} data-retention-turn={turn.id} aria-label={`第 ${turn.index} 次提问`} className="retention-turn">
  <article data-testid="retained-message-user" className="retention-message retention-message-user">
   <div className="retention-avatar" aria-hidden="true"><MessageOutlined /></div>
   <div className="retention-message-main">
    <MessageHeader user label="输入" time={turn.started_at} />
    <div className="retention-user-bubble">
     <div className={longInput && !inputExpanded ? 'retention-preview retention-preview-input' : ''} data-testid="retained-text-request">{turn.user_input
       ? props.renderText(turn.user_input, 'request')
       : props.onViewRawEvidence && blockedInputEvidenceId
         ? <Space size={8}><Text type="secondary">输入已被阻断，原文另存</Text><Button type="link" size="small" onClick={() => props.onViewRawEvidence?.(blockedInputEvidenceId)}>查看原文</Button></Space>
         : <Text type="secondary">未留存文字输入</Text>}</div>
     {longInput ? <Button type="link" size="small" onClick={() => setInputExpanded(!inputExpanded)} aria-expanded={inputExpanded}>{inputExpanded ? '收起输入' : '展开完整输入'}</Button> : null}
     {turn.user_input && props.onViewRawEvidence && blockedInputEvidenceId ? <Button type="link" size="small" onClick={() => props.onViewRawEvidence?.(blockedInputEvidenceId)}>查看被阻断的原文</Button> : null}
     {props.renderArtifacts(artifacts.filter((a) => a.direction === 'input'), 'input')}
    </div>
   </div>
  </article>
  <div className="retention-process">
   <div className="retention-process-summary">
    <Button size="small" type="text" icon={expanded ? <DownOutlined /> : <RightOutlined />} aria-expanded={expanded} aria-controls={panelId}
     onClick={() => setExpanded((value) => !value)}>{expanded ? '收起过程' : '查看过程'} · {turn.request_count} 次模型交互</Button>
    {toolCount > 0 ? <span className="retention-tools-summary">{toolNames.slice(0, 3).join(' · ')}{toolNames.length > 3 ? ' …' : ''} · {toolCount} 次工具调用</span> : behavior.isLoading ? <span>工具记录加载中…</span> : behavior.isError ? <span>工具记录加载失败，展开重试</span> : <span>未留存工具明细</span>}
    <span>{turn.observed_duration_ms > 0 ? `${Math.ceil(turn.observed_duration_ms / 1000)} 秒` : ''}</span>
    {outcomeLabel ? <Tag color="orange">{outcomeLabel}</Tag> : confirmed ? <Tag color="green">已完成</Tag> : null}
    {turn.evidence_status !== 'complete' ? <Tag color="orange">留痕存在缺口</Tag> : null}
   </div>
   {expanded ? <div id={panelId} className="retention-process-detail">
    <Text type="secondary">{confirmed ? '已收到完成标记' : '结束状态待确认'}{turn.correlation_source === 'unlinked' ? ' · 回合关联待确认' : turn.correlation_source === 'conversation_history' ? ' · 按会话内留存的用户输入历史归并' : ''}</Text>
    <div className="retention-process-replies"><Text strong>过程回复</Text>
     {!props.processMessages && process.isLoading ? <Text type="secondary">过程回复加载中…</Text> : null}
     {!props.processMessages && process.isError ? <Alert type="warning" message="过程回复加载失败" action={<Button size="small" onClick={() => void process.refetch()}>重试过程回复</Button>} /> : null}
     {messages.map((item) => <div key={item.id} data-retention-message={item.id} data-testid={item.id === 'retained-reasoning' ? 'retained-text-reasoning' : undefined} className="retention-progress-message"><Text type="secondary">AI 进度回复 {timeLabel(item.created_at)}</Text>{props.renderText(item.content, 'response')}</div>)}
     {(props.processMessages || !process.isLoading && !process.isError) && messages.length === 0 ? <Text type="secondary">未留存中间文字回复</Text> : null}
     {process.isFetchNextPageError ? <Text type="warning">后续过程加载失败，可点击下方按钮重试</Text> : null}
     {process.hasNextPage ? <Button loading={process.isFetchingNextPage} onClick={() => void process.fetchNextPage()}>加载更多过程回复</Button> : null}
    </div>
    {protocolTools.length ? <aside aria-label="协议工具记录" className="retention-behavior"><Text strong>工具调用记录</Text>{protocolTools.map((tool) => <div key={tool.id} className="retention-behavior-event"><Space wrap><Text strong>{tool.name || '工具结果'}</Text><Tag color={tool.kind === 'result_observed' ? 'blue' : 'default'}>{tool.kind === 'result_observed' ? '已观察结果' : '模型提出调用'}</Tag></Space><div className="retention-behavior-text">来源请求：{tool.request_id}</div></div>)}<Text type="secondary">工具参数与执行错误见下方已留存的审计明细。</Text></aside> : null}
    <BehaviorPanel {...props} requestId={turn.request_ids[0] || props.requestId} members={turn.request_ids} />
   </div> : null}
  </div>
  <article data-testid="retained-message-assistant" className="retention-message retention-message-assistant">
   <div className="retention-avatar" aria-hidden="true"><RobotOutlined /></div>
   <div className="retention-message-main">
    <MessageHeader label={`${props.agentLabel} · ${confirmed ? '最终答复' : '最新答复'}`} time={turn.answer?.created_at} />
    <div className={longAnswer && !answerExpanded ? 'retention-preview retention-preview-answer' : ''} data-testid="retained-text-response">{turn.answer ? props.renderText(turn.answer.content, 'response') : <><Text type="secondary">尚未观察到可展示的答复</Text><div><Text type="secondary">未留存可展示的模型正文，可展开过程查看中间回复。</Text></div></>}</div>
    {longAnswer ? <Button type="link" size="small" aria-expanded={answerExpanded} onClick={() => setAnswerExpanded(!answerExpanded)}>{answerExpanded ? '收起回答' : '展开完整回答'}</Button> : null}
    {props.renderArtifacts(artifacts.filter((a) => a.direction === 'output'), 'output')}
   </div>
  </article>
  {(outcomeEvidence.length > 0 || behavior.isError) ? <div className="retention-audit-footer">
   <div className="retention-audit-summary">
    <Text type="secondary">{callSummary}{incompleteCount ? `${callSummary ? ' · ' : ''}${incompleteCount} 次检测未完成` : ''}{!callSummary && !incompleteCount ? '有审计记录' : ''}</Text>
    <Button type="link" size="small" aria-expanded={auditExpanded} aria-controls={`retention-audit-${turn.id}`} onClick={() => setAuditExpanded((value) => !value)}>{auditExpanded ? '收起审计明细' : '查看审计明细'}</Button>
   </div>
   {auditExpanded ? <aside id={`retention-audit-${turn.id}`} aria-label="审计明细" className="retention-audit-detail">
    {behavior.isError ? <Alert type="warning" message="审计明细加载失败" action={<Button size="small" onClick={() => void behavior.refetch()}>重试</Button>} /> : null}
    {evidenceGroups.map((group) => <div key={group.key} className="retention-audit-group">
     <Space wrap><Text strong>{group.event.title}</Text><Tag>{group.records.reduce((sum, event) => sum + (event.count || 1), 0)} 条</Tag></Space>
     <div>{group.event.detail}</div>
     <details><summary>查看时间与请求编号</summary>{group.records.map((event) => <div key={event.id} className="retention-audit-source"><time>{timeLabel(event.timestamp)}</time><span>来源请求：{event.request_id || '未留存'}</span></div>)}</details>
    </div>)}
   </aside> : null}
  </div> : null}
 </section>
}

function BehaviorPanel(props: Omit<Props, 'turns'>) {
 const members = props.members.length > 0 ? props.members : [props.requestId]
 const timeline = useQuery({
  queryKey: ['retention-visible-behavior', props.identity, props.requestId, members, props.window],
  queryFn: ({ signal }) => accessRetentionApi.getTimeline(props.requestId, members, { ...props.window, signal }),
  enabled: !!props.requestId,
 })
 const events = (timeline.data?.data?.data || []).filter((event) => event.type !== 'tool_inventory' && event.type !== 'security_event' && event.type !== 'request_outcome')
 return <aside aria-label="智能体行为" className="retention-behavior"><Text strong>调用与工具行为</Text>
   {timeline.isLoading ? <Text type="secondary">行为记录加载中…</Text> : null}
   {timeline.isError ? <Alert type="warning" message="行为记录加载失败" action={<Button size="small" onClick={() => void timeline.refetch()}>重试行为记录</Button>} /> : null}
   {events.map((event) => <div key={event.id} className="retention-behavior-event">
     <Space wrap size={[6, 4]}><Text strong>{event.title}</Text>{event.count && event.count > 1 ? <Tag>{event.count} 次</Tag> : null}
      {event.fact_label ? <Tag>{event.fact_label}</Tag> : null}
      {event.event_kind === 'invocation_proposed' ? <Tag color="orange">执行未确认</Tag> : event.status ? <Tag color={event.status === 'failed' ? 'red' : event.status === 'success' ? 'green' : 'default'}>{({ success: '成功', failed: '失败', unknown: '状态未知', recorded: '已记录', in_progress: '补检中' } as Record<string, string>)[event.status] || event.status}</Tag> : null}
     </Space>
     {event.detail ? <div className="retention-behavior-text">{event.detail}</div> : null}
     {event.timestamp ? <Text type="secondary">{timeLabel(event.timestamp)}</Text> : null}
   </div>)}
   {!timeline.isLoading && !timeline.isError && events.length === 0 ? <Text type="secondary">暂未留存可验证的行为记录</Text> : null}
 </aside>
}

function SearchMatches({ keyword, hits, truncated, onLocate }: { keyword: string; hits: AccessRetentionSearchHit[]; truncated?: boolean; onLocate: (hit: AccessRetentionSearchHit) => void }) {
 const [index, setIndex] = useState(0)
 const at = Math.min(index, Math.max(0, hits.length - 1))
 const hit = hits[at]
 const label = hit ? ({ user_input: '当前用户输入', model_output: '模型回答', process: '折叠的过程回复', request_context: '请求携带的历史对话', retained_text: '关联留存正文', file: '附件名称' })[hit.kind] : ''
 const current = hits.some((item) => item.kind === 'user_input' || item.kind === 'model_output')
 return <section aria-label="正文搜索命中" style={{ border: '1px solid var(--status-warn)', borderRadius: 10, padding: 16, background: 'var(--bg-card)' }}>
  <Space direction="vertical" size={10} style={{ width: '100%' }}>
   <Space wrap><Text strong>正文命中「{keyword}」</Text><Tag color="gold">{hits.length}{truncated ? '+' : ''} 处命中片段</Tag></Space>
   {!hit ? <Text type="secondary">当前可展示的正文中未找到命中片段。列表还会搜索关联调用及文件信息，请核对搜索范围与关联调用。</Text> : <>
    {!current ? <Text type="secondary">本次输入和最新回答未命中；匹配内容在下方标明的历史对话、过程或附件中。</Text> : null}
    <Space wrap><Tag color={hit.kind === 'request_context' ? 'purple' : 'blue'}>{label}</Tag><Text type="secondary">{hit.role === 'user' ? '用户消息' : hit.role === 'assistant' ? '模型消息' : '文件'}{hit.message_index !== undefined ? ` · 消息序号 ${hit.message_index}` : ''}</Text></Space>
    <div style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', lineHeight: 1.8, padding: 12, background: 'var(--bg-secondary)', borderRadius: 6 }}><RetentionKeywordText text={hit.snippet} keyword={keyword} /></div>
    <Space wrap><Text type="secondary">{at + 1} / {hits.length}{truncated ? '（仅展示前 60 处）' : ''}</Text><Button size="small" disabled={at === 0} onClick={() => setIndex(at - 1)}>上一处</Button><Button size="small" disabled={at + 1 >= hits.length} onClick={() => setIndex(at + 1)}>下一处</Button>{hit.turn_id ? <Button size="small" type="primary" onClick={() => onLocate(hit)}>定位到问答</Button> : null}</Space>
    <Text type="secondary" style={{ fontSize: 12 }}>来源请求：{hit.request_id}</Text>
   </>}
  </Space>
 </section>
}

export default function RetentionTurnList({ turns, ...props }: Props) {
 const root = useRef<HTMLDivElement>(null)
 const [visibleCount, setVisibleCount] = useState(30)
 const [activeSearchHit, setActiveSearchHit] = useState<AccessRetentionSearchHit>()
 const visibleStart = Math.max(0, turns.length - visibleCount)
 const locate = (hit: AccessRetentionSearchHit) => {
  const index = turns.findIndex((turn) => turn.id === hit.turn_id)
  if (index >= 0) setVisibleCount((count) => Math.max(count, turns.length - index))
  setActiveSearchHit(hit)
  requestAnimationFrame(() => {
   const target = Array.from(root.current?.querySelectorAll<HTMLElement>('[data-retention-turn]') || []).find((node) => node.dataset.retentionTurn === hit.turn_id)
   target?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  })
 }
 const unassigned = props.artifacts.filter((artifact) => !artifact.request_id || !turns.some((turn) => turn.request_ids.includes(artifact.request_id!)))
 return <div ref={root} className="retention-conversation">
  {props.searchKeyword ? <SearchMatches key={props.searchKeyword} keyword={props.searchKeyword} hits={props.searchHits || []} truncated={props.searchHitsTruncated} onLocate={locate} /> : null}
  <div className="retention-conversation-toolbar">
   <div><strong>对话留证</strong><span>一问一答 · 过程默认折叠</span></div>
   <span>{turns.length} 次提问 · {turns.reduce((sum, turn) => sum + turn.request_count, 0)} 次模型调用</span>
  </div>
  {props.riskState === 'risk' || props.riskState === 'blocked' ? <div className="retention-risk-note" role="status"><ExclamationCircleOutlined /> {props.riskState === 'blocked' ? '此任务包含请求拒绝或安全回复记录；具体原因见下方调用结果。' : '此任务包含风险记录（审计线索）；规则命中不等于实际阻断。'}</div> : null}
  {visibleStart > 0 ? <Button className="retention-load-earlier" onClick={() => setVisibleCount((count) => count + 30)}>查看更早的对话 · 还有 {visibleStart} 次提问</Button> : null}
  {turns.length ? turns.slice(visibleStart).map((turn) => <Turn key={turn.id} turn={turn} {...props} activeSearchHit={activeSearchHit} />) : <Empty description="暂无可还原的问答" />}
  {unassigned.length > 0 ? <details className="retention-extra"><summary>未关联到具体提问的附件 · {unassigned.length} 个</summary>{props.renderArtifacts(unassigned.filter((a) => a.direction === 'input'), 'input')}{props.renderArtifacts(unassigned.filter((a) => a.direction === 'output'), 'output')}</details> : null}
  {props.supplementaryArtifacts}
 </div>
}
