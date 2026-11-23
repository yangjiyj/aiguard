import { useState } from 'react'
import { Alert, Button, Card, Collapse, Descriptions, Empty, Pagination, Space, Table, Tabs, Tag, Timeline, Typography } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { agentEndpointApi, agentKeys } from '../../services/agentEndpoint'
import type { AgentEvent, AgentAlert } from '../../services/agentEndpoint.types'
import { assetTypes, decisionColors, decisions, eventTypes, label, modes, products, riskColors, risks, sessionStatuses, sources, stopReasons, time, toolTypes } from './dict'

import { eventRiskLevel, firstStoredLocalDecisionEvent, mergeToolEvents, redactRaw, type TimelineEntry } from './testable'
const json=(value:unknown)=><pre style={{whiteSpace:'pre-wrap',wordBreak:'break-word',maxHeight:380,overflow:'auto'}}>{JSON.stringify(value,null,2)}</pre>
const detail=(event:AgentEvent)=>event.payload??{}
const toolPayload=(event:AgentEvent)=>{const payload=detail(event);return payload.tool && typeof payload.tool==='object'?payload.tool as Record<string,unknown>:payload}
const decision=(value:Record<string,unknown>)=>String(value?.effective??value?.effective_decision??value?.decision??value?.raw??value?.raw_decision??'')
export default function AgentSessionDetail() {
  const {id=''}=useParams()
  const [activeTab,setActiveTab]=useState('overview')
  const [turnPage,setTurnPage]=useState(1)
  const [eventPage,setEventPage]=useState(1)
  // 角色并不等价于服务端原文证据权限；客户端保守脱敏。
  const fullContent=false
  const query=useQuery({queryKey:agentKeys.session(id),queryFn:()=>agentEndpointApi.session(id),enabled:!!id})
  const session=query.data?.overview
  const allEvents=query.data?.events??[]
  const localDecisionEvent=firstStoredLocalDecisionEvent(allEvents)
  const sessionLocalDecision=localDecisionEvent?.local_decision??{}
  const eventQuery=useQuery({queryKey:agentKeys.events(session?.session_id??'',eventPage),queryFn:()=>agentEndpointApi.events(session!.session_id,eventPage),enabled:activeTab==='events' && !!session})
  const turns=query.data?.turns??[]
  const visibleTurns=turns.slice((turnPage-1)*10,turnPage*10)
  const timeline=visibleTurns.map(turn=>({turn,entries:mergeToolEvents(allEvents.filter(e=>e.prompt_id===turn.prompt_id))}))
  const unassigned=mergeToolEvents(allEvents.filter(e=>!turns.some(turn=>turn.prompt_id===e.prompt_id)))
  const eventCard=(entry:TimelineEntry)=>{
    const {pre,post}=entry;const tool=toolPayload(pre);const result=post?toolPayload(post):{};const local=decision(pre.local_decision);const server=decision(pre.server_decision)
    const highlighted=[local,server].some(x=>x==='block'||x==='confirm')
    const riskLevel=eventRiskLevel(pre)
    const childSession=String(detail(pre).child_session_id??detail(pre).session_id??'')
    return <Card key={pre.id} size="small" style={{borderColor:highlighted?'var(--status-danger)':undefined}} title={<Space wrap><Tag color={highlighted?'red':'blue'}>{label(eventTypes,pre.event_type)}{post?' / 工具结果':''}</Tag><Typography.Text>{pre.tool_name||String(tool.name??'')}</Typography.Text><Typography.Text type="secondary">{time(pre.occurred_at)}</Typography.Text></Space>}>
      <Space wrap><span>类型：{label(toolTypes,pre.tool_type)}</span><span>目标摘要：{String(tool.description??tool.path??'未记录')}</span><Tag color={decisionColors[local]}>{`本地判定：${label(decisions,local)}`}</Tag><Tag color={decisionColors[server]}>{`服务端判定：${label(decisions,server)}`}</Tag><Tag color={riskLevel ? riskColors[riskLevel] : 'default'}>{riskLevel ? label(risks,riskLevel) : '风险等级：未记录'}</Tag>{Boolean(result.result && typeof result.result==='object') && <span>耗时：{String((result.result as Record<string,unknown>).duration_ms??'未记录')} 毫秒 · 成功：{(result.result as Record<string,unknown>).success?'是':'否'}</span>}</Space>
      {(pre.event_type==='subagent.start'||pre.event_type==='subagent.stop') && childSession && <div>子会话：<Link to={`/agent/sessions/${encodeURIComponent(childSession)}`}>{childSession}</Link></div>}
      <Collapse ghost size="small" items={[{key:'detail',label:'展开事件详情',children:json(redactRaw({调用前:pre.payload,调用后:post?.payload,本地决策:pre.local_decision,服务端决策:pre.server_decision},fullContent))}]}/>
    </Card>
  }
  if(query.isError) return <Alert type="error" message="会话详情加载失败，请检查权限或会话编号" showIcon/>
  return <div style={{display:'grid',gap:16}}><Space><Link to="/agent/sessions">返回会话列表</Link><Typography.Title level={3} style={{margin:0}}>会话详情</Typography.Title></Space>
    {session && <Tabs activeKey={activeTab} onChange={setActiveTab} items={[
      {key:'overview',label:'会话概览',children:<Card><Descriptions bordered column={2} size="small" items={[
        {key:'id',label:'会话编号',children:session.session_id,span:2},
        {key:'endpoint',label:'端点',children:session.endpoint_id?<Link to={`/agent/endpoints?endpoint=${encodeURIComponent(session.endpoint_id)}`}>{session.endpoint_id}</Link>:'未关联'},
        {key:'product',label:'产品',children:label(products,session.product)}, {key:'model',label:'模型',children:session.model??'未记录'},
        {key:'permission',label:'权限模式',children:session.permission_mode??'未记录'}, {key:'cwd',label:'工作目录标签',children:session.project_label??session.cwd_hash??'未记录'},
        {key:'start',label:'开始时间',children:time(session.started_at)}, {key:'end',label:'结束时间',children:time(session.ended_at)},
        {key:'source',label:'来源',children:label(sources,session.source)}, {key:'status',label:'状态',children:label(sessionStatuses,session.status)},
        {key:'turns',label:'轮次 / 事件',children:`${session.turn_count} / ${session.event_count}`},
        {key:'hits',label:'阻断 / 收敛',children:`${session.blocked_count} / ${session.would_block_count}`},
        {key:'mode',label:'端侧模式',children:label(modes,String(sessionLocalDecision.mode??''))},
        {key:'local-source',label:'本地决策来源',children:String(sessionLocalDecision.source??'未记录')},
        {key:'local-decision',label:'本地判定',children:decision(sessionLocalDecision)||'未记录'},
        {key:'local-policy',label:'本地策略版本 / 规则',children:[sessionLocalDecision.policy_version!=null?'版本 '+String(sessionLocalDecision.policy_version):'',String(sessionLocalDecision.rule_id??sessionLocalDecision.matched_rule_id??'')].filter(Boolean).join(' / ')||'未记录'},
      ]}/></Card>},
      {key:'timeline',label:'时间线',children:<Card>{timeline.length?timeline.map(({turn,entries})=><Card key={turn.id} size="small" style={{marginBottom:12}} title={`第 ${turn.seq} 轮 · ${time(turn.started_at)} · ${label(stopReasons,turn.stop_reason)}`}><Timeline items={entries.map(entry=>({children:eventCard(entry)}))}/></Card>):<Empty description="暂无轮次记录"/>}{unassigned.length>0 && <Card title="未关联轮次的事件" size="small"><Timeline items={unassigned.map(entry=>({children:eventCard(entry)}))}/></Card>}<Pagination style={{marginTop:12}} current={turnPage} pageSize={10} total={turns.length} onChange={setTurnPage}/></Card>},
      {key:'events',label:'行为事件',children:<Card><Table size="small" rowKey="id" loading={eventQuery.isLoading} dataSource={eventQuery.data?.items??[]} pagination={{current:eventPage,pageSize:50,total:eventQuery.data?.total??0,onChange:setEventPage}} columns={[
        {title:'时间',render:(_:unknown,e:AgentEvent)=>time(e.occurred_at)}, {title:'事件类型',render:(_:unknown,e:AgentEvent)=>label(eventTypes,e.event_type)}, {title:'工具名称',dataIndex:'tool_name'},
        {title:'工具类型',render:(_:unknown,e:AgentEvent)=>label(toolTypes,e.tool_type)}, {title:'本地决策',render:(_:unknown,e:AgentEvent)=>label(decisions,decision(e.local_decision))},
        {title:'风险',render:(_:unknown,e:AgentEvent)=>label(risks,e.severity)}, {title:'工具审计',render:(_:unknown,e:AgentEvent)=>{const log=query.data?.tool_call_logs.find(x=>!!e.tool_call_log_id && x.id===e.tool_call_log_id);return log?<Link to={`/security/agent-tools?session_id=${encodeURIComponent(session.session_id)}&tool_call_log_id=${encodeURIComponent(log.id)}`}>查看工具调用 {log.id.slice(0,8)}</Link>:null}},
      ]}/></Card>},
      {key:'alerts',label:'关联告警',children:<Card><Table rowKey="id" dataSource={query.data?.alerts??[]} columns={[{title:'时间',render:(_:unknown,e:AgentAlert)=>time(e.created_at)},{title:'级别',render:(_:unknown,e:AgentAlert)=>label(risks,e.severity)},{title:'告警类型',dataIndex:'alert_type'},{title:'操作',render:(_:unknown,e:AgentAlert)=><Link to={`/security/alerts?event_id=${encodeURIComponent(e.event_id??'')}&session_id=${encodeURIComponent(session.session_id)}`}>查看告警</Link>}]}/></Card>},
      {key:'assets',label:'资产变化',children:<Card>{allEvents.filter(e=>e.event_type==='config.change'||e.event_type==='instructions.loaded').map(e=><Card key={e.id} size="small" style={{marginBottom:8}} title={`${label(eventTypes,e.event_type)} · ${time(e.occurred_at)}`}><Tag>{label(assetTypes,String(e.payload?.asset_type??''))}</Tag>{json(redactRaw(e.payload,fullContent))}</Card>)}{!allEvents.some(e=>e.event_type==='config.change'||e.event_type==='instructions.loaded')&&<Empty description="暂无资产变化"/>}</Card>},
      {key:'raw',label:'原始信息',children:<Card><Alert type="info" showIcon message="原始信息按内容证据权限脱敏：无权查看正文时仅展示哈希与长度。" style={{marginBottom:12}}/>{allEvents.map(e=><Collapse key={e.id} items={[{key:e.id,label:`${label(eventTypes,e.event_type)} · ${time(e.occurred_at)}`,children:json(redactRaw(e,fullContent))}]}/>)}</Card>},
    ]}/>}
    {query.isLoading && <Button loading>加载会话中</Button>}
  </div>
}
