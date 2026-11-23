import { useState } from 'react'
import { Alert, Card, Col, DatePicker, Input, InputNumber, Row, Select, Space, Statistic, Table, Tag, Typography } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { agentEndpointApi, agentKeys } from '../../services/agentEndpoint'
import type { AgentSession, AgentSessionFilters } from '../../services/agentEndpoint.types'
import { label, products, risks, sessionStatuses, time } from './dict'

export default function AgentSessions() {
  const [filters,setFilters]=useState<AgentSessionFilters>({page:1,page_size:20})
  const [today] = useState(()=>new Date(new Date().setHours(0,0,0,0)).toISOString())
  const list=useQuery({queryKey:agentKeys.sessions(filters),queryFn:()=>agentEndpointApi.sessions(filters)})
  const overview=useQuery({queryKey:agentKeys.overview,queryFn:agentEndpointApi.overview})
  const todaySessions=useQuery({queryKey:agentKeys.sessions({from:today,page:1,page_size:1}),queryFn:()=>agentEndpointApi.sessions({from:today,page:1,page_size:1})})
  const todayHits=useQuery({queryKey:agentKeys.sessions({from:today,page:1,page_size:200}),queryFn:()=>agentEndpointApi.sessions({from:today,page:1,page_size:200})})
  const filter=(key:keyof AgentSessionFilters,value:string|number|undefined)=>setFilters(prev=>({...prev,[key]:value??undefined,page:1}))
  const hits=todayHits.data?.items.reduce((sum,x)=>sum+x.blocked_count+x.would_block_count,0)
  return <div style={{display:'grid',gap:16}}><Typography.Title level={3}>智能体会话</Typography.Title>
    <Row gutter={[12,12]}>
      {[['活跃会话',overview.data?.sessions_active],['今日会话',todaySessions.data?.total],['近 24 小时事件（非今日）',overview.data?.events_24h],['今日阻断 / 收敛命中（基于前 200 条会话）',todayHits.data?.total && todayHits.data.total>200?'超过 200 条，无法准确统计':todayHits.isError || hits == null ? '—' : hits]].map(([title,value])=><Col key={String(title)} xs={12} md={6}><Card><Statistic title={title} value={value??'-'}/></Card></Col>)}
    </Row>
    <Space wrap>
      <Input.Search allowClear placeholder="会话编号或项目标签" style={{width:220}} onSearch={value=>filter('q',value)}/>
      <Input.Search allowClear placeholder="端点编号" style={{width:180}} onSearch={value=>filter('endpoint_id',value)}/>
      <Select allowClear placeholder="产品" options={products} style={{width:150}} onChange={value=>filter('product',value)}/>
      <Select allowClear placeholder="状态" options={sessionStatuses} style={{width:130}} onChange={value=>filter('status',value)}/>
      <DatePicker.RangePicker showTime onChange={values=>setFilters(prev=>({...prev,from:values?.[0]?.toISOString(),to:values?.[1]?.toISOString(),page:1}))}/>
      <InputNumber min={0} max={100} placeholder="最低风险分" onChange={value=>filter('min_risk',value??undefined)}/>
    </Space>
    <Card>{list.isError && <Alert type="error" message="会话列表加载失败" showIcon/>}
      <Table rowKey="id" loading={list.isLoading} scroll={{x:1600}} dataSource={list.data?.items??[]} pagination={{current:filters.page,pageSize:20,total:list.data?.total??0,onChange:page=>setFilters(prev=>({...prev,page}))}} columns={[
        {title:'会话编号',render:(_:unknown,x:AgentSession)=><Link to={`/agent/sessions/${encodeURIComponent(x.session_id)}`}>{x.session_id.slice(0,16)}</Link>},
        {title:'产品',render:(_:unknown,x:AgentSession)=>label(products,x.product)},
        {title:'端点',render:(_:unknown,x:AgentSession)=>x.endpoint_id?<Link to={`/agent/endpoints?endpoint=${encodeURIComponent(x.endpoint_id)}`}>{x.endpoint_id.slice(0,16)}</Link>:'网关会话'},
        {title:'模型',render:(_:unknown,x:AgentSession)=>x.model??'未记录'},
        {title:'项目标签',render:(_:unknown,x:AgentSession)=>x.project_label??'未记录'},
        {title:'开始时间',render:(_:unknown,x:AgentSession)=>time(x.started_at)},
        {title:'最后活动',render:(_:unknown,x:AgentSession)=>time(x.last_request_at)},
        {title:'轮次',dataIndex:'turn_count'},{title:'工具调用',dataIndex:'tool_call_count'},
        {title:'阻断 / 收敛',render:(_:unknown,x:AgentSession)=>`${x.blocked_count} / ${x.would_block_count}`},
        {title:'风险分',render:(_:unknown,x:AgentSession)=><Tag color={x.risk_score>=80?'magenta':x.risk_score>=60?'red':'green'}>{x.risk_score} · {x.risk_score>=80?label(risks,'critical'):x.risk_score>=60?label(risks,'high'):label(risks,'low')}</Tag>},
        {title:'状态',render:(_:unknown,x:AgentSession)=><Tag color={x.status==='active'?'processing':'default'}>{label(sessionStatuses,x.status)}</Tag>},
      ]}/>
    </Card>
  </div>
}
