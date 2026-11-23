import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { endpointState, eventTypes, modes, products, toolTypes, decisions, startSources, deniedBy } from '../pages/agent/dict'

import { eventRiskLevel, exactToolPreEvents, firstStoredLocalDecisionEvent, mergeToolEvents, redactRaw, secretVisible } from '../pages/agent/testable'
import type { AgentEvent, EnrollmentCreated } from '../services/agentEndpoint.types'
import AgentEndpoints from '../pages/agent/AgentEndpoints'

vi.mock('../services/agentEndpoint', async (importOriginal) => {
  const source = await importOriginal<typeof import('../services/agentEndpoint')>()
  return {...source,agentEndpointApi:{...source.agentEndpointApi,endpoints:vi.fn(async(params:{q?:string})=>({items:[],page:1,page_size:20,total:params.q?0:0}))}}
})
const options=(items:{value:string}[])=>items.map(item=>item.value)
const agentEvent = (overrides: Partial<AgentEvent>): AgentEvent => ({
  id: 'event',
  endpoint_id: 'ep',
  session_id: 'sess',
  prompt_id: '',
  tool_use_id: '',
  event_type: 'tool.pre',
  occurred_at: '2026-01-01T00:00:00Z',
  received_at: '2026-01-01T00:00:00Z',
  tool_name: '',
  tool_type: 'other',
  mcp_server: '',
  payload: {},
  local_decision: {},
  server_decision: {},
  severity: '',
  ...overrides,
})
describe('中文枚举与端点状态',()=>{
  it('覆盖契约全部产品、模式、工具、决策、事件及来源',()=>{
    expect(options(products)).toEqual(['claude-code','openclaw','opencode','hermes','codex','cursor','vscode','python-sdk','dify','other'])
    expect(options(modes)).toEqual(['monitor','would_block','block'])
    expect(options(toolTypes)).toEqual(['system','file','network','database','mcp','skill','agent','browser','other'])
    expect(options(decisions)).toEqual(['allow','audit','confirm','block'])
    expect(options(startSources)).toEqual(['startup','resume','clear','compact','fork'])
    expect(options(deniedBy)).toEqual(['user','hook','policy','unknown'])
    expect(options(eventTypes)).toEqual(['session.start','session.end','turn.start','turn.end','tool.pre','tool.post','tool.failure','tool.denied','permission.request','subagent.start','subagent.stop','config.change','instructions.loaded','context.compact','asset.snapshot','adapter.health'])
  })
  it('心跳过期显示陈旧',()=>expect(endpointState('active',new Date(Date.now()-20*60_000).toISOString())).toBe('stale'))
})
describe('交互与隐私',()=>{
  it('selects stored tool-local decisions and refuses to infer missing risk or cross-identity evidence',()=>{
    const sessionStart=agentEvent({id:'start',event_type:'session.start',local_decision:{}})
    const pre=agentEvent({id:'pre',event_type:'tool.pre',tool_use_id:'tool-use',tool_call_log_id:'tool-log',local_decision:{source:'local',mode:'block',effective_decision:'block',policy_version:8}})
    const overview={session_id:'sess',endpoint_id:'ep'} as any
    const tool={id:'tool-log',session_id:'sess',endpoint_id:'ep',tool_call_id:'tool-use'}
    expect(firstStoredLocalDecisionEvent([sessionStart,pre])?.id).toBe('pre')
    expect(eventRiskLevel(pre)).toBe('')
    expect(exactToolPreEvents([pre],overview,tool)).toEqual([pre])
    expect(exactToolPreEvents([pre],overview,{...tool,endpoint_id:'ep-other'})).toHaveLength(0)
    expect(exactToolPreEvents([pre],overview,{...tool,tool_call_id:'other-tool'})).toHaveLength(0)
    expect(exactToolPreEvents([pre],overview,{...tool,session_id:'other-session'})).toHaveLength(0)
  })
  it('空列表显示接入引导与筛选',async()=>{
    render(<MemoryRouter><QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><AgentEndpoints/></QueryClientProvider></MemoryRouter>)
    expect(await screen.findByText('创建注册令牌')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('主机名、用户或端点编号')).toBeInTheDocument()
  })
  it('创建令牌仅当前持有明文时展示',()=>{
    const token={token:'secret'} as EnrollmentCreated
    expect(secretVisible(token)).toBe(true)
    expect(secretVisible(null)).toBe(false)
  })
  it('合并工具调用前后事件且保留其余事件',()=>{
    const event=(id:string,event_type:string,tool_use_id:string,second:number)=>agentEvent({id,event_type,tool_use_id,session_id:'a',occurred_at:`2026-01-01T00:00:${String(second).padStart(2,'0')}Z`})
    const entries=mergeToolEvents([event('post','tool.post','call',2),event('pre','tool.pre','call',1),event('other','tool.failure','fail',3)])
    expect(entries).toHaveLength(2)
    expect(entries[0].pre.id).toBe('pre')
    expect(entries[0].post?.id).toBe('post')
  })
  it('无内容权限时正文与命令只留哈希长度',()=>{
    const raw={content:{user_prompt:'private',prompt_hash:'sha256:test',prompt_len:7},tool:{args_summary:{command:'secret',command_hash:'hash',command_len:6}}}
    const masked=JSON.stringify(redactRaw(raw,false))
    expect(masked).not.toContain('private')
    expect(masked).not.toContain('secret')
    expect(masked).toContain('sha256:test')
    expect(masked).toContain('hash')
  })
})
