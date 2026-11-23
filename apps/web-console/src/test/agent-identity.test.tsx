import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App } from 'antd'
import AgentIdentityPanel from '../components/AgentIdentityPanel'
import { identityScopeOptions, type IdentityRecord } from '../utils/agentIdentity'
import { apiClient } from '../services/api'
import { agentSourceLabel, getAgentDetection } from '../utils/agents'
const sample: IdentityRecord = { request_id: 'request-a', created_at: '2026-09-12T00:00:00Z', agent_type: 'main', source: 'client_header', declared_type: 'main', declared_name: '', user_agent: '', client_id: '', user_id: '7813951c-67e4-41ec-b866-8a85f87cd1ec', user_name: '政企测试账号', project_name: '办公助手', source_ip: '192.0.2.1', channel: 'forward', environment: 'customer' }
describe('agent identity review', () => {
 beforeEach(() => vi.restoreAllMocks())
 it('does not turn an IP or generic tool evidence into a persistent identity', () => {
  expect(identityScopeOptions(sample).filter(x => !x.disabled).map(x => x.value)).toEqual(['request'])
  const generic = { ...sample, client_id: 'shared', declared_type: 'agent-tool-call', source: 'content' }
  expect(identityScopeOptions(generic)[1].disabled).toBe(true)
  expect(identityScopeOptions({ ...generic, user_agent: 'client/1' })[1].disabled).toBe(false)
  expect(getAgentDetection('main').label).toContain('客户端待确认')
  expect(agentSourceLabel('explicit_header')).toBe('自报请求头')
  expect(agentSourceLabel('registered_identity')).toBe('接入登记')
 })
 it('shows retained evidence and defaults confirmation to a single request', async () => {
  vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { items: [sample], has_more: false } })
  const post = vi.spyOn(apiClient, 'post')
  render(<App><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><AgentIdentityPanel open onClose={() => {}} /></QueryClientProvider></App>)
  fireEvent.click(await screen.findByText('核对并确认'))
  await waitFor(() => expect(screen.getByText('核对客户端身份')).toBeInTheDocument())
  expect(screen.getByText('未关联命名密钥')).toBeInTheDocument()
  expect(screen.getByText('政企测试账号')).toBeInTheDocument()
  expect(screen.getByText('办公助手')).toBeInTheDocument()
  expect(screen.queryByText(sample.user_id)).not.toBeInTheDocument()
  expect(screen.queryByText('归属用户 ID')).not.toBeInTheDocument()
  expect(screen.getByText('只确认当前请求')).toBeInTheDocument()
  expect(screen.getByText('客户端声明名称 / 类型')).toBeInTheDocument()
  fireEvent.click(screen.getByText('保存确认'))
  await waitFor(() => expect(screen.getByText('请选择已核实的客户端')).toBeInTheDocument())
  expect(post).not.toHaveBeenCalled()
 })
})
