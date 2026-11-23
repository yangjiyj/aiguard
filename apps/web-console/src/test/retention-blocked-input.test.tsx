import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import RetentionTurnList from '../components/RetentionTurnList'
import { accessRetentionApi, type AccessRetentionTurn } from '../services/api'

function turnOf(overrides: Partial<AccessRetentionTurn> = {}): AccessRetentionTurn {
 return {
  id: 'turn-a', index: 1, user_input: '',
  request_ids: ['req_1', 'req_2'], request_count: 2, process_count: 0,
  status: 'completed', finality_source: 'last_observed_response', correlation_source: 'history_occurrence',
  evidence_status: 'complete', observed_duration_ms: 0,
  ...overrides,
 }
}
function renderTurnList(turns: AccessRetentionTurn[], onViewRawEvidence?: (requestId: string) => void) {
 const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
 return render(<QueryClientProvider client={client}><RetentionTurnList
   turns={turns} requestId="req_1" members={['req_1', 'req_2']} identity="user-a"
   window={{ from: '2026-09-01T00:00:00Z', to: '2026-09-11T00:00:00Z' }}
   riskState="risk" agentLabel="WorkBuddy" artifacts={[]}
   renderText={(text) => <div>{text}</div>} renderArtifacts={() => null}
   onViewRawEvidence={onViewRawEvidence}
 /></QueryClientProvider>)
}

beforeEach(() => vi.spyOn(accessRetentionApi, 'getTimeline').mockResolvedValue({ data: { data: [] } } as any))
afterEach(() => vi.restoreAllMocks())

describe('没有留存文字的输入在对话留证里的显示', () => {
 it('该回合有原文留证且有查看入口时写明原文另存，并按有留证的请求打开', () => {
  const onViewRawEvidence = vi.fn()
  renderTurnList([turnOf({ blocked_input_evidence_request_ids: ['req_2'] })], onViewRawEvidence)
  expect(screen.getByText('输入已被阻断，原文另存')).toBeTruthy()
  expect(screen.queryByText('未留存文字输入')).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: '查看原文' }))
  expect(onViewRawEvidence).toHaveBeenCalledWith('req_2')
 })
 it('没有查看入口（角色无权限）时保持原样', () => {
  renderTurnList([turnOf({ blocked_input_evidence_request_ids: ['req_2'] })])
  expect(screen.getByText('未留存文字输入')).toBeTruthy()
  expect(screen.queryByRole('button', { name: '查看原文' })).toBeNull()
 })
 it('没有原文留证时保持原样，不看回合状态', () => {
  renderTurnList([turnOf({ status: 'blocked' }), turnOf({ id: 'turn-b', index: 2, status: 'blocked', blocked_input_evidence_request_ids: [] })], vi.fn())
  expect(screen.getAllByText('未留存文字输入')).toHaveLength(2)
  expect(screen.queryByText('输入已被阻断，原文另存')).toBeNull()
  expect(screen.queryByRole('button', { name: '查看原文' })).toBeNull()
 })
 it('有留存文字且有留证：文字照常显示，另给被阻断原文的入口，不出现无文字的新文案', () => {
  const onViewRawEvidence = vi.fn()
  renderTurnList([turnOf({ user_input: '请检查代码', blocked_input_evidence_request_ids: ['req_2'] })], onViewRawEvidence)
  expect(screen.getByText('请检查代码')).toBeTruthy()
  expect(screen.queryByText('输入已被阻断，原文另存')).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: '查看被阻断的原文' }))
  expect(onViewRawEvidence).toHaveBeenCalledWith('req_2')
 })
 it('有留存文字且有留证但没传回调时没有入口', () => {
  renderTurnList([turnOf({ user_input: '请检查代码', blocked_input_evidence_request_ids: ['req_2'] })])
  expect(screen.getByText('请检查代码')).toBeTruthy()
  expect(screen.queryByRole('button', { name: '查看被阻断的原文' })).toBeNull()
 })
 it('有留存文字但没有留证字段时没有入口', () => {
  renderTurnList([turnOf({ user_input: '请检查代码' })], vi.fn())
  expect(screen.queryByRole('button', { name: '查看被阻断的原文' })).toBeNull()
 })
})
