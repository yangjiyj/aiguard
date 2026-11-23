import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AgentNativeTimeline from '../pages/agent/AgentNativeTimeline'
import AuditQueryIdentityBoundary from '../components/AuditQueryIdentityBoundary'
import { nativeEventsApi, nativeEventKeys, type NativeObservation } from '../services/nativeEvents'
import { unifiedAssetsApi } from '../services/unifiedAssets'
import { useAuthStore } from '../stores/auth'

const source = 'a'.repeat(64), refHash = 'b'.repeat(64)
const event: NativeObservation = {
  sequence_id: 100, endpoint_id: 'ep/a', event_id: 'event-a', source_id: source,
  producer: { kind: 'service', native_id: 'collector-a' }, event_type: 'run.started',
  occurred_at: '2026-09-25T00:00:00Z', received_at: '2026-09-25T00:01:00Z',
  references: [{ role: 'run', ref_hash: refHash, ref: { kind: 'run', namespace: 'app/a', native_id: 'run-a' } }],
  payload: { private: 'private-payload-a', legacy_event_id: 'unverified-legacy-a' },
}
function mount(initial = '/agent/native-events') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><AuditQueryIdentityBoundary><MemoryRouter initialEntries={[initial]}><AgentNativeTimeline /></MemoryRouter></AuditQueryIdentityBoundary></QueryClientProvider>)
  return client
}
beforeEach(() => {
  vi.restoreAllMocks()
  useAuthStore.setState({ user: { id: 'user-a', username: 'A', role: 'tenant_admin', tenant_id: 'tenant-a' }, isAuthenticated: true, token: 'never-in-cache-key' })
  vi.spyOn(nativeEventsApi, 'list').mockImplementation(async filters => ({
    items: [{ ...event, event_id: filters.before_sequence ? 'event-b' : event.event_id }],
    next_before_sequence: filters.before_sequence ? undefined : 100,
    order_basis: 'server_sequence_desc_not_causal', provenance: 'authenticated_endpoint_with_reported_native_claims',
  }))
  vi.spyOn(unifiedAssetsApi, 'nativeReferenceLink').mockResolvedValue({ linked: false })
})
const actionEvent: NativeObservation = {
  ...event, event_id: 'action-a', event_type: 'action.observed',
  payload: { legacy_event_id: 'agent-event-a' },
  investigation: {
    legacy_event: { status: 'matched', id: 'agent-event-a' },
    session: { status: 'matched', id: 'session/a' },
    alert: { status: 'matched', id: 'security-event-a' },
  },
}
describe('原生运行调查', () => {
  it('只展示精确核验的旧事件、同端点会话和告警编号', async () => {
    vi.mocked(nativeEventsApi.list).mockResolvedValue({
      items: [actionEvent], order_basis: 'server_sequence_desc_not_causal',
      provenance: 'authenticated_endpoint_with_reported_native_claims',
    })
    mount()
    fireEvent.click(await screen.findByRole('button', { name: '动作观察 · action-a' }))
    expect(screen.getByText('旧事件关联核验')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'session/a' })).toHaveAttribute('href', '/agent/sessions/session%2Fa')
    expect(screen.getByRole('link', { name: 'security-event-a' })).toHaveAttribute('href', '/security/alerts?event_id=security-event-a')
    expect(screen.queryByRole('link', { name: 'agent-event-a' })).not.toBeInTheDocument()
    expect(screen.getAllByText(/匹配不证明因果或执行/).length).toBeGreaterThan(0)
  })
  it('仅向告警页允许的角色提供精确事件深链', async () => {
    useAuthStore.setState({ user: { id: 'admin', username: 'admin', role: 'admin', tenant_id: 'tenant-a' }, isAuthenticated: true, token: 't' })
    vi.mocked(nativeEventsApi.list).mockResolvedValue({ items: [actionEvent], order_basis: '', provenance: '' })
    mount()
    fireEvent.click(await screen.findByRole('button', { name: '动作观察 · action-a' }))
    expect(screen.getByText('security-event-a').closest('a')).toBeNull()
  })
  it('按来源 ID 和完整 ref_hash 展示现有操作员资产映射', async () => {
    vi.mocked(unifiedAssetsApi.nativeReferenceLink).mockResolvedValue({ linked: true, asset_id: 'ua/a' })
    mount()
    fireEvent.click(await screen.findByRole('button', { name: '运行开始 · event-a' }))
    const assetLink = await screen.findByRole('link', { name: '资产 ua/a' })
    expect(assetLink).toHaveAttribute('href', '/agent/assets?asset_id=ua%2Fa')
    expect(unifiedAssetsApi.nativeReferenceLink).toHaveBeenCalledWith(source, refHash)
    expect(screen.getByText('操作员关联')).toBeInTheDocument()
  })
  it.each([
    ['missing', 'no_same_tenant_endpoint_match', '未找到', '未找到同租户且同端点的精确事件编号'],
    ['ambiguous', 'multiple_same_tenant_endpoint_matches', '匹配不唯一', '同租户且同端点存在多个事件编号匹配'],
  ] as const)('明确显示旧事件 %s 且不生成下游链接', async (status, reason, label, reasonText) => {
    vi.mocked(nativeEventsApi.list).mockResolvedValue({
      items: [{
        ...actionEvent,
        investigation: {
          legacy_event: { status, reason },
          session: { status: 'unavailable', reason: 'legacy_event_unresolved' },
          alert: { status: 'unavailable', reason: 'legacy_event_unresolved' },
        },
      }],
      order_basis: 'server_sequence_desc_not_causal',
      provenance: 'authenticated_endpoint_with_reported_native_claims',
    })
    mount()
    fireEvent.click(await screen.findByRole('button', { name: '动作观察 · action-a' }))
    expect(screen.getByText(label)).toBeInTheDocument()
    expect(screen.getByText(reasonText)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'session/a' })).not.toBeInTheDocument()
    expect(screen.queryByText('security-event-a')).not.toBeInTheDocument()
  })
  it('展示声明边界、独立时间与端点链接，不生成旧会话或告警链接', async () => {
    mount()
    fireEvent.click(await screen.findByRole('button', { name: '运行开始 · event-a' }))
    expect(screen.getByText('原生关系与动作结果由采集端上报')).toBeInTheDocument()
    expect(screen.getByText('以下原生对象关联由来源声明')).toBeInTheDocument()
    expect(screen.getByText('run-a')).toBeInTheDocument()
    const manualLink = await screen.findByRole('link', { name: '在资产目录中手工关联' })
    expect(manualLink).toHaveAttribute('href', '/agent/assets?source_id=' + source + '&ref_hash=' + refHash)
    expect(screen.getAllByRole('link', { name: 'ep/a' })[0]).toHaveAttribute('href', '/agent/endpoints?endpoint=ep%2Fa')
    expect(screen.queryByRole('link', { name: 'unverified-legacy-a' })).not.toBeInTheDocument()
    expect(screen.getByText(/private-payload-a/)).toBeInTheDocument()
  })
  it('游标翻页关闭详情，上一页与刷新恢复首批', async () => {
    mount()
    fireEvent.click(await screen.findByRole('button', { name: '运行开始 · event-a' }))
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    await screen.findByRole('button', { name: '运行开始 · event-b' })
    expect(screen.queryByText(/private-payload-a/)).not.toBeInTheDocument()
    expect(nativeEventsApi.list).toHaveBeenLastCalledWith(expect.objectContaining({ before_sequence: 100, limit: 20 }))
    expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '上一页' }))
    await screen.findByRole('button', { name: '运行开始 · event-a' })
    expect(screen.getByRole('button', { name: '上一页' })).toBeDisabled()
  })
  it('对象下钻同时限定真实端点、来源和完整引用', async () => {
    mount()
    fireEvent.click(await screen.findByRole('button', { name: '运行开始 · event-a' }))
    fireEvent.click(screen.getByRole('button', { name: '查看该对象记录' }))
    await waitFor(() => expect(nativeEventsApi.list).toHaveBeenLastCalledWith({
      endpoint_id: 'ep/a', source_id: source, ref_hash: refHash, before_sequence: undefined, limit: 20,
    }))
    expect(screen.getByText('已限定同一原生对象')).toBeInTheDocument()
    expect(screen.queryByText(/private-payload-a/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '清除筛选' }))
    await waitFor(() => expect(nativeEventsApi.list).toHaveBeenLastCalledWith(expect.objectContaining({ source_id: undefined, ref_hash: undefined })))
  })
  it.each([400, 402, 403, 404, 500])('错误 %s 不显示虚假空记录', async status => {
    vi.mocked(nativeEventsApi.list).mockRejectedValue({ response: { status } })
    mount()
    await screen.findByRole('button', { name: '重试' })
    await waitFor(() => expect(screen.queryByText('暂无匹配的原生记录；未采集到记录不代表没有运行活动')).not.toBeInTheDocument())
    expect(screen.queryByRole('button', { name: '运行开始 · event-a' })).not.toBeInTheDocument()
  })
  it('重查被拒时清除当前详情；摘要不补造原始内容', async () => {
    const client = mount()
    fireEvent.click(await screen.findByRole('button', { name: '运行开始 · event-a' }))
    vi.mocked(nativeEventsApi.list).mockRejectedValue({ response: { status: 403 } })
    await act(async () => { await client.invalidateQueries({ queryKey: ['agent'] }) })
    expect(await screen.findByText('无权查看当前原生运行记录（403）')).toBeInTheDocument()
    expect(screen.queryByText(/private-payload-a/)).not.toBeInTheDocument()
    vi.mocked(nativeEventsApi.list).mockResolvedValue({ items: [{ ...event, payload: undefined }], order_basis: '', provenance: '' })
    fireEvent.click(screen.getByRole('button', { name: '重试' }))
    await screen.findByRole('button', { name: '运行开始 · event-a' })
    expect(screen.queryByText(/private-payload-a/)).not.toBeInTheDocument()
  })
  it('身份改变立即清除旧详情与缓存', async () => {
    const client = mount()
    fireEvent.click(await screen.findByRole('button', { name: '运行开始 · event-a' }))
    vi.mocked(nativeEventsApi.list).mockImplementation(() => new Promise(() => {}))
    act(() => useAuthStore.getState().setUser({ id: 'user-b', username: 'B', role: 'auditor', tenant_id: 'tenant-b' }))
    expect(screen.queryByText(/private-payload-a/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '运行开始 · event-a' })).not.toBeInTheDocument()
    expect(JSON.stringify(client.getQueryCache().getAll().map(q => q.queryKey))).not.toContain('tenant-a|user-a')
    expect(JSON.stringify(nativeEventKeys.list('tenant-a|user-a|tenant_admin', { limit: 20 }))).not.toContain('never-in-cache-key')
  })
})
