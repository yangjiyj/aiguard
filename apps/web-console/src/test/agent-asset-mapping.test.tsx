import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AgentAssetCoverage from '../pages/agent/AgentAssetCoverage'
import { unifiedAssetsApi, type UnifiedAsset } from '../services/unifiedAssets'
import { useAuthStore } from '../stores/auth'

const refHash = 'b'.repeat(64)
const asset: UnifiedAsset = {
  id: 'ua-1', asset_type: 'workflow', name: '现有工作流', owner_user_id: '', business_unit: '', business_service: '',
  catalog_status: 'unreviewed', catalog_reason: '', first_seen: '2026-09-24T00:00:00Z', last_seen: '2026-09-25T00:00:00Z',
  instance_count: 0, managed_instance_count: 0, observed_instance_count: 0, control_evidence_count: 0,
  discovered: false, managed: false, observed: false, controlled: false, control_state: 'unknown',
}
function mount(entry: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}><AgentAssetCoverage /></MemoryRouter></QueryClientProvider>)
  return client
}
beforeEach(() => {
  vi.restoreAllMocks()
  useAuthStore.setState({ user: { id: 'operator', username: 'operator', role: 'tenant_admin', tenant_id: 'tenant-a' }, isAuthenticated: true, token: 't' })
  vi.spyOn(unifiedAssetsApi, 'list').mockResolvedValue({ items: [asset], total: 1, page: 1, page_size: 20 } as any)
  vi.spyOn(unifiedAssetsApi, 'history').mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20 } as any)
  vi.spyOn(unifiedAssetsApi, 'nativeReferenceLink').mockResolvedValue({ linked: false })
  vi.spyOn(unifiedAssetsApi, 'linkSource').mockResolvedValue({ linked: true })
})
describe('资产目录中的原生来源手工关联', () => {
  it('只将完整引用关联到操作者选中的现有资产', async () => {
    vi.mocked(unifiedAssetsApi.nativeReferenceLink)
      .mockResolvedValueOnce({ linked: false })
      .mockResolvedValue({ linked: true, asset_id: 'ua-1' })
    mount('/agent/assets?source_id=source-a&ref_hash=' + refHash)
    const linkButton = await screen.findByRole('button', { name: '关联此来源' })
    fireEvent.click(linkButton)
    fireEvent.click(await screen.findByRole('button', { name: '确认关联' }))
    await waitFor(() => expect(unifiedAssetsApi.linkSource).toHaveBeenCalledWith('ua-1', {
      source_type: 'identity_event', source_namespace: 'native:source-a', native_id: refHash,
    }))
    expect(await screen.findByText('此引用已有操作员关联')).toBeInTheDocument()
  })
  it('通过资产 ID 精确打开现有资产详情', async () => {
    mount('/agent/assets?asset_id=ua-1')
    expect(await screen.findByText('资产详情与调查')).toBeInTheDocument()
    expect(unifiedAssetsApi.list).toHaveBeenCalledWith(expect.objectContaining({ asset_id: 'ua-1' }))
    expect(unifiedAssetsApi.history).toHaveBeenCalledWith('ua-1', 1)
  })
})
