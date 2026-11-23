import { apiClient } from './api'
import type { Page } from './agentEndpoint.types'

export interface UnifiedAsset {
  id: string; asset_type: string; name: string
  owner_user_id: string; business_unit: string; business_service: string
  catalog_status: string; catalog_reason: string; catalog_expires_at?: string
  first_seen: string; last_seen: string
  instance_count: number; managed_instance_count: number; observed_instance_count: number
  control_evidence_count: number
  discovered: boolean; managed: boolean; observed: boolean; controlled: boolean; control_state: string
}
export interface AssetObservation {
  id: string; asset_id: string; source_asset_id: string; instance_id: string
  source_type: string; source_namespace: string; native_id: string
  source_event_id: string; provenance: string; source_occurred_at: string; received_at: string
  name: string; version: string; hash: string; present: boolean; scan_status: string; scan_decision: string
}
export interface AssetFilters { page: number; page_size: number; asset_type?: string; catalog_status?: string; asset_id?: string }
export interface NativeReferenceAssetLink { linked: boolean; asset_id?: string }
export const isFullNativeReferenceHash = (value?: string) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
export const unifiedAssetsApi = {
  list: async (params: AssetFilters) => (await apiClient.get<Page<UnifiedAsset>>('/agent/unified-assets', { params })).data,
  history: async (id: string, page: number) => (await apiClient.get<Page<AssetObservation>>(`/agent/unified-assets/${encodeURIComponent(id)}/history`, { params: { page, page_size: 20 } })).data,
  nativeReferenceLink: async (sourceID: string, refHash: string) => (await apiClient.get<NativeReferenceAssetLink>('/agent/unified-assets/native-reference-link', { params: { source_id: sourceID, ref_hash: refHash } })).data,
  linkSource: async (assetID: string, source: { source_type: 'identity_event'; source_namespace: string; native_id: string }) => (await apiClient.put('/agent/unified-assets/' + encodeURIComponent(assetID) + '/sources', source)).data,
}
export const unifiedAssetKeys = {
  list: (scope: string, filters: AssetFilters) => ['agent', scope, 'unified-assets', filters] as const,
  history: (scope: string, id: string, page: number) => ['agent', scope, 'unified-asset-history', id, page] as const,
  nativeReferenceLink: (scope: string, sourceID: string, refHash: string) => ['agent', scope, 'native-reference-asset-link', sourceID, refHash] as const,
}
