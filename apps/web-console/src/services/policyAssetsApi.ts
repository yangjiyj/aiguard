import api from './api'

export type PolicyAsset = {
  id: string
  rule_type: string
  name: string
  severity: string
  action: string
  enabled: boolean
  description?: string
  source: 'tenant' | 'industry'
  industry: string
  applicable: boolean
  executable: boolean
  writable: boolean
}

export type PolicyAssetResponse = {
  data: PolicyAsset[]
  total_assets: number
  applicable_assets: number
  executable_assets: number
}

export const policyAssetApi = {
  list: () => api.get<PolicyAssetResponse>('/security/policy-assets'),
  updateAction: (id: string, action: 'audit' | 'mask' | 'block') =>
    api.put<PolicyAsset>(`/security/policy-assets/${id}`, { action }),
}
