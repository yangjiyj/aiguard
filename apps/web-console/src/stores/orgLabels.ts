import { create } from 'zustand'
import { settingsApi } from '../services/api'

interface OrgLabelsState {
  tier1: string
  tier2: string
  loaded: boolean
  fetch: () => Promise<void>
}

export const useOrgLabels = create<OrgLabelsState>((set) => ({
  tier1: '单位',
  tier2: '部门',
  loaded: false,
  fetch: async () => {
    try {
      const r = await settingsApi.getOrgLabels()
      const d = r.data?.data || r.data || {}
      set({ tier1: d.org_tier1_label || '单位', tier2: d.org_tier2_label || '部门', loaded: true })
    } catch {
      set({ loaded: true })
    }
  },
}))
