import { create } from 'zustand'
import { alertApi } from '../services/api'

interface AlertInboxState {
  unread: number
  refresh: () => Promise<void>
}

export const useAlertInboxStore = create<AlertInboxState>((set) => ({
  unread: 0,
  refresh: async () => {
    try {
      const res = await alertApi.inbox(true)
      const items = res.data?.data?.data || res.data?.data || []
      set({ unread: Array.isArray(items) ? items.length : 0 })
    } catch (_e) {
      // silent - alert count not critical
    }
  },
}))
