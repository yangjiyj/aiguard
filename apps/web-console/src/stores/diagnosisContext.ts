import { create } from 'zustand'

export const useDiagnosisContext = create<{
  context: { requestId: string } | null
  setContext: (context: { requestId: string }) => void
  clear: () => void
}>((set) => ({
  context: null,
  setContext: (context) => set({ context }),
  clear: () => set({ context: null }),
}))
