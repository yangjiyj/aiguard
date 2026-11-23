import api from './api'

export type LeakTraceMatch = {
  request_id: string
  occurred_at: string
  user_id?: string
  username?: string
  client_name?: string
  agent_type?: string
  provider?: string
  target?: string
  fragments?: number[]
}

export type LeakTraceResult = {
  method: 'watermark' | 'fragments' | 'none'
  watermark: 'verified' | 'forged' | 'absent'
  fragments?: string[]
  matches: LeakTraceMatch[]
  note?: string
}

export const leakTraceApi = {
  trace: (text: string) => api.post<LeakTraceResult>('/audit/leak-trace', { text }),
}
