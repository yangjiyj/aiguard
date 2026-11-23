import { apiClient } from './api'

export interface NativeRef { kind: string; namespace: string; native_id: string; revision?: string }
export interface NativeEventReference { role: string; ref_hash: string; ref: NativeRef }
export interface NativeEventResolution {
  status: 'matched' | 'missing' | 'ambiguous' | 'unavailable' | 'not_applicable'
  reason?: string
  id?: string
}
export interface NativeEventInvestigation {
  legacy_event: NativeEventResolution
  session: NativeEventResolution
  alert: NativeEventResolution
}
export interface NativeObservation {
  sequence_id: number; endpoint_id: string; event_id: string; source_id: string
  producer: { kind: string; native_id: string }
  event_type: string; occurred_at: string; received_at: string
  references: NativeEventReference[]; status?: string; outcome?: string
  payload?: Record<string, unknown>
  investigation?: NativeEventInvestigation
}
export interface NativeEventPage {
  items: NativeObservation[]; next_before_sequence?: number
  order_basis: string; provenance: string
}
export interface NativeEventFilter { endpoint_id?: string; source_id?: string; ref_hash?: string; before_sequence?: number; limit: number }
export const nativeEventsApi = {
  list: async (params: NativeEventFilter) => (await apiClient.get<NativeEventPage>('/agent/native-events', { params })).data,
}
export const nativeEventKeys = {
  list: (scope: string, filters: NativeEventFilter) => ['agent', scope, 'native-events', filters] as const,
}
