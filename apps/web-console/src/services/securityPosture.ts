import api from './api'

export type PostureMode = 'record' | 'protect' | 'mixed' | 'unknown'
export interface PostureChannel {
  id: string
  configured_mode: PostureMode
  effective_mode: PostureMode
  runtime_verified: boolean
  mode_sources?: string[]
  fail_modes: { id: string; mode: 'open' | 'closed' | 'unknown' }[]
  controls: { id: string; enabled: boolean | null; wired: boolean | null }[]
}
export interface SecurityPosture {
  tenant_id: string
  generated_at: string
  runtime_verified: boolean
  channels: PostureChannel[]
  ml_layers: { id: string; configured_enabled: boolean; runtime_enabled: boolean | null; runtime_verified: boolean }[]
  warnings: string[]
}

export const securityPostureApi = {
  get: async (): Promise<SecurityPosture> => {
    const response = await api.get<SecurityPosture>('/security/posture')
    const posture = response.data
    if (!posture || !Array.isArray(posture.channels) || !Array.isArray(posture.ml_layers) || !Array.isArray(posture.warnings)) {
      throw new Error('invalid_security_posture')
    }
    return posture
  },
}
