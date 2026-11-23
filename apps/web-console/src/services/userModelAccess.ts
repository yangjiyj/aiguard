import { apiClient } from './api'

export interface UserModelExtraGrant {
 id: string
 model: string
 reason: string
 expires_at: string | null
 created_by: string
 created_at: string
 revoked_at: string | null
}
export type ModelAccessSource = 'department' | 'personal_extra' | 'personal_narrowed'
export interface UserModelAccess {
 extra_grants?: UserModelExtraGrant[]
 model_sources?: Record<string,ModelAccessSource>
 stale_models?: string[]
 user_id: string
 department_id: string
 department_name: string
 department_models: string[]
 effective_models: string[]
 mode: 'inherit' | 'allowlist'
 model_names: string[]
 version: number
 department_version: number
 chat_allowed: boolean
}
export interface UserModelPolicyInput {
 mode: 'inherit' | 'allowlist'
 model_names: string[]
 version: number
}
export const userModelAccessApi = {
 get: (id: string) => apiClient.get<{data:UserModelAccess}>(`/users/${encodeURIComponent(id)}/model-access`),
 addExtra: (id: string, grant: {model:string;reason:string;expires_at:string|null}) => apiClient.post<{data:UserModelExtraGrant}>(`/users/${encodeURIComponent(id)}/model-access/extra-grants`,grant),
 revokeExtra: (id: string, grantId:string) => apiClient.post(`/users/${encodeURIComponent(id)}/model-access/extra-grants/${encodeURIComponent(grantId)}/revoke`),
 set: (id: string, policy: UserModelPolicyInput) => apiClient.put<{data:UserModelAccess}>(`/users/${encodeURIComponent(id)}/model-access`, policy),
}
