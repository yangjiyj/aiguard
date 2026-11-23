import { apiClient } from './api'

export type DepartmentMappingMatchType = 'department' | 'groups' | 'ou' | 'member_of'

export interface IdentityDepartmentMapping {
  id: string
  source_type: 'oidc' | 'ldap' | 'ad'
  source_id: string
  external_group: string
  match_type: DepartmentMappingMatchType
  department_id: string
  department_name?: string
  priority: number
  enabled: boolean
}

export type IdentityDepartmentMappingInput = Omit<IdentityDepartmentMapping, 'id' | 'department_name'>

export interface DepartmentMappingPreview {
  matched: boolean
  ambiguous: boolean
  department_id?: string
  department_name?: string
  candidate_ids?: string[]
  candidate_departments?: { department_id: string; department_name: string }[]
}

export const identityDepartmentMappingsApi = {
  list: (sourceType: IdentityDepartmentMapping['source_type'], sourceID: string) =>
    apiClient.get<{ data: IdentityDepartmentMapping[] }>('/identity/department-mappings', {
      params: { source_type: sourceType, source_id: sourceID },
    }),
  create: (data: IdentityDepartmentMappingInput) =>
    apiClient.post<IdentityDepartmentMapping>('/identity/department-mappings', data),
  update: (id: string, data: IdentityDepartmentMappingInput) =>
    apiClient.patch<IdentityDepartmentMapping>('/identity/department-mappings/' + encodeURIComponent(id), data),
  delete: (id: string) => apiClient.delete('/identity/department-mappings/' + encodeURIComponent(id)),
  preview: (data: {
    source_type: IdentityDepartmentMapping['source_type']
    source_id: string
    external_departments: string[]
    external_groups: string[]
  }) => apiClient.post<DepartmentMappingPreview>('/identity/department-mappings/preview', data),
}
