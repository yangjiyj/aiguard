import api from './api'

export type RawEvidenceMeta = {
  id: string
  request_id: string
  session_id?: string
  user_id?: string
  direction: 'input' | 'output'
  role: string
  message_index: number
  disposition: 'masked' | 'blocked'
  block_id?: string
  rule_ids: string[]
  rule_names: string[]
  categories: string[]
  content_chars: number
  created_at: string
  // 原文超过 512K 字符时截断保存；original_chars 是截断前的字符数。
  truncated?: boolean
  original_chars?: number
  // 非空：同会话重复出现的原文，本行只是引用，查看时取首次出现那条的原文。
  ref_evidence_id?: string
}

export type RawEvidenceList = { items: RawEvidenceMeta[]; total: number; enabled: boolean }
// hits：命中段（UTF-16 下标，直接切 text）；rules：本条涉及的阻断/脱敏规则及是否在原文里定位到。
export type RawEvidenceHit = { start: number; end: number; rule_name: string; action?: string }
export type RawEvidenceRule = { rule_name: string; action?: string; located: boolean; semantic?: boolean; reason?: string }
export type RawEvidenceReveal = RawEvidenceMeta & { text: string; hits?: RawEvidenceHit[]; rules?: RawEvidenceRule[] }
export type RawEvidenceQuery = { request_id?: string; block_id?: string; rule?: string; direction?: string; disposition?: string; limit?: number; offset?: number }

export const rawEvidenceApi = {
  list: (params: RawEvidenceQuery) => api.get<RawEvidenceList>('/audit/raw-evidence', { params }),
  reveal: (id: string, reason = '') => api.post<RawEvidenceReveal>(`/audit/raw-evidence/${encodeURIComponent(id)}/reveal`, { reason }),
  getSettings: () => api.get<{ enabled: boolean }>('/audit/raw-evidence/settings'),
  setEnabled: (enabled: boolean) => api.put<{ enabled: boolean }>('/audit/raw-evidence/settings', { enabled }),
}
