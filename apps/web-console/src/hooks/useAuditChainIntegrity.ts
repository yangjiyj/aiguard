import { useQuery } from '@tanstack/react-query'
import { auditChainApi, type AuditChainIntegrity } from '../services/api'

// 审计链签名密钥状态与最近一次完整性校验结果（只读）。
export function useAuditChainIntegrity(enabled = true) {
  return useQuery({
    queryKey: ['audit-chain-integrity'],
    queryFn: async () => (await auditChainApi.integrity()).data as AuditChainIntegrity,
    enabled,
    staleTime: 60_000,
    refetchInterval: 5 * 60_000,
    retry: false,
  })
}
