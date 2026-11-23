import { useQuery } from '@tanstack/react-query'
import { blockRecordsApi } from '../services/api'
import { useAuditQueryIdentity } from './useAuditQueryIdentity'

// 阻断溯源（告警、留痕、按内容证据权限返回的命中原文）。阻断记录页的详情和 BlockTraceEvidence 共用这一个查询定义，
// 同一阻断只请求一次。
export function useBlockTrace(blockId?: string) {
  const identity = useAuditQueryIdentity()
  return useQuery({
    queryKey: ['block-trace', identity, blockId || ''],
    queryFn: ({ signal }) => blockRecordsApi.trace(blockId!, signal).then((response) => response.data),
    enabled: Boolean(blockId),
  })
}
