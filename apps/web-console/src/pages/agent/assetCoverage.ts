import type { AgentEndpoint } from '../../services/agentEndpoint.types'
import type { UnifiedAsset } from '../../services/unifiedAssets'

export const catalogLabels: Record<string, string> = { unreviewed: '未审核', approved: '已批准', exception: '例外有效', expired: '例外已过期' }
export function coverageGaps(asset: UnifiedAsset): string[] {
  const gaps: string[] = []
  if (!asset.discovered) gaps.push('缺少发现记录')
  if (!asset.managed) gaps.push('未关联有效接入端点')
  if (!asset.observed) gaps.push('最新快照未报告存在')
  if (!asset.owner_user_id) gaps.push('责任人未登记')
  if (asset.catalog_status === 'unreviewed') gaps.push('目录未审核')
  if (asset.catalog_status === 'expired') gaps.push('目录例外已过期')
  gaps.push('资产运行时观测证据未提供')
  if (!asset.controlled || asset.control_state !== 'evidenced' || asset.control_evidence_count <= 0) gaps.push('缺少控制生效证据')
  return gaps
}
export function endpointHealth(endpoint: AgentEndpoint, now = Date.now()) {
  const heartbeat = Date.parse(endpoint.last_heartbeat_at ?? '')
  if (endpoint.status === 'revoked') return { label: '已吊销', reason: '端点接入凭据已吊销' }
  if (!Number.isFinite(heartbeat)) return { label: '未知', reason: '未上报有效心跳时间' }
  if (heartbeat > now + 60_000) return { label: '未知', reason: '心跳时间超前，请检查时钟' }
  if (endpoint.status === 'stale' || now - heartbeat > 15 * 60_000) return { label: '失联', reason: '最近心跳超过 15 分钟或服务端已标记失联' }
  if (endpoint.status !== 'active') return { label: '离线', reason: '服务端未标记为活跃端点' }
  return { label: '在线', reason: '活跃端点在最近 15 分钟内上报心跳' }
}
export function assetError(error: unknown): string {
  const status = (error as { response?: { status?: number } })?.response?.status
  if (status === 403) return '无权查看当前资产数据（403）'
  if (status === 402) return '当前授权或额度不允许访问资产数据（402）'
  if (status === 404) return '资产或来源端点已不存在（404）'
  return '数据加载失败，请检查服务状态后重试'
}
