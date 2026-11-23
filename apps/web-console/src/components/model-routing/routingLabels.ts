import type { ModelRoutingRule } from '../../services/api'

const STRATEGY_LABELS = { priority: '稳定优先', weighted: '按权重分流', smart: '智能优化', fixed: '固定线路' } as const
const OBJECTIVE_LABELS = { stability: '稳定优先', latency: '速度优先', cost: '成本优先', balanced: '综合均衡', custom: '自定义顺序' } as const

export function strategyLabel(rule: ModelRoutingRule | null): string {
  if (!rule) return '尚未配置'
  const base = STRATEGY_LABELS[rule.config.strategy]
  return rule.config.strategy === 'smart' && rule.config.objective ? `${base} · ${OBJECTIVE_LABELS[rule.config.objective]}` : base
}
