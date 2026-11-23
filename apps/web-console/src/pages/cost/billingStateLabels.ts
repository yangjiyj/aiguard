// 调用明细里“账单状态”的中文展示。被预算断流拒绝的请求没有账单行，结果来自 request_logs.billing_outcome。
export interface BillingStateMeta { label: string; color: string }

export const billingStateMeta: Record<string, BillingStateMeta> = {
  settled: { label: '已结算', color: 'success' },
  reserved: { label: '待结算', color: 'processing' },
  released: { label: '已释放', color: 'default' },
  unpriced: { label: '未定价', color: 'warning' },
  failed: { label: '计费失败', color: 'error' },
  exception: { label: '异常待核对', color: 'error' },
  not_billed: { label: '无计费事实', color: 'default' },
  budget_exhausted: { label: '预算用尽被拒', color: 'error' },
  budget_unpriced: { label: '未定价被拒', color: 'warning' },
  budget_unavailable: { label: '计费不可用被拒', color: 'error' },
}

export const billingStateLabel = (state: string): BillingStateMeta =>
  billingStateMeta[state] || { label: '未知计费状态', color: 'default' }
