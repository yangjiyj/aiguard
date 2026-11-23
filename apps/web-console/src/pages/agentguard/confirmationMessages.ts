// W5 5.2 / 5.3: shared wording for resolving AgentGuard confirmations.

type ResolutionError = {
  response?: { status?: number; data?: { error?: { code?: string; message?: string } } }
}

export function agentGuardResolutionSuccessMessage(status?: number): string {
  if (status === 202) {
    return '已记录第一位审批人，需另一位审批人批准后才生效'
  }
  return '确认请求已处理'
}

export function agentGuardResolutionErrorMessage(error: unknown, fallback: string): string {
  const code = (error as ResolutionError)?.response?.data?.error?.code
  switch (code) {
    case 'confirmation_self_approval_forbidden':
      return '审批人不能批准自己触发的工具调用，请由其他管理员处理'
    case 'confirmation_second_approver_required':
      return '已开启双人审批，第二次批准必须由另一位审批人完成'
    case 'confirmation_expired':
      return '确认请求已过期，请让发起人重新发起'
    default:
      return fallback
  }
}
