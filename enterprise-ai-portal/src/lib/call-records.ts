import type { PortalBillingState } from './control-plane';
import { formatMoneyMicros } from './money-micros';

export type CallStatusTone = 'success' | 'warning' | 'danger';

export interface CallStatusPresentation {
  label: string;
  tone: CallStatusTone;
}

export function endpointTypeLabel(endpointType: string): string {
  switch (endpointType.trim().toLowerCase()) {
    case 'chat':
    case 'chat_completions':
      return 'Chat API';
    case 'responses':
      return 'Responses API';
    case 'messages':
    case 'anthropic_messages':
      return 'Messages API';
    case 'embeddings':
      return 'Embeddings API';
    case 'images':
      return 'Images API';
    default:
      return '模型 API';
  }
}

export function agentTypeLabel(agentType: string): string {
  const raw = agentType.trim();
  const normalized = raw.toLowerCase().replace(/[\s_]+/g, '-');
  switch (normalized) {
    case 'codex':
    case 'openai-codex':
      return 'Codex';
    case 'claude-code':
    case 'claudecode':
      return 'Claude Code';
    case 'openclaw':
    case 'open-claw':
      return 'OpenClaw';
    case 'cursor':
      return 'Cursor';
    case 'cline':
      return 'Cline';
    default:
      return raw ? '其他智能体' : '';
  }
}

export function callSourceLabel(endpointType: string, agentType: string): string {
  const endpoint = endpointTypeLabel(endpointType);
  const agent = agentTypeLabel(agentType);
  return agent ? agent + ' · ' + endpoint : endpoint;
}

export function callStatusPresentation(status: string, upstreamStatus = 0): CallStatusPresentation {
  const normalized = status.trim().toLowerCase();
  if (
    (normalized === 'success' || normalized === 'completed' || normalized === 'ok') &&
    upstreamStatus < 400
  ) {
    return { label: '成功', tone: 'success' };
  }
  if (
    normalized.includes('429') ||
    normalized.includes('rate_limit') ||
    normalized.includes('throttl') ||
    upstreamStatus === 429
  ) {
    return { label: '已限流', tone: 'warning' };
  }
  return { label: '失败', tone: 'danger' };
}

export function formatSecurityEvents(count: number): string {
  return count > 0 ? count + ' 个安全事件' : '无安全事件';
}

function actionLabel(action: string): string {
  switch (action.trim().toLowerCase()) {
    case 'audit':
      return '审计留痕';
    case 'block':
    case 'deny':
      return '拦截';
    case 'redact':
    case 'mask':
      return '脱敏';
    case 'allow':
      return '记录放行';
    default:
      return action.trim() ? '已记录处置' : '';
  }
}

export function formatSecurityAction(inputAction: string, outputAction: string): string {
  const input = actionLabel(inputAction);
  const output = actionLabel(outputAction);
  if (!input && !output) return '未记录处置';
  if (input && output && input === output) return input;
  if (input && output) return '输入' + input + '、输出' + output;
  if (input === '拦截' || input === '脱敏') return '输入' + input;
  if (output === '拦截' || output === '脱敏') return '输出' + output;
  return input || output;
}

const tokenFormatter = new Intl.NumberFormat('zh-CN', {
  maximumFractionDigits: 0,
  useGrouping: true,
});

export function formatTokenCount(value: number): string {
  return tokenFormatter.format(Math.max(0, Math.trunc(value)));
}

export function billingAmountPresentation(
	state: PortalBillingState,
	amountMicros: number | null,
	currency: string,
	tenantCurrency?: string,
): string {
	switch (state) {
		case 'reserved':
			return '待结算';
		case 'released':
			return '未扣费';
		case 'exception':
			return '计费异常';
		case 'unpriced':
			return '未定价';
		case 'failed':
			return '计费失败';
		case 'not_billed':
			return '无计费账单';
		case 'settled': {
			if (amountMicros === null && currency === '') {
				return '—';
			}
			if (!Number.isSafeInteger(amountMicros) || (amountMicros as number) < 0) {
				return '计费异常';
			}
			return formatMoneyMicros(amountMicros as number, currency, tenantCurrency);
		}
	}
}
