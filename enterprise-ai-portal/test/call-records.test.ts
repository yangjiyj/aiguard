import test from 'node:test';
import assert from 'node:assert/strict';

import {
  callSourceLabel,
  callStatusPresentation,
  formatSecurityAction,
  formatSecurityEvents,
  formatTokenCount,
	billingAmountPresentation,
} from '../src/lib/call-records.js';

test('callSourceLabel names known agents and never guesses a Portal origin', () => {
	assert.equal(callSourceLabel('responses', 'codex'), 'Codex · Responses API');
	assert.equal(callSourceLabel('responses', 'openai-codex'), 'Codex · Responses API');
	assert.equal(callSourceLabel('anthropic_messages', 'claude-code'), 'Claude Code · Messages API');
	assert.equal(callSourceLabel('chat', 'openclaw'), 'OpenClaw · Chat API');
	assert.equal(callSourceLabel('chat', ''), 'Chat API');
	assert.equal(callSourceLabel('chat', 'internal-agent-v2'), '其他智能体 · Chat API');
	assert.equal(callSourceLabel('unknown', ''), '模型 API');
});

test('callStatusPresentation distinguishes success, throttling and failures', () => {
  assert.deepEqual(callStatusPresentation('success', 200), {
    label: '成功',
    tone: 'success',
  });
  assert.deepEqual(callStatusPresentation('billing_http_429', 0), {
    label: '已限流',
    tone: 'warning',
  });
  assert.deepEqual(callStatusPresentation('upstream_error', 502), {
    label: '失败',
    tone: 'danger',
  });
});

test('security overview never claims a security pass without evidence', () => {
  assert.equal(formatSecurityEvents(0), '无安全事件');
  assert.equal(formatSecurityEvents(2), '2 个安全事件');
  assert.equal(formatSecurityAction('', ''), '未记录处置');
  assert.equal(formatSecurityAction('audit', ''), '审计留痕');
  assert.equal(formatSecurityAction('block', 'redact'), '输入拦截、输出脱敏');
});

test('formatTokenCount uses a stable Chinese thousands separator', () => {
  assert.equal(formatTokenCount(0), '0');
  assert.equal(formatTokenCount(1234567), '1,234,567');
});

test('billing amount presentation distinguishes zero price and non-settled states', () => {
	assert.equal(billingAmountPresentation('settled', 0, 'CNY'), '¥0.00');
	assert.equal(billingAmountPresentation('settled', 1250000, 'CNY'), '¥1.25');
	assert.equal(billingAmountPresentation('settled', null, ''), '—');
	assert.equal(billingAmountPresentation('reserved', null, ''), '待结算');
	assert.equal(billingAmountPresentation('released', null, ''), '未扣费');
	assert.equal(billingAmountPresentation('exception', null, ''), '计费异常');
	assert.equal(billingAmountPresentation('not_billed', null, ''), '无计费账单');
});


test('postpaid states show pricing status without pretending a charge was settled', () => {
  assert.equal(billingAmountPresentation('unpriced', null, ''), '未定价');
  assert.equal(billingAmountPresentation('failed', null, ''), '计费失败');
});
