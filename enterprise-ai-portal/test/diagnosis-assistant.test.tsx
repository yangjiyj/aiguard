import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { DiagnosisFinding } from '../src/lib/diagnosis';

const finding = (over: Record<string, unknown> = {}): DiagnosisFinding => ({
  check_id: 'up_param', severity: 'error', level: 'confirmed', title: '上游拒绝了参数',
  impact: '请求被模型服务拒绝', advice: [{ text: '去掉多余参数后重试' }], excluded: ['网络', '额度'],
  evidence: [{ kind: 'request', ref: 'req_abc', summary: '返回 400' }], ...over,
} as DiagnosisFinding);

test('结论卡片：确定/疑似/无法判断、影响、建议、已排除、排查过程与证据', async () => {
  Object.assign(globalThis, { React });
  const { DiagnosisReportCard } = await import('../src/components/diagnosis-assistant.js');
  const html = renderToStaticMarkup(React.createElement(DiagnosisReportCard, {
    report: {
      tier: 'L2', ok_count: 3,
      findings: [finding(), finding({ check_id: 'b', level: 'suspected', title: '疑似限流' }), finding({ check_id: 'c', level: 'unknown', title: '原因不明' }), finding({ check_id: 'ok', severity: 'ok', title: '一切正常项' })],
      steps: [{ summary: '查了这条请求' }],
    },
  }));
  for (const text of ['确定', '疑似', '无法判断', '上游拒绝了参数', '请求被模型服务拒绝', '去掉多余参数后重试', '已排除：网络，额度', '另有 3 项正常', '排查过程', '查了这条请求', '证据', 'req_abc']) {
    assert.ok(html.includes(text), text);
  }
  assert.ok(!html.includes('一切正常项'), '正常项不展开');
  assert.ok(!html.includes('导出'), '员工端没有导出');
  assert.ok(!html.includes('<a '), '格式不合法的编号只显示文本，不做跳转');
});

test('助手入口：右上角机器人按钮，没有设置与导出', async () => {
  Object.assign(globalThis, { React });
  const { DiagnosisAssistant } = await import('../src/components/diagnosis-assistant.js');
  const html = renderToStaticMarkup(React.createElement(DiagnosisAssistant));
  assert.ok(html.includes('aria-label="诊断助手"'));
  assert.ok(!html.includes('设置'));
});

test('摘要标签：问题文本优先，体检与时间兜底', async () => {
  const { summaryLabel, visibleFindings } = await import('../src/lib/diagnosis.js');
  assert.equal(summaryLabel({ id: '1', status: 'done', input: { kind: 'question', text: ' 为什么慢 ' } }), '为什么慢');
  assert.equal(summaryLabel({ id: '2', status: 'done', input: { kind: 'health', text: '' } }), '一键体检');
  assert.equal(summaryLabel({ id: '3', status: 'done' }), '诊断记录');
  assert.equal(visibleFindings({ findings: [finding(), finding({ severity: 'ok' })] }).length, 1);
});

test('请求编号证据是门户内链接，带 basePath，非法编号只显示文本', async () => {
  Object.assign(globalThis, { React });
  const { DiagnosisReportCard } = await import('../src/components/diagnosis-assistant.js');
  const id = 'req_0123abcd-0123-abcd-0123-0123abcd4567';
  const html = renderToStaticMarkup(React.createElement(DiagnosisReportCard, {
    report: { findings: [finding({ evidence: [
      { kind: 'request', ref: id, summary: '返回 400' },
      { kind: 'request', ref: 'req_abc', summary: '无效编号' },
    ] })] },
  }));
  assert.ok(html.includes('href="/chat/records?request_id=' + id + '"'));
  assert.ok(!html.includes('request_id=req_abc'));
});
