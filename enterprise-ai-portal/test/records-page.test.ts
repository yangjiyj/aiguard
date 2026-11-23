import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = (path: string) => readFile(new URL(path, import.meta.url), 'utf8');

test('records page defaults to per-call token records with an overview-only expansion', async () => {
  const page = await source('../src/app/records/page.tsx');

	assert.match(page, /\/api\/me\/call-records/);
	assert.match(page, /callCursor/);
	assert.match(page, /nextCursor/);
	assert.doesNotMatch(page, /\/api\/me\/call-records\?limit=[\s\S]{0,180}&offset=/);
  assert.match(page, /调用留痕/);
  assert.match(page, /文件留痕/);
  assert.match(page, /输入 Token/);
  assert.match(page, /输出 Token/);
  assert.match(page, /总 Token/);
	assert.match(page, /消耗金额/);
	assert.match(page, /billingAmountPresentation/);
  assert.match(page, /展开调用概览/);


  assert.match(page, /ChevronDown/);
  assert.match(page, /hidden min-h-16[^\"]*lg:grid/);
  assert.match(page, /px-4 py-3 lg:hidden/);
  assert.match(page, /调用留痕暂时不可用/);
  assert.match(page, /文件留痕暂时不可用/);
  assert.doesNotMatch(page, /问答全文|提示词|回答正文|原始审计 JSON/);
});

test('sidebar describes token and file records without claiming content retention', async () => {
  const nav = await source('../src/components/portal-nav.tsx');
  assert.match(nav, /调用记录/);
  assert.doesNotMatch(nav, /查看调用记录与内容留存/);
});


test('调用记录桌面与移动布局均展示缓存，详情保留读写明细与输入口径', async () => {
  const page = await source('../src/app/records/page.tsx');
  assert.match(page, /缓存读取 Token/);
  assert.match(page, /缓存写入 Token/);
  assert.match(page, /输入 Token 已包含缓存读取与写入/);
  const desktop = page.slice(page.indexOf('hidden min-h-16'), page.indexOf('px-4 py-3 lg:hidden'));
  const mobile = page.slice(page.indexOf('px-4 py-3 lg:hidden'), page.indexOf('{expanded &&'));
  for (const layout of [desktop, mobile]) {
    assert.match(layout, /record.cachedInputTokens/);
    assert.match(layout, /"—"/);
  }
});

test('缓存数值真实渲染：桌面、移动端与展开详情；零缓存显示破折号', async () => {
  const React = await import('react');
  const { renderToStaticMarkup } = await import('react-dom/server');
  const ts = await import('typescript');
  const helpers = await import('../src/lib/call-records.js');
  const { cn } = await import('../src/lib/utils.js');
  const { ChevronDown } = await import('lucide-react');
  const page = await source('../src/app/records/page.tsx');
  // 直接编译页面私有行组件，避免为测试增加 Next 页面不支持的命名导出。
  const tpsHelpers = page.slice(page.indexOf('function outputTps('), page.indexOf('function StatusBadge('));
  const component = tpsHelpers + page.slice(page.indexOf('function CallRecordRows('), page.indexOf('function FileRecordRows('));
  const compiled = ts.transpileModule(component, {
    compilerOptions: { jsx: ts.JsxEmit.React, module: ts.ModuleKind.None },
  }).outputText;
  const dependencies = { React, ...helpers, cn, ChevronDown, StatusBadge: () => null, formatDate: (value: string) => value, formatLatency: (value: number) => `${value} ms` };
  const Rows = new Function(...Object.keys(dependencies), `${compiled}; return CallRecordRows;`)(...Object.values(dependencies));
  const record = {
    requestId: 'req-cache', createdAt: '2026-10-22T00:00:00Z', model: 'Claude', status: 'success', upstreamStatus: 200,
    inputTokens: 90364, cachedInputTokens: 90086, cacheWriteInputTokens: 118, outputTokens: 4, totalTokens: 90368,
    latencyMs: 100, agentType: 'claude-code', endpointType: 'messages', inputAction: '', outputAction: '', securityEventCount: 0,
    billingAmountMicros: null, billingCurrency: '', billingState: 'unpriced',
  };
  const render = (row: typeof record, expanded: boolean) => renderToStaticMarkup(React.createElement(Rows, {
    records: [row], expandedRequestId: expanded ? row.requestId : null, onToggle: () => {},
  }));
  const collapsed = render(record, false);
  assert.equal(collapsed.split(helpers.formatTokenCount(90086)).length - 1, 2);
  assert.equal(collapsed.split('输入 Token 已包含缓存读取与写入').length - 1, 2);
  assert.ok(!collapsed.includes('缓存写入 Token'));
  const expanded = render(record, true);
  assert.match(expanded, /缓存读取 Token<\/dt><dd[^>]*>90,086<\/dd>/);
  assert.match(expanded, /缓存写入 Token<\/dt><dd[^>]*>118<\/dd>/);
  assert.equal(collapsed.split(helpers.formatTokenCount(90368)).length - 1, 2);
  const zero = render({ ...record, cachedInputTokens: 0, cacheWriteInputTokens: 0 }, true);
  assert.equal(zero.split('>—<').length - 1, 2);
  assert.match(zero, /缓存写入 Token<\/dt><dd[^>]*>0<\/dd>/);
});


test('个人记录仅展示总耗时与全时间范围汇总，不呈现分段原因', async () => {
  const page = await source('../src/app/records/page.tsx');
  assert.match(page, /平均总耗时/);
  assert.match(page, /成功率/);
  assert.match(page, /请求数/);
  assert.match(page, /总耗时/);
  assert.match(page, /setCallSummary/);
  assert.doesNotMatch(page, /上游|网关|安全检测|延迟/);
});

test('调用记录页读取 request_id 并交给接口筛选、展开该条', async () => {
  const page = await source('../src/app/records/page.tsx');
  assert.match(page, /useSearchParams/);
  assert.match(page, /searchParams\.get\("request_id"\)/);
  assert.match(page, /params\.set\("request_id", focusRequestId\)/);
  assert.match(page, /useState<string \| null>\(focusRequestId \|\| null\)/);
  assert.match(page, /React\.Suspense/);
});
