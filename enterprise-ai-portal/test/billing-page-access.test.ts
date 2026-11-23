import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
let session: { user: { id: string } } | null = { user: { id: 'employee' } };
mock.module('@/auth', { namedExports: { auth: async () => session } });
mock.module('next/navigation', { namedExports: { redirect: (path: string) => { throw new Error('redirect:' + path); } } });
function Billing() { return null; }
mock.module('@/components/billing-page', { defaultExport: Billing });
// tsx uses the classic JSX transform while Next uses its own automatic transform.
Object.assign(globalThis, { React });

test('all signed-in employees can open customer center regardless of prepaid build flag', async () => {
  const { default: Page } = await import('../src/app/billing/page.js');
  for (const flag of ['false', 'true', undefined]) {
    if (flag === undefined) delete process.env.NEXT_PUBLIC_BILLING_ENABLED;
    else process.env.NEXT_PUBLIC_BILLING_ENABLED = flag;
    session = { user: { id: 'employee' } };
    const result = await Page();
    assert.equal(result.props.active, 'billing');
    assert.equal(result.props.children.type, Billing);
  }
});
test('customer center still requires a signed-in employee', async () => {
  const { default: Page } = await import('../src/app/billing/page.js');
  session = null;
  await assert.rejects(Page, /redirect:\/login/);
});

test('API 密钥独立成页，复用计费数据组件的 keys 视图', async () => {
  const { default: Page } = await import('../src/app/keys/page.js');
  session = { user: { id: 'employee' } };
  const result = await Page();
  assert.equal(result.props.active, 'keys');
  assert.equal(result.props.children.type, Billing);
  assert.equal(result.props.children.props.view, 'keys');
  session = null;
  await assert.rejects(Page, /redirect:\/login/);
});
