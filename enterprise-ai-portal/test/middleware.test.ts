import test from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';

import { middleware } from '../src/middleware.js';

test('protected browser redirect keeps a relative deep-link callback', () => {
  const request = new NextRequest('http://0.0.0.0:3100/chat/records?tab=audit');
  const response = middleware(request);
  assert.equal(response.status, 307);

  const location = response.headers.get('location');
  assert.ok(location);
  const redirect = new URL(location);
  // Middleware redirects must carry the externally mounted base path itself.
  assert.equal(redirect.pathname, '/chat/login');
  assert.equal(redirect.searchParams.get('callbackUrl'), '/chat/records?tab=audit');
  assert.equal(redirect.searchParams.get('callbackUrl')?.includes('0.0.0.0'), false);
});

test('API requests still fail closed without a session', async () => {
  const request = new NextRequest('http://0.0.0.0:3100/chat/api/records');
  const response = middleware(request);
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: 'unauthorized' });
});

test('a protected request with a session cookie passes through', () => {
  const request = new NextRequest('http://0.0.0.0:3100/chat/records', {
    headers: { cookie: 'authjs.session-token=test-session' },
  });
  assert.equal(middleware(request).status, 200);
});

test('public path lookalikes remain protected', () => {
  const request = new NextRequest('http://0.0.0.0:3100/chat/login-backup');
  const response = middleware(request);
  assert.equal(response.status, 307);
  assert.equal(new URL(response.headers.get('location')!).pathname, '/chat/login');
});

test('portal root redirect explicitly preserves the external base path', () => {
  const request = new NextRequest('http://0.0.0.0:3100/chat');
  const response = middleware(request);
  const redirect = new URL(response.headers.get('location')!);

  assert.equal(response.status, 307);
  assert.equal(redirect.pathname, '/chat/login');
  assert.equal(redirect.searchParams.get('callbackUrl'), '/chat');
});

for (const cookieName of ['authjs.session-token.0', 'authjs.session-token.1', '__Secure-authjs.session-token.0', '__Secure-authjs.session-token.1']) {
 test(`chunked session cookie ${cookieName} reaches authoritative server authorization`, () => {
  const request = new NextRequest('http://portal.test/chat', {headers: {cookie: `${cookieName}=chunk`}});
  assert.equal(middleware(request).status, 200);
 });
}
test('cookie name lookalikes and empty chunks do not bypass the login redirect', () => {
 for (const cookie of ['authjs.session-token.backup=chunk', 'authjs.session-token.0=']) {
  assert.equal(middleware(new NextRequest('http://portal.test/chat', {headers: {cookie}})).status, 307);
 }
});
