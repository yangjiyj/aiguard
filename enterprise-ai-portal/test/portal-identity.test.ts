import test from 'node:test';
import assert from 'node:assert/strict';

import {
  extractStableIdentityClaims,
  mapPortalIdentityClaims,
  mapVerifiedOidcProfile,
  PORTAL_EMPLOYEE_ROLE,
} from '../src/lib/portal-identity.js';

test('extractStableIdentityClaims: 已验证 OIDC token 提供完整字段时返回稳定身份', () => {
  const claims = extractStableIdentityClaims(
    { issuer: 'https://sso.corp.test', providerAccountId: 'pa-123' },
    {
      sub: 'oidc-sub-42',
      preferred_username: 'alice@corp.test',
      email: 'alice@corp.test',
      department: 'SEC-E2E',
      groups: ['staff', 'engineering', 'staff'],
    },
  );
  assert.deepEqual(claims, {
    issuer: 'https://sso.corp.test',
    subject: 'oidc-sub-42',
    username: 'alice@corp.test',
    email: 'alice@corp.test',
    groups: ['staff', 'engineering'],
    departments: ['SEC-E2E'],
  });
});

test('extractStableIdentityClaims: preferred_username 缺失时回退 sub 作为 username', () => {
  const claims = extractStableIdentityClaims(
    { issuer: 'https://sso.corp.test' },
    { sub: 'oidc-sub-99', email: 'bob@corp.test' },
  );
  assert.equal(claims?.username, 'oidc-sub-99');
  assert.equal(claims?.subject, 'oidc-sub-99');
});

test('extractStableIdentityClaims: issuer 缺失返回 null（不让门户拿到无签发者的身份）', () => {
  const claims = extractStableIdentityClaims(
    { providerAccountId: 'pa' },
    { sub: 's', preferred_username: 'u' },
  );
  assert.equal(claims, null);
});

test('extractStableIdentityClaims: subject 缺失返回 null（稳定键缺一不可）', () => {
  const claims = extractStableIdentityClaims(
    { issuer: 'https://sso.corp.test' },
    { preferred_username: 'u' },
  );
  assert.equal(claims, null);
});

test('extractStableIdentityClaims: account 或 profile 为空返回 null', () => {
  assert.equal(extractStableIdentityClaims(null, { sub: 's' }), null);
  assert.equal(extractStableIdentityClaims({ issuer: 'i' }, null), null);
});

test('extractStableIdentityClaims: groups 非数组/含非字符串项被过滤', () => {
  const claims = extractStableIdentityClaims(
    { issuer: 'https://sso.corp.test' },
    {
      sub: 's',
      preferred_username: 'u',
      groups: ['valid', 123, null, '  ', 'valid', { x: 1 }] as unknown as string[],
    },
  );
  assert.deepEqual(claims?.groups, ['valid']);
});

test('extractStableIdentityClaims: 不信任 profile.issuer，只用 account.issuer（已验证签发者）', () => {
  // profile 自报的 issuer 是浏览器可伪造字段，绝不可作为身份依据。
  const claims = extractStableIdentityClaims(
    { issuer: 'https://verified.sso.corp.test' },
    {
      sub: 's',
      preferred_username: 'u',
      // 故意塞入伪造 issuer，应被忽略
      ...(({ issuer: 'https://attacker.example' } as Record<string, unknown>)),
    } as { sub?: unknown; preferred_username?: unknown; issuer?: unknown },
  );
  assert.equal(claims?.issuer, 'https://verified.sso.corp.test');
});

test('mapPortalIdentityClaims: 保留兼容路径，department 经规整后映射', () => {
  const mapped = mapPortalIdentityClaims({ department: '  研发部  ' });
  assert.equal(mapped.department, '研发部');
  assert.equal(mapped.role, PORTAL_EMPLOYEE_ROLE);
});

test('mapPortalIdentityClaims: 部门含控制字符被丢弃', () => {
  const malicious = 'sales' + String.fromCharCode(0x0a) + 'inject';
  const mapped = mapPortalIdentityClaims({ department: malicious });
  assert.equal(mapped.department, null);
});

test('mapVerifiedOidcProfile: preserves only bounded identity claims for Auth.js callbacks', () => {
  const mapped = mapVerifiedOidcProfile({
    sub: ' stable-sub ',
    preferred_username: ' alice ',
    email: ' alice@example.test ',
    name: ' Alice ',
    groups: ['dept-research', 'dept-research', 7, '  '] as unknown[],
    department: ' research ',
    token: 'must-not-survive',
  });
  assert.deepEqual(mapped, {
    id: 'stable-sub',
    sub: 'stable-sub',
    preferred_username: 'alice',
    email: 'alice@example.test',
    name: 'Alice',
    groups: ['dept-research'],
    department: 'research',
    departments: ['research'],
  });
  assert.equal('token' in mapped, false);
});

test('mapVerifiedOidcProfile: drops overlong and control-character group values', () => {
  const mapped = mapVerifiedOidcProfile({
    sub: 's',
    groups: ['ok', 'x'.repeat(2049), 'bad\nvalue'],
  });
  assert.deepEqual(mapped.groups, ['ok']);
});
