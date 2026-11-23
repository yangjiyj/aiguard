import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';

import { checkInternalToken } from '../src/auth.js';
import { decryptKey, encryptKey } from '../src/crypto.js';
import { evaluateGroup } from '../src/evaluate.js';
import {
  __resetChatPortalFlagCache,
  getChatPortalEnabled,
} from '../src/gateway-flags.js';
import {
  extractLobeUserId,
  MappingError,
  stripUser,
} from '../src/mapping.js';
import { fromAlias, toAlias } from '../src/model-alias.js';
import { JitProvisioner } from '../src/jit.js';
import { PROXY_PATHS, resolveProxyPath } from '../src/proxy.js';
import { EmployeeKeyDecryptionError, KeyStore } from '../src/store.js';
import {
  canAccessAdmin,
  canAccessDept,
  departmentsToProjectIds,
  resolveManagerDepartments,
  resolveRole,
} from '../src/roles.js';

test('内部 Token 使用 SHA-256 等长摘要做常量时间校验', () => {
  assert.equal(checkInternalToken('Bearer portal-test-token', 'portal-test-token'), true);
  assert.equal(checkInternalToken('Bearer x', 'portal-test-token'), false);
  assert.equal(checkInternalToken('Basic portal-test-token', 'portal-test-token'), false);
  assert.equal(checkInternalToken(undefined, 'portal-test-token'), false);
  assert.equal(checkInternalToken('Bearer portal-test-token', ''), false);

  const source = readFileSync(new URL('../src/auth.ts', import.meta.url), 'utf8');
  assert.match(source, /createHash\('sha256'\)/);
  assert.match(source, /timingSafeEqual\(presented, expected\)/);
  assert.doesNotMatch(source, /match\[1\]\s*===\s*expectedToken/);
});

test('员工 Key 使用 AES-256-GCM 加解密并拒绝篡改密文', () => {
  const secret = 'synthetic-secret-for-recovery-tests';
  const plaintext = 'synthetic-employee-key';
  const encrypted = encryptKey(plaintext, secret);

  assert.notEqual(encrypted, plaintext);
  assert.equal(encrypted.split(':').length, 3);
  assert.equal(decryptKey(encrypted, secret), plaintext);

  const parts = encrypted.split(':');
  const ciphertext = Buffer.from(parts[2], 'base64');
  ciphertext[0] ^= 1;
  const tampered = `${parts[0]}:${parts[1]}:${ciphertext.toString('base64')}`;
  assert.throws(() => decryptKey(tampered, secret));
  assert.throws(() => decryptKey(encrypted, 'different-synthetic-secret'));
});

test('员工 Key 加密密钥漂移时返回可恢复错误且不泄露密文', async () => {
  const keyEnc = encryptKey('synthetic-old-key', 'synthetic-old-encryption-secret');
  const prisma = {
    employeeKey: {
      findUnique: async () => ({
        status: 'active',
        keyEnc,
        email: 'employee@example.test',
        ssoSubject: 'employee-subject',
        gatewayKeyId: 'gateway-key-old',
        keyPrefix: 'jjd_old',
        mappedGroup: 'default',
        gatewayProjectId: 'project-default',
        lastDepartment: null,
        lastEvaluatedAt: new Date('2026-08-29T00:00:00Z'),
        gatewayUserId: 'employee-1',
        scopeVersion: 2,
      }),
    },
  };
  const store = new KeyStore(prisma, 'synthetic-new-encryption-secret', 'tenant-test');

  await assert.rejects(
    () => store.findActive('employee-subject'),
    (error: unknown) => {
      assert.ok(error instanceof EmployeeKeyDecryptionError);
      assert.equal(error.gatewayKeyId, 'gateway-key-old');
      assert.equal(error.lobeUserId, 'employee-subject');
      assert.doesNotMatch(error.message, /synthetic-old-key|synthetic-old-encryption-secret|synthetic-new-encryption-secret|keyEnc/);
      return true;
    },
  );
});

test('模型列表在登录后自动创建或重签员工 Key', () => {
  const source = readFileSync(new URL('../src/server.ts', import.meta.url), 'utf8');
  const modelsRoute = source.slice(source.indexOf("url.pathname === '/v1/models'"));
  const routeBlock = modelsRoute.slice(0, modelsRoute.indexOf('// 代理面路由'));
  assert.match(routeBlock, /runWithIdentity\(direct/);
  assert.match(routeBlock, /settleEmployeeKey\(traceId, direct\.ssoSubject\)/);
  assert.match(source, /EmployeeKeyDecryptionError/);
  assert.match(source, /employee_key_reissued/);
  assert.match(source, /recoverEncryption/);
  assert.match(source, /employee_key_user_rebound/);
});

test('加密恢复与账号补绑都保留可信的网关 user_id', async () => {
  const created: Array<Record<string, unknown>> = [];
  const saved: Array<Record<string, unknown>> = [];
  const revoked: string[] = [];
  const jit = new JitProvisioner({
    getStoredKey: async () => ({
      gatewayKeyId: 'gateway-key-old',
      gatewayProjectId: 'project-default',
      email: 'employee@example.test',
      ssoSubject: 'employee-subject',
      gatewayUserId: 'user-old',
      scopeVersion: 2,
      mappedGroup: 'default',
      lastDepartment: 'department-1',
    }),
    createGatewayKey: async (input: Record<string, unknown>) => {
      created.push(input);
      return { id: `gateway-key-${created.length}`, keyPrefix: `jjd_${created.length}`, fullKey: `secret-${created.length}` };
    },
    saveEmployeeKey: async (input: Record<string, unknown>) => { saved.push(input); },
    revokeGatewayKey: async (keyId: string) => { revoked.push(keyId); },
  }, 90, 'project-default', 2);

  assert.deepEqual(await jit.recoverEncryption('employee-subject'), { resigned: true });
  assert.equal(created[0]?.userId, 'user-old');
  assert.equal(saved[0]?.gatewayUserId, 'user-old');

  assert.deepEqual(await jit.bindGatewayUser('employee-subject', 'user-authorized'), { resigned: true });
  assert.equal(created[1]?.userId, 'user-authorized');
  assert.equal(saved[1]?.gatewayUserId, 'user-authorized');
  assert.deepEqual(revoked, ['gateway-key-old', 'gateway-key-old']);
});

test('用户归因兼容 body.user 与 Responses safety_identifier', () => {
  assert.equal(extractLobeUserId({ user: 'user-chat' }), 'user-chat');
  assert.equal(
    extractLobeUserId({ safety_identifier: 'user-responses' }),
    'user-responses',
  );
  assert.equal(
    extractLobeUserId({ user: 'trusted-user', safety_identifier: 'fallback-user' }),
    'trusted-user',
  );
  assert.throws(
    () => extractLobeUserId({ model: 'gpt-5.5' }),
    (error: unknown) => error instanceof MappingError && error.code === 'user_missing',
  );
  assert.deepEqual(
    stripUser({ user: 'internal-only', safety_identifier: 'user-responses', model: 'gpt-5.5' }),
    { safety_identifier: 'user-responses', model: 'gpt-5.5' },
  );
});

test('模型别名可双向转换且不改动普通模型', () => {
  assert.equal(toAlias('gpt-5.5'), 'gpt5.5');
  assert.equal(fromAlias('gpt5.5'), 'gpt-5.5');
  assert.equal(fromAlias(toAlias('gpt-4.1-mini')), 'gpt-4.1-mini');
  assert.equal(toAlias('glm-5.2'), 'glm-5.2');
  assert.equal(fromAlias('glm-5.2'), 'glm-5.2');
});

test('代理只允许三个 POST 数据面端点', () => {
  assert.deepEqual(PROXY_PATHS, [
    '/v1/chat/completions',
    '/v1/responses',
    '/v1/embeddings',
  ]);
  for (const path of PROXY_PATHS) {
    assert.equal(resolveProxyPath('POST', path), path);
    assert.equal(resolveProxyPath('GET', path), null);
  }
  assert.equal(resolveProxyPath('POST', '/v1/models'), null);
  assert.equal(resolveProxyPath('POST', '/admin/v1/users'), null);
});

test('部门映射按优先级命中，未映射部门回落默认项目', () => {
  const rules = [
    {
      enabled: true,
      matchType: 'department',
      matchValue: 'security',
      mappedGroup: 'security-late',
      gatewayProjectId: 'project-z',
      priority: 20,
    },
    {
      enabled: true,
      matchType: 'department',
      matchValue: 'security',
      mappedGroup: 'security',
      gatewayProjectId: 'project-a',
      priority: 10,
    },
  ];

  assert.deepEqual(evaluateGroup('security', rules, 'project-default'), {
    mappedGroup: 'security',
    gatewayProjectId: 'project-a',
  });
  assert.deepEqual(evaluateGroup('unknown', rules, 'project-default'), {
    mappedGroup: 'default',
    gatewayProjectId: 'project-default',
  });
});

test('角色与部门作用域只收窄，不把无部门主管放大为全租户', () => {
  const rules = [
    {
      enabled: true,
      matchType: 'department',
      matchValue: 'security',
      mappedGroup: 'security',
      gatewayProjectId: 'project-security',
      priority: 10,
    },
    {
      enabled: true,
      matchType: 'department',
      matchValue: 'finance',
      mappedGroup: 'finance',
      gatewayProjectId: 'project-finance',
      priority: 10,
    },
  ];

  // W9 9.6：角色只认 EmployeeRole 表（不再有 claim 覆盖参数）；无记录/非法 → employee。
  assert.equal(resolveRole('admin'), 'admin');
  assert.equal(resolveRole(null), 'employee');
  assert.equal(resolveRole('root'), 'employee');
  assert.deepEqual(resolveManagerDepartments(null, []), []);
  assert.deepEqual(resolveManagerDepartments('security', []), ['security']);
  assert.deepEqual(
    resolveManagerDepartments('ignored', [' finance ', 'security', 'finance']),
    ['finance', 'security'],
  );
  assert.deepEqual(
    departmentsToProjectIds(['security', 'unknown', 'finance', 'security'], rules),
    ['project-finance', 'project-security'],
  );
  assert.equal(canAccessAdmin({ role: 'manager' }), false);
  assert.equal(canAccessDept({ role: 'admin' }), false);
});

test('chat_portal_enabled 控制面不可达时 fail closed', async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
    __resetChatPortalFlagCache();
  });

  globalThis.fetch = (async () => {
    throw new Error('synthetic control-plane outage');
  }) as typeof fetch;
  __resetChatPortalFlagCache();

  const enabled = await getChatPortalEnabled({
    gatewayCpUrl: 'http://control-plane.invalid',
    portalApiSecret: 'synthetic-internal-token',
    tenantId: 'tenant-test',
  });
  assert.equal(enabled, false);
});
