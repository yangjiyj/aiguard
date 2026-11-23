import test, { mock } from 'node:test';
import assert from 'node:assert/strict';

// mock 必须在 user-service.ts 首次加载前注册（否则 prisma 已被解析为真实客户端）。
// 用动态 import 在 mock 注册后再加载 user-service；测试模块缓存命中后 export 复用。
// 单一 mock 实例 + 共享 calls 容器，多个场景按 baseline 切片断言。
type CallRecord = {
  where: { id: string };
  create: Record<string, unknown>;
  update: Record<string, unknown>;
};

const calls: CallRecord[] = [];

mock.module('@/lib/prisma', {
  namedExports: {
    prisma: {
      userProfile: {
        upsert: async (args: CallRecord) => {
          calls.push(args);
          return { ...args.create, ...args.update };
        },
      },
    },
  },
});

test('applyControlPlaneResolution：控制面 ID 用于授权，门户档案保留可读部门声明', async () => {
  const { applyControlPlaneResolution } = await import('../src/lib/user-service.js');
  const baseline = calls.length;

  const result = await applyControlPlaneResolution(
    'oidc-sub-ignored',
    'alice@corp.test',
    'Alice',
    '研发部',
    {
      userId: 'user_cp_a1',
      departmentId: 'dept_research',
      departmentVersion: 1,
      chatAllowed: true,
      resolution: 'automatic',
      created: true,
    },
  );

  assert.equal(calls.length - baseline, 1);
  const call = calls[calls.length - 1]!;
  assert.equal(call.where.id, 'user_cp_a1', '主键必须是控制面 user_id，不能是 OIDC sub');
  assert.equal(call.create.id, 'user_cp_a1');
  assert.equal(call.create.department, '研发部', '门户部门字段不能暴露控制面内部 ID');
  assert.equal(call.create.role, 'employee');
  assert.equal(call.update.department, '研发部');

  assert.deepEqual(result, {
    userId: 'user_cp_a1',
    email: 'alice@corp.test',
    name: 'Alice',
    departmentId: 'dept_research',
    chatAllowed: true,
  });
});

test('applyControlPlaneResolution：应急管理 chat_allowed=false 仍写档案（调用方据此拒绝登录）', async () => {
  const { applyControlPlaneResolution } = await import('../src/lib/user-service.js');
  const baseline = calls.length;

  const result = await applyControlPlaneResolution('sub', 'em@corp.test', null, null, {
    userId: 'user_cp_em',
    departmentId: 'dept_unassigned',
    departmentVersion: 1,
    chatAllowed: false,
    resolution: 'emergency',
    created: false,
  });

  assert.equal(calls.length - baseline, 1);
  assert.equal(result.chatAllowed, false, 'chatAllowed 必须透传，让调用方拒绝 Chat 登录');
  assert.equal(result.userId, 'user_cp_em');
  assert.equal(result.departmentId, 'dept_unassigned');
});
