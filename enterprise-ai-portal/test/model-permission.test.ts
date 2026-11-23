import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';

import { verifyCurrentDepartment } from '../src/lib/model-service.js';
import type { StableIdentityClaims } from '../src/lib/control-plane.js';

const identity: StableIdentityClaims = {
  issuer: 'https://idp.example',
  subject: 'sub-1',
  username: 'alice',
  email: 'alice@example.com',
  groups: [],
};

interface Cfg {
  departmentId: string;
  departmentVersion: number;
  chatAllowed: boolean;
}

async function withServer(cfg: Cfg, fn: (baseUrl: string) => Promise<void>) {
  const server = createServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify({
        user_id: 'user_cp_1',
        department_id: cfg.departmentId,
        chat_allowed: cfg.chatAllowed,
        resolution: 'manual',
        created: false,
        department_version: cfg.departmentVersion,
      }),
    );
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const addr = server.address();
  assert.ok(addr && typeof addr === 'object');
  const baseUrl = `http://127.0.0.1:${addr.port}`;
  try {
    await fn(baseUrl);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

// 场景1+2+3：用户在 A，迁移到 B 后下次请求立即看不到 A（stale=true，需刷新）。
test('verifyCurrentDepartment: 部门迁移 A→B 后会话基线立即过期', async () => {
  // 登录时基线是 A，version=t0
  const baseline = {
    userId: 'user_cp_1',
    departmentId: 'dept_A',
    departmentVersion: 1000,
    chatAllowed: true,
  };

  // 控制面现在返回 B（已迁移），version=t1
  await withServer(
    { departmentId: 'dept_B', departmentVersion: 2000, chatAllowed: true },
    async (baseUrl) => {
      const result = await verifyCurrentDepartment(baseline, identity, {
        gateway: {
          baseUrl,
          portalSecret: 'secret',
          chatPortalEnabled: true,
        } as never,
      });
      assert.equal(result.ok, false, '部门变化后 ok 必须为 false');
      assert.equal(result.stale, true, 'stale 必须为 true（调用方需刷新）');
      assert.equal(result.denied, false);
      assert.equal(result.latest?.departmentId, 'dept_B');
      assert.equal(result.latest?.departmentVersion, 2000);
    },
  );
});

// 场景3 续：版本变化但 departmentId 相同（回迁或触发器刷新），仍判 stale。
test('verifyCurrentDepartment: departmentVersion 变化即判 stale（防回迁绕过）', async () => {
  const baseline = {
    userId: 'user_cp_1',
    departmentId: 'dept_A',
    departmentVersion: 1000,
    chatAllowed: true,
  };
  await withServer(
    { departmentId: 'dept_A', departmentVersion: 2000, chatAllowed: true },
    async (baseUrl) => {
      const result = await verifyCurrentDepartment(baseline, identity, {
        gateway: {
          baseUrl,
          portalSecret: 'secret',
          chatPortalEnabled: true,
        } as never,
      });
      assert.equal(result.stale, true, 'version 变化必须判 stale');
      assert.equal(result.ok, false);
    },
  );
});

// 场景1 续：部门未变，ok=true，可继续敏感操作。
test('verifyCurrentDepartment: 部门未变时 ok=true', async () => {
  const baseline = {
    userId: 'user_cp_1',
    departmentId: 'dept_A',
    departmentVersion: 1000,
    chatAllowed: true,
  };
  await withServer(
    { departmentId: 'dept_A', departmentVersion: 1000, chatAllowed: true },
    async (baseUrl) => {
      const result = await verifyCurrentDepartment(baseline, identity, {
        gateway: {
          baseUrl,
          portalSecret: 'secret',
          chatPortalEnabled: true,
        } as never,
      });
      assert.equal(result.ok, true);
      assert.equal(result.stale, false);
      assert.equal(result.denied, false);
    },
  );
});

// 场景4：删除 B 映射后用户进未分配部门（departmentId 变化），stale=true。
test('verifyCurrentDepartment: 迁到未分配部门后 stale', async () => {
  const baseline = {
    userId: 'user_cp_1',
    departmentId: 'dept_B',
    departmentVersion: 2000,
    chatAllowed: true,
  };
  await withServer(
    { departmentId: 'team_unassigned_xxx', departmentVersion: 3000, chatAllowed: true },
    async (baseUrl) => {
      const result = await verifyCurrentDepartment(baseline, identity, {
        gateway: {
          baseUrl,
          portalSecret: 'secret',
          chatPortalEnabled: true,
        } as never,
      });
      assert.equal(result.stale, true);
      assert.equal(result.latest?.departmentId, 'team_unassigned_xxx');
    },
  );
});

// 场景6：应急管理员（chat_allowed=false）模型列表必须为空——denied=true。
// 含两种情形：基线已是应急，或控制面最新解析为应急。
test('verifyCurrentDepartment: 应急管理员 denied（模型列表为空）', async () => {
  // 基线应急
  const emergencyBaseline = {
    userId: 'user_emerg',
    departmentId: 'dept_root',
    departmentVersion: 1000,
    chatAllowed: false,
  };
  const result1 = await verifyCurrentDepartment(emergencyBaseline, identity, {
    gateway: { baseUrl: 'http://127.0.0.1:1', portalSecret: 's', chatPortalEnabled: true } as never,
  });
  assert.equal(result1.denied, true, '基线应急必须 denied');
  assert.equal(result1.ok, false);

  // 控制面新解析为应急（管理员刚把用户设为 emergency）
  const baseline2 = {
    userId: 'user_emerg',
    departmentId: 'dept_root',
    departmentVersion: 1000,
    chatAllowed: true,
  };
  await withServer(
    { departmentId: 'dept_root', departmentVersion: 2000, chatAllowed: false },
    async (baseUrl) => {
      const result2 = await verifyCurrentDepartment(baseline2, identity, {
        gateway: {
          baseUrl,
          portalSecret: 'secret',
          chatPortalEnabled: true,
        } as never,
      });
      assert.equal(result2.denied, true, '控制面返应急必须 denied');
      assert.equal(result2.ok, false);
      assert.equal(result2.stale, false, '应急优先于 stale 判定');
    },
  );
});

// 场景5 间接覆盖：旧 team_members 残留不影响——本服务只认控制面的 department_id
// （单一事实源），不读 team_members。这里通过"控制面返回的 departmentId 是唯一依据"
// 来表达：即便浏览器侧有任何旧缓存，verifyCurrentDepartment 永远以控制面为准。

// fail-closed：控制面不可达时不放过敏感操作。
test('verifyCurrentDepartment: 控制面不可达时 fail-closed', async () => {
  const baseline = {
    userId: 'user_cp_1',
    departmentId: 'dept_A',
    departmentVersion: 1000,
    chatAllowed: true,
  };
  const result = await verifyCurrentDepartment(baseline, identity, {
    gateway: { baseUrl: 'http://127.0.0.1:1', portalSecret: 's', chatPortalEnabled: true } as never,
  });
  assert.equal(result.ok, false);
  assert.equal(result.stale, false);
  assert.equal(result.denied, false);
  assert.ok(result.errorCode, '必须有 errorCode');
});
