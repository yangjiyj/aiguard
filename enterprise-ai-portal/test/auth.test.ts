import test, { mock } from 'node:test';
import assert from 'node:assert/strict';

// 测试策略：mock 控制面客户端 + user-service + portal-identity，在它们被首次 import 前注册。
// auth.ts 的 callbacks 重构为模块级命名导出（signInCallback/jwtCallback/sessionCallback），
// 测试直接调用并断言 token/session 字段。
type Resolution = {
  userId: string;
  departmentId: string;
  chatAllowed: boolean;
  portalAllowed?: boolean;
  resolution: string;
  created: boolean;
  departmentVersion?: number;
};

const ensurePortalUserCalls: Array<{ tenantId: string; identity: unknown }> = [];
const applyResolutionCalls: Array<{ oidcSubject: string; resolution: Resolution }> = [];

let nextResolution: Resolution = {
  userId: 'user_cp_default',
  departmentId: 'dept_default',
  chatAllowed: true,
  resolution: 'automatic',
  created: true,
};
let nextEnsureError: Error | null = null;
let nextEnsureErrorAtCall: number | null = null;

// W2.4：刷新时复查控制面授权上下文。
const authorizationCalls: Array<{ tenantId: string; userId: string }> = [];
type AuthzOutcome =
  | { kind: 'ok'; departmentId: string; departmentVersion: number }
  | { kind: 'error'; code: string; status: number };
let nextAuthz: AuthzOutcome = { kind: 'ok', departmentId: 'dept_research', departmentVersion: 1729 };

class MockControlPlaneError extends Error {
  code: string;
  status: number;
  constructor(code: string, status: number, message: string) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

function setNextResolution(r: Resolution) {
  nextResolution = r;
}
function setNextEnsureError(e: Error | null) {
  nextEnsureError = e;
}
function setNextEnsureErrorAtCall(call: number | null) {
  nextEnsureErrorAtCall = call;
}

mock.module('@/lib/control-plane', {
  namedExports: {
    ensurePortalUser: async (tenantId: string, identity: unknown) => {
      ensurePortalUserCalls.push({ tenantId, identity });
      if (nextEnsureError) throw nextEnsureError;
      if (nextEnsureErrorAtCall === ensurePortalUserCalls.length) {
        throw new Error('control plane down');
      }
      return nextResolution;
    },
    getCurrentPortalAuthorization: async (tenantId: string, userId: string) => {
      authorizationCalls.push({ tenantId, userId });
      if (nextAuthz.kind === 'error') {
        throw new MockControlPlaneError(nextAuthz.code, nextAuthz.status, 'denied');
      }
      return {
        userId,
        departmentId: nextAuthz.departmentId,
        departmentName: 'Research',
        departmentVersion: nextAuthz.departmentVersion,
        chatAllowed: true,
        modelIds: [],
      };
    },
    redeemChatLoginTicket: async () => {throw new Error('not a ticket test')},
    PORTAL_DEFAULT_TENANT_ID: 'tenant_default',
    ControlPlaneError: MockControlPlaneError,
  },
});

mock.module('@/lib/user-service', {
  namedExports: {
    applyControlPlaneResolution: async (oidcSubject: string, _email: string, _name: string | null, _department: string | null, resolution: Resolution) => {
      applyResolutionCalls.push({ oidcSubject, resolution });
      return {
        userId: resolution.userId,
        email: _email,
        name: _name,
        departmentId: resolution.departmentId,
        chatAllowed: resolution.chatAllowed,
      };
    },
  },
});

mock.module('@/lib/portal-identity', {
  namedExports: {
    extractStableIdentityClaims: (
      account: { issuer?: string; providerAccountId?: string } | null,
      profile: { sub?: string; preferred_username?: string; email?: string; groups?: string[] } | null,
    ) => {
      if (!account || !profile) return null;
      const issuer = account.issuer ?? '';
      const subject = profile.sub ?? account.providerAccountId ?? '';
      const username = profile.preferred_username ?? subject;
      if (!issuer || !subject || !username) return null;
      return { issuer, subject, username, email: profile.email ?? '', groups: profile.groups ?? [] };
    },
    mapPortalIdentityClaims: () => ({ department: null, role: 'employee' }),
    PORTAL_EMPLOYEE_ROLE: 'employee',
  },
});

type Callbacks = {
  jwtCallback: (params: {
    token: Record<string, unknown>;
    account?: { issuer?: string; provider?: string; providerAccountId?: string } | null;
    profile?: { sub?: string; preferred_username?: string; email?: string; groups?: string[]; name?: string } | null;
    user?: { email?: string; name?: string | null };
    trigger?: 'signIn' | 'signUp' | 'update';
  }) => Promise<Record<string, unknown>>;
  signInCallback: (params: {
    account?: { issuer?: string; provider?: string; providerAccountId?: string } | null;
    profile?: { sub?: string; preferred_username?: string; email?: string; groups?: string[]; name?: string } | null;
    user?: { email?: string; name?: string | null };
  }) => Promise<boolean|string>;
  sessionCallback: (params: {
    session: { user?: Record<string, unknown> };
    token: Record<string, unknown>;
  }) => Promise<{ user?: Record<string, unknown> }>;
};

let cbs: Callbacks;
test.before(async () => {
  process.env.OIDC_ISSUER = 'https://configured-idp.test/realms/jjdguard';
  // 动态 import 在 mock 注册后执行，避免 TLA + 确保 mock 拦截生效。
  const mod = (await import('../src/auth.js')) as unknown as Callbacks;
  cbs = mod;
});

function setup() {
  ensurePortalUserCalls.length = 0;
  applyResolutionCalls.length = 0;
  setNextResolution({ userId: 'user_cp_default', departmentId: 'dept_default', chatAllowed: true, resolution: 'automatic', created: true });
  setNextEnsureError(null);
  setNextEnsureErrorAtCall(null);
  authorizationCalls.length = 0;
  nextAuthz = { kind: 'ok', departmentId: 'dept_research', departmentVersion: 1729 };
}

const nowSeconds = () => Math.floor(Date.now() / 1000);

const validAccount = { issuer: 'https://sso.corp.test', providerAccountId: 'pa-1' };
const validProfile = { sub: 'oidc-sub-42', preferred_username: 'alice@corp.test', email: 'alice@corp.test', groups: ['staff'] };

test('B6 RED→GREEN: jwt callback 首次登录调控制面并把权威字段写进 token', async () => {
  setup();
  setNextResolution({
    userId: 'user_cp_a1',
    departmentId: 'dept_research',
    chatAllowed: true,
    resolution: 'automatic',
    created: true,
    departmentVersion: 1729,
  });

  const token: Record<string, unknown> = { sub: 'oidc-sub-42' };
  const result = await cbs.jwtCallback({
    token,
    account: validAccount,
    profile: validProfile,
    user: { email: 'alice@corp.test', name: 'Alice' },
    trigger: 'signIn',
  });

  // B6 核心：三个权威字段必须被赋值到 token（修复前 0 赋值）
  assert.equal(result.controlPlaneUserId, 'user_cp_a1', 'controlPlaneUserId 必须落 token');
  assert.equal(result.departmentId, 'dept_research', 'departmentId 必须落 token');
  assert.equal(result.chatAllowed, true, 'chatAllowed 必须落 token');
  assert.equal(result.departmentVersion, 1729, 'departmentVersion 必须落 token');
  assert.equal(ensurePortalUserCalls.length, 1);
  assert.equal(applyResolutionCalls.length, 1);
});

test('jwt callback: 非 signIn trigger 每次复核已有绑定，不重新创建身份', async () => {
  setup();
  const token: Record<string, unknown> = {
    sub: 'oidc-sub-42',
    controlPlaneUserId: 'user_cp_a1', externalSubject:'oidc-sub-42',
    departmentId: 'dept_research',
    departmentVersion: 1729,
    chatAllowed: true,
    authTime: nowSeconds() - 60,
    authzCheckedAt: nowSeconds() - 30,
  };

  const result = await cbs.jwtCallback({ token, trigger: undefined });

  assert.equal(ensurePortalUserCalls.length, 0, '刷新时不能重复调控制面');
  assert.equal(authorizationCalls.length, 1, '每次刷新都复核身份，不能因旧缓存漏掉撤销');
  assert.equal(result?.controlPlaneUserId, 'user_cp_a1', '已有字段必须保留');
  assert.equal(result?.departmentId, 'dept_research');
  assert.equal(result?.departmentVersion, 1729);
  assert.equal(result?.chatAllowed, true);
});

test('W2.4: jwt callback 首次登录记录 authTime/authzCheckedAt', async () => {
  setup();
  setNextResolution({
    userId: 'user_cp_a1', departmentId: 'dept_research', chatAllowed: true,
    resolution: 'automatic', created: false, departmentVersion: 3,
  });
  const before = nowSeconds();
  const result = await cbs.jwtCallback({
    token: { sub: 'oidc-sub-42', authTime: 1, authzCheckedAt: 1 },
    account: validAccount, profile: validProfile, trigger: 'signIn',
  });
  assert.ok(typeof result?.authTime === 'number' && (result.authTime as number) >= before);
  assert.equal(result?.authzCheckedAt, result?.authTime);
});

test('W2.4: 用户在控制面被禁用后，下一次会话复查清除会话（返回 null）', async () => {
  setup();
  nextAuthz = { kind: 'error', code: 'authorization_denied', status: 403 };
  const result = await cbs.jwtCallback({
    token: {
      sub: 'oidc-sub-42', controlPlaneUserId: 'user_cp_a1', externalSubject:'oidc-sub-42', departmentId: 'dept_research',
      departmentVersion: 1729, chatAllowed: true,
      authTime: nowSeconds() - 3600, authzCheckedAt: nowSeconds() - 600,
    },
    trigger: undefined,
  });
  assert.equal(authorizationCalls.length, 1);
  assert.deepEqual(authorizationCalls[0], { tenantId: 'tenant_default', userId: 'user_cp_a1' });
  assert.equal(result, null, '被禁用用户的会话必须失效');
});

test('W2.4/W2.5: 用户被删除（控制面 404）后会话失效', async () => {
  setup();
  nextAuthz = { kind: 'error', code: 'not_found', status: 404 };
  const result = await cbs.jwtCallback({
    token: {
      controlPlaneUserId: 'user_cp_a1', externalSubject:'oidc-sub-42', departmentId: 'd', departmentVersion: 1, chatAllowed: true,
      authTime: nowSeconds() - 3600, authzCheckedAt: nowSeconds() - 600,
    },
    trigger: undefined,
  });
  assert.equal(result, null);
});

test('W2.4: 控制面瞬时不可达时保留会话、不推进复查时间（下次重试）', async () => {
  setup();
  nextAuthz = { kind: 'error', code: 'control_plane_unreachable', status: 0 };
  const checkedAt = nowSeconds() - 600;
  const result = await cbs.jwtCallback({
    token: {
      controlPlaneUserId: 'user_cp_a1', externalSubject:'oidc-sub-42', departmentId: 'd', departmentVersion: 1, chatAllowed: true,
      authTime: nowSeconds() - 3600, authzCheckedAt: checkedAt,
    },
    trigger: undefined,
  });
  assert.equal(result?.controlPlaneUserId, 'user_cp_a1');
  assert.equal(result?.authzCheckedAt, checkedAt);
});

test('W2.4: 会话自登录起超过 8 小时即失效，刷新不能续命', async () => {
  setup();
  const result = await cbs.jwtCallback({
    token: {
      controlPlaneUserId: 'user_cp_a1', externalSubject:'oidc-sub-42', departmentId: 'd', departmentVersion: 1, chatAllowed: true,
      authTime: nowSeconds() - 8 * 3600 - 1, authzCheckedAt: nowSeconds() - 10,
    },
    trigger: undefined,
  });
  assert.equal(result, null);
  assert.equal(authorizationCalls.length, 0);
});

test('W2.4: 升级前签发、没有 authTime 的授权 token 按过期处理', async () => {
  setup();
  const result = await cbs.jwtCallback({
    token: { controlPlaneUserId: 'user_cp_a1', externalSubject:'oidc-sub-42', departmentId: 'd', departmentVersion: 1, chatAllowed: true },
    trigger: undefined,
  });
  assert.equal(result, null);
});

test('W2.6: 复查时部门变更同步到会话，不需要重新登录', async () => {
  setup();
  nextAuthz = { kind: 'ok', departmentId: 'dept_sales', departmentVersion: 12 };
  const now = nowSeconds();
  const result = await cbs.jwtCallback({
    token: {
      controlPlaneUserId: 'user_cp_a1', externalSubject:'oidc-sub-42', departmentId: 'dept_research', departmentVersion: 1729,
      chatAllowed: true, authTime: now - 3600, authzCheckedAt: now - 600,
    },
    trigger: undefined,
  });
  assert.equal(result?.departmentId, 'dept_sales');
  assert.equal(result?.departmentVersion, 12);
  assert.ok((result?.authzCheckedAt as number) >= now);
});

test('W2.4: 未授权 token 刷新时不调控制面', async () => {
  setup();
  const result = await cbs.jwtCallback({ token: { sub: 'x', chatAllowed: false }, trigger: undefined });
  assert.equal(authorizationCalls.length, 0);
  assert.equal(result?.sub, 'x');
});

test('W2.4: 会话配置为 8 小时绝对上限', async () => {
  const mod = (await import('../src/auth.js')) as unknown as Record<string, number>;
  assert.equal(mod.PORTAL_SESSION_MAX_AGE_SECONDS, 8 * 3600);
  assert.ok(mod.PORTAL_SESSION_UPDATE_AGE_SECONDS > 0);
  assert.ok(mod.PORTAL_AUTHZ_RECHECK_SECONDS <= mod.PORTAL_SESSION_UPDATE_AGE_SECONDS);
});

test('signIn callback: 应急 chatAllowed=false 时拒绝登录（return false）', async () => {
  setup();
  setNextResolution({
    userId: 'user_cp_em',
    departmentId: 'dept_unassigned',
    chatAllowed: false,
    resolution: 'emergency',
    created: false,
  });

  const ok = await cbs.signInCallback({ account: validAccount, profile: validProfile, user: { email: 'em@corp.test' } });
  assert.equal(ok, false, '应急管理必须被拒绝登录');
});

test('signIn callback: 控制面抛错时拒绝登录（保守拒绝，不降级到 sub）', async () => {
  setup();
  setNextEnsureError(new Error('control plane down'));

  const ok = await cbs.signInCallback({ account: validAccount, profile: validProfile, user: { email: 'x@corp.test' } });
  assert.equal(ok, false, '控制面不可达时必须拒绝登录');
});

test('signIn callback: 控制面不可达时不写 prisma（避免半成品档案）', async () => {
  setup();
  setNextEnsureError(new Error('unreachable'));
  await cbs.signInCallback({ account: validAccount, profile: validProfile, user: { email: 'x@corp.test' } });
  assert.equal(applyResolutionCalls.length, 0, '控制面失败时不应写 prisma');
});

test('signIn callback: 缺 account 或 profile 时拒绝登录', async () => {
  setup();
  assert.equal(await cbs.signInCallback({ profile: validProfile }), false);
  assert.equal(await cbs.signInCallback({ account: validAccount }), false);
  assert.equal(ensurePortalUserCalls.length, 0);
});

test('jwt callback: 第二次控制面解析失败时清除旧业务授权字段', async () => {
  setup();
  setNextEnsureError(new Error('control plane down'));

  const result = await cbs.jwtCallback({
    token: {
      sub: 'stale-sub',
      id: 'stale-user',
      controlPlaneUserId: 'stale-user',
      departmentId: 'stale-department',
      chatAllowed: true,
    },
    account: validAccount,
    profile: validProfile,
    user: { email: 'alice@corp.test', name: 'Alice' },
    trigger: 'signIn',
  });

  assert.equal(result.controlPlaneUserId, undefined);
  assert.equal(result.id, undefined);
  assert.equal(result.departmentId, undefined);
  assert.equal(result.chatAllowed, false);
  assert.equal(applyResolutionCalls.length, 0);
});

test('登录流程: signIn 解析成功但 jwt 第二次解析失败时不建立业务会话', async () => {
  setup();
  setNextEnsureErrorAtCall(2);

  const signInAllowed = await cbs.signInCallback({
    account: validAccount,
    profile: validProfile,
    user: { email: 'alice@corp.test', name: 'Alice' },
  });
  assert.equal(signInAllowed, true);

  const token = await cbs.jwtCallback({
    token: {
      sub: 'stale-sub',
      id: 'stale-user',
      controlPlaneUserId: 'stale-user',
      departmentId: 'stale-department',
      chatAllowed: true,
    },
    account: validAccount,
    profile: validProfile,
    user: { email: 'alice@corp.test', name: 'Alice' },
    trigger: 'signIn',
  });
  const session = await cbs.sessionCallback({
    session: { user: { id: 'stale-user' } },
    token,
  });

  assert.equal(ensurePortalUserCalls.length, 2);
  assert.deepEqual(ensurePortalUserCalls[0]?.identity, ensurePortalUserCalls[1]?.identity);
  assert.equal(session.user?.id, undefined);
  assert.equal(session.user?.chatAllowed, false);
});

test('signIn callback: 缺关键字段（无 issuer/sub）拒绝登录', async () => {
  setup();
  const ok = await cbs.signInCallback({
    account: { providerAccountId: 'pa' }, // 无 issuer
    profile: { sub: 's', preferred_username: 'u' },
    user: {},
  });
  assert.equal(ok, false);
});

test('signIn callback uses configured issuer for a real Auth.js account shape', async () => {
  setup();
  const ok = await cbs.signInCallback({
    account: { provider: 'account-login', providerAccountId: 'pa-real' },
    profile: { sub: 's-real', preferred_username: 'real-user' },
    user: {},
  });
  assert.equal(ok, true);
  assert.equal(ensurePortalUserCalls.length, 1);
  assert.deepEqual(ensurePortalUserCalls[0]?.identity, {
    issuer: 'https://configured-idp.test/realms/jjdguard',
    subject: 's-real',
    username: 'real-user',
    email: '',
    groups: [],
  });
});

test('signIn callback preserves trusted provider-mapped groups when raw callback profile is standard-only', async () => {
  setup();
  const ok = await cbs.signInCallback({
    account: { provider: 'account-login', providerAccountId: 'pa-grouped' },
    profile: {
      sub: 's-grouped',
      preferred_username: 'grouped-user',
      email: 'grouped@example.test',
    },
    user: {
      email: 'grouped@example.test',
      name: 'Grouped',
      groups: ['dept-research'],
      department: 'research',
    } as unknown as { email?: string; name?: string | null },
  });
  assert.equal(ok, true);
  assert.equal(ensurePortalUserCalls.length, 1);
  assert.deepEqual(
    (ensurePortalUserCalls[0]?.identity as { groups?: string[] }).groups,
    ['dept-research'],
  );
});

test('session callback: token 有 controlPlaneUserId 时优先暴露控制面权威字段', async () => {
  setup();
  const session = await cbs.sessionCallback({
    session: { user: { id: 'fallback-sub' } },
    token: {
      sub: 'oidc-sub-42',
      externalSubject: 'oidc-sub-42',
      controlPlaneUserId: 'user_cp_a1',
      departmentId: 'dept_research',
      departmentVersion: 1729,
      chatAllowed: true,
      email: 'alice@corp.test',
      name: 'Alice',
      department: 'engineering',
    },
  });
  assert.equal(session.user?.id, 'user_cp_a1', 'session.user.id 必须是控制面 user_id，不是 OIDC sub');
  assert.equal(session.user?.departmentId, 'dept_research');
  assert.equal(session.user?.departmentVersion, 1729);
  assert.equal(session.user?.chatAllowed, true);
  assert.equal(session.user?.department, 'engineering', '门户展示部门应来自已验证企业声明');
  assert.equal(session.user?.externalSubject, 'oidc-sub-42', 'portal-proxy 必须收到 OIDC subject 而非控制面 user_id');
});

test('session callback: chatAllowed=false（应急）不暴露业务 user.id', async () => {
  setup();
  const session = await cbs.sessionCallback({
    session: { user: { role: 'admin', departmentVersion: 41 } },
    token: {
      controlPlaneUserId: 'user_cp_em',
      departmentId: 'dept_unassigned',
      departmentVersion: 42,
      chatAllowed: false,
      role: 'platform_admin',
    },
  });
  assert.equal(session.user?.chatAllowed, false, '应急 chatAllowed 必须透传到 session');
  assert.equal(session.user?.id, undefined, '应急身份不能成为有效业务会话');
  assert.equal(session.user?.departmentVersion, undefined, '未授权 session 必须清除旧部门 revision');
  assert.equal(session.user?.role, undefined, '未授权 session 必须清除旧业务角色');
});

test('session callback: 只有 OIDC sub 时不生成业务 user.id', async () => {
  setup();
  const session = await cbs.sessionCallback({
    session: { user: { id: 'stale-user', email: 'alice@corp.test' } },
    token: { sub: 'oidc-sub-42', email: 'alice@corp.test' },
  });

  assert.equal(session.user?.id, undefined);
  assert.equal(session.user?.chatAllowed, false);
});

test('jwt callback clears stale authorization when chat is denied', async () => {
  setup();
  setNextResolution({
    userId: 'user_cp_em',
    departmentId: 'dept_unassigned',
    departmentVersion: 42,
    chatAllowed: false,
    resolution: 'emergency',
    created: false,
  });

  const result = await cbs.jwtCallback({
    token: {
      id: 'stale-user',
      controlPlaneUserId: 'stale-user',
      departmentId: 'stale-department',
      departmentVersion: 41,
      chatAllowed: true,
      role: 'platform_admin',
    },
    account: validAccount,
    profile: validProfile,
    user: { email: 'em@corp.test' },
    trigger: 'signIn',
  });

  assert.equal(result.chatAllowed, false);
  assert.equal(result.id, undefined);
  assert.equal(result.controlPlaneUserId, undefined);
  assert.equal(result.departmentId, undefined);
  assert.equal(result.departmentVersion, undefined);
  assert.equal(result.role, undefined);
});

test('session callback rejects an authorized token with a zero revision', async () => {
  setup();
  const session = await cbs.sessionCallback({
    session: { user: { id: 'stale-user', role: 'admin' } },
    token: {
      controlPlaneUserId: 'user_cp_1',
      departmentId: 'dept_a',
      departmentVersion: 0,
      chatAllowed: true,
      role: 'employee',
    },
  });
  assert.equal(session.user?.chatAllowed, false);
  assert.equal(session.user?.id, undefined);
  assert.equal(session.user?.departmentId, undefined);
  assert.equal(session.user?.departmentVersion, undefined);
  assert.equal(session.user?.role, undefined);
});

test('OIDC personal portal login permits an active account without business model access',async()=>{
 setNextEnsureError(null);
 setNextEnsureErrorAtCall(null);
 setNextResolution({userId:'personal-admin',departmentId:'',departmentVersion:3,chatAllowed:false,portalAllowed:true,resolution:'emergency',created:false});
 assert.equal(await cbs.signInCallback({account:validAccount,profile:validProfile}),true);
 const token=await cbs.jwtCallback({token:{},account:validAccount,profile:validProfile,trigger:'signIn'});
 assert.ok(token);
 const session=await cbs.sessionCallback({session:{user:{}},token});
 assert.ok(session.user);
 assert.equal(session.user.id,'personal-admin');
 assert.equal(session.user.role,'employee');
});


test('OIDC binding revocation invalidates an old session even inside the former cache interval',async()=>{
 setup();nextAuthz={kind:'error',code:'not_found',status:404};
 const result=await cbs.jwtCallback({token:{controlPlaneUserId:'user_cp_a1',externalSubject:'oidc-sub-42',portalAllowed:true,chatAllowed:true,departmentVersion:1,authTime:nowSeconds()-10,authzCheckedAt:nowSeconds()},trigger:undefined});
 assert.equal(authorizationCalls.length,1);
 assert.equal(result,null);
});

test('OIDC provisioning errors redirect to actionable identity guidance without claims',async()=>{
 for(const code of ['identity_conflict','identity_not_ready']){
  setup();setNextEnsureError(new MockControlPlaneError(code,code==='identity_conflict'?409:503,'private upstream detail'));
  const result=await cbs.signInCallback({account:validAccount,profile:validProfile});
  assert.equal(result,'/chat/login?error='+code);
 }
});
