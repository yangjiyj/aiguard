// Auth.js v5：员工门户只暴露通用企业 OIDC 登录。
// 浏览器提交的身份、角色和项目字段都不是授权依据——授权依据来自控制面 EnsurePortalUser
// 返回的 user_id/department_id/chat_allowed（基于已验证 OIDC token 的稳定身份解析）。
//
// NextAuth v5 callback 执行顺序：signIn → jwt → session。
//   - signIn callback 无法改 token，但能 return false 中止登录。
//   - jwt callback 在 trigger==="signIn" 时拿到 account/profile/user，负责写 token。
// 所以控制面调用分工：
//   - signInCallback 调控制面做"是否放行"决策（应急/不可达时 return false）；
//   - jwtCallback 在 trigger==="signIn" 时再调一次控制面（幂等，稳定键命中返同一结果）
//     并把权威字段写入 token，同时持久化 prisma。
// 两次控制面调用是 NextAuth v5 跨 callback 传递数据的必要权衡，EnsurePortalUser 幂等保证安全。
import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import type { JWT } from 'next-auth/jwt';

import {
  PORTAL_EMPLOYEE_ROLE,
  extractStableIdentityClaims,
  mapPortalIdentityClaims,
  mapVerifiedOidcProfile,
} from '@/lib/portal-identity';
import { applyControlPlaneResolution } from '@/lib/user-service';
import {
  ControlPlaneError,
  PORTAL_DEFAULT_TENANT_ID,
  ensurePortalUser,
  getCurrentPortalAuthorization,
  redeemChatLoginTicket,
  type ChatLoginIdentity,
} from '@/lib/control-plane';
import { PORTAL_AUTH_BASE_PATH, portalPath } from '@/lib/portal-path';
import { authenticateEmployeeCredentials } from '@/lib/employee-login';

declare module 'next-auth/jwt' {
  interface JWT {
    /** W2.4：本次业务授权建立时间（epoch 秒），用于 8 小时绝对上限。 */
    authTime?: number;
    portalAllowed?: boolean;
    tenantId?: string;
    /** W2.4：最近一次向控制面复查授权的时间（epoch 秒）。 */
    authzCheckedAt?: number;
  }
}

// Only objects produced by the server-side Credentials authorize function
// carry this proof. Client fields cannot fabricate or overwrite a Chat identity.
const verifiedChatUsers = new WeakMap<object, ChatLoginIdentity>();

export async function authorizeEmployeeLocal(credentials: Partial<Record<string, unknown>>,request?:Request) {
  const identity = await authenticateEmployeeCredentials(credentials,request);
  const user = {id:identity.userId, name:identity.username, email:identity.email};
  verifiedChatUsers.set(user, identity);
  return user;
}

export async function authorizeChatTicket(credentials: Partial<Record<string, unknown>>) {
  if (typeof credentials.ticket !== 'string') return null;
  try {
    const identity = await redeemChatLoginTicket(credentials.ticket);
    if (identity.tenantId !== PORTAL_DEFAULT_TENANT_ID || !(identity.portalAllowed ?? identity.chatAllowed)) return null;
    const user = { id: identity.userId, name: identity.username, email: identity.email };
    verifiedChatUsers.set(user, identity);
    return user;
  } catch {
    return null;
  }
}

function clearBusinessAuthorization(token: JWT) {
  delete token.id;
  delete token.tenantId;
  delete token.controlPlaneUserId;
  delete token.departmentId;
  delete token.departmentVersion;
  delete token.role;
  delete token.authTime;
  delete token.authzCheckedAt;
  delete token.externalSubject;
  delete token.localLogin;
  delete token.localCredentialVersion;
  token.chatAllowed = false;
  token.portalAllowed = false;
}

// signIn callback：仅校验个人门户身份；模型授权不决定能否登录个人中心。
// 不写 token（NextAuth v5 signIn 无 token 写入权），也不写 prisma（jwt callback 负责持久化，
// 避免 signIn 放行后 jwt 失败导致半成品档案）。
export async function signInCallback({
  account,
  profile,
  user,
}: {
  user?: ProviderMappedUser;
  account?: AccountLike | null;
  profile?: ProfileLike | null;
}): Promise<boolean|string> {
  if (account?.provider === 'chat-ticket' || account?.provider === 'employee-local') return !!user && verifiedChatUsers.has(user);
  if (!account || !profile) return false;
  const identity = extractStableIdentityClaims(trustedAccount(account), trustedProfile(profile, user));
  if (!identity) {
    // 缺关键字段一律拒绝——绝不落默认值让门户拿到错误授权。
    return false;
  }
  try {
    const resolution = await ensurePortalUser(PORTAL_DEFAULT_TENANT_ID, identity);
    // 所有人类账号可进入个人门户；模型使用权限由业务请求单独复查。
    return resolution.portalAllowed ?? resolution.chatAllowed;
  } catch (error) {
    if(error instanceof ControlPlaneError&&(error.code==='identity_conflict'||error.code==='identity_not_ready')) {
      return portalPath('/login?error='+error.code);
    }
    // 控制面不可达/拒绝时不放行——保守拒绝，绝不降级到本地 sub 作为授权依据。
    return false;
  }
}

// jwt callback：首次登录（trigger==="signIn"）时调控制面拿权威字段写 token + 持久化 prisma；
// 刷新（trigger!=="signIn"）时保留已有字段。控制面调用幂等，与 signInCallback 重复调用安全。
export async function jwtCallback({
  token,
  account,
  profile,
  user,
  trigger,
}: {
  token: JWT;
  account?: AccountLike | null;
  profile?: ProfileLike | null;
  user?: ProviderMappedUser;
  trigger?: 'signIn' | 'signUp' | 'update';
}): Promise<JWT | null> {
  if (trigger !== 'signIn') return refreshAuthorizedToken(token);

  // 每次登录都先撤销 token 中可能残留的业务授权。只有本次控制面解析成功且
  // 明确允许 Chat 时，才重新写入权威用户和部门字段。
  clearBusinessAuthorization(token);

  if (account?.provider === 'chat-ticket' || account?.provider === 'employee-local') {
    const identity = user ? verifiedChatUsers.get(user) : undefined;
    if (!identity || identity.tenantId !== PORTAL_DEFAULT_TENANT_ID) return null;
    try {
      // Profile persistence precedes token authorization. A failed write must
      // never leave an authorized cookie or retain a previous user's grants.
      await applyControlPlaneResolution(identity.externalSubject, identity.email, identity.username,
        identity.departmentName, identity);
      token.id = identity.userId;
      token.controlPlaneUserId = identity.userId;
      token.departmentId = identity.departmentId;
      token.departmentVersion = identity.departmentVersion;
      token.chatAllowed = identity.chatAllowed;
      token.portalAllowed = identity.portalAllowed ?? identity.chatAllowed;
      token.tenantId = identity.tenantId;
      token.externalSubject = identity.externalSubject;
      token.localLogin = true;
      token.localCredentialVersion=identity.localCredentialVersion;
      token.name = identity.username;
      token.email = identity.email;
      token.department = identity.departmentName;
      token.role = PORTAL_EMPLOYEE_ROLE;
      token.authTime = currentEpochSeconds();
      token.authzCheckedAt = token.authTime;
      return token;
    } catch {
      clearBusinessAuthorization(token);
      return null;
    } finally {
      if (user) verifiedChatUsers.delete(user);
    }
  }

  if (account && profile) {
    const verifiedProfile = trustedProfile(profile, user);
    const claims = mapPortalIdentityClaims(verifiedProfile as Record<string, unknown>);
    token.sub = (verifiedProfile.sub as string | undefined) ?? (account.providerAccountId as string | undefined) ?? token.sub;
    token.email = (verifiedProfile.email as string | undefined) ?? token.email;
    token.name = (verifiedProfile.name as string | null | undefined) ?? token.name;
    token.department = claims.department;

    const identity = extractStableIdentityClaims(trustedAccount(account), verifiedProfile);
    if (identity) {
      try {
        const resolution = await ensurePortalUser(PORTAL_DEFAULT_TENANT_ID, identity);
        if (
          !(resolution.portalAllowed ?? resolution.chatAllowed) ||
          !Number.isSafeInteger(resolution.departmentVersion) ||
          resolution.departmentVersion <= 0
        ) return token;
        token.controlPlaneUserId = resolution.userId;
        token.departmentId = resolution.departmentId;
        token.departmentVersion = resolution.departmentVersion;
        token.chatAllowed = resolution.chatAllowed;
        token.portalAllowed = resolution.portalAllowed ?? resolution.chatAllowed;
        token.tenantId = PORTAL_DEFAULT_TENANT_ID;
        token.externalSubject = identity.subject;
        token.role = PORTAL_EMPLOYEE_ROLE;
        const nowSeconds = currentEpochSeconds();
        token.authTime = nowSeconds;
        token.authzCheckedAt = nowSeconds;
        if (token.controlPlaneUserId) {
          token.id = token.controlPlaneUserId;
        }
        // 持久化到 prisma：以控制面 user_id 为主键。只在拿到权威 resolution 后写，
        // 控制面失败时（catch）跳过写入，避免半成品档案。
        await applyControlPlaneResolution(
          identity.subject,
          user?.email ?? identity.email,
          (user?.name as string | null | undefined) ?? null,
          claims.department,
          resolution,
        );
      } catch {
        clearBusinessAuthorization(token);
        // 控制面失败：signInCallback 已据此拒绝登录；jwt 这里静默跳过 token 写入，
        // 不抛错（NextAuth v5 jwt 抛错会导致整个登录流程崩），并保持 token 未授权。
      }
    }
  }
  return token;
}

// W2.4/W2.5：门户会话生命周期。
//   - PORTAL_SESSION_MAX_AGE_SECONDS：自登录起的绝对上限（8 小时），刷新不能续命；
//   - 每次会话读取均向控制面复查主体绑定和授权，不设复查缓存。
// 控制面明确拒绝（用户禁用/删除/目录同步停用/应急）时 jwt callback 返回 null，
// Auth.js 据此清除会话 cookie。控制面暂时不可达时保留 token、下次再查——
// 每个 BFF 请求另有 requireActivePortalUser 按请求 fail-closed 兜底。
// 保留兼容导出；0 表示不缓存授权复查，每次请求均验证绑定。
export const PORTAL_AUTHZ_RECHECK_SECONDS = 0;
export const PORTAL_SESSION_MAX_AGE_SECONDS = 8 * 60 * 60;
export const PORTAL_SESSION_UPDATE_AGE_SECONDS = 15 * 60;

function currentEpochSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function isEpochSeconds(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

async function refreshAuthorizedToken(token: JWT): Promise<JWT | null> {
  // 未授权 token（无控制面 user_id）没有业务权限可吊销，原样返回。
  if (!token.controlPlaneUserId || (token.portalAllowed ?? token.chatAllowed) !== true) return token;
  if(typeof token.externalSubject!=="string"||!token.externalSubject.trim())return null;

  if(token.localLogin===true && (!Number.isSafeInteger(token.localCredentialVersion) || (token.localCredentialVersion??0)<=0))return null;
  const now = currentEpochSeconds();
  // 旧版本签发、没有 authTime 的授权 token 无法证明登录时间，按过期处理。
  if (!isEpochSeconds(token.authTime) || now - token.authTime >= PORTAL_SESSION_MAX_AGE_SECONDS) {
    return null;
  }

  try {
    const authorization = await getCurrentPortalAuthorization(
      token.tenantId || PORTAL_DEFAULT_TENANT_ID,
      token.controlPlaneUserId,
      {externalSubject:token.externalSubject,loginMode:token.localLogin?'local':'oidc',...(token.localLogin?{localCredentialVersion:token.localCredentialVersion}:{})},
    );
    // Explicit local identity revocation invalidates the cached session. Each
    // business request also validates its current binding independently.
    if (token.localLogin && (authorization.localCredentialVersion !== token.localCredentialVersion || authorization.localLoginAllowed === false ||
      (typeof authorization.localExternalSubject === 'string' && authorization.localExternalSubject !== token.externalSubject))) return null;
    // 换部门（W2.6）：会话随控制面刷新部门与版本，不需要重新登录。
    token.portalAllowed = authorization.portalAllowed ?? authorization.chatAllowed;
    token.chatAllowed = authorization.chatAllowed;
    token.departmentId = authorization.departmentId;
    token.departmentVersion = authorization.departmentVersion;
    token.authzCheckedAt = now;
    return token;
  } catch (error) {
    if (
      error instanceof ControlPlaneError &&
      (error.code === 'authorization_denied' || error.status === 404 || error.code === 'not_found')
    ) {
      return null;
    }
    // 瞬时故障：不更新 authzCheckedAt，下一次读取会话时重试。
    return token;
  }
}

// session callback：把 token 的权威字段暴露给业务代码。
// controlPlaneUserId + portalAllowed=true 构成有效个人门户会话。泛型 S 保留完整 Session 类型，
// 这样返回值类型与传入一致，避免 TS 抱怨缺 DefaultSession 字段。
export async function sessionCallback<S extends { user?: unknown }>({
  session,
  token,
}: {
  session: S;
  token: JWT;
}): Promise<S> {
  // session.user 在 next-auth.d.ts 里被扩展为含 departmentId/chatAllowed/role 等字段；
  // 这里用 Record 视图赋值避免 TS 对扩展 Session 接口的严格检查。
  const user = ((session.user as Record<string, unknown> | undefined) ?? {}) as Record<string, unknown>;
  if (
    token.controlPlaneUserId &&
    (token.portalAllowed ?? token.chatAllowed) === true &&
    typeof token.departmentVersion === 'number' &&
    Number.isSafeInteger(token.departmentVersion) &&
    (token.departmentVersion ?? 0) > 0
  ) {
    (session as { user: unknown }).user = {
      ...user,
      id: token.controlPlaneUserId,
      email: token.email ?? user.email ?? '',
      name: token.name ?? user.name,
      department: token.department ?? null,
      departmentId: token.departmentId ?? null,
      departmentVersion: token.departmentVersion ?? 0,
      chatAllowed: token.chatAllowed === true,
      portalAllowed: (token.portalAllowed ?? token.chatAllowed) === true,
      tenantId: token.tenantId || PORTAL_DEFAULT_TENANT_ID,
      role: PORTAL_EMPLOYEE_ROLE,
      // portal-proxy 的直接身份契约使用已验证 OIDC subject；业务授权仍使用上面的控制面 user_id。
      externalSubject: typeof token.externalSubject === 'string' ? token.externalSubject : null,
      localLogin: token.localLogin === true,
      localCredentialVersion:token.localLogin===true?token.localCredentialVersion:undefined,
    };
  } else {
    const unauthorizedUser = { ...user };
    delete unauthorizedUser.id;
    delete unauthorizedUser.department;
    delete unauthorizedUser.departmentId;
    delete unauthorizedUser.role;
    delete unauthorizedUser.departmentVersion;
    delete unauthorizedUser.externalSubject;
    delete unauthorizedUser.localLogin;
    delete unauthorizedUser.localCredentialVersion;
    (session as { user: unknown }).user = {
      ...unauthorizedUser,
      chatAllowed: false,
      portalAllowed: false,
    };
  }
  return session;
}

// 已验证 OIDC token 的局部形状——只取稳定身份字段，与 @auth/core 的 Account/Profile 兼容。
type AccountLike = {
  issuer?: unknown;
  provider?: unknown;
  providerAccountId?: unknown;
};
type ProfileLike = {
  sub?: unknown;
  preferred_username?: unknown;
  email?: unknown;
  groups?: unknown;
  name?: unknown;
  department?: unknown;
  departments?: unknown;
  [key: string]: unknown;
};
type ProviderMappedUser = {
  id?: string;
  email?: string | null;
  name?: string | null;
  sub?: unknown;
  preferred_username?: unknown;
  groups?: unknown;
  department?: unknown;
  departments?: unknown;
};


// 任务10：Chat 双登录入口。两个 provider 共用同一 OIDC realm（issuer/clientId/secret 相同），
// 仅登录入口不同。callbacks（signIn/jwt/session）对两个 provider 一视同仁——都走控制面
// EnsurePortalUser 做稳定身份解析 + chat_allowed 校验 + 权威字段写入 session。
//
// 安全：kc_idp_hint 只在 enterprise-sso provider 上出现，且值来自受控服务端配置（环境变量
// OIDC_ENTERPRISE_IDP_HINT，默认 enterprise）。绝不从 query string / req 透传——
// 防止客户端注入任意 IdP alias 把用户引到钓鱼 IdP。
const PORTAL_OIDC_ISSUER = process.env.OIDC_ISSUER!;
const PORTAL_OIDC_CLIENT_ID = process.env.OIDC_CLIENT_ID!;
const PORTAL_OIDC_CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET!;
export const PORTAL_OIDC_LOGIN_AVAILABLE = Boolean(PORTAL_OIDC_ISSUER?.trim() && PORTAL_OIDC_CLIENT_ID?.trim() && PORTAL_OIDC_CLIENT_SECRET?.trim());
// 服务端固定的企业 IdP 提示。受控配置，默认 enterprise；无 NEXT_PUBLIC_ 前缀故不内联进客户端。
const ENTERPRISE_IDP_HINT = process.env.OIDC_ENTERPRISE_IDP_HINT || 'enterprise';
// 「企业目录账号登录」(account-login) 不带 IdP 提示，落在身份服务自带的账号密码页（给 AD/LDAP 用）。
// 只接企业 SSO 的站点没有这类账号，用户点进去输入企业用户名只会得到「用户不存在」。
// 服务端开关：显式设为 false 时不注册该 provider、登录页也不显示该按钮。
// 默认开启，未设置时行为与之前完全一致；这是服务端环境变量，不接受任何请求侧输入。
export const PORTAL_ACCOUNT_LOGIN_ENABLED = process.env.OIDC_ACCOUNT_LOGIN_ENABLED?.trim().toLowerCase() !== 'false';

// Auth.js does not expose issuer on its runtime Account object. Reattach it
// only for the two fixed OIDC providers, from server-controlled configuration.
function trustedAccount(account: AccountLike | null | undefined): AccountLike | null | undefined {
  if (!account || (typeof account.issuer === 'string' && account.issuer.trim())) return account;
  if (
    (account.provider === 'account-login' || account.provider === 'enterprise-sso') &&
    PORTAL_OIDC_ISSUER
  ) {
    return { ...account, issuer: PORTAL_OIDC_ISSUER };
  }
  return account;
}

function trustedProfile(
  profile: ProfileLike,
  user: ProviderMappedUser | null | undefined,
): ProfileLike {
  if (!user) return profile;
  return {
    ...profile,
    sub: profile.sub ?? user.sub,
    preferred_username: profile.preferred_username ?? user.preferred_username,
    email: profile.email ?? user.email,
    name: profile.name ?? user.name,
    groups: profile.groups ?? user.groups,
    department: profile.department ?? user.department,
    departments: profile.departments ?? user.departments,
  };
}

export const { handlers, auth, signIn, signOut } = NextAuth({
  trustHost: true,
  basePath: PORTAL_AUTH_BASE_PATH,
  // Keep Auth.js's internal credentials form out of the customer flow.
  pages: { signIn: portalPath('/login'), error: portalPath('/login') },
  // 两个 provider 直接内联：让 TS 从 Provider 联合类型把 type 收窄为 'oidc' 字面量。
  providers: [
    Credentials({
      id:'employee-local', name:'员工账号登录',
      credentials:{username:{type:'text'},password:{type:'password'},captcha_id:{type:'text'},captcha_code:{type:'text'},totp_code:{type:'text'}},
      authorize:authorizeEmployeeLocal,
    }),
    Credentials({
      id: 'chat-ticket',
      name: '账号登录交接',
      credentials: { ticket: { type: 'text' } },
      authorize: authorizeChatTicket,
    }),
    ...(PORTAL_OIDC_LOGIN_AVAILABLE ? [
    // account-login：落 OIDC IdP 默认登录页（本地账号 / AD / LDAP 都从这里进）。
    // 故意不设 kc_idp_hint，让 IdP 展示自己的登录页与身份源选择。
    // 可由 OIDC_ACCOUNT_LOGIN_ENABLED=false 关闭（只接企业 SSO 的站点）。
    ...(PORTAL_ACCOUNT_LOGIN_ENABLED ? [{
      id: 'account-login',
      name: '账号登录',
      type: 'oidc' as const,
      issuer: PORTAL_OIDC_ISSUER,
      clientId: PORTAL_OIDC_CLIENT_ID,
      clientSecret: PORTAL_OIDC_CLIENT_SECRET,
      authorization: {
        params: {
          // 任务10：scope 加 groups，供稳定身份解析与企业目录分组使用。
          scope: 'openid email profile groups',
          code_challenge_method: 'S256',
        },
      },
      checks: ['pkce', 'state', 'nonce'] as ('pkce' | 'state' | 'nonce')[],
      profile: mapVerifiedOidcProfile,
    }] : []),
    // enterprise-sso：同一 OIDC authorize endpoint，服务端固定 kc_idp_hint=enterprise，
    // 直接把用户引到企业目录 IdP，绕过 IdP 登录页。
    {
      id: 'enterprise-sso',
      name: '企业 SSO 登录',
      type: 'oidc' as const,
      issuer: PORTAL_OIDC_ISSUER,
      clientId: PORTAL_OIDC_CLIENT_ID,
      clientSecret: PORTAL_OIDC_CLIENT_SECRET,
      authorization: {
        params: {
          scope: 'openid email profile groups',
          code_challenge_method: 'S256',
          // 服务端固定 kc_idp_hint（默认 enterprise，由 OIDC_ENTERPRISE_IDP_HINT 覆盖），
          // 不接受任何请求侧输入。account-login provider 不带此参数。
          kc_idp_hint: ENTERPRISE_IDP_HINT,
        },
      },
      checks: ['pkce', 'state', 'nonce'] as ('pkce' | 'state' | 'nonce')[],
      profile: mapVerifiedOidcProfile,
    },
    ] : []),
  ],
  session: {
    strategy: 'jwt',
    maxAge: PORTAL_SESSION_MAX_AGE_SECONDS,
    updateAge: PORTAL_SESSION_UPDATE_AGE_SECONDS,
  },
  callbacks: {
    jwt: jwtCallback,
    session: sessionCallback,
    signIn: signInCallback,
  },
});
