import { PORTAL_AUTH_BASE_PATH } from './portal-path';

// 登录发起请求（POST /chat/api/auth/signin/<provider>）。
// @auth/core 会把这个请求 URL 上的 query 并入发往 IdP 的授权参数，且优先级高于
// provider 里服务端固定的 authorization.params（见 lib/actions/signin/authorization-url.js）。
// 如果不处理，请求方能改写 kc_idp_hint，或注入 prompt/max_age/login_hint/acr_values 等参数。
// 本项目的约定是授权参数只来自服务端配置，所以登录发起请求的 query 一律丢弃。
//
// 解析方式与 @auth/core 的 parseActionAndProviderId 保持一致（去掉 base 后按 / 切分并忽略空段），
// 避免 //、尾部斜杠等写法绕过判断。
export function isProviderSigninPath(pathname: string): boolean {
  if (!pathname.startsWith(PORTAL_AUTH_BASE_PATH)) return false;
  const [action, providerId] = pathname
    .slice(PORTAL_AUTH_BASE_PATH.length)
    .split('/')
    .filter(Boolean);
  return action === 'signin' && Boolean(providerId);
}

// 只处理 /signin/<provider>。不带 provider 的 /signin（跳转到登录页，靠 callbackUrl/error）、
// /callback/*（code、state）、/session、/csrf 都不动。
export function dropSigninAuthorizationQuery(url: Pick<URL, 'pathname' | 'search'>): void {
  if (isProviderSigninPath(url.pathname)) url.search = '';
}
