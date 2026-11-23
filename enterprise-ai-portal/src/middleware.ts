// 鉴权代理：默认拦截所有受保护路径，未登录跳 /login
// 白名单：_next 静态资源、favicon、api/auth（Auth.js 回调）、login、style（设计走查，无敏感）
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { portalPath, stripPortalBasePath } from '@/lib/portal-path';

const PUBLIC_PREFIXES = ['/_next', '/favicon.ico', '/api/auth', '/api/login/captcha', '/login', '/style'];

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const routePath = stripPortalBasePath(pathname);
  // 公开路径直接放行
  if (PUBLIC_PREFIXES.some((p) => routePath === p || routePath.startsWith(p + '/'))) {
    return NextResponse.next();
  }

  // Auth.js v5 JWT session cookie（开发 http 用 authjs.session-token）
  const hasSession = req.cookies.getAll().some(({ name, value }) => value &&
    /^(?:__Secure-)?authjs\.session-token(?:\.\d+)?$/.test(name));
  if (!hasSession) {
    if (routePath.startsWith('/api/')) {
      return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
    }
    // 注意：middleware 的 NextResponse.redirect 不会自动补 next.config.ts 的
    // basePath（线上实测 Location 原样返回 /login，而 /login 并非有效路由，
    // 最终落到 Next 默认 404 页「404 | This page could not be found.」）。
    // 因此这里必须用 portalPath 显式带上 /chat 前缀，生成 /chat/login。
    // 服务端组件里的 redirect() 才会自动补 basePath（那边不能再包 portalPath，
    // 否则会变成 /chat/chat/login，见 app/page.tsx）。
    const loginUrl = new URL(portalPath('/login'), req.url);
    // Next sees its container bind address (often 0.0.0.0) behind chat-edge.
    // A same-origin relative target preserves the deep link without trusting a
    // spoofable forwarded host or creating an external/open redirect.
    loginUrl.searchParams.set('callbackUrl', portalPath(routePath) + req.nextUrl.search);
    return NextResponse.redirect(loginUrl);
  }
  return NextResponse.next();
}

export const config = {
  // 匹配所有路径（matcher 在 middleware 内部判断公开/受保护）
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
