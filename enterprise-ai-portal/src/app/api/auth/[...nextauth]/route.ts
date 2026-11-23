import { handlers } from '@/auth';
import { portalPath } from '@/lib/portal-path';
import { dropSigninAuthorizationQuery } from '@/lib/auth-request';
import { NextRequest } from 'next/server';

function restoreExternalBasePath(request: NextRequest): NextRequest {
  const url = request.nextUrl.clone();
  const configuredAuthUrl = process.env.AUTH_URL ?? process.env.NEXTAUTH_URL;
  if (configuredAuthUrl) {
    const publicUrl = new URL(configuredAuthUrl);
    url.protocol = publicUrl.protocol;
    url.hostname = publicUrl.hostname;
    url.port = publicUrl.port;
  }
  url.pathname = portalPath(url.pathname);
  // 登录发起请求上的 query 会被 Auth.js 并入授权参数（优先级高于服务端固定值），一律丢弃。
  dropSigninAuthorizationQuery(url);
  return new NextRequest(url, request);
}

export function GET(request: NextRequest) {
  return handlers.GET(restoreExternalBasePath(request));
}

export function POST(request: NextRequest) {
  return handlers.POST(restoreExternalBasePath(request));
}
