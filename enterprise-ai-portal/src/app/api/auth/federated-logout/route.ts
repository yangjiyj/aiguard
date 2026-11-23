import { signOut } from '@/auth';
import {
  assertTrustedLogoutRequest,
  loadFederatedLogoutConfig,
  loadLogoutRequestConfig,
  resolveFederatedLogoutUrl,
} from '@/lib/federated-logout';

function seeOther(location: string): Response {
  return new Response(null, {
    status: 303,
    headers: { location },
  });
}

export async function POST(request: Request) {
  let requestConfig;
  try {
    requestConfig = loadLogoutRequestConfig();
  } catch {
    return Response.json({ error: 'logout_unavailable' }, { status: 503 });
  }
  try {
    assertTrustedLogoutRequest(request, requestConfig);
  } catch {
    return Response.json({ error: 'invalid_logout_request' }, { status: 403 });
  }

  // 先销毁门户会话；远端发现或登出失败不能让本地会话继续有效。
  await signOut({ redirect: false });

  let config;
  try {
    config = loadFederatedLogoutConfig();
  } catch {
    return seeOther(requestConfig.postLogoutRedirectUri);
  }
  try {
    const target = await resolveFederatedLogoutUrl(config);
    return seeOther(target.href);
  } catch {
    return seeOther(config.postLogoutRedirectUri);
  }
}
