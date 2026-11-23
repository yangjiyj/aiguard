const DISCOVERY_TIMEOUT_MS = 3_000;
const MAX_DISCOVERY_BYTES = 64 * 1024;

export interface FederatedLogoutEnvironment {
  OIDC_ISSUER?: string;
  OIDC_CLIENT_ID?: string;
  PORTAL_PUBLIC_URL?: string;
}

export interface LogoutRequestConfig {
  postLogoutRedirectUri: string;
}

export interface FederatedLogoutConfig extends LogoutRequestConfig {
  issuer: string;
  issuerOrigin: string;
  discoveryUrl: URL;
  clientId: string;
}

interface LogoutDiscoveryDocument {
  issuer?: unknown;
  end_session_endpoint?: unknown;
}

function requiredValue(value: string | undefined, name: string): string {
  if (!value || value !== value.trim()) {
    throw new Error(`${name} is not configured safely`);
  }
  return value;
}

function parseBaseUrl(raw: string, name: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${name} is not a valid URL`);
  }
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error(`${name} is not configured safely`);
  }
  return url;
}

function canonicalIssuer(raw: string, name: string): { href: string; url: URL } {
  const url = parseBaseUrl(raw, name);
  const href = url.href.replace(/\/+$/, '');
  return { href, url: new URL(href) };
}

export function loadLogoutRequestConfig(
  env: Pick<FederatedLogoutEnvironment, 'PORTAL_PUBLIC_URL'> = {
    PORTAL_PUBLIC_URL: process.env.PORTAL_PUBLIC_URL,
  },
): LogoutRequestConfig {
  const postLogoutRedirectUri = requiredValue(env.PORTAL_PUBLIC_URL, 'PORTAL_PUBLIC_URL');
  parseBaseUrl(postLogoutRedirectUri, 'PORTAL_PUBLIC_URL');
  return { postLogoutRedirectUri };
}

export function loadFederatedLogoutConfig(
  env: FederatedLogoutEnvironment = {
    OIDC_ISSUER: process.env.OIDC_ISSUER,
    OIDC_CLIENT_ID: process.env.OIDC_CLIENT_ID,
    PORTAL_PUBLIC_URL: process.env.PORTAL_PUBLIC_URL,
  },
): FederatedLogoutConfig {
  const requestConfig = loadLogoutRequestConfig(env);
  const issuerValue = requiredValue(env.OIDC_ISSUER, 'OIDC_ISSUER');
  const clientId = requiredValue(env.OIDC_CLIENT_ID, 'OIDC_CLIENT_ID');
  const issuer = canonicalIssuer(issuerValue, 'OIDC_ISSUER');

  return {
    ...requestConfig,
    issuer: issuer.href,
    issuerOrigin: issuer.url.origin,
    discoveryUrl: new URL(`${issuer.href}/.well-known/openid-configuration`),
    clientId,
  };
}

export function assertTrustedLogoutRequest(
  request: Request,
  config: LogoutRequestConfig,
): void {
  if (request.method !== 'POST') {
    throw new Error('logout request method is not allowed');
  }
  const origin = request.headers.get('origin');
  if (!origin) {
    throw new Error('logout request origin is missing');
  }

  let requestOrigin: URL;
  try {
    requestOrigin = new URL(origin);
  } catch {
    throw new Error('logout request origin is invalid');
  }
  const expectedOrigin = new URL(config.postLogoutRedirectUri).origin;
  if (origin !== requestOrigin.origin || requestOrigin.origin !== expectedOrigin) {
    throw new Error('logout request origin is not trusted');
  }

  const fetchSite = request.headers.get('sec-fetch-site');
  if (fetchSite && fetchSite !== 'same-origin') {
    throw new Error('logout request is not same-origin');
  }
}

export function buildFederatedLogoutUrl(
  config: FederatedLogoutConfig,
  discovery: LogoutDiscoveryDocument,
): URL {
  if (typeof discovery.issuer !== 'string') {
    throw new Error('OIDC discovery issuer is missing');
  }
  const discoveredIssuer = canonicalIssuer(discovery.issuer, 'discovery issuer');
  if (discoveredIssuer.href !== config.issuer) {
    throw new Error('OIDC discovery issuer mismatch');
  }
  if (typeof discovery.end_session_endpoint !== 'string') {
    throw new Error('OIDC end-session endpoint is missing');
  }

  let endpoint: URL;
  try {
    endpoint = new URL(discovery.end_session_endpoint);
  } catch {
    throw new Error('OIDC end-session endpoint is invalid');
  }
  if (
    !['http:', 'https:'].includes(endpoint.protocol) ||
    endpoint.username ||
    endpoint.password ||
    endpoint.hash ||
    endpoint.origin !== config.issuerOrigin
  ) {
    throw new Error('OIDC end-session endpoint is not same-origin');
  }

  endpoint.searchParams.set('client_id', config.clientId);
  endpoint.searchParams.set(
    'post_logout_redirect_uri',
    config.postLogoutRedirectUri,
  );
  return endpoint;
}

async function readBoundedDiscoveryBody(response: Response): Promise<string> {
  if (!response.body) return '';

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_DISCOVERY_BYTES) {
        await reader.cancel();
        throw new Error('OIDC discovery response is too large');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

export async function resolveFederatedLogoutUrl(
  config: FederatedLogoutConfig,
  fetcher: typeof fetch = fetch,
): Promise<URL> {
  const response = await fetcher(config.discoveryUrl, {
    method: 'GET',
    headers: { accept: 'application/json' },
    redirect: 'error',
    cache: 'no-store',
    signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error('OIDC discovery request failed');
  }

  const declaredLength = Number.parseInt(
    response.headers.get('content-length') ?? '',
    10,
  );
  if (Number.isFinite(declaredLength) && declaredLength > MAX_DISCOVERY_BYTES) {
    try {
      await response.body?.cancel();
    } catch {
      // 连接回收失败不覆盖稳定的超限错误。
    }
    throw new Error('OIDC discovery response is too large');
  }
  const body = await readBoundedDiscoveryBody(response);

  let discovery: LogoutDiscoveryDocument;
  try {
    discovery = JSON.parse(body) as LogoutDiscoveryDocument;
  } catch {
    throw new Error('OIDC discovery response is invalid');
  }
  return buildFederatedLogoutUrl(config, discovery);
}
