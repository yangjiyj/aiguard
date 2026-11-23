export function loadConfig(env = process.env) {
    const required = (name) => {
        const value = env[name];
        if (!value)
            throw new Error(`缺少必需环境变量 ${name}`);
        return value;
    };
    const projectId = env.PORTAL_PROJECT_ID ?? 'project_default';
    // OIDC：issuer/clientId/redirect 有 dev 默认；client_secret 缺失则 OIDC 整体禁用（后台退回 break-glass）。
    const oidcIssuer = (env.PORTAL_OIDC_ISSUER ?? 'http://home:8180/realms/chat-portal-dev').replace(/\/+$/, '');
    const oidcClientSecret = env.PORTAL_OIDC_CLIENT_SECRET ?? '';
    const oidc = oidcClientSecret
        ? {
            issuer: oidcIssuer,
            authorizeUrl: `${oidcIssuer}/protocol/openid-connect/auth`,
            tokenUrl: `${oidcIssuer}/protocol/openid-connect/token`,
            jwksUri: `${oidcIssuer}/protocol/openid-connect/certs`,
            clientId: env.PORTAL_OIDC_CLIENT_ID ?? 'chat-portal-admin',
            clientSecret: oidcClientSecret,
            redirectUri: env.PORTAL_OIDC_REDIRECT_URI ?? 'http://home:8280/portal/auth/callback',
            scope: env.PORTAL_OIDC_SCOPE ?? 'openid email profile',
        }
        : null;
    return {
        port: Number(env.PORT ?? 8788),
        internalToken: required('PORTAL_INTERNAL_TOKEN'),
        keyEncSecret: required('PORTAL_KEY_ENC_SECRET'),
        gatewayBaseUrl: (env.GATEWAY_BASE_URL ?? 'http://gateway-core:8080').replace(/\/+$/, ''),
        gatewayCpUrl: (env.GATEWAY_CP_URL ?? 'http://control-plane:8081').replace(/\/+$/, ''),
        portalApiSecret: required('NEWAPI_PORTAL_API_SECRET'),
        lobeDatabaseUrl: required('LOBE_DATABASE_URL'),
        tenantId: env.PORTAL_TENANT_ID ?? 'tenant_default',
        projectId,
        keyTtlDays: Number(env.PORTAL_KEY_TTL_DAYS ?? 90),
        // 无命中默认落此 project（未配则退回 PORTAL_PROJECT_ID / project_default）
        defaultProjectId: env.PORTAL_DEFAULT_PROJECT_ID ?? projectId,
        reevalTtlSec: Number(env.PORTAL_REEVAL_TTL_SEC ?? 300),
        // 未配置 → adminAuth 一律拒绝，break-glass 入口锁死（不 fail-fast，主链照常）
        adminToken: env.PORTAL_ADMIN_TOKEN ?? '',
        oidc,
        cookieSecure: (env.PORTAL_COOKIE_SECURE ?? 'false') === 'true',
        postLoginPath: env.PORTAL_OIDC_POST_LOGIN_PATH ?? '/admin',
        // 严格只认字面量 "true"（防误开）；默认 false＝打通功能锁死。
        userSyncAllowed: env.PORTAL_GATEWAY_USER_SYNC_ALLOWED === 'true',
        // 严格只认字面量 "true"；默认 false＝读本地（安全默认，验证网关读通后再翻）。
        gatewayRulesRead: env.PORTAL_GATEWAY_RULES_READ === 'true',
    };
}
