export interface GatewayEnv {
  baseUrl: string;
  portalSecret: string;
}

function firstNonEmpty(...values: Array<string | undefined>): string {
  for (const value of values) {
    const normalized = value?.trim();
    if (normalized) return normalized;
  }
  return "";
}

export function loadGatewayEnv(env: Readonly<Record<string, string | undefined>> = process.env): GatewayEnv {
  const baseUrl = firstNonEmpty(env.JJD_CP_URL, env.NEWAPI_CP_URL);
  const portalSecret = firstNonEmpty(
    env.JJD_PORTAL_API_SECRET,
    env.NEWAPI_PORTAL_API_SECRET,
  );
  const missing: string[] = [];
  if (!baseUrl) missing.push("JJD_CP_URL (or NEWAPI_CP_URL)");
  if (!portalSecret) {
    missing.push("JJD_PORTAL_API_SECRET (or NEWAPI_PORTAL_API_SECRET)");
  }
  if (missing.length > 0) {
    throw new Error(`Missing gateway configuration: ${missing.join(", ")}`);
  }
  return { baseUrl, portalSecret };
}
