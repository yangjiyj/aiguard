import {normalizeGatewayBase} from './gateway-access';
export const normalizeOpenAIBaseUrl = (value: string): string => normalizeGatewayBase(value);

export function resolvePublicGatewayUrl(env: NodeJS.ProcessEnv | Record<string, string | undefined>): string {
  const configured = env.GATEWAY_PUBLIC_URL?.trim() ?? '';
  if (configured) return normalizeOpenAIBaseUrl(configured);

  return '';
}
