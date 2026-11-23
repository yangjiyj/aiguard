import {signedClientIP,clientIPHeaders} from './signed-client-ip';
import { CredentialsSignin } from 'next-auth';
import { loadGatewayEnv } from './gateway-env';
import { PORTAL_DEFAULT_TENANT_ID, redeemChatLoginTicket, type ChatLoginIdentity } from './control-plane';

type LoginCode = 'invalid_credentials' | 'captcha_invalid' | 'account_locked' | 'rate_limited' |
  'totp_required' | 'totp_invalid' | 'password_change_required' | 'password_policy_violation' |
  'password_history_violation' | 'password_updated_retry' | 'authorization_denied' | 'login_unavailable' |
  'password_sync_unavailable' | 'password_identity_sync_failed' | 'password_updated_identity_sync_failed' |
  'password_change_conflict' | 'password_managed_externally' | 'totp_setup_required' | 'identity_not_ready';

export class EmployeeCredentialsError extends CredentialsSignin {
  code: LoginCode;
  constructor(code: LoginCode) { super(); this.code = code; }
}

const ERROR_CODES: Record<string, LoginCode> = {
  invalid_captcha:'captcha_invalid', invalid_credentials:'invalid_credentials', account_locked:'account_locked',
  rate_limited:'rate_limited', totp_required:'totp_required', totp_invalid:'totp_invalid',
  password_change_required:'password_change_required', authorization_denied:'authorization_denied',
  password_policy_violation:'password_policy_violation',password_history_violation:'password_history_violation',
  password_too_short:'password_policy_violation',password_too_few_classes:'password_policy_violation',
  password_contains_username:'password_policy_violation',password_reused:'password_history_violation',
  password_updated_session_revoke_failed:'password_updated_retry',
  password_sync_unavailable:'password_sync_unavailable',password_identity_sync_failed:'password_identity_sync_failed',
  password_updated_identity_sync_failed:'password_updated_identity_sync_failed',password_change_conflict:'password_change_conflict',
  password_managed_externally:'password_managed_externally',
  totp_setup_required:'totp_setup_required',login_ip_not_allowed:'authorization_denied',chat_identity_not_ready:'identity_not_ready', chat_login_unavailable:'login_unavailable', captcha_unavailable:'login_unavailable',
};

function normalizedCredentials(raw: Partial<Record<string, unknown>>) {
  const string = (name: string) => typeof raw[name] === 'string' ? raw[name] as string : '';
  const rawUsername = string('username');
  const username = rawUsername.trim();
  const password = string('password');
  const captchaId = string('captcha_id').trim();
  const captchaCode = string('captcha_code').trim();
  const totpCode = string('totp_code').trim();
  const newPassword = string('new_password');
  if (!username || username.length>128 || /[\u0000-\u001f\u007f]/.test(rawUsername) ||
      !password || password.length>1024 || !captchaId || captchaId.length>256 ||
      /[\u0000-\u001f\u007f]/.test(captchaId) || !captchaCode || captchaCode.length>16 ||
      !/^[A-Za-z0-9]+$/.test(captchaCode) || (totpCode && !/^\d{6}$/.test(totpCode)) || newPassword.length>1024) {
    throw new EmployeeCredentialsError('invalid_credentials');
  }
  return {username,password,captcha_id:captchaId,captcha_code:captchaCode,totp_code:totpCode,...(newPassword?{new_password:newPassword}:{})};
}

export async function authenticateEmployeeCredentials(credentials: Partial<Record<string, unknown>>, request?:Request): Promise<ChatLoginIdentity> {
  const body = normalizedCredentials(credentials);
  const clientHeaders=request?clientIPHeaders(signedClientIP(request.headers)):{};
  try {
    const gateway = loadGatewayEnv();
    const response = await fetch(gateway.baseUrl+'/admin/v1/employee-login', {
      method:'POST', headers:{'content-type':'application/json', 'X-JJDGuard-Tenant-Id':PORTAL_DEFAULT_TENANT_ID,...clientHeaders},
      body:JSON.stringify(body), cache:'no-store', signal:AbortSignal.timeout(10000),
    });
    const payload = await response.json().catch(()=>null) as {
      user?: {id?:unknown; role?:unknown; tenant_id?:unknown}; chat_ticket?:unknown; error?:unknown;
    } | null;
    if (!response.ok) {
      const envelope = payload?.error;
      const serverCode = typeof envelope==='string' ? envelope :
        envelope && typeof envelope==='object' && 'code' in envelope && typeof envelope.code==='string' ? envelope.code : '';
      if(body.new_password && serverCode==='chat_login_unavailable')throw new EmployeeCredentialsError('password_updated_retry');
      const mapped = ERROR_CODES[serverCode];
      const code = typeof mapped==='string' ? mapped : undefined;
      throw new EmployeeCredentialsError(code ?? (response.status===401 ? 'invalid_credentials' : 'login_unavailable'));
    }
    if (!payload?.user || typeof payload.user.role!=='string' || !payload.user.role.trim() || payload.user.tenant_id!==PORTAL_DEFAULT_TENANT_ID ||
        typeof payload.user.id!=='string' || !payload.user.id || typeof payload.chat_ticket!=='string' ||
        !/^[A-Za-z0-9_-]{43}$/.test(payload.chat_ticket)) throw new EmployeeCredentialsError('authorization_denied');
    const identity = await redeemChatLoginTicket(payload.chat_ticket, {fetchImpl:(input,init)=>fetch(input,{...init,signal:AbortSignal.timeout(10000)})});
    if (identity.userId!==payload.user.id || identity.tenantId!==PORTAL_DEFAULT_TENANT_ID || !(identity.portalAllowed ?? identity.chatAllowed)) {
      throw new EmployeeCredentialsError('authorization_denied');
    }
    return identity;
  } catch (error) {
    if (error instanceof EmployeeCredentialsError) throw error;
    // Credential errors and upstream payloads never enter Auth.js logs or browser URLs.
    throw new EmployeeCredentialsError('login_unavailable');
  }
}
