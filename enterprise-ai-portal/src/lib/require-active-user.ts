// W2.3: every portal BFF route that acts for a signed-in employee must re-check,
// on each request, that the control-plane user is still active. The NextAuth
// JWT only proves who signed in and when; it keeps working after the account is
// disabled, removed, or deactivated by directory sync.
//
// The check fails closed: a control-plane outage returns 502 instead of letting
// a possibly disabled user through.
//
// Usage:
//   const active = await requireActivePortalUser(await auth());
//   if (active instanceof Response) return active;
//   active.user.id // authoritative control-plane user id
import {
  ControlPlaneError,
  getCurrentPortalAuthorization,
  PORTAL_DEFAULT_TENANT_ID,
  type EnsurePortalUserOptions,
  type PortalAuthorizationContext,
} from './control-plane';

export interface ActivePortalUser extends Pick<PortalAuthorizationContext,'modelSources'|'extraGrants'|'staleModels'> {
  /** Control-plane user id; equals session.user.id. */
  id: string;
  email: string | null;
  name: string | null;
  departmentId: string;
  departmentName: string;
  departmentVersion: number;
  modelIds: string[];
  projectId?: string;
  historyUserIds?:string[];
}

export interface ActivePortalUserResult {
  user: ActivePortalUser;
}

/** Structural subset of the NextAuth session; avoids importing '@/auth' here. */
export interface PortalSessionLike {
  user?: {
    id?: unknown;
    email?: unknown;
    name?: unknown;
    localLogin?: unknown;
    localCredentialVersion?: unknown;
    externalSubject?: unknown;
    tenantId?: unknown;
  } | null;
}

export interface RequireActivePortalUserOptions extends EnsurePortalUserOptions {
  tenantId?: string;
}

const NO_STORE = { 'cache-control': 'private, no-store' } as const;

function deny(error: string, status: number): Response {
  return Response.json({ error }, { status, headers: NO_STORE });
}

function optionalString(value: unknown): string | null {
  return typeof value === 'string' && value ? value : null;
}

export async function requireActivePortalUser(
  session: PortalSessionLike | null | undefined,
  options: RequireActivePortalUserOptions = {},
): Promise<ActivePortalUserResult | Response> {
  const rawId = session?.user?.id;
  const userId = typeof rawId === 'string' ? rawId.trim() : '';
  if (!userId) return deny('unauthorized', 401);

  const { tenantId, ...controlPlaneOptions } = options;
  let authorization;
  try {
    authorization = await getCurrentPortalAuthorization(
      tenantId || optionalString(session?.user?.tenantId) || PORTAL_DEFAULT_TENANT_ID,
      userId,
      {...controlPlaneOptions,
       ...(typeof session?.user?.externalSubject==='string'?{externalSubject:session.user.externalSubject,loginMode:session.user.localLogin===true?'local' as const:'oidc' as const,...(session.user.localLogin===true&&typeof session.user.localCredentialVersion==='number'?{localCredentialVersion:session.user.localCredentialVersion}:{})}:{}),
      },
    );
  } catch (error) {
    if (error instanceof ControlPlaneError) {
      // Personal portal revocation (disabled, deactivated, or non-human identity).
      if (error.code === 'authorization_denied') return deny('authorization_denied', 403);
      // The user row is gone or belongs to another tenant: the session is stale.
      if (error.status === 404 || error.code === 'not_found') return deny('user_inactive', 403);
    }
    return deny('control_plane_unavailable', 502);
  }

  // Session rechecks may use a short cache, but a local credential must never
  // act for an account taken over by enterprise directory credentials.
  if (session?.user?.localLogin === true && (
    !Number.isSafeInteger(session.user.localCredentialVersion) || Number(session.user.localCredentialVersion)<=0 ||
    authorization.localCredentialVersion !== session.user.localCredentialVersion || authorization.localLoginAllowed !== true ||
    authorization.localExternalSubject !== session.user.externalSubject
  )) return deny('local_identity_revoked', 403);

  return {
    user: {
      id: authorization.userId,
      email: optionalString(session?.user?.email),
      name: optionalString(session?.user?.name),
      departmentId: authorization.departmentId,
      departmentName: authorization.departmentName,
      departmentVersion: authorization.departmentVersion,
      modelIds: authorization.modelIds,
      ...(authorization.modelSources?{modelSources:authorization.modelSources}:{}),...(authorization.extraGrants?{extraGrants:authorization.extraGrants}:{}),...(authorization.staleModels?{staleModels:authorization.staleModels}:{}),
      ...(authorization.historyUserIds?{historyUserIds:authorization.historyUserIds}:{}),
      ...(authorization.projectId ? {projectId:authorization.projectId} : {}),
    },
  };
}
