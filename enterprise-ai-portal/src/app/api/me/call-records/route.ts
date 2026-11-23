import { auth } from '@/auth';
import {
  ControlPlaneError,
  listPortalCallRecords,
  PORTAL_DEFAULT_TENANT_ID,
} from '@/lib/control-plane';
import type { PortalCallRecordQuery } from '@/lib/control-plane';
import { requireActivePortalUser } from '@/lib/require-active-user';

function boundedQueryParam(
  searchParams: URLSearchParams,
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const raw = searchParams.get(name);
  if (raw === null || !/^-?\d+$/.test(raw)) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) return fallback;
  return Math.min(Math.max(value, minimum), maximum);
}

function cursorQueryParam(searchParams: URLSearchParams): string | null {
  const raw = searchParams.get('cursor');
  if (raw === null || raw === '') return '';
  if (raw.length > 512 || raw.trim() !== raw || !/^[A-Za-z0-9_-]+$/.test(raw)) {
    return null;
  }
  return raw;
}

const REQUEST_ID_PATTERN = /^(?:req_)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export async function GET(request: Request) {
  const session = await auth();
  if (!session?.user?.id) {
    return Response.json({ error: 'unauthorized' }, { status: 401 });
  }
  const active = await requireActivePortalUser(session);
  if (active instanceof Response) return active;

  const searchParams = new URL(request.url).searchParams;
  // The browser cannot select another principal. Attribution comes only from auth().
  void searchParams.get('user');
  const cursor = cursorQueryParam(searchParams);
  if (cursor === null) {
    return Response.json(
      { error: 'invalid_cursor' },
      { status: 400, headers: { 'cache-control': 'private, no-store' } },
    );
  }
  const requestId = searchParams.get('request_id') ?? '';
  if (requestId && !REQUEST_ID_PATTERN.test(requestId)) {
    return Response.json(
      { error: 'invalid_request_id' },
      { status: 400, headers: { 'cache-control': 'private, no-store' } },
    );
  }
  const query: PortalCallRecordQuery = {
    limit: boundedQueryParam(searchParams, 'limit', 50, 1, 200),
    days: boundedQueryParam(searchParams, 'days', 30, 1, 90),
  };
  if (cursor) query.cursor = cursor;
  if (requestId) query.requestId = requestId;

  try {
    const page = await listPortalCallRecords(
      PORTAL_DEFAULT_TENANT_ID,
      session.user.id,
      query,
    );
    return Response.json(page, {
      headers: { 'cache-control': 'private, no-store' },
    });
  } catch (error) {
    if (
      error instanceof ControlPlaneError &&
      error.status === 400 &&
      error.code === 'invalid_cursor'
    ) {
      return Response.json(
        { error: 'invalid_cursor' },
        { status: 400, headers: { 'cache-control': 'private, no-store' } },
      );
    }
    return Response.json(
      { error: 'control_plane_unavailable' },
      { status: 502, headers: { 'cache-control': 'private, no-store' } },
    );
  }
}
