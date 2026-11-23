export const PORTAL_BASE_PATH = "/chat";
export const PORTAL_AUTH_BASE_PATH = `${PORTAL_BASE_PATH}/api/auth`;

export function portalPath(path: string): string {
  if (!path.startsWith("/")) {
    throw new Error("portal path must be absolute");
  }
  if (
    path === PORTAL_BASE_PATH ||
    path.startsWith(`${PORTAL_BASE_PATH}/`) ||
    path.startsWith(`${PORTAL_BASE_PATH}?`)
  ) {
    return path;
  }
  return path === "/" ? PORTAL_BASE_PATH : `${PORTAL_BASE_PATH}${path}`;
}

export function stripPortalBasePath(pathname: string): string {
  if (pathname === PORTAL_BASE_PATH) return "/";
  if (pathname.startsWith(`${PORTAL_BASE_PATH}/`)) {
    return pathname.slice(PORTAL_BASE_PATH.length) || "/";
  }
  return pathname;
}
