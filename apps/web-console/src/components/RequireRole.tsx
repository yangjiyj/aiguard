import { Navigate } from "react-router-dom"
import { useAuthStore } from "../stores/auth"
import { canAccessPath, roleHome } from "../utils/access"

// Guards a route by its path in PAGE_ACCESS. Unlike the pre-W4 guard there is
// no blanket platform_admin bypass.
export default function RequireRole({ path, children }: { path: string; children: JSX.Element }) {
  const { user } = useAuthStore()
  const role = user?.role || ""
  if (canAccessPath(role, path, user?.tenant_id)) return children
  return <Navigate to={roleHome(role)} replace />
}

