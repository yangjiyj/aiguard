"use client";

import { useEffect } from "react";
import { useSession } from "next-auth/react";
import { usePathname } from "next/navigation";
import { portalPath, stripPortalBasePath } from "@/lib/portal-path";

export function SessionGuard({ children }: { children: React.ReactNode }) {
  const { data, status } = useSession();
  const pathname = usePathname();
  const route = stripPortalBasePath(pathname ?? "/login");
  const protectedPage = route !== "/login" && !route.startsWith("/login/") && route !== "/style";
  const expired = protectedPage && (status === "unauthenticated" || (status === "authenticated" && !data?.user?.id));
  useEffect(() => {
    if (expired) window.location.replace(portalPath("/login?error=session_expired"));
  }, [expired]);
  return children;
}
