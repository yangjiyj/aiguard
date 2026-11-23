import { auth } from "@/auth";
import { redirect } from "next/navigation";
import BillingPage from "@/components/billing-page";
import { PortalShell } from "@/components/portal-shell";

export const dynamic = "force-dynamic";

export default async function Page() {
  // 服务端 redirect() 自动补 basePath（/chat），传不带前缀的路径即可；
  // 包 portalPath 会产生 /chat/chat/... 双重前缀。
  // Customer self-service is available in both prepaid and usage-only deployments.
  // Billing enforcement belongs to the control plane, not a compiled public flag.
  const session = await auth();
  if (!session?.user?.id) redirect("/login?error=session_expired");
  return <PortalShell active="billing"><BillingPage /></PortalShell>;
}
