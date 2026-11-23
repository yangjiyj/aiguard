import { auth } from "@/auth";
import { redirect } from "next/navigation";
import { PortalShell } from "@/components/portal-shell";
import { ModelsPage } from "@/components/models/models-page";

export const dynamic = "force-dynamic";

export default async function Page() {
  // 服务端 redirect() 自动补 basePath（/chat），传不带前缀的路径即可。
  const session = await auth();
  if (!session?.user?.id) redirect("/login?error=session_expired");
  return <PortalShell active="models"><ModelsPage /></PortalShell>;
}
