import { auth } from "@/auth";
import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { ChatStoreProvider } from "@/components/chat/store";

export const dynamic = "force-dynamic";

export default async function Page() {
  const session = await auth();
  if (!session?.user?.id) {
    // 服务端 redirect() 会自动补 next.config.ts 的 basePath（/chat），
    // 这里必须传不带前缀的路径；包 portalPath 会变成 /chat/chat/login。
    redirect("/login?error=session_expired");
  }
  return (
    <ChatStoreProvider>
      <AppShell />
    </ChatStoreProvider>
  );
}
