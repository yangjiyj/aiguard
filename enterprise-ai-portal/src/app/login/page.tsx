import { PORTAL_ACCOUNT_LOGIN_ENABLED, PORTAL_OIDC_LOGIN_AVAILABLE } from "@/auth";
import { LoginOptions } from "@/components/login-options";
import { brand } from "@/lib/brand";

// 任务10：Chat 登录页（账号登录 + 企业 SSO 双入口）。
// 页面是服务端组件：仅从 NextAuth 回跳的固定 error 枚举里取 error code 做中性化展示，
// 不回显上游 OIDC error_description / token。两个入口的 kc_idp_hint 完全由服务端 auth.ts 固定。
export default async function LoginPage({
  searchParams,
}: {
  searchParams?: Promise<{ error?: string }>;
}) {
  const params = searchParams ? await searchParams : undefined;
  const error =
    params && typeof params.error === "string" ? params.error : null;

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="w-full max-w-sm space-y-6 text-center">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-primary text-xl font-bold text-primary-foreground">
          {brand.logoText}
        </div>
        <div className="space-y-1.5">
          <h1 className="text-2xl font-semibold tracking-tight">{brand.name}</h1>
          <p className="text-sm text-muted-foreground">选择登录方式</p>
        </div>
        <LoginOptions error={error} enterpriseLoginAvailable={PORTAL_OIDC_LOGIN_AVAILABLE} accountLoginAvailable={PORTAL_ACCOUNT_LOGIN_ENABLED} />
        <p className="text-xs text-muted-foreground">
          登录即表示您遵守公司信息安全规范，对话内容受审计留存。
        </p>
      </div>
    </div>
  );
}
