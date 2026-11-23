"use client";

import React, { useState } from "react";
import { signIn } from "next-auth/react";
import { portalPath } from "@/lib/portal-path";
import { EmployeeLoginForm } from "@/components/employee-login-form";

const FRIENDLY_ERROR_TEXT: Record<string, string> = {
  OAuthCallback: "登录未完成，请重试或联系管理员。",
  OAuthCallbackError: "登录未完成，请重试或联系管理员。",
  identity_conflict: "登录身份与已有账号冲突，请联系管理员在用户管理中合并账号或换绑身份。",
  identity_not_ready: "个人入口尚未配置完成，请联系管理员检查身份绑定与未分配部门。",
  AccessDenied: "登录被拒绝，请联系管理员。",
  Configuration: "登录服务暂不可用，请稍后再试。",
  Default: "登录未完成，请重试。",
  session_expired: "登录状态已失效，请重新登录。",
};

function friendlyError(code: string) {
  const message = FRIENDLY_ERROR_TEXT[code];
  return typeof message === "string" ? message : FRIENDLY_ERROR_TEXT.Default;
}

export function LoginOptions({ error, enterpriseLoginAvailable = true, accountLoginAvailable = true }: { error?: string | null; enterpriseLoginAvailable?: boolean; accountLoginAvailable?: boolean }) {
  const [pending, setPending] = useState<"account" | "sso" | null>(null);
  const [localPending,setLocalPending]=useState(false);
  const [enterpriseFailed, setEnterpriseFailed] = useState(false);
  const enterpriseSignIn = async (provider: "account-login" | "enterprise-sso", kind: "account" | "sso") => {
    if(pending!==null||localPending)return;
    setPending(kind);
    setEnterpriseFailed(false);
    try {
      await signIn(provider, { callbackUrl: portalPath("/") });
    } catch {
      setEnterpriseFailed(true);
      setPending(null);
    }
  };

  return (
    <div className="space-y-5">
      {(error || enterpriseFailed) && <p role="alert" className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">{enterpriseFailed ? FRIENDLY_ERROR_TEXT.Configuration : friendlyError(error ?? "")}</p>}
      <EmployeeLoginForm disabled={pending !== null} onPendingChange={setLocalPending} />
      {enterpriseLoginAvailable && <div className="space-y-3 border-t pt-5">
        <p className="text-xs text-muted-foreground">{accountLoginAvailable ? "企业目录账号也可通过以下入口登录" : "也可以使用企业 SSO 登录"}</p>
        {accountLoginAvailable && <button type="button" onClick={() => { void enterpriseSignIn("account-login", "account"); }} disabled={pending !== null || localPending} className="h-11 w-full rounded-lg border border-input bg-background px-4 text-sm font-medium transition-colors hover:bg-accent disabled:opacity-60">{pending === "account" ? "正在跳转…" : "企业目录账号登录"}</button>}
        <button type="button" onClick={() => { void enterpriseSignIn("enterprise-sso", "sso"); }} disabled={pending !== null || localPending} className="h-11 w-full rounded-lg border border-input bg-background px-4 text-sm font-medium transition-colors hover:bg-accent disabled:opacity-60">{pending === "sso" ? "正在跳转…" : "企业 SSO 登录"}</button>
      </div>}
    </div>
  );
}

export default LoginOptions;
