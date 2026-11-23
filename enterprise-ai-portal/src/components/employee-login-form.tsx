"use client";

import React, { useCallback, useEffect, useState } from "react";
import { signIn } from "next-auth/react";
import Image from "next/image";
import { Eye, EyeOff, RefreshCw } from "lucide-react";
import { portalPath } from "@/lib/portal-path";

type Captcha = { captcha_id: string; image: string; expires_in?: number };

const LOGIN_ERRORS: Record<string, string> = {
  captcha_invalid: "验证码不正确或已失效，请重新输入。",
  invalid_credentials: "登录失败，请检查凭据；公司统一身份账号请使用企业账号登录。",
  account_locked: "登录失败，请检查凭据；公司统一身份账号请使用企业账号登录。",
  rate_limited: "登录尝试过于频繁，请稍后重试。",
  totp_required: "请输入账号已绑定的动态验证码。",
  totp_invalid: "动态验证码不正确，请重试。",
  password_change_required: "账号密码需要更新，请设置新密码后继续登录。",
  password_policy_violation: "新密码不符合账号安全策略，请修改后重试。",
  password_history_violation: "请使用未曾用过的新密码。",
  password_updated_retry: "密码已更新，登录交接暂未完成，请使用新密码重试。",
  password_sync_unavailable: "密码尚未更新，登录服务暂不可用，请稍后使用原密码重试。",
  password_identity_sync_failed: "密码同步未完成，账号已暂停登录，请联系管理员修复。",
  password_updated_identity_sync_failed: "新密码已保存，账号已暂停登录，请联系管理员修复后再登录。",
  password_change_conflict: "账号凭据已发生变化，请刷新页面后重新登录。",
  password_managed_externally: "此账号的密码由企业身份源管理，请在企业身份源修改密码。",
  authorization_denied: "当前账号未获准使用 Chat，请联系管理员。",
  totp_setup_required: "请先在管理控制台绑定动态验证码后登录个人中心。",
  identity_not_ready: "个人入口尚未配置完成，请联系管理员检查身份绑定与未分配部门。",
  login_unavailable: "登录服务暂不可用，请稍后重试。",
};

export function EmployeeLoginForm({ disabled = false, onPendingChange }: { disabled?: boolean; onPendingChange?:(pending:boolean)=>void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [needsPasswordChange, setNeedsPasswordChange] = useState(false);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [captcha, setCaptcha] = useState<Captcha | null>(null);
  const [captchaCode, setCaptchaCode] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [needsTotp, setNeedsTotp] = useState(false);
  const [loadingCaptcha, setLoadingCaptcha] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const refreshCaptcha = useCallback(async () => {
    setLoadingCaptcha(true);
    setCaptcha(null);
    setCaptchaCode("");
    try {
      const response = await fetch(portalPath("/api/login/captcha"), { cache: "no-store" });
      const payload = await response.json() as Partial<Captcha>;
      if (!response.ok || typeof payload.captcha_id !== "string" || typeof payload.image !== "string") {
        throw new Error("captcha_unavailable");
      }
      setCaptcha(payload as Captcha);
    } catch {
      setError("验证码暂不可用，请刷新重试。");
    } finally {
      setLoadingCaptcha(false);
    }
  }, []);

  useEffect(() => { void Promise.resolve().then(refreshCaptcha); }, [refreshCaptcha]);

  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (submitting || disabled || !captcha) return;
    if (needsPasswordChange && newPassword !== confirmPassword) {
      setError("两次输入的新密码不一致，请重新确认。");
      return;
    }
    setSubmitting(true);
    onPendingChange?.(true);
    setError("");
    try {
      const result = await signIn("employee-local", {
        username: username.trim(), password, captcha_id: captcha.captcha_id,
        captcha_code: captchaCode.trim(), totp_code: totpCode.trim(),
        ...(needsPasswordChange ? {new_password:newPassword} : {}),
        redirect: false, redirectTo: portalPath("/"),
      });
      if (result?.ok && !result.error) {
        setPassword("");
        setNewPassword("");
        setConfirmPassword("");
        setTotpCode("");
        window.location.replace(portalPath("/"));
        return;
      }
      const code = result?.code ?? "invalid_credentials";
      if (code === "totp_required" || code === "totp_invalid") setNeedsTotp(true);
      if (code === "password_change_required") setNeedsPasswordChange(true);
      if (code === "password_updated_retry") {
        setPassword(newPassword);
        setNewPassword("");
        setConfirmPassword("");
        setNeedsPasswordChange(false);
      }
      setError(typeof LOGIN_ERRORS[code] === "string" ? LOGIN_ERRORS[code] : LOGIN_ERRORS.login_unavailable);
      await refreshCaptcha();
    } catch {
      setError(LOGIN_ERRORS.login_unavailable);
      await refreshCaptcha();
    } finally {
      setSubmitting(false);
      onPendingChange?.(false);
    }
  };

  const busy = disabled || submitting;
  const inputClass = "mt-1.5 h-11 w-full rounded-lg border border-input bg-background px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-60";
  return (
    <form onSubmit={submit} className="space-y-4 text-left" aria-label="员工账号登录">
      <label htmlFor="employee-username" className="block text-sm font-medium">
        用户名
        <input id="employee-username" name="username" value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" maxLength={128} required disabled={busy} className={inputClass} />
      </label>
      <div>
        <label htmlFor="employee-password" className="block text-sm font-medium">密码</label>
        <div className="relative">
          <input id="employee-password" name="password" type={showPassword ? "text" : "password"} value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" maxLength={1024} required disabled={busy} className={inputClass + " pr-11"} />
          <button type="button" onClick={() => setShowPassword((value) => !value)} aria-label={showPassword ? "隐藏密码" : "显示密码"} disabled={busy} className="absolute bottom-0 right-0 flex h-11 w-11 items-center justify-center text-muted-foreground hover:text-foreground">{showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>
        </div>
      </div>
      {needsPasswordChange && <div className="space-y-3 rounded-lg border bg-muted/30 p-3">
        <label htmlFor="employee-new-password" className="block text-sm font-medium">新密码<input id="employee-new-password" name="new_password" type="password" value={newPassword} onChange={(event)=>setNewPassword(event.target.value)} autoComplete="new-password" minLength={8} maxLength={1024} required disabled={busy} className={inputClass} /></label>
        <label htmlFor="employee-confirm-password" className="block text-sm font-medium">确认新密码<input id="employee-confirm-password" name="new_password_confirmation" type="password" value={confirmPassword} onChange={(event)=>setConfirmPassword(event.target.value)} autoComplete="new-password" minLength={8} maxLength={1024} required disabled={busy} className={inputClass} /></label>
      </div>}
      <div>
        <label htmlFor="employee-captcha" className="block text-sm font-medium">验证码</label>
        <div className="mt-1.5 flex items-center gap-2">
          <input id="employee-captcha" name="captcha_code" value={captchaCode} onChange={(event) => setCaptchaCode(event.target.value)} autoComplete="off" maxLength={16} required disabled={busy || loadingCaptcha} className={inputClass.replace("mt-1.5 ", "") + " min-w-0 flex-1"} />
          <div className="flex h-11 w-28 shrink-0 items-center justify-center overflow-hidden rounded-lg border bg-muted">
            {captcha ? <Image src={captcha.image} alt="登录验证码" width={112} height={44} unoptimized className="h-full w-full object-contain" /> : <span className="text-xs text-muted-foreground">{loadingCaptcha ? "加载中…" : "加载失败"}</span>}
          </div>
          <button type="button" onClick={() => { setError(""); void refreshCaptcha(); }} disabled={busy || loadingCaptcha} className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border hover:bg-accent disabled:opacity-50" aria-label="刷新验证码"><RefreshCw className={"h-4 w-4" + (loadingCaptcha ? " animate-spin" : "")} /></button>
        </div>
      </div>
      {needsTotp && <label htmlFor="employee-totp" className="block text-sm font-medium">动态验证码<input id="employee-totp" name="totp_code" value={totpCode} onChange={(event) => setTotpCode(event.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={6} required disabled={busy} className={inputClass} /></label>}
      {error && <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>}
      <button type="submit" disabled={busy || loadingCaptcha || !captcha} className="h-11 w-full rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50">{submitting ? "正在登录…" : "登录 Chat"}</button>
    </form>
  );
}
