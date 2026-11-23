"use client";

import * as React from "react";
import { ExternalLink, LayoutDashboard, LogOut, Settings, ShieldCheck } from "lucide-react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ThemeToggle } from "@/components/theme-toggle";
import { portalPath } from "@/lib/portal-path";

export type SidebarUser = { name?: string | null; department?: string | null; email?: string | null; role?: string | null };

function submitFederatedLogout() {
  const form = document.createElement("form");
  form.method = "POST";
  form.action = portalPath("/api/auth/federated-logout");
  form.hidden = true;
  document.body.appendChild(form);
  form.submit();
}

function roleLabel(role: string) {
  switch (role) {
    case "admin":
      return "管理员";
    case "manager":
      return "主管";
    default:
      return "员工";
  }
}

function UserAvatar({ user }: { user: SidebarUser | null }) {
  return <Avatar className="h-8 w-8">
    <AvatarFallback className="bg-accent text-xs font-medium text-foreground">{user?.name ? user.name.slice(0, 1) : ""}</AvatarFallback>
  </Avatar>;
}

// 账号区：不依赖对话 store，对话页和工作台共用。user 为 null 表示还在读取，只画占位。
export function SidebarAccount({ user, onPreferences, compact }: { user: SidebarUser | null; onPreferences?: () => void; compact?: boolean }) {
  const trigger = compact
    ? <button aria-label="账号菜单" className="rounded-full transition-opacity hover:opacity-80"><UserAvatar user={user} /></button>
    : <button className="flex min-w-0 flex-1 items-center gap-2.5 rounded-lg px-1.5 py-1 text-left transition-colors hover:bg-accent">
      <UserAvatar user={user} />
      {user ? <div className="min-w-0 flex-1 leading-tight">
        <p className="truncate text-[13px]">{user.name}</p>
        {user.department && <p className="truncate text-[11px] text-muted-foreground">{user.department}</p>}
      </div> : <div data-loading className="flex-1 space-y-1.5" aria-hidden><div className="h-2.5 w-16 animate-pulse rounded bg-muted" /><div className="h-2 w-10 animate-pulse rounded bg-muted" /></div>}
    </button>;
  const menu = <DropdownMenu>
      <DropdownMenuTrigger asChild>{trigger}</DropdownMenuTrigger>
      <DropdownMenuContent align={compact ? "end" : "start"} side={compact ? "bottom" : "top"} className="w-56">
        <DropdownMenuLabel className="flex flex-col gap-0.5">
          <span>{user?.name ?? ""}</span>
          <span className="text-xs font-normal text-muted-foreground">{user?.email ?? ""}</span>
          <span className="mt-1 inline-flex w-fit rounded bg-muted px-1.5 py-0.5 text-[10px]">{roleLabel(user?.role ?? "employee")}</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {(user?.role === "manager" || user?.role === "admin") && (
          <DropdownMenuItem asChild>
            <a href={process.env.NEXT_PUBLIC_PORTAL_DEPT_URL ?? "/portal/dept"} target="_blank" rel="noopener noreferrer">
              <LayoutDashboard className="mr-2 h-3.5 w-3.5" />
              部门看板
              <ExternalLink className="ml-auto h-3 w-3 text-muted-foreground" />
            </a>
          </DropdownMenuItem>
        )}
        {user?.role === "admin" && (
          <DropdownMenuItem asChild>
            <a href={process.env.NEXT_PUBLIC_PORTAL_ADMIN_URL ?? "/admin"} target="_blank" rel="noopener noreferrer">
              <ShieldCheck className="mr-2 h-3.5 w-3.5" />
              管理后台
              <ExternalLink className="ml-auto h-3 w-3 text-muted-foreground" />
            </a>
          </DropdownMenuItem>
        )}
        {onPreferences && (
          <DropdownMenuItem onSelect={(e) => { e.preventDefault(); onPreferences(); }}>
            <Settings className="mr-2 h-3.5 w-3.5" />
            偏好设置
          </DropdownMenuItem>
        )}
        <DropdownMenuSeparator />
        <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={submitFederatedLogout}>
          <LogOut className="mr-2 h-3.5 w-3.5" />
          退出登录
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>;
  if (compact) return menu;
  return <div className="flex items-center gap-1 border-t border-sidebar-border px-2 py-2.5">
    {menu}
    <ThemeToggle />
  </div>;
}
