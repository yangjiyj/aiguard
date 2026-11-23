"use client";

import * as React from "react";
import {
  MessageSquarePlus,
  Search,
  MoreHorizontal,
  Pencil,
  Trash2,
  PanelLeftClose,
  PanelLeft,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { BrandMark } from "@/components/brand-mark";
import { SidebarHeader, WorkspaceNav, useWorkspaceCollapsed, type WorkspaceKey } from "@/components/portal-nav";
import { portalPath } from "@/lib/portal-path";
import { SidebarAccount } from "@/components/sidebar-account";
import { useChatStore } from "./store";
import { PreferencesDialog } from "./preferences-dialog";
import { OUTCOME_LABELS, PORTAL_ERROR_MESSAGES } from "@/lib/portal-errors";
import { MAX_TITLE_LENGTH } from "@/lib/chat-history";
import { groupByDate } from "@/lib/chat-groups";


function ConversationRow({
  title,
  active,
  onSelect,
  onRename,
  onDelete,
}: {
  title: string;
  active: boolean;
  onSelect: () => void;
  onRename: () => void;
  onDelete: () => void;
}) {
  return (
    <div
      className={cn(
        "group/row relative flex h-8 items-center gap-1 rounded-lg px-3 text-[13px] transition-colors",
        active ? "bg-accent text-foreground" : "text-muted-foreground hover:bg-accent/60 hover:text-foreground"
      )}
    >
      <button
        onClick={onSelect}
        className="min-w-0 flex-1 truncate text-left"
        title={title}
      >
        {title}
      </button>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            className={cn(
              "shrink-0 rounded p-0.5 opacity-0 transition-opacity hover:bg-background group-hover/row:opacity-100",
              active && "opacity-100"
            )}
            aria-label="更多操作"
          >
            <MoreHorizontal className="h-4 w-4" />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onClick={onRename}>
            <Pencil className="mr-2 h-3.5 w-3.5" />
            重命名
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={onDelete}
            className="text-destructive focus:text-destructive"
          >
            <Trash2 className="mr-2 h-3.5 w-3.5" />
            删除
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

export function Sidebar({
  collapsed,
  onToggle,
  active,
}: {
  collapsed: boolean;
  onToggle: () => void;
  // 在工作台页时传入当前页；此时选会话、新对话都跳回对话页。
  active?: WorkspaceKey;
}) {
  const { conversations, currentId, select, newConversation, rename, remove, user } =
    useChatStore();
  const [prefsOpen, setPrefsOpen] = React.useState(false);
  const [workspaceCollapsed, toggleWorkspace] = useWorkspaceCollapsed();
  const startNew = React.useCallback(() => {
    if (active) window.location.assign(portalPath("/"));
    else void newConversation();
  }, [active, newConversation]);
  const openConversation = (id: string) => {
    if (active) window.location.assign(portalPath(`/?c=${encodeURIComponent(id)}`));
    else select(id);
  };
  const [query, setQuery] = React.useState("");
  const [editingId, setEditingId] = React.useState<string | null>(null);
  const [editValue, setEditValue] = React.useState("");

  const list = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    const base = conversations.map((c) => ({
      id: c.id,
      title: c.title,
      updatedAt: c.updatedAt,
    }));
    const filtered = q
      ? base.filter((c) => c.title.toLowerCase().includes(q))
      : base;
    return groupByDate(filtered);
  }, [conversations, query]);

  const startRename = (id: string, title: string) => {
    setEditingId(id);
    setEditValue(title);
  };
  const [listError, setListError] = React.useState<string | null>(null);
  const commitRename = () => {
    const id = editingId;
    setEditingId(null);
    if (!id) return;
    rename(id, editValue).catch(() => setListError(PORTAL_ERROR_MESSAGES.rename_failed));
  };
  // 6.13：删除先确认；失败要提示（不能静默）
  const confirmRemove = (id: string) => {
    if (!window.confirm(OUTCOME_LABELS.deleteConfirm)) return;
    setListError(null);
    remove(id).catch(() => setListError(PORTAL_ERROR_MESSAGES.delete_failed));
  };

  if (collapsed) {
    return (
      <aside className="flex h-full w-16 flex-col items-center border-r border-sidebar-border bg-sidebar py-3">
        <BrandMark size="sm" className="mb-3" />
        <Button
          variant="ghost"
          size="icon"
          onClick={onToggle}
          aria-label="展开侧栏"
          className="h-9 w-9 rounded-lg"
        >
          <PanelLeft className="h-4 w-4" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          onClick={startNew}
          aria-label="新建对话"
          className="mt-2 h-9 w-9 rounded-lg"
        >
          <MessageSquarePlus className="h-4 w-4" />
        </Button>
        <div className="mt-auto">
          <Avatar className="h-8 w-8">
            <AvatarFallback className="bg-accent text-xs text-foreground">
              {(user?.name ?? "U").slice(0, 1)}
            </AvatarFallback>
          </Avatar>
        </div>
      </aside>
    );
  }

  return (
    <aside className="flex h-full w-64 flex-col border-r border-sidebar-border bg-sidebar">
      <SidebarHeader
        onNewChat={startNew}
        trailing={
          <Button
            variant="ghost"
            size="icon"
            onClick={onToggle}
            aria-label="收起侧栏"
            className="h-7 w-7 rounded-lg text-muted-foreground"
          >
            <PanelLeftClose className="h-4 w-4" />
          </Button>
        }
      />

      <div className="px-2.5 pb-1 pt-2.5">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜索对话"
            className="h-8 w-full rounded-lg border border-transparent bg-transparent pl-9 pr-3 text-[13px] outline-none transition-colors placeholder:text-muted-foreground hover:bg-accent/60 focus-visible:border-sidebar-border focus-visible:bg-background"
          />
        </div>
      </div>

      <ScrollArea className="flex-1 px-2.5">
        <div className="pb-2">
          {listError && (
            <p role="alert" className="mx-1 mb-2 rounded-lg bg-destructive/5 px-2.5 py-1.5 text-xs text-destructive">
              {listError}
            </p>
          )}
          {list.map((group) => (
            <div key={group.label}>
              <p className="px-3 pb-1 pt-3 text-[11px] font-medium text-muted-foreground/70">
                {group.label}
              </p>
              {group.items.map((c) =>
                editingId === c.id ? (
                  <div key={c.id} className="py-0.5">
                    <input
                      autoFocus
                      value={editValue}
                      maxLength={MAX_TITLE_LENGTH}
                      onChange={(e) => setEditValue(e.target.value)}
                      onBlur={commitRename}
                      onKeyDown={(e) => {
                        // 6.13：输入法组字中的 Enter 是确认候选词，不是提交
                        if (e.nativeEvent.isComposing || e.nativeEvent.keyCode === 229) return;
                        if (e.key === "Enter") commitRename();
                        if (e.key === "Escape") setEditingId(null);
                      }}
                      className="h-8 w-full rounded-lg border bg-background px-3 text-[13px] outline-none focus:border-primary"
                    />
                  </div>
                ) : (
                  <ConversationRow
                    key={c.id}
                    title={c.title}
                    active={currentId === c.id}
                    onSelect={() => openConversation(c.id)}
                    onRename={() => startRename(c.id, c.title)}
                    onDelete={() => confirmRemove(c.id)}
                  />
                )
              )}
            </div>
          ))}
        </div>
      </ScrollArea>

      <WorkspaceNav active={active} collapsed={workspaceCollapsed} onToggle={toggleWorkspace} />
      <SidebarAccount user={user} onPreferences={() => setPrefsOpen(true)} />
      <PreferencesDialog open={prefsOpen} onOpenChange={setPrefsOpen} />
    </aside>
  );
}
