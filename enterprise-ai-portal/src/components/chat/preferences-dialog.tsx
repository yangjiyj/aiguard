"use client";

import * as React from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { X } from "lucide-react";
import { useChatStore } from "./store";
import { useTheme } from "next-themes";
import { usePreferences } from "@/components/preferences-provider";
import { PREFS_STORAGE_KEY, MAX_QUICK_PROMPTS, type FontSize } from "@/lib/preferences";
import { allConversationsToMarkdown, downloadText, safeFilename } from "@/lib/export";
import { portalPath } from "@/lib/portal-path";
import { describePortalError, PORTAL_ERROR_MESSAGES } from "@/lib/portal-errors";
import { DEFAULT_TRASH_RETENTION_DAYS } from "@/lib/trash-policy";

export function PreferencesDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const { models, currentModel, setCurrentModel, refreshList } = useChatStore();
  const { theme, setTheme } = useTheme();
  const { prefs, update } = usePreferences();

  // 表单本地态：打开时从已存偏好载入，"取消"即丢弃
  const [defaultModel, setDefaultModel] = React.useState<string>("");
  const [sendOnEnter, setSendOnEnter] = React.useState<boolean>(true);
  const [fontSize, setFontSize] = React.useState<FontSize>("base");
  const [quickPrompts, setQuickPrompts] = React.useState<string[]>([]);
  const [newPrompt, setNewPrompt] = React.useState<string>("");
  const [exporting, setExporting] = React.useState(false);
  const [exportError, setExportError] = React.useState<string | null>(null);
  const [trash, setTrash] = React.useState<{ id: string; title: string }[]>([]);

  /* eslint-disable react-hooks/set-state-in-effect -- 打开对话框时从已保存偏好重置可取消的表单草稿。 */
  React.useEffect(() => {
    if (open) {
      setDefaultModel(prefs.defaultModel ?? currentModel);
      setSendOnEnter(prefs.sendOnEnter);
      setFontSize(prefs.fontSize);
      setQuickPrompts(prefs.quickPrompts);
      setNewPrompt("");
    }
  }, [open, currentModel, prefs]);
  /* eslint-enable react-hooks/set-state-in-effect */

  const addQuickPrompt = () => {
    const t = newPrompt.trim();
    if (!t) return;
    setQuickPrompts((prev) =>
      prev.includes(t) ? prev : [...prev, t].slice(0, MAX_QUICK_PROMPTS)
    );
    setNewPrompt("");
  };
  const removeQuickPrompt = (i: number) => {
    setQuickPrompts((prev) => prev.filter((_, idx) => idx !== i));
  };

  const onSave = () => {
    update({ defaultModel, sendOnEnter, fontSize, quickPrompts });
    // 默认模型立即应用到当前会话
    setCurrentModel(defaultModel);
    onOpenChange(false);
  };

  const onExportAll = async () => {
    setExporting(true);
    setExportError(null);
    try {
      // 6.17：一次请求取全量（服务端写导出留痕），不再逐条串行拉取；失败要提示
      const res = await fetch(portalPath("/api/conversations/export"));
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(describePortalError({ code: (body as { error?: string }).error ?? "export_failed", status: res.status }).message);
      }
      const data = (await res.json()) as { ai_label?: string; conversations?: { title: string; messages: { role: string; content: string; model?: string }[] }[] };
      const full = data.conversations ?? [];
      downloadText(
        `${safeFilename("我的对话历史")}-${full.length}个.md`,
        allConversationsToMarkdown(full, { aiLabel: data.ai_label })
      );
    } catch (e) {
      setExportError(e instanceof Error ? e.message : PORTAL_ERROR_MESSAGES.export_failed);
    } finally {
      setExporting(false);
    }
  };

  const loadTrash = React.useCallback(async () => {
    try {
      const res = await fetch(portalPath("/api/conversations?trash=1"));
      if (!res.ok) return;
      const data = (await res.json()) as { conversations?: { id: string; title: string }[] };
      setTrash(data.conversations ?? []);
    } catch {}
  }, []);

  /* eslint-disable react-hooks/set-state-in-effect -- 打开对话框时拉取回收站列表。 */
  React.useEffect(() => {
    if (open) void loadTrash();
  }, [open, loadTrash]);
  /* eslint-enable react-hooks/set-state-in-effect */

  const restore = async (id: string) => {
    const res = await fetch(portalPath(`/api/conversations/${id}`), {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ restore: true }),
    }).catch(() => null);
    if (res?.ok) {
      setTrash((prev) => prev.filter((c) => c.id !== id));
      await refreshList();
    }
  };

  const onClearLocalCache = () => {
    try {
      // 只清偏好与 chat store 的本地态；服务端历史不动
      window.localStorage.removeItem(PREFS_STORAGE_KEY);
      window.localStorage.removeItem("eap.conversations.v1");
    } catch {}
    onOpenChange(false);
    window.location.reload();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>偏好设置</DialogTitle>
          <DialogDescription>
            这些设置只保存在当前浏览器，不影响服务端数据。
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <label className="text-sm font-medium">默认模型</label>
            <Select value={defaultModel} onValueChange={setDefaultModel}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {models.map((m) => (
                  <SelectItem key={m.id} value={m.id}>
                    {m.displayName}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              新建对话时自动使用此模型。
            </p>
          </div>

          <div className="space-y-1.5">
            <label className="text-sm font-medium">发送方式</label>
            <Select
              value={sendOnEnter ? "enter" : "mod-enter"}
              onValueChange={(v) => setSendOnEnter(v === "enter")}
            >
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="enter">Enter 发送（Shift+Enter 换行）</SelectItem>
                <SelectItem value="mod-enter">⌘/Ctrl+Enter 发送（Enter 换行）</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5">
            <label className="text-sm font-medium">字号</label>
            <Select value={fontSize} onValueChange={(v) => setFontSize(v as FontSize)}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="sm">小</SelectItem>
                <SelectItem value="base">默认</SelectItem>
                <SelectItem value="lg">大</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">调整对话区文字大小。</p>
          </div>

          <div className="space-y-1.5">
            <label className="text-sm font-medium">常用提示词</label>
            <div className="flex gap-2">
              <input
                value={newPrompt}
                onChange={(e) => setNewPrompt(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    addQuickPrompt();
                  }
                }}
                placeholder="添加一条常用提示词…"
                className="h-9 flex-1 rounded-lg border bg-background px-3 text-sm outline-none transition-colors focus:border-primary/50 focus:ring-2 focus:ring-ring/20"
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={addQuickPrompt}
                className="shrink-0"
              >
                添加
              </Button>
            </div>
            {quickPrompts.length > 0 && (
              <ul className="mt-1 space-y-1">
                {quickPrompts.map((p, i) => (
                  <li
                    key={p}
                    className="flex items-center gap-2 rounded-lg border bg-card px-2.5 py-1.5 text-sm"
                  >
                    <span className="min-w-0 flex-1 truncate">{p}</span>
                    <button
                      type="button"
                      onClick={() => removeQuickPrompt(i)}
                      aria-label="删除"
                      className="shrink-0 rounded p-0.5 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </li>
                ))}
              </ul>
            )}
            <p className="text-xs text-muted-foreground">
              在欢迎页作为快捷入口，一键发起对话。最多 {MAX_QUICK_PROMPTS} 条。
            </p>
          </div>

          <div className="space-y-1.5">
            <label className="text-sm font-medium">主题</label>
            <Select value={theme ?? "system"} onValueChange={setTheme}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="light">浅色</SelectItem>
                <SelectItem value="dark">深色</SelectItem>
                <SelectItem value="system">跟随系统</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5">
            <label className="text-sm font-medium">导出</label>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={onExportAll}
              disabled={exporting}
              className="w-full justify-start"
            >
              {exporting ? "导出中…" : "导出全部对话为 Markdown"}
            </Button>
            <p className="text-xs text-muted-foreground">
              把你的全部对话历史下载成一个 Markdown 文件（只含你自己的对话）。
            </p>
            {exportError && <p role="alert" className="text-xs text-destructive">{exportError}</p>}
          </div>

          {trash.length > 0 && (
            <div className="space-y-1.5">
              <label className="text-sm font-medium">回收站</label>
              <ul className="max-h-40 space-y-1 overflow-y-auto">
                {trash.map((c) => (
                  <li key={c.id} className="flex items-center gap-2 rounded-lg border bg-card px-2.5 py-1.5 text-sm">
                    <span className="min-w-0 flex-1 truncate">{c.title}</span>
                    <Button type="button" variant="ghost" size="sm" className="h-7 shrink-0 px-2 text-xs" onClick={() => restore(c.id)}>
                      恢复
                    </Button>
                  </li>
                ))}
              </ul>
              <p className="text-xs text-muted-foreground">
                删除的对话保留 {DEFAULT_TRASH_RETENTION_DAYS} 天（以管理员配置为准），到期后自动清除。
              </p>
            </div>
          )}

          <div className="space-y-1.5">
            <label className="text-sm font-medium">本地缓存</label>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={onClearLocalCache}
              className="w-full justify-start"
            >
              清空本地缓存并刷新
            </Button>
            <p className="text-xs text-muted-foreground">
              只清除浏览器侧的偏好与临时缓存，不影响你的对话历史（历史在服务端）。
            </p>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button onClick={onSave}>保存</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
