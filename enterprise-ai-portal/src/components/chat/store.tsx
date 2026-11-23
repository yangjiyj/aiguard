"use client";

import * as React from "react";
import { portalPath } from "@/lib/portal-path";
import { clearConversationParam, initialConversationId } from "@/lib/chat-initial";
import type { PortalError } from "@/lib/portal-errors";
import type { ImageAttachmentMeta } from "@/lib/upload";
import type { FileAttachment } from "./composer";

export type DisplayAttachment = { name: string; mime: string; size: number; previewUrl: string };

/** assistant 轮次结局（与服务端 Message.status 同口径）。null/undefined = 完整。 */
export type MessageStatus = "interrupted" | "blocked" | "failed" | null;

export type ChatMessage = {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  model?: string;
  createdAt?: string;
  attachments?: DisplayAttachment[]; // 仅内存展示，不落库、不进历史请求
  /** 6.6：当轮原始附件（仅内存），重新生成时原样重发 */
  sendImages?: ImageAttachmentMeta[];
  sendFiles?: FileAttachment[];
  status?: MessageStatus;
  error?: PortalError;
  /** 6.16：网关 X-Security-Action（mask / audit） */
  securityAction?: string;
  /** 浏览器端本轮计时，仅内存展示 */
  timing?: { ttftMs: number | null; tps: number | null };
};

export type Conversation = {
  id: string;
  title: string;
  model?: string;
  updatedAt: number;
  messages: ChatMessage[];
};

export type CurrentUser = {
  id: string;
  email: string;
  name: string | null;
  department: string | null;
  role: string;
};

export type ModelsState = "loading" | "ready" | "empty" | "error";

export type ChatStore = {
  conversations: Conversation[];
  currentId: string | null;
  current: Conversation | null;
  /** 6.7：当前会话消息是否已从服务端加载完成（未完成禁用发送） */
  currentLoaded: boolean;
  currentModel: string;
  modelsState: ModelsState;
  user: CurrentUser | null;
  models: { id: string; displayName: string; capabilities?: Record<string, unknown> }[];
  /** 读最新会话快照（不受闭包影响） */
  getConversation: (id: string) => Conversation | undefined;
  select: (id: string | null) => void;
  newConversation: () => Promise<string>;
  ensureConversationPersisted: (id: string, fallbackTitle: string) => Promise<string>;
  rename: (id: string, title: string) => Promise<void>;
  remove: (id: string) => Promise<void>;
  setCurrentModel: (model: string) => void;
  appendMessage: (id: string, msg: ChatMessage) => void;
  updateMessage: (id: string, messageId: string, content: string) => void;
  patchMessage: (id: string, messageId: string, patch: Partial<ChatMessage>) => void;
  appendToMessage: (id: string, messageId: string, chunk: string) => void;
  loadConversationMessages: (id: string) => Promise<void>;
  refreshList: () => Promise<void>;
};

const Ctx = React.createContext<ChatStore | null>(null);

type ServerMessage = {
  id: string;
  role: string;
  content: string;
  model: string | null;
  createdAt: string;
  status?: string | null;
  errorCode?: string | null;
  /** 输出计量（服务端落库，历史消息据此回显「首字 · t/s」） */
  ttftMs?: number | null;
  tps?: number | null;
};

function toStatus(s: string | null | undefined): MessageStatus {
  return s === "interrupted" || s === "blocked" || s === "failed" ? s : null;
}

export function ChatStoreProvider({ children }: { children: React.ReactNode }) {
  const [conversations, setConversations] = React.useState<Conversation[]>([]);
  const [currentId, setCurrentId] = React.useState<string | null>(null);
  // 6.11：不再硬编码默认模型；模型接口失败/为空时保持空，发送按钮禁用
  const [currentModel, setCurrentModel] = React.useState("");
  const [modelsState, setModelsState] = React.useState<ModelsState>("loading");
  const [user, setUser] = React.useState<CurrentUser | null>(null);
  const [models, setModels] = React.useState<{ id: string; displayName: string }[]>([]);
  const [loadedIds, setLoadedIds] = React.useState<ReadonlySet<string>>(() => new Set());
  const loadingRef = React.useRef<Set<string>>(new Set());
  const conversationsRef = React.useRef<Conversation[]>([]);
  React.useLayoutEffect(() => {
    conversationsRef.current = conversations;
  }, [conversations]);

  const markLoaded = React.useCallback((id: string) => {
    setLoadedIds((prev) => {
      if (prev.has(id)) return prev;
      const next = new Set(prev);
      next.add(id);
      return next;
    });
  }, []);

  const getConversation = React.useCallback(
    (id: string) => conversationsRef.current.find((c) => c.id === id),
    [],
  );

  // 初始化：拉用户、模型、会话列表
  const refreshList = React.useCallback(async () => {
    try {
      const res = await fetch(portalPath("/api/conversations"));
      if (!res.ok) return;
      const data = await res.json();
      const list: Conversation[] = (data.conversations ?? []).map((c: { id: string; title: string; updatedAt: string }) => ({
        id: c.id,
        title: c.title,
        updatedAt: new Date(c.updatedAt).getTime(),
        messages: [],
      }));
      setConversations((prev) => {
        // 已在内存里的会话保留消息（避免刷新列表把正在进行的对话清空）
        const byId = new Map(prev.map((c) => [c.id, c]));
        return list.map((c) => {
          const existing = byId.get(c.id);
          return existing ? { ...c, messages: existing.messages } : c;
        });
      });
      const initial = initialConversationId(window.location.search, list.map((c) => c.id));
      if (initial) clearConversationParam();
      setCurrentId((cur) => cur ?? initial);
    } catch {}
  }, []);

  React.useEffect(() => {
    (async () => {
      try {
        const meRes = await fetch(portalPath("/api/me"));
        if (meRes.ok) {
          const me = await meRes.json();
          if (me.authenticated) {
            setUser(me.user);
          }
        }
      } catch {}
      try {
        const mRes = await fetch(portalPath("/api/models"));
        if (mRes.ok) {
          const m = await mRes.json();
          if (m.models?.length) {
            setModels(m.models);
            setCurrentModel(m.defaultModelId ?? m.models[0].id);
            setModelsState("ready");
          } else {
            setModelsState("empty");
          }
        } else {
          setModelsState("error");
        }
      } catch {
        setModelsState("error");
      }
      await refreshList();
    })();
  }, [refreshList]);

  const select = React.useCallback((id: string | null) => {
    setCurrentId(id);
  }, []);

  const loadConversationMessages = React.useCallback(async (id: string) => {
    if (id.startsWith("tmp-") || loadingRef.current.has(id)) return;
    if (conversationsRef.current.find((c) => c.id === id)?.messages.length) {
      markLoaded(id);
      return;
    }
    loadingRef.current.add(id);
    try {
      const res = await fetch(portalPath(`/api/conversations/${id}`));
      if (!res.ok) return;
      const data = await res.json();
      const msgs: ChatMessage[] = (data.messages ?? []).map((m: ServerMessage) => ({
        id: m.id,
        role: m.role as ChatMessage["role"],
        content: m.content,
        model: m.model ?? undefined,
        createdAt: m.createdAt,
        status: toStatus(m.status),
        timing: m.role === "assistant" && (m.ttftMs != null || m.tps != null)
          ? { ttftMs: m.ttftMs ?? null, tps: m.tps ?? null }
          : undefined,
      }));
      // 6.7：只在该会话还没有本地消息时写入，绝不覆盖加载期间本地追加的消息
      setConversations((prev) =>
        prev.map((c) => (c.id === id && c.messages.length === 0 ? { ...c, messages: msgs } : c)),
      );
    } catch {
    } finally {
      loadingRef.current.delete(id);
      markLoaded(id);
    }
  }, [markLoaded]);

  React.useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- 选择会话后从服务端同步该会话消息。
    if (currentId) void loadConversationMessages(currentId);
  }, [currentId, loadConversationMessages]);

  const newConversation = React.useCallback(async () => {
    // 懒创建：只生成内存态临时 id，不落库、不进侧栏列表。
    // 首条消息发送时由 ensureConversationPersisted 真正落库。
    const tmpId = `tmp-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    setCurrentId(tmpId);
    return tmpId;
  }, []);

  // 若 id 是临时态（tmp- 前缀），落库换真 id 并进列表；否则原样返回。
  const ensureConversationPersisted = React.useCallback(
    async (id: string, fallbackTitle: string): Promise<string> => {
      if (!id.startsWith("tmp-")) return id;
      const res = await fetch(portalPath("/api/conversations"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ title: fallbackTitle.slice(0, 24) || "新对话" }),
      });
      if (!res.ok) throw new Error(`conversation_create_failed_${res.status}`);
      const data = await res.json();
      const realId = data.conversation.id as string;
      const conv: Conversation = {
        id: realId,
        title: data.conversation.title,
        updatedAt: new Date(data.conversation.updatedAt).getTime(),
        messages: [],
      };
      // 同步更新 ref，让随后的 getConversation 立即可见
      conversationsRef.current = [conv, ...conversationsRef.current];
      setConversations((prev) => [conv, ...prev]);
      markLoaded(realId);
      setCurrentId(realId);
      return realId;
    },
    [markLoaded],
  );

  // 6.13：失败回滚并抛错，调用方负责提示
  const rename = React.useCallback(async (id: string, title: string) => {
    const before = conversationsRef.current.find((c) => c.id === id)?.title;
    const next = title.replace(/\s+/g, " ").trim().slice(0, 60);
    if (!next || next === before) return;
    setConversations((prev) => prev.map((c) => (c.id === id ? { ...c, title: next } : c)));
    let ok = false;
    try {
      const res = await fetch(portalPath(`/api/conversations/${id}`), {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ title: next }),
      });
      ok = res.ok;
    } catch {}
    if (!ok) {
      setConversations((prev) => prev.map((c) => (c.id === id && before ? { ...c, title: before } : c)));
      throw new Error("rename_failed");
    }
  }, []);

  // 6.13：先等服务端成功再从列表移除；失败抛错
  const remove = React.useCallback(async (id: string) => {
    let ok = false;
    try {
      const res = await fetch(portalPath(`/api/conversations/${id}`), { method: "DELETE" });
      ok = res.ok;
    } catch {}
    if (!ok) throw new Error("delete_failed");
    setConversations((prev) => {
      const next = prev.filter((c) => c.id !== id);
      setCurrentId((cur) => (cur === id ? next[0]?.id ?? null : cur));
      return next;
    });
  }, []);

  const setCurrentModelBoth = React.useCallback((model: string) => {
    setCurrentModel(model);
  }, []);

  const mapMessage = React.useCallback(
    (id: string, messageId: string, fn: (m: ChatMessage) => ChatMessage) => {
      setConversations((prev) =>
        prev.map((c) =>
          c.id === id
            ? { ...c, updatedAt: Date.now(), messages: c.messages.map((m) => (m.id === messageId ? fn(m) : m)) }
            : c,
        ),
      );
    },
    [],
  );

  const appendMessage = React.useCallback((id: string, msg: ChatMessage) => {
    setConversations((prev) =>
      prev.map((c) =>
        c.id === id
          ? { ...c, updatedAt: Date.now(), messages: [...c.messages, msg] }
          : c
      )
    );
  }, []);

  const updateMessage = React.useCallback(
    (id: string, messageId: string, content: string) => mapMessage(id, messageId, (m) => ({ ...m, content })),
    [mapMessage],
  );

  const patchMessage = React.useCallback(
    (id: string, messageId: string, patch: Partial<ChatMessage>) => mapMessage(id, messageId, (m) => ({ ...m, ...patch })),
    [mapMessage],
  );

  const appendToMessage = React.useCallback(
    (id: string, messageId: string, chunk: string) =>
      mapMessage(id, messageId, (m) => ({ ...m, content: m.content + chunk })),
    [mapMessage],
  );

  const current = React.useMemo(
    () => conversations.find((c) => c.id === currentId) ?? null,
    [conversations, currentId],
  );
  const currentLoaded = !currentId || currentId.startsWith("tmp-") || loadedIds.has(currentId);

  const value = React.useMemo<ChatStore>(
    () => ({
      conversations,
      currentId,
      current,
      currentLoaded,
      currentModel,
      modelsState,
      user,
      models,
      getConversation,
      select,
      newConversation,
      ensureConversationPersisted,
      rename,
      remove,
      setCurrentModel: setCurrentModelBoth,
      appendMessage,
      updateMessage,
      patchMessage,
      appendToMessage,
      loadConversationMessages,
      refreshList,
    }),
    [
      conversations,
      currentId,
      current,
      currentLoaded,
      currentModel,
      modelsState,
      user,
      models,
      getConversation,
      select,
      newConversation,
      ensureConversationPersisted,
      rename,
      remove,
      setCurrentModelBoth,
      appendMessage,
      updateMessage,
      patchMessage,
      appendToMessage,
      loadConversationMessages,
      refreshList,
    ]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useChatStore() {
  const ctx = React.useContext(Ctx);
  if (!ctx) throw new Error("useChatStore 必须在 ChatStoreProvider 内使用");
  return ctx;
}
