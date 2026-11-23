"use client";

import * as React from "react";
import { ArrowUp, Plus, Square } from "lucide-react";

import { cn } from "@/lib/utils";
import { usePreferences } from "@/components/preferences-provider";
import { shouldSubmitOnKey } from "@/lib/preferences";
import { OUTCOME_LABELS, PORTAL_ERROR_MESSAGES, UPLOAD_ACTION_LABELS, uploadErrorMessage } from "@/lib/portal-errors";
import {
  DEFAULT_IMAGE_POLICY,
  mimeAllowed,
  formatBytes,
  validateImageParts,
  type ImageAttachmentMeta,
} from "@/lib/upload";
import { portalPath } from "@/lib/portal-path";

// 文件附件（经 /api/upload 上传后，文本以 extracted_content 契约进 messages）
export type FileAttachment = {
  name: string;
  size: number;
  reference: string; // 网关留证 Key
  text: string;      // 抽取文本（进 extracted_content）
  uploading: boolean;
  error?: string;
  /** 6.2：控制面实际处置（audit / mask） */
  action?: string;
  /** 本地唯一 id，避免同名文件互相覆盖状态 */
  localId?: string;
};

/** 6.2：/api/upload 失败体 → 员工可读一句话（code 查表；未知 code 带上便于报障） */
export { uploadErrorMessage } from "@/lib/portal-errors";

export function Composer({
  onSend,
  onStop,
  isStreaming,
  disabled,
  allowImages = true,
  model,
  modelSlot,
  placeholder,
}: {
  onSend: (text: string, attachments: ImageAttachmentMeta[], files: FileAttachment[]) => void;
  onStop?: () => void;
  isStreaming?: boolean;
  disabled?: boolean;
  /** 6.11：当前模型不支持图片输入时为 false */
  allowImages?: boolean;
  /** 上传文件时随附当前模型 */
  model: string;
  /** 空状态时把模型选择放进输入框左下；对话中由顶栏承载 */
  modelSlot?: React.ReactNode;
  placeholder?: string;
}) {
  const { prefs } = usePreferences();
  const [value, setValue] = React.useState("");
  const [attachments, setAttachments] = React.useState<ImageAttachmentMeta[]>([]);
  const [files, setFiles] = React.useState<FileAttachment[]>([]);
  const [attachErr, setAttachErr] = React.useState<string | null>(null);
  const ref = React.useRef<HTMLTextAreaElement>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = Math.min(el.scrollHeight, 200) + "px";
  }, [value]);

  const effectivePlaceholder =
    placeholder ??
    "向企业 AI 助手提问，可直接粘贴图片或文件…";

  // 前端第一道门禁：类型/大小/张数/总量（后端 /api/chat 再从真实字节权威校验）
  const onFiles = async (files: FileList | File[] | null) => {
    if (!files) return;
    setAttachErr(null);
    if (!allowImages) {
      setAttachErr(OUTCOME_LABELS.imageNotSupported);
      return;
    }
    const picked: ImageAttachmentMeta[] = [];
    for (const f of Array.from(files)) {
      if (!mimeAllowed(f.type, DEFAULT_IMAGE_POLICY)) {
        setAttachErr(`不支持的类型：${f.type || f.name}`);
        continue;
      }
      const dataUrl = await new Promise<string>((res, rej) => {
        const r = new FileReader();
        r.onload = () => res(String(r.result));
        r.onerror = () => rej(r.error);
        r.readAsDataURL(f);
      });
      picked.push({ name: f.name, mime: f.type, size: f.size, dataUrl });
    }
    const next = [...attachments, ...picked];
    const v = validateImageParts(
      next.map((a) => ({ mime: a.mime, bytes: a.size })),
      DEFAULT_IMAGE_POLICY
    );
    if (!v.ok) {
      setAttachErr(v.errors[0]);
      return;
    }
    setAttachments(next);
  };

  const removeAttachment = (i: number) => setAttachments((a) => a.filter((_, idx) => idx !== i));

  // 统一文件分派：图片走 onFiles（dataURL chip），文档走 onDocFiles（上传留证）
  const addFiles = (list: FileList | File[] | null) => {
    if (!list) return;
    const arr = Array.from(list);
    const images = arr.filter((f) => mimeAllowed(f.type, DEFAULT_IMAGE_POLICY));
    const docs = arr.filter((f) => !mimeAllowed(f.type, DEFAULT_IMAGE_POLICY));
    if (images.length > 0) onFiles(images);
    if (docs.length > 0) onDocFiles(docs);
  };

  // 粘贴：剪贴板图片 → 附件；剪贴板文件 → 文档上传
  const handlePaste = (e: React.ClipboardEvent) => {
    const items = e.clipboardData?.items;
    if (!items) return;
    const files: File[] = [];
    for (const item of Array.from(items)) {
      if (item.kind === "file") {
        const f = item.getAsFile();
        if (f) files.push(f);
      }
    }
    if (files.length > 0) {
      e.preventDefault(); // 阻止图片被当文本插入 textarea
      addFiles(files);
    }
  };

  // 拖拽：拖入文件区
  const [dragOver, setDragOver] = React.useState(false);
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    addFiles(e.dataTransfer?.files ?? null);
  };

  // 文件上传：控制面按真实字节做类型门禁；门户不根据浏览器 MIME 抢先拒绝。
  const onDocFiles = async (list: FileList | File[] | null) => {
    if (!list) return;
    setAttachErr(null);
    for (const f of Array.from(list)) {
      const localId = `${f.name}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
      setFiles((prev) => [...prev, { name: f.name, size: f.size, reference: "", text: "", uploading: true, localId }]);
      try {
        const fd = new FormData();
        fd.append("file", f);
        fd.append("model", model);
        const r = await fetch(portalPath("/api/upload"), { method: "POST", body: fd });
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          throw new Error(uploadErrorMessage(r.status, err));
        }
        const data = (await r.json()) as { reference: string; text: string; action?: string };
        setFiles((prev) =>
          prev.map((x) =>
            x.localId === localId
              ? { ...x, uploading: false, reference: data.reference, text: data.text, action: data.action }
              : x,
          ),
        );
      } catch (e) {
        setFiles((prev) =>
          prev.map((x) =>
            x.localId === localId
              ? { ...x, uploading: false, error: e instanceof Error ? e.message : PORTAL_ERROR_MESSAGES.upstream_unavailable }
              : x,
          ),
        );
      }
    }
  };

  const removeFile = (i: number) => setFiles((f) => f.filter((_, idx) => idx !== i));

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (
      shouldSubmitOnKey(
        {
          key: e.key,
          shiftKey: e.shiftKey,
          metaKey: e.metaKey,
          ctrlKey: e.ctrlKey,
          isComposing: e.nativeEvent.isComposing,
          keyCode: e.nativeEvent.keyCode,
        },
        prefs.sendOnEnter
      )
    ) {
      e.preventDefault();
      submit();
    }
  };

  const submit = () => {
    const text = value.trim();
    const readyFiles = files.filter((f) => !f.uploading && !f.error);
    if ((!text && attachments.length === 0 && readyFiles.length === 0) || isStreaming || disabled) return;
    if (files.some((f) => f.uploading)) return; // 上传中不允许发送
    onSend(text, attachments, readyFiles);
    setValue("");
    setAttachments([]);
    setFiles([]);
    setAttachErr(null);
  };

  const hasUploading = files.some((f) => f.uploading);
  const canSend = (!!value.trim() || attachments.length > 0 || files.some((f) => !f.uploading && !f.error)) && !hasUploading;

  return (
    <div
      className="w-full"
      onPaste={handlePaste}
      onDrop={handleDrop}
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
    >
      <div className="mx-auto w-full max-w-[760px] px-4 pb-4 sm:px-6">
        <div
          className={cn(
            "flex flex-col rounded-2xl border bg-card transition-colors focus-within:border-foreground/20",
            dragOver && "border-primary ring-2 ring-primary/30"
          )}
        >
          {attachments.length > 0 && (
            <div className="flex flex-wrap gap-2 px-3 pt-3">
              {attachments.map((a, i) => (
                <div
                  key={i}
                  className="relative flex items-center gap-2 rounded-[10px] border bg-background py-1 pl-1 pr-2"
                >
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src={a.dataUrl} alt={a.name} className="h-9 w-9 rounded object-cover" />
                  <div className="max-w-[10rem]">
                    <div className="truncate text-xs">{a.name}</div>
                    <div className="text-[10px] text-muted-foreground">{formatBytes(a.size)}</div>
                  </div>
                  <button
                    type="button"
                    aria-label="移除附件"
                    onClick={() => removeAttachment(i)}
                    className="ml-1 text-muted-foreground hover:text-foreground"
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}
          {attachErr && <p className="px-3 pt-2 text-xs text-destructive">{attachErr}</p>}

          {files.length > 0 && (
            <div className="flex flex-wrap gap-2 px-3 pt-3">
              {files.map((f, i) => (
                <div
                  key={i}
                  className="relative flex items-center gap-2 rounded-[10px] border bg-background px-2.5 py-1.5"
                >
                  <div className="max-w-[12rem]">
                    <div className="truncate text-xs">{f.name}</div>
                    <div className="text-[10px] text-muted-foreground">
                      {f.uploading ? "上传中…" : f.error ? <span className="text-destructive">{f.error}</span> : `${formatBytes(f.size)} · ${UPLOAD_ACTION_LABELS[f.action ?? "audit"] ?? UPLOAD_ACTION_LABELS.audit}`}
                    </div>
                  </div>
                  {!f.uploading && (
                    <button
                      type="button"
                      aria-label="移除文件"
                      onClick={() => removeFile(i)}
                      className="ml-1 text-muted-foreground hover:text-foreground"
                    >
                      ×
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}

          <textarea
            ref={ref}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={disabled}
            rows={1}
            placeholder={effectivePlaceholder}
            className="max-h-[200px] min-h-11 w-full resize-none bg-transparent px-4 pb-1 pt-3 text-[15px] leading-relaxed outline-none placeholder:text-muted-foreground/70 disabled:opacity-50"
          />

          <div className="flex items-center gap-1.5 px-3 pb-2.5 pt-1">
            {/* 6.12：显式文件选择（移动端无法粘贴/拖拽） */}
            <input
              ref={fileInputRef}
              type="file"
              multiple
              hidden
              onChange={(e) => {
                addFiles(e.target.files);
                e.target.value = "";
              }}
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              disabled={disabled || isStreaming}
              className="flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-lg border text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
              aria-label="选择文件"
              title="选择文件"
            >
              <Plus className="h-4 w-4" />
            </button>
            {modelSlot}

            <div className="flex-1" />

            {isStreaming ? (
              <button
                type="button"
                onClick={onStop}
                className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[9px] bg-foreground text-background transition-opacity hover:opacity-90"
                aria-label="停止生成"
              >
                <Square className="h-3.5 w-3.5 fill-current" />
              </button>
            ) : (
              <button
                type="button"
                onClick={submit}
                disabled={!canSend || disabled}
                className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[9px] bg-foreground text-background transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-25"
                aria-label="发送"
              >
                <ArrowUp className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>

        <p className="mt-2 text-center text-[11px] text-muted-foreground/70">
          AI 生成内容可能存在误差，请核实重要信息 · 本次对话已按企业账号留痕审计
        </p>
      </div>
    </div>
  );
}
