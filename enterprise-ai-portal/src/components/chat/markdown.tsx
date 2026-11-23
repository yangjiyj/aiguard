"use client";

import * as React from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeHighlight from "rehype-highlight";
import remarkMath from "remark-math";
import rehypeKatex from "rehype-katex";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Check, Copy, ImageOff } from "lucide-react";
import { isAllowedImageSrc } from "@/lib/markdown-policy";
import { OUTCOME_LABELS } from "@/lib/portal-errors";

function CodeBlock({ children, className }: { children: React.ReactNode; className?: string }) {
  const [copied, setCopied] = React.useState(false);
  const codeRef = React.useRef<HTMLElement>(null);

  const onCopy = async () => {
    const text = codeRef.current?.innerText ?? "";
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore
    }
  };

  return (
    <div className="group relative">
      <pre className={cn("prose-chat", className)}>
        <code ref={codeRef}>{children}</code>
      </pre>
      <Button
        variant="ghost"
        size="icon"
        onClick={onCopy}
        className="absolute right-2 top-2 h-7 w-7 opacity-0 transition-opacity group-hover:opacity-100"
        aria-label="复制代码"
      >
        {copied ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
      </Button>
    </div>
  );
}

function MarkdownImpl({
  content,
  streaming = false,
  className,
}: {
  content: string;
  streaming?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("prose-chat", streaming && "streaming-cursor", className)}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm, remarkMath]}
        rehypePlugins={[rehypeHighlight, rehypeKatex]}
        components={{
          pre: ({ children }) => <>{children}</>,
          code: ({ className: cls, children, ...props }) => {
            const isBlock = /language-/.test(cls ?? "");
            if (isBlock) {
              return <CodeBlock className={cls}>{children}</CodeBlock>;
            }
            return (
              <code className={cls} {...props}>
                {children}
              </code>
            );
          },
          a: ({ children, ...props }) => (
            <a target="_blank" rel="noopener noreferrer" {...props}>
              {children}
            </a>
          ),
          img: ({ src, alt }) => {
            if (isAllowedImageSrc(src)) {
              // eslint-disable-next-line @next/next/no-img-element
              return <img src={src as string} alt={alt ?? ""} referrerPolicy="no-referrer" />;
            }
            // 外链图片不渲染 <img>（浏览器会自动请求），也不给可点链接，只留占位
            return (
              <span
                className="inline-flex items-center gap-1 rounded border border-dashed border-border px-1.5 py-0.5 text-xs text-muted-foreground"
                data-blocked-image=""
                title={typeof src === "string" ? src : undefined}
              >
                <ImageOff className="h-3 w-3" aria-hidden="true" />
                {OUTCOME_LABELS.externalImageBlocked}
                {alt ? `：${alt}` : ""}
              </span>
            );
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}

export const Markdown = React.memo(MarkdownImpl);
