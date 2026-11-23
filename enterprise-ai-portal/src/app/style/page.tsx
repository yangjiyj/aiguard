import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Separator } from "@/components/ui/separator";
import { Markdown } from "@/components/chat/markdown";
import { brand } from "@/lib/brand";
import { ModelLogo } from "@/components/model-logo";
import { VENDORS } from "@/lib/model-catalog";

const SWATCHES = [
  { name: "primary", var: "var(--primary)", text: "primary-foreground" },
  { name: "secondary", var: "var(--color-secondary)", text: "secondary-foreground" },
  { name: "accent", var: "var(--color-accent)", text: "accent-foreground" },
  { name: "muted", var: "var(--color-muted)", text: "muted-foreground" },
  { name: "destructive", var: "var(--color-destructive)", text: "destructive-foreground" },
  { name: "border", var: "var(--color-border)", text: "foreground" },
];

const TYPE_SIZES = [
  { label: "标题 H1", cls: "text-3xl font-semibold tracking-tight" },
  { label: "标题 H2", cls: "text-2xl font-semibold" },
  { label: "标题 H3", cls: "text-lg font-semibold" },
  { label: "正文", cls: "text-sm" },
  { label: "辅助说明", cls: "text-xs text-muted-foreground" },
];

const DEMO_MD = `### Markdown 渲染示例

支持 **加粗**、*斜体*、\`行内代码\`、[链接](https://example.com)。

- 无序列表项
- 第二项

1. 有序列表
2. 第二条

> 引用块：克制、高级、易读。

\`\`\`typescript
function hello(name: string) {
  return \`Hello, \${name}!\`;
}
\`\`\`

| 模型 | 说明 |
|---|---|
| GLM-5.2 | 主力 |
| GLM-4.6 | 通用 |`;

export default function StylePage() {
  return (
    <main className="mx-auto max-w-4xl px-6 py-10">
      <header className="mb-10">
        <p className="text-xs text-muted-foreground">设计系统走查</p>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight">
          {brand.name} · Style
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          色板、字阶、组件、Markdown 渲染一览。浅/深双主题可右上角切换。
        </p>
      </header>

      {/* 品牌色板 */}
      <Section title="品牌强调色">
        <div className="flex flex-wrap gap-2">
          {[
            ["brand-50", "var(--brand-50)"],
            ["brand-100", "var(--brand-100)"],
            ["brand-300", "var(--brand-300)"],
            ["brand-500", "var(--brand-500)"],
            ["brand-600", "var(--brand-600)"],
            ["brand-700", "var(--brand-700)"],
            ["brand-900", "var(--brand-900)"],
          ].map(([name, c]) => (
            <div key={name} className="overflow-hidden rounded-lg border">
              <div className="h-16 w-24" style={{ background: c }} />
              <div className="px-2 py-1 text-center text-[10px] text-muted-foreground">
                {name}
              </div>
            </div>
          ))}
        </div>
      </Section>

      {/* 语义色 */}
      <Section title="语义色">
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          {SWATCHES.map((s) => (
            <div
              key={s.name}
              className="flex h-16 items-center justify-center rounded-lg border text-xs font-medium"
              style={{
                background: s.var,
                color: `var(--color-${s.text})`,
              }}
            >
              {s.name}
            </div>
          ))}
        </div>
      </Section>

      {/* 字阶 */}
      <Section title="字阶">
        <div className="space-y-3">
          {TYPE_SIZES.map((t) => (
            <div key={t.label} className="flex items-baseline gap-4">
              <span className="w-20 shrink-0 text-[11px] text-muted-foreground">
                {t.label}
              </span>
              <span className={t.cls}>企业 AI 对话门户</span>
            </div>
          ))}
        </div>
      </Section>

      {/* 按钮 */}
      <Section title="按钮">
        <div className="flex flex-wrap items-center gap-3">
          <Button>主要按钮</Button>
          <Button variant="secondary">次要</Button>
          <Button variant="outline">描边</Button>
          <Button variant="ghost">幽灵</Button>
          <Button variant="destructive">危险</Button>
          <Button variant="link">链接</Button>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <Button size="sm">小</Button>
          <Button size="default">默认</Button>
          <Button size="lg">大</Button>
          <Button size="icon" aria-label="图标按钮">A</Button>
          <Button disabled>禁用</Button>
        </div>
      </Section>

      {/* 头像 */}
      <Section title="头像">
        <div className="flex items-center gap-3">
          <Avatar>
            <AvatarFallback className="bg-primary text-primary-foreground">
              {brand.logoText}
            </AvatarFallback>
          </Avatar>
          <Avatar>
            <AvatarFallback>张</AvatarFallback>
          </Avatar>
          <Avatar>
            <AvatarFallback className="bg-muted">U</AvatarFallback>
          </Avatar>
        </div>
      </Section>

      <Separator className="my-8" />

      {/* Markdown */}
      <Section title="Markdown 渲染">
        <div className="rounded-xl border bg-card p-5">
          <Markdown content={DEMO_MD} />
        </div>
      </Section>

      {/* 消息样式示例 */}
      <Section title="消息样式（整块全宽）">
        <div className="space-y-0 rounded-xl border">
          <div className="border-b px-5 py-4">
            <div className="mb-1 flex items-center gap-2">
              <Avatar className="h-7 w-7">
                <AvatarFallback className="bg-muted text-[10px]">你</AvatarFallback>
              </Avatar>
              <span className="text-sm font-semibold">你</span>
            </div>
            <p className="text-sm">解释一下零信任的核心思想。</p>
          </div>
          <div className="px-5 py-4">
            <div className="mb-1 flex items-center gap-2">
              <Avatar className="h-7 w-7">
                <AvatarFallback className="bg-primary text-[10px] text-primary-foreground">
                  {brand.logoText}
                </AvatarFallback>
              </Avatar>
              <span className="text-sm font-semibold">{brand.shortName}</span>
              <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                glm-5.2
              </span>
            </div>
            <Markdown
              content={`**从不信任，始终校验**。任何访问请求默认不信任，必须经过身份、设备、上下文的实时校验后才放行。`}
            />
          </div>
        </div>
      </Section>

      <Section title="模型 Logo（官方品牌标记）">
        <div className="flex flex-wrap gap-3">
          {VENDORS.filter((v) => v.id !== "other").map((v) => (
            <div key={v.id} className="flex items-center gap-2 rounded-lg border px-3 py-2">
              <span className="flex h-6 w-6 items-center justify-center rounded-md bg-muted">
                <ModelLogo vendorId={v.id} size={16} />
              </span>
              <span className="text-xs text-muted-foreground">{v.name}</span>
            </div>
          ))}
        </div>
      </Section>

      <Section title="视觉能力标识">
        <div className="flex flex-wrap gap-1.5">
          <span className="rounded-full bg-emerald-100 px-1.5 py-0.5 text-[10px] font-medium text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300">
            视觉
          </span>
          <span className="text-[11px] text-muted-foreground">（仅支持图片输入的模型显示此标识）</span>
        </div>
      </Section>

      <footer className="mt-12 text-center text-xs text-muted-foreground">
        {brand.name} · M1 界面先行 · Mock 数据
      </footer>
    </main>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mb-8">
      <h2 className="mb-3 text-sm font-semibold text-muted-foreground">
        {title}
      </h2>
      {children}
    </section>
  );
}
