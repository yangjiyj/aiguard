/**
 * M1 Mock 流式回复
 * 假装是大模型在逐字返回；M2 替换为真上游 SSE。
 */

const REPLIES: string[] = [
  `好的，我来帮你梳理。

**思路概览**

1. 先明确目标和约束；
2. 拆解关键步骤；
3. 给出可执行的建议。

> 提示：落地时注意和现有流程对齐，避免一次性改太多。

\`\`\`typescript
// 示例：最小可运行骨架
function plan(steps: string[]) {
  return steps.map((s, i) => ({ step: i + 1, action: s }));
}
\`\`\`

如果需要更详细的方案，告诉我具体场景。`,
  `这个问题可以这样看：

| 维度 | 说明 |
|---|---|
| 收益 | 提升一致性、可追溯 |
| 成本 | 一次性接入 + 持续维护 |
| 风险 | 改动范围需控制 |

核心是**分阶段推进**，先小范围验证再扩展。`,
  `明白。我的建议是：

- **优先级**：先做影响面最大、改动最小的一项；
- **验证**：每步都留可回滚的口子；
- **度量**：定一两个可观察的指标，避免"感觉变好"。

需要的话，我可以帮你出一版具体的执行清单。`,
];

let replyIdx = 0;

export function pickMockReply(): string {
  const r = REPLIES[replyIdx % REPLIES.length];
  replyIdx += 1;
  return r;
}

/**
 * 模拟流式：把回复按 token 切片，逐片回调。
 * 支持 abort。
 */
export function streamMockReply(
  text: string,
  onChunk: (chunk: string) => void,
  onDone: () => void,
  onError: (e: Error) => void
): { cancel: () => void } {
  let cancelled = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  void onError;

  // 按字符切片（中文按字，英文/符号也按字），偶尔停顿模拟真实流
  const chars = Array.from(text);
  let i = 0;

  const tick = () => {
    if (cancelled) return;
    if (i >= chars.length) {
      onDone();
      return;
    }
    // 每次吐 1~3 个字符
    const step = Math.min(chars.length - i, 1 + Math.floor(Math.random() * 3));
    onChunk(chars.slice(i, i + step).join(""));
    i += step;
    // 标点处稍作停顿，更像真实生成
    const last = chars[i - 1];
    const delay =
      last === "。" || last === "，" || last === "\n" ? 60 + Math.random() * 80 : 12 + Math.random() * 28;
    timer = setTimeout(tick, delay);
  };

  // 起步稍延迟
  timer = setTimeout(tick, 120);

  return {
    cancel() {
      cancelled = true;
      if (timer) clearTimeout(timer);
    },
  };
}
