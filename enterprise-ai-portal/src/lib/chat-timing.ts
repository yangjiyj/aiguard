// 浏览器端单轮计时：只用于消息下方的「首字 · t/s」展示，不上报、不落库。
// 生成窗口不足 200ms 时不给 TPS，与控制面 TPS 口径一致。
export class ChatTimer {
  private readonly start: number;
  private first: number | null = null;
  private end: number | null = null;
  private tokens: number | null = null;

  constructor(private readonly now: () => number = () => performance.now()) {
    this.start = now();
  }

  chunk() {
    if (this.first === null) this.first = this.now();
  }

  usage(outputTokens: number) {
    this.tokens = outputTokens;
    this.end = this.now();
  }

  result(): { ttftMs: number | null; tps: number | null } {
    const ttftMs = this.first === null ? null : Math.round(this.first - this.start);
    const span = this.first !== null && this.end !== null ? this.end - this.first : 0;
    const tps = this.tokens !== null && this.tokens > 0 && span >= 200 ? Math.round((this.tokens * 1000 / span) * 10) / 10 : null;
    return { ttftMs, tps };
  }
}
