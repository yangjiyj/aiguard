// 品牌配置：默认值 + env 覆盖
export type BrandConfig = {
  name: string;
  shortName: string;
  logoText?: string;
  accent?: string;
  favicon?: string;
};

export const brand: BrandConfig = {
  name: process.env.BRAND_NAME ?? "企业 AI 对话门户",
  shortName: process.env.BRAND_SHORT_NAME ?? "AI 门户",
  logoText: "AI",
  accent: process.env.BRAND_ACCENT ?? "#2451eb",
};

export const examplePrompts: string[] = [
  "帮我写一封项目进度同步邮件，重点说明本周风险",
  "把这段会议纪要整理成可执行的待办清单",
  "用通俗的语言解释什么是零信任安全架构",
  "帮我审阅这份需求文档，指出可能的遗漏和风险点",
];
