import test from "node:test";
import assert from "node:assert/strict";
import { allConversationsToMarkdown, conversationToMarkdown } from "../src/lib/export.js";
import { DEFAULT_AI_LABEL_TEXT, exportAILabel } from "../src/lib/ai-label.js";

test("导出标识：默认开启，可关闭，可改文案并限长", () => {
  assert.equal(exportAILabel({}), DEFAULT_AI_LABEL_TEXT);
  assert.equal(DEFAULT_AI_LABEL_TEXT, "本文件中「助手」的回复为 AI 生成内容。");
  for (const off of ["0", "false", "OFF", " no "]) {
    assert.equal(exportAILabel({ PORTAL_AI_LABEL: off }), "");
  }
  assert.equal(exportAILabel({ PORTAL_AI_LABEL_TEXT: " 助手回复由人工智能\n生成 " }), "助手回复由人工智能 生成");
  assert.equal(exportAILabel({ PORTAL_AI_LABEL_TEXT: "长".repeat(60) }), "长".repeat(40));
});

test("导出标识：单个对话放在标题下，全部导出只在文件头放一次", () => {
  const conv = { title: "A", messages: [{ role: "assistant", content: "y" }] };
  const one = conversationToMarkdown(conv, { aiLabel: DEFAULT_AI_LABEL_TEXT });
  assert.ok(one.startsWith(`# A\n\n> ${DEFAULT_AI_LABEL_TEXT}\n\n## 助手\n`));

  const all = allConversationsToMarkdown([conv, { ...conv, title: "B" }], { aiLabel: "标识" });
  assert.ok(all.startsWith("> 标识\n\n# A\n"));
  assert.equal(all.split("> 标识").length - 1, 1);

  assert.equal(conversationToMarkdown(conv), "# A\n\n## 助手\n\ny\n");
  assert.ok(!allConversationsToMarkdown([conv]).includes(">"));
});
