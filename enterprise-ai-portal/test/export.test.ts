import test from "node:test";
import assert from "node:assert/strict";
import {
  conversationToMarkdown,
  allConversationsToMarkdown,
  safeFilename,
} from "../src/lib/export.js";

test("conversationToMarkdown：标题 + 逐条角色", () => {
  const md = conversationToMarkdown({
    title: "零信任是什么",
    messages: [
      { role: "user", content: "解释零信任" },
      { role: "assistant", content: "永不信任，始终校验。", model: "glm-5.2" },
    ],
  });
  assert.ok(md.startsWith("# 零信任是什么\n"));
  assert.ok(md.includes("## 我\n"));
  assert.ok(md.includes("## 助手（glm-5.2）\n"));
  assert.ok(md.includes("永不信任，始终校验。"));
  assert.ok(md.endsWith("\n"));
});

test("conversationToMarkdown：空标题回退、系统角色", () => {
  const md = conversationToMarkdown({
    title: "",
    messages: [{ role: "system", content: "你是助手" }],
  });
  assert.ok(md.startsWith("# 对话\n"));
  assert.ok(md.includes("## 系统\n"));
});

test("allConversationsToMarkdown：多对话拼接 + 空回退", () => {
  assert.ok(allConversationsToMarkdown([]).includes("暂无对话"));
  const md = allConversationsToMarkdown([
    { title: "A", messages: [{ role: "user", content: "x" }] },
    { title: "B", messages: [{ role: "assistant", content: "y" }] },
  ]);
  assert.ok(md.includes("# A"));
  assert.ok(md.includes("# B"));
  assert.ok(md.includes("\n---\n"));
});

test("safeFilename：去非法字符/限长/回退", () => {
  assert.equal(safeFilename("a/b:c*?.md"), "a b c .md".trim());
  assert.equal(safeFilename("   "), "对话");
  assert.equal(safeFilename("", "x"), "x");
  assert.equal(safeFilename("很长".repeat(50)).length <= 60, true);
});
