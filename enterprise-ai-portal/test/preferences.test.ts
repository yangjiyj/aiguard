import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_PREFS,
  loadPrefs,
  shouldSubmitOnKey,
  normalizeQuickPrompts,
  MAX_QUICK_PROMPTS,
} from "../src/lib/preferences.js";

test("loadPrefs 在无 window（SSR）时返回默认值", () => {
  assert.deepEqual(loadPrefs(), DEFAULT_PREFS);
});

test("shouldSubmitOnKey：Enter 发送模式", () => {
  const k = (o: Partial<Parameters<typeof shouldSubmitOnKey>[0]>) =>
    ({ key: "Enter", shiftKey: false, metaKey: false, ctrlKey: false, ...o });
  assert.equal(shouldSubmitOnKey(k({}), true), true); // Enter → 发送
  assert.equal(shouldSubmitOnKey(k({ shiftKey: true }), true), false); // Shift+Enter → 换行
  assert.equal(shouldSubmitOnKey(k({ isComposing: true }), true), false); // 输入法组字 → 不发送
  assert.equal(shouldSubmitOnKey({ key: "a", shiftKey: false, metaKey: false, ctrlKey: false }, true), false);
});

test("shouldSubmitOnKey：⌘/Ctrl+Enter 发送模式", () => {
  const k = (o: Partial<Parameters<typeof shouldSubmitOnKey>[0]>) =>
    ({ key: "Enter", shiftKey: false, metaKey: false, ctrlKey: false, ...o });
  assert.equal(shouldSubmitOnKey(k({}), false), false); // Enter → 换行
  assert.equal(shouldSubmitOnKey(k({ metaKey: true }), false), true); // ⌘+Enter → 发送
  assert.equal(shouldSubmitOnKey(k({ ctrlKey: true }), false), true); // Ctrl+Enter → 发送
});

test("normalizeQuickPrompts：过滤非串/去空白/去重/限量", () => {
  assert.deepEqual(normalizeQuickPrompts("不是数组"), []);
  assert.deepEqual(normalizeQuickPrompts(undefined), []);
  assert.deepEqual(
    normalizeQuickPrompts(["  写周报  ", "", 42, "写周报", "翻译"]),
    ["写周报", "翻译"]
  ); // 去空白 + 去重 + 丢非串/空
  const many = Array.from({ length: 30 }, (_, i) => `p${i}`);
  assert.equal(normalizeQuickPrompts(many).length, MAX_QUICK_PROMPTS);
});
