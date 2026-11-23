// W6 纯逻辑单测：错误映射表 / SSE 解析 / history 校验 / 标题 / 回收站 / 外链图片 / 水印 / IME。
// 中文断言全部引用源常量，不在测试里手打。
import test from "node:test";
import assert from "node:assert/strict";
import {
  describePortalError,
  parseErrorBody,
  PORTAL_ERROR_MESSAGES,
  codeForStatus,
} from "../src/lib/portal-errors.js";
import { parseSSEData, SSELineParser } from "../src/lib/sse.js";
import { validateChatHistory, normalizeTitle, MAX_TITLE_LENGTH, MAX_HISTORY_MESSAGES } from "../src/lib/chat-history.js";
import { trashRetentionDays, trashCutoff, DEFAULT_TRASH_RETENTION_DAYS } from "../src/lib/trash-policy.js";
import { isAllowedImageSrc } from "../src/lib/markdown-policy.js";
import { watermarkConfig, watermarkLines, watermarkAccount, formatWatermarkTime } from "../src/lib/watermark.js";
import { shouldSubmitOnKey } from "../src/lib/preferences.js";

test("portal-errors: every code in the table resolves to its own copy", () => {
  for (const [code, message] of Object.entries(PORTAL_ERROR_MESSAGES)) {
    assert.equal(describePortalError({ code }).message, message, code);
  }
});

test("portal-errors: model_not_found tells the user to pick another model instead of retrying", () => {
  const described = describePortalError({ code: "model_not_found", status: 404 });
  assert.equal(described.code, "model_not_found");
  assert.equal(described.kind, "invalid");
  assert.ok(described.message.includes("模型"));
  assert.ok(!described.message.includes("model_not_found"), "must not leak the raw code to end users");
});

test("portal-errors: blocked kinds keep gateway notice, others do not", () => {
  const blocked = describePortalError({ code: "security_blocked", upstreamMessage: "n", blockId: "b" });
  assert.equal(blocked.kind, "blocked");
  assert.equal(blocked.notice, "n");
  assert.equal(blocked.blockId, "b");
  const fileBlocked = describePortalError({ code: "file_content_blocked", upstreamMessage: "n" });
  assert.equal(fileBlocked.kind, "blocked");
  const other = describePortalError({ code: "provider_timeout", upstreamMessage: "internal detail" });
  assert.equal(other.notice, undefined);
});

test("portal-errors: aliases and status fallback", () => {
  assert.equal(describePortalError({ code: "invalid_json" }).code, "invalid_request");
  assert.equal(describePortalError({ code: "upstream_error" }).code, "upstream_unavailable");
  assert.equal(describePortalError({ status: 402 }).code, "insufficient_balance");
  assert.equal(codeForStatus(413), "request_body_too_large");
  const unknown = describePortalError({ code: "brand_new_code", status: 503 });
  assert.equal(unknown.code, "brand_new_code");
  assert.ok(unknown.message.includes("brand_new_code"), "unknown code is surfaced for support");
});

test("portal-errors: parseErrorBody handles gateway, proxy, portal and flat control-plane bodies", () => {
  assert.deepEqual(parseErrorBody(JSON.stringify({ error: { code: "c", message: "m", request_id: "r", block_id: "b" } })),
    { code: "c", message: "m", requestId: "r", blockId: "b" });
  assert.equal(parseErrorBody(JSON.stringify({ error: { code: "c", message: "m", trace_id: "t" } }))?.requestId, "t");
  assert.equal(parseErrorBody(JSON.stringify({ error: "rate_limited" }))?.code, "rate_limited");
  assert.equal(parseErrorBody(JSON.stringify({ code: "file_content_blocked", message: "x" }))?.code, "file_content_blocked");
  assert.equal(parseErrorBody("not json"), null);
});

test("sse: parseSSEData recognises delta / finish / done / error frames", () => {
  assert.deepEqual(parseSSEData("[DONE]"), [{ type: "done" }]);
  assert.deepEqual(parseSSEData(JSON.stringify({ choices: [{ delta: { content: "x" }, finish_reason: "stop" }] })),
    [{ type: "delta", content: "x" }, { type: "finish", reason: "stop" }]);
  const [ev] = parseSSEData(JSON.stringify({ error: { code: "security_blocked", message: "m", request_id: "r" } }));
  assert.equal(ev?.type, "error");
  assert.equal(parseSSEData("{not json").length, 0);
});

test("sse: SSELineParser buffers across arbitrary chunk boundaries", () => {
  const stream = `data: ${JSON.stringify({ choices: [{ delta: { content: "abc" } }] })}\n\ndata: [DONE]\n\n`;
  for (let cut = 1; cut < stream.length; cut++) {
    const p = new SSELineParser();
    const events = [...p.push(stream.slice(0, cut)), ...p.push(stream.slice(cut)), ...p.flush()];
    assert.deepEqual(events, [{ type: "delta", content: "abc" }, { type: "done" }], `cut=${cut}`);
  }
});

test("sse: flush handles a trailing line with no newline", () => {
  const p = new SSELineParser();
  assert.deepEqual(p.push("data: [DONE]"), []);
  assert.deepEqual(p.flush(), [{ type: "done" }]);
});

test("6.15 validateChatHistory rejects system/tool roles and forged multimodal history", () => {
  assert.equal(validateChatHistory([{ role: "system", content: "x" }, { role: "user", content: "y" }]).ok, false);
  assert.equal(validateChatHistory([{ role: "tool", content: "x" }]).ok, false);
  assert.equal(validateChatHistory([{ role: "assistant", content: "x" }]).ok, false, "last must be user");
  assert.equal(validateChatHistory([{ role: "user", content: [{ type: "text", text: "a" }] }, { role: "user", content: "b" }]).ok, false);
  assert.equal(validateChatHistory([{ role: "user", content: [{ type: "text", text: "a" }] }]).ok, true);
  assert.equal(validateChatHistory([]).ok, false);
  assert.equal(validateChatHistory(Array.from({ length: MAX_HISTORY_MESSAGES + 1 }, () => ({ role: "user", content: "x" }))).ok, false);
  const ok = validateChatHistory([{ role: "user", content: "a", name: "evil" }, { role: "assistant", content: "b" }, { role: "user", content: "c" }]);
  assert.ok(ok.ok);
  if (ok.ok) assert.deepEqual(Object.keys(ok.messages[0]!), ["role", "content"], "extra fields are stripped");
});

test("6.13 normalizeTitle trims, collapses whitespace and caps length by code point", () => {
  assert.equal(normalizeTitle("  a\n\nb  "), "a b");
  assert.equal(normalizeTitle("   "), null);
  assert.equal(normalizeTitle(42), null);
  const emoji = "\u{1F600}".repeat(MAX_TITLE_LENGTH + 5);
  assert.equal(Array.from(normalizeTitle(emoji)!).length, MAX_TITLE_LENGTH);
});

test("6.17 trash retention reads env with sane bounds", () => {
  assert.equal(trashRetentionDays({}), DEFAULT_TRASH_RETENTION_DAYS);
  assert.equal(trashRetentionDays({ PORTAL_TRASH_RETENTION_DAYS: "7" }), 7);
  assert.equal(trashRetentionDays({ PORTAL_TRASH_RETENTION_DAYS: "0" }), DEFAULT_TRASH_RETENTION_DAYS);
  assert.equal(trashRetentionDays({ PORTAL_TRASH_RETENTION_DAYS: "abc" }), DEFAULT_TRASH_RETENTION_DAYS);
  assert.equal(trashCutoff(10 * 86400_000, 3).getTime(), 7 * 86400_000);
});

test("6.8 only inline / same-origin image sources are allowed", () => {
  for (const ok of ["data:image/png;base64,AAAA", "/chat/logo.png", "./a.png", "a.png", "blob:http://x/1"]) {
    assert.equal(isAllowedImageSrc(ok), true, ok);
  }
  for (const bad of [
    "https://evil.test/x.png?q=secret",
    "http://evil.test/x.png",
    "//evil.test/x.png",
    "\\\\evil.test\\x.png",
    "/\\evil.test/x.png",
    " https://evil.test/x.png",
    "ht\ttps://evil.test/x.png",
    "javascript:alert(1)",
    "data:text/html;base64,AAAA",
    "data:image/svg+xml;base64,AAAA",
    "ftp://evil.test/x",
    "",
    undefined,
  ]) {
    assert.equal(isAllowedImageSrc(bad), false, String(bad));
  }
});

test("6.9 watermark config, account and lines", () => {
  assert.equal(watermarkConfig({}).enabled, true);
  for (const off of ["0", "false", "OFF", "no"]) assert.equal(watermarkConfig({ PORTAL_WATERMARK: off }).enabled, false, off);
  assert.equal(watermarkConfig({ PORTAL_WATERMARK_EXTRA: "x".repeat(100) }).extra.length, 40);
  assert.equal(watermarkAccount({ email: "e1024@corp.test", id: "u1" }), "e1024");
  assert.equal(watermarkAccount({ email: "", id: "u1" }), "u1");
  assert.deepEqual(watermarkLines({ name: "N", email: "e1024@corp.test" }, "2026-01-02 03:04", "ACME"), ["N e1024", "ACME 2026-01-02 03:04"]);
  assert.deepEqual(watermarkLines({}, "", ""), []);
  assert.equal(formatWatermarkTime(new Date(2026, 0, 2, 3, 4)), "2026-01-02 03:04");
});

test("6.13 IME composition (keyCode 229) never submits", () => {
  const base = { key: "Enter", shiftKey: false, metaKey: false, ctrlKey: false };
  assert.equal(shouldSubmitOnKey({ ...base, keyCode: 229 }, true), false);
  assert.equal(shouldSubmitOnKey({ ...base, isComposing: true }, true), false);
  assert.equal(shouldSubmitOnKey({ ...base, keyCode: 13 }, true), true);
});
