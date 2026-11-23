import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_IMAGE_POLICY,
  mimeAllowed,
  bytesOfBase64,
  formatBytes,
  validateImageParts,
  extractImageParts,
  sanitizeFilename,
} from "../src/lib/upload.js";

test("mimeAllowed：白名单内外", () => {
  const p = DEFAULT_IMAGE_POLICY;
  assert.equal(mimeAllowed("image/png", p), true);
  assert.equal(mimeAllowed("image/jpeg", p), true);
  assert.equal(mimeAllowed("image/webp", p), true);
  assert.equal(mimeAllowed("image/gif", p), false);
  assert.equal(mimeAllowed("application/pdf", p), false);
});

test("bytesOfBase64：由 base64 长度估字节数（忽略 padding）", () => {
  // 3 字节 → base64 "AAAA"(4 字符, 0 padding)
  assert.equal(bytesOfBase64("AAAA"), 3);
  // 1 字节 → "AA==" (2 padding)
  assert.equal(bytesOfBase64("AA=="), 1);
  // 2 字节 → "AAA=" (1 padding)
  assert.equal(bytesOfBase64("AAA="), 2);
});

test("formatBytes：人类可读", () => {
  assert.equal(formatBytes(0), "0 B");
  assert.equal(formatBytes(1024), "1.0 KB");
  assert.equal(formatBytes(1536), "1.5 KB");
  assert.equal(formatBytes(1048576), "1.0 MB");
});

test("extractImageParts：从多模态 content 数组抽出图片块", () => {
  const content = [
    { type: "text" as const, text: "看这张" },
    { type: "image_url" as const, image_url: { url: "data:image/png;base64,AAAA" } },
  ];
  const parts = extractImageParts(content);
  assert.equal(parts.length, 1);
  assert.equal(parts[0].mime, "image/png");
  assert.equal(parts[0].base64, "AAAA");
  assert.equal(parts[0].bytes, 3);
});

test("extractImageParts：纯字符串 content → 空数组", () => {
  assert.deepEqual(extractImageParts("你好"), []);
});

test("validateImageParts：类型/大小/张数三关", () => {
  const p = { ...DEFAULT_IMAGE_POLICY, maxFileMB: 1, maxAttachments: 2 };
  const mk = (mime: string, bytes: number) => ({ mime, base64: "", bytes });
  // 合法
  assert.deepEqual(validateImageParts([mk("image/png", 500)], p).errors, []);
  // 类型越界
  assert.match(validateImageParts([mk("image/gif", 10)], p).errors[0], /类型/);
  // 单图超大
  assert.match(validateImageParts([mk("image/png", 2 * 1024 * 1024)], p).errors[0], /大小|MB/);
  // 张数超限
  assert.match(
    validateImageParts([mk("image/png", 1), mk("image/png", 1), mk("image/png", 1)], p).errors[0],
    /张数|数量/
  );
});

test("validateImageParts：总大小关（DoS 护栏）", () => {
  const p = { ...DEFAULT_IMAGE_POLICY, maxTotalMB: 1, maxAttachments: 10, maxFileMB: 20 };
  const mk = (bytes: number) => ({ mime: "image/png", base64: "", bytes });
  // 两张各 700KB → 总 ~1.37MB > 1MB
  assert.match(validateImageParts([mk(700 * 1024), mk(700 * 1024)], p).errors[0], /总大小/);
});

test("sanitizeFilename：去路径/危险字符、保留中文、空回退", () => {
  const s = sanitizeFilename("../../etc/passwd");
  assert.ok(!s.includes("/") && !s.includes(".."), `不应含 / 或 ..，实际 ${s}`);
  assert.equal(sanitizeFilename("猫咪.png"), "猫咪.png");
  assert.equal(sanitizeFilename("a/b\\c.png"), "a_b_c.png");
  assert.equal(sanitizeFilename("", 2), "图片3");
});

// ---- T2：多模态组装 / 落库降解 / sha256 ----
import {
  assembleUserContent,
  textForPersistence,
  sha256Hex,
} from "../src/lib/upload.js";

test("assembleUserContent：无图 → 纯字符串", () => {
  assert.equal(assembleUserContent("你好", []), "你好");
});

test("assembleUserContent：有图 → text 块 + image_url 块", () => {
  const c = assembleUserContent("看图", [
    { name: "a.png", mime: "image/png", size: 3, dataUrl: "data:image/png;base64,AAAA" },
  ]);
  assert.ok(Array.isArray(c));
  assert.deepEqual((c as unknown[])[0], { type: "text", text: "看图" });
  assert.deepEqual((c as unknown[])[1], {
    type: "image_url",
    image_url: { url: "data:image/png;base64,AAAA" },
  });
});

test("assembleUserContent：空文本 + 图 → 省略 text 块", () => {
  const c = assembleUserContent("", [
    { name: "a.png", mime: "image/png", size: 3, dataUrl: "data:image/png;base64,AAAA" },
  ]) as unknown[];
  assert.equal(c.length, 1);
  assert.equal((c[0] as { type: string }).type, "image_url");
});

test("textForPersistence：多模态 content 降解为 文本 + [图片:名] 占位（无 base64）", () => {
  const content = [
    { type: "text" as const, text: "看这张" },
    { type: "image_url" as const, image_url: { url: "data:image/png;base64,AAAA" } },
  ];
  const out = textForPersistence(content, ["猫.png"]);
  assert.equal(out, "看这张\n[图片:猫.png]");
  assert.ok(!out.includes("base64"), "落库文本绝不含 base64");
});

test("textForPersistence：纯字符串原样返回", () => {
  assert.equal(textForPersistence("你好", []), "你好");
});

test("sha256Hex：已知向量 sha256('abc')", async () => {
  const hex = await sha256Hex(new TextEncoder().encode("abc"));
  assert.equal(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});
