import test from "node:test";
import assert from "node:assert/strict";
import {
  mimeToExtractorKind,
  truncateText,
  buildIngestRequest,
} from "../src/lib/file-extract.js";

test("mimeToExtractorKind：分派到正确的抽取器", () => {
  assert.equal(mimeToExtractorKind("application/pdf"), "pdf");
  assert.equal(
    mimeToExtractorKind("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    "docx",
  );
  assert.equal(
    mimeToExtractorKind("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "xlsx",
  );
  assert.equal(
    mimeToExtractorKind("application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    "pptx",
  );
  assert.equal(mimeToExtractorKind("text/plain"), "text");
  assert.equal(mimeToExtractorKind("text/csv"), "text");
  assert.equal(mimeToExtractorKind("text/markdown"), "text");
  assert.equal(mimeToExtractorKind("application/json"), "text");
  assert.equal(mimeToExtractorKind("application/octet-stream"), "unsupported");
  assert.equal(mimeToExtractorKind("application/x-rar-compressed"), "unsupported");
});

test("truncateText：超长截断带省略号", () => {
  assert.equal(truncateText("abc", 10), "abc");
  assert.equal(truncateText("abcdefghij", 5), "abcde…");
});

test("buildIngestRequest：组装网关 ingest payload（不含 user_id，由调用方注入）", () => {
  const req = buildIngestRequest({
    filename: "doc.pdf",
    mime: "application/pdf",
    size: 100,
    sha256: "abc123",
    bytesBase64: "AAAA",
    extractedText: "hello world",
    model: "glm-5.2",
  });
  assert.equal(req.filename, "doc.pdf");
  assert.equal(req.mime_type, "application/pdf");
  assert.equal(req.size, 100);
  assert.equal(req.sha256, "abc123");
  assert.equal(req.bytes_base64, "AAAA");
  assert.equal(req.extracted_text, "hello world");
  assert.equal(req.model, "glm-5.2");
  assert.equal(req.user_id, undefined); // 调用方注入
});
