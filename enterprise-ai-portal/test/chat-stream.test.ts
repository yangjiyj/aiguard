// W6 · 6.1 / 6.3 / 6.4 / 6.5：浏览器侧流消费。fixture 按网关真实返回形状构造
// （apps/gateway-core/internal/handler/chat_completions.go：writeSSEError / liveChatBlockPayloads /
// writeErrorResponse）。断言里的中文一律引用映射表，不手打。
import test from "node:test";
import assert from "node:assert/strict";
import { streamChatRequest, type StreamOutcome } from "../src/lib/chat-stream.js";
import { PORTAL_ERROR_MESSAGES } from "../src/lib/portal-errors.js";

function sseResponse(chunks: string[], headers: Record<string, string> = {}, status = 200): Response {
  const enc = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(ctrl) {
      for (const c of chunks) ctrl.enqueue(enc.encode(c));
      ctrl.close();
    },
  });
  return new Response(body, { status, headers: { "content-type": "text/event-stream", ...headers } });
}

function run(res: Response | (() => Promise<Response>)) {
  return new Promise<{ text: string; outcome: StreamOutcome; meta: { securityAction?: string } }>((resolve) => {
    let text = "";
    let meta: { securityAction?: string } = {};
    const fetchImpl = (async () => (typeof res === "function" ? res() : res)) as unknown as typeof fetch;
    streamChatRequest("/api/chat", {}, {
      onChunk: (t) => { text += t; },
      onMeta: (m) => { meta = m; },
      onEnd: (outcome) => resolve({ text, outcome, meta }),
    }, fetchImpl);
  });
}

const delta = (s: string) => `data: ${JSON.stringify({ choices: [{ delta: { content: s } }] })}\n\n`;

test("6.1 HTTP 200 + SSE error frame (writeSSEError) ends as blocked with request id", async () => {
  const frame = `data: ${JSON.stringify({ error: { code: "security_blocked", message: "policy notice from gateway", request_id: "req-1" } })}\n\n`;
  const r = await run(sseResponse([delta("partial "), frame]));
  assert.equal(r.text, "partial ");
  assert.equal(r.outcome.kind, "error");
  if (r.outcome.kind !== "error") return;
  assert.equal(r.outcome.error.code, "security_blocked");
  assert.equal(r.outcome.error.kind, "blocked");
  assert.equal(r.outcome.error.message, PORTAL_ERROR_MESSAGES.security_blocked);
  assert.equal(r.outcome.error.notice, "policy notice from gateway");
  assert.equal(r.outcome.error.requestId, "req-1");
});

test("6.1 liveChatBlockPayloads error-mode frame carries block_id", async () => {
  const frame = `data: ${JSON.stringify({ error: { message: "blocked", type: "security_error", code: "security_blocked", block_id: "blk-9" } })}\n\n`;
  const r = await run(sseResponse([frame, "data: [DONE]\n\n"]));
  assert.equal(r.outcome.kind, "error");
  if (r.outcome.kind !== "error") return;
  assert.equal(r.outcome.error.blockId, "blk-9");
  assert.equal(r.outcome.error.kind, "blocked");
});

test("6.1 provider_timeout / model_route_unavailable SSE frames map to table copy", async () => {
  for (const code of ["provider_timeout", "model_route_unavailable"] as const) {
    const frame = `data: ${JSON.stringify({ error: { code, message: "upstream detail", request_id: "r" } })}\n\n`;
    const r = await run(sseResponse([frame]));
    assert.equal(r.outcome.kind, "error");
    if (r.outcome.kind !== "error") continue;
    assert.equal(r.outcome.error.code, code);
    assert.equal(r.outcome.error.message, PORTAL_ERROR_MESSAGES[code]);
    assert.equal(r.outcome.error.notice, undefined, "non-blocked errors do not echo upstream text");
  }
});

test("6.4 a data line split across chunks is not lost", async () => {
  const line = delta("hello world");
  const cut = line.indexOf("world");
  const r = await run(sseResponse([line.slice(0, cut), line.slice(cut), "data: [DO", "NE]\n\n"]));
  assert.equal(r.text, "hello world");
  assert.deepEqual(r.outcome, { kind: "done" });
});

test("6.4 CRLF line endings are accepted", async () => {
  const r = await run(sseResponse([delta("a").replace(/\n/g, "\r\n"), "data: [DONE]\r\n\r\n"]));
  assert.equal(r.text, "a");
  assert.deepEqual(r.outcome, { kind: "done" });
});

test("6.5 stream closing without [DONE] is interrupted, not silently done", async () => {
  const r = await run(sseResponse([delta("half")]));
  assert.equal(r.text, "half");
  assert.equal(r.outcome.kind, "error");
  if (r.outcome.kind !== "error") return;
  assert.equal(r.outcome.error.code, "stream_interrupted");
});

test("6.3 non-2xx JSON (402/429/403/504) maps by code, never raw JSON", async () => {
  const cases: Array<[number, unknown, string]> = [
    [402, { error: { code: "insufficient_balance", message: "x", request_id: "r402" } }, "insufficient_balance"],
    [429, { error: { code: "quota_exceeded", message: "x" } }, "quota_exceeded"],
    [403, { error: { code: "forbidden_model", message: "x" } }, "forbidden_model"],
    [504, { error: { code: "provider_timeout", message: "x" } }, "provider_timeout"],
    // 门户自有路由的扁平体
    [429, { error: "rate_limited", message: "x" }, "rate_limited"],
  ];
  for (const [status, body, code] of cases) {
    const r = await run(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));
    assert.equal(r.outcome.kind, "error");
    if (r.outcome.kind !== "error") continue;
    assert.equal(r.outcome.error.code, code);
    assert.equal(r.outcome.error.message, PORTAL_ERROR_MESSAGES[code as keyof typeof PORTAL_ERROR_MESSAGES]);
    assert.doesNotMatch(r.outcome.error.message, /[{}]/);
  }
});

test("6.3 blocked JSON from /api/chat keeps notice and block id", async () => {
  const body = { error: "security_blocked", message: "m", notice: "gateway notice", block_id: "b1", status: 403 };
  const r = await run(new Response(JSON.stringify(body), { status: 403 }));
  assert.equal(r.outcome.kind, "error");
  if (r.outcome.kind !== "error") return;
  assert.equal(r.outcome.error.notice, "gateway notice");
  assert.equal(r.outcome.error.blockId, "b1");
});

test("6.3 non-JSON 5xx falls back by status", async () => {
  const r = await run(new Response("<html>bad gateway</html>", { status: 502 }));
  assert.equal(r.outcome.kind, "error");
  if (r.outcome.kind !== "error") return;
  assert.equal(r.outcome.error.message, PORTAL_ERROR_MESSAGES.upstream_unavailable);
});

test("6.16 keepalive comments are ignored and in-stream security action reaches onMeta", async () => {
  // 网关保活已提前发头：头里没有最终动作，改由末帧 x_jjdguard_security_action 带出
  const usage = `data: ${JSON.stringify({ choices: [], usage: { total_tokens: 3 }, x_jjdguard_security_action: "mask" })}\n\n`;
  const r = await run(sseResponse([": keepalive\n\n", ": keepalive\n\n", delta("ok"), usage, "data: [DONE]\n\n"]));
  assert.equal(r.text, "ok");
  assert.equal(r.outcome.kind, "done");
  assert.equal(r.meta.securityAction, "mask");
});

test("6.16 X-Security-Action header is surfaced via onMeta", async () => {
  const r = await run(sseResponse([delta("x"), "data: [DONE]\n\n"], { "x-security-action": "mask" }));
  assert.equal(r.meta.securityAction, "mask");
});

test("6.5 cancel ends exactly once as stopped", async () => {
  let ends = 0;
  let last: StreamOutcome | undefined;
  const never = new ReadableStream<Uint8Array>({ start() {} });
  const fetchImpl = (async () => new Response(never, { status: 200 })) as unknown as typeof fetch;
  const h = streamChatRequest("/api/chat", {}, {
    onChunk: () => {},
    onEnd: (o) => { ends += 1; last = o; },
  }, fetchImpl);
  await new Promise((r) => setTimeout(r, 10));
  h.cancel();
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(ends, 1);
  assert.deepEqual(last, { kind: "stopped" });
});

test("usage frame before [DONE] reports output tokens", async () => {
  const usage = `data: ${JSON.stringify({ choices: [], usage: { prompt_tokens: 3, completion_tokens: 7 } })}\n\n`;
  const seen: number[] = [];
  const outcome = await new Promise<StreamOutcome>((resolve) => {
    const fetchImpl = (async () => sseResponse([delta("hi"), usage, "data: [DONE]\n\n"])) as unknown as typeof fetch;
    streamChatRequest("/api/chat", {}, { onChunk: () => {}, onUsage: (n) => seen.push(n), onEnd: resolve }, fetchImpl);
  });
  assert.equal(outcome.kind, "done");
  assert.deepEqual(seen, [7]);
});
