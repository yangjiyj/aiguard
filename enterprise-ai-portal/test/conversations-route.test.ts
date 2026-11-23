// W6 · 6.10 / 6.13 / 6.17：会话 API（软删 / 恢复 / 回收站 / 批量导出留痕 / 标题归一 / 账号复核）。
import test, { mock } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";

type Conv = { id: string; userId: string; title: string; deletedAt: Date | null; updatedAt: Date };
const convs = new Map<string, Conv>();
const exportEvents: unknown[] = [];
let deleteManyWhere: unknown = null;
let exportAuditFails = false;
let chatAllowed = true;
let historicalOwners:string[]|undefined;

const server = createServer(async (req, res) => {
  for await (const _ of req) void _;
  res.setHeader("content-type", "application/json");
  if (req.url === "/admin/v1/portal-integration/users/user-fixture/authorization-context") {
    res.end(JSON.stringify({ data: {
      user_id: "user-fixture", department_id: "d", department_name: "d", department_version: 1,
      chat_allowed: chatAllowed, model_ids: [],history_user_ids:historicalOwners,
    } }));
    return;
  }
  res.statusCode = 404;
  res.end("{}");
});
type ListRoute = typeof import("../src/app/api/conversations/route.js");
type OneRoute = typeof import("../src/app/api/conversations/[id]/route.js");
type ExportRoute = typeof import("../src/app/api/conversations/export/route.js");
let list: ListRoute;
let one: OneRoute;
let exp: ExportRoute;

test.before(async () => {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  process.env.JJD_CP_URL = `http://127.0.0.1:${address.port}`;
  process.env.JJD_PORTAL_API_SECRET = "s";
  list = (await import("../src/app/api/conversations/route.js?fixture=conv" as string)) as ListRoute;
  one = (await import("../src/app/api/conversations/[id]/route.js?fixture=conv-one" as string)) as OneRoute;
  exp = (await import("../src/app/api/conversations/export/route.js?fixture=conv-export" as string)) as ExportRoute;
});

mock.module("@/auth", {
  namedExports: { auth: async () => ({ user: { id: "user-fixture", email: "u@x.test" } }) },
});
mock.module("@/lib/prisma", {
  namedExports: {
    prisma: {
      conversation: {
        findUnique: async ({ where }: { where: { id: string } }) => convs.get(where.id) ?? null,
        update: async ({ where, data }: { where: { id: string }; data: Partial<Conv> }) => {
          const c = { ...convs.get(where.id)!, ...data };
          convs.set(where.id, c);
          return c;
        },
        deleteMany: async ({ where }: { where: unknown }) => { deleteManyWhere = where; return { count: 0 }; },
        findMany: async ({ where }: { where: { userId: string|{in:string[]}; deletedAt: null | { not: null } } }) =>
          [...convs.values()]
            .filter((c) => typeof where.userId==='string'?c.userId===where.userId:where.userId.in.includes(c.userId))
            .filter((c) => (where.deletedAt === null ? c.deletedAt === null : c.deletedAt !== null))
            .map((c) => ({ ...c, messages: [{ role: "user", content: "q", model: null }] })),
        create: async ({ data }: { data: Conv }) => data,
      },
      exportEvent: {
        create: async ({ data }: { data: unknown }) => {
          if (exportAuditFails) throw new Error("db down");
          exportEvents.push(data);
          return data;
        },
      },
      message: { findMany: async () => [] },
    },
  },
});

test.after(() => server.close());
test.beforeEach(() => {
  convs.clear();
  exportEvents.length = 0;
  exportAuditFails = false;
  chatAllowed = true;
  historicalOwners=undefined;
  const now = new Date();
  convs.set("c1", { id: "c1", userId: "user-fixture", title: "t1", deletedAt: null, updatedAt: now });
  convs.set("c2", { id: "c2", userId: "user-fixture", title: "t2", deletedAt: null, updatedAt: now });
  convs.set("x", { id: "x", userId: "someone-else", title: "t", deletedAt: null, updatedAt: now });
});

const ctx = (id: string) => ({ params: Promise.resolve({ id }) });
const nreq = (url: string, init?: RequestInit) => new Request(url, init) as unknown as Parameters<OneRoute["PATCH"]>[0];

test("6.17 DELETE is a soft delete; trash lists it; restore brings it back", async () => {
  const del = await one.DELETE(nreq("http://p/api/conversations/c1", { method: "DELETE" }), ctx("c1"));
  assert.equal(del.status, 200);
  assert.ok(convs.get("c1")?.deletedAt instanceof Date, "row is kept with deletedAt");

  const active = await (await list.GET(new Request("http://p/api/conversations"))).json();
  assert.deepEqual(active.conversations.map((c: Conv) => c.id), ["c2"]);
  const trash = await (await list.GET(new Request("http://p/api/conversations?trash=1"))).json();
  assert.deepEqual(trash.conversations.map((c: Conv) => c.id), ["c1"]);
  assert.ok(deleteManyWhere, "expired trash is purged on list");

  assert.equal((await one.GET(nreq("http://p/api/conversations/c1"), ctx("c1"))).status, 404, "trashed conversation is not readable");

  const restore = await one.PATCH(nreq("http://p/api/conversations/c1", { method: "PATCH", body: JSON.stringify({ restore: true }) }), ctx("c1"));
  assert.equal(restore.status, 200);
  assert.equal(convs.get("c1")?.deletedAt, null);
});

test("6.17 another user's conversation cannot be deleted or restored", async () => {
  assert.equal((await one.DELETE(nreq("http://p/api/conversations/x", { method: "DELETE" }), ctx("x"))).status, 404);
  assert.equal(convs.get("x")?.deletedAt, null);
});

test("6.13 rename normalises the title", async () => {
  const res = await one.PATCH(nreq("http://p/api/conversations/c2", { method: "PATCH", body: JSON.stringify({ title: "  a\n b " }) }), ctx("c2"));
  assert.equal(res.status, 200);
  assert.equal(convs.get("c2")?.title, "a b");
  const blank = await one.PATCH(nreq("http://p/api/conversations/c2", { method: "PATCH", body: JSON.stringify({ title: "  " }) }), ctx("c2"));
  assert.equal(blank.status, 400);
});

test("6.17 export returns all active conversations in one call and writes an ExportEvent", async () => {
  const res = await exp.GET();
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.conversations.length, 2);
  assert.deepEqual(exportEvents, [{ userId: "user-fixture", scope: "all", conversationCount: 2, messageCount: 2 }]);
});

test("6.17 export is refused when the audit row cannot be written", async () => {
  exportAuditFails = true;
  const res = await exp.GET();
  assert.equal(res.status, 503);
  assert.equal((await res.json()).error, "export_audit_unavailable");
});

test("6.10 disabled user cannot list, read, delete or export", async () => {
  chatAllowed = false;
  assert.equal((await list.GET(new Request("http://p/api/conversations"))).status, 403);
  assert.equal((await one.GET(nreq("http://p/api/conversations/c1"), ctx("c1"))).status, 403);
  assert.equal((await one.DELETE(nreq("http://p/api/conversations/c1", { method: "DELETE" }), ctx("c1"))).status, 403);
  assert.equal(convs.get("c1")?.deletedAt, null);
  assert.equal((await exp.GET()).status, 403);
});

test("merged historical conversations remain readable/exportable without granting unrelated histories",async()=>{
 historicalOwners=["old-user","user-fixture"];
 convs.set("old-conversation",{id:"old-conversation",userId:"old-user",title:"old",deletedAt:null,updatedAt:new Date()});
 const page=await (await list.GET(new Request("http://p/api/conversations"))).json();
 assert.equal(page.conversations.length,3);
 assert.equal((await one.GET(nreq("http://p/api/conversations/old-conversation"),ctx("old-conversation"))).status,200);
 assert.equal((await one.GET(nreq("http://p/api/conversations/x"),ctx("x"))).status,404);
 const exported=await (await exp.GET()).json();
 assert.equal(exported.conversations.length,3);
});
