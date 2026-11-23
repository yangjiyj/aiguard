import assert from "node:assert/strict"
import http from "node:http"
import { once } from "node:events"
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { test } from "node:test"

import { createHttpServer } from "./server.js"

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve))
  return server.address().port
}

async function close(server) {
  server.close()
  await once(server, "close")
}

function request(port, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get({ hostname: "127.0.0.1", port, path, headers }, resolve)
    req.on("error", reject)
  })
}

async function readBody(res) {
  let body = ""
  for await (const chunk of res) {
    body += chunk
  }
  return body
}

async function startUpstream(handler) {
  const server = http.createServer(handler)
  const port = await listen(server)
  return { server, url: `http://127.0.0.1:${port}` }
}

test("proxies the exact posture API path to control-plane with authentication and query intact", async () => {
  let calls = 0
  const upstream = await startUpstream((req, res) => {
    calls++
    assert.equal(req.method, "GET")
    assert.equal(req.url, "/api/security/posture?tenant_id=forged")
    assert.equal(req.headers.authorization, "Bearer posture-session")
    assert.equal(req.headers.cookie, "session=posture-cookie")
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" })
    res.end('{"tenant_id":"tenant-authenticated","channels":[]}')
  })
  const server = createHttpServer({ controlPlaneTarget: upstream.url })
  const port = await listen(server)
  try {
    const res = await request(port, "/api/security/posture?tenant_id=forged", {
      Authorization: "Bearer posture-session",
      Cookie: "session=posture-cookie",
    })
    assert.equal(res.statusCode, 200)
    assert.equal(res.headers["cache-control"], "no-store")
    assert.deepEqual(JSON.parse(await readBody(res)), { tenant_id: "tenant-authenticated", channels: [] })
    assert.equal(calls, 1)
  } finally {
    await close(server)
    await close(upstream.server)
  }
})

test("posture API proxy preserves control-plane authentication refusals", async () => {
  const upstream = await startUpstream((_req, res) => {
    res.writeHead(401, { "content-type": "application/json" })
    res.end('{"error":"authentication_required"}')
  })
  const server = createHttpServer({ controlPlaneTarget: upstream.url })
  const port = await listen(server)
  try {
    const res = await request(port, "/api/security/posture")
    assert.equal(res.statusCode, 401)
    assert.equal(await readBody(res), '{"error":"authentication_required"}')
  } finally {
    await close(server)
    await close(upstream.server)
  }
})

test("posture proxy does not admit adjacent or other API paths", async () => {
  let calls = 0
  const upstream = await startUpstream((_req, res) => {
    calls++
    res.end("unexpected upstream")
  })
  const server = createHttpServer({ controlPlaneTarget: upstream.url })
  const port = await listen(server)
  try {
    for (const route of ["/api/security/posture/", "/api/security/posture/extra", "/api/security/posturex", "/api/health"]) {
      const res = await request(port, route)
      assert.equal(res.statusCode, 404, route)
      assert.equal(await readBody(res), "not found")
    }
    assert.equal(calls, 0)
  } finally {
    await close(server)
    await close(upstream.server)
  }
})

test("posture API proxy preserves the read-only upstream response for writes", async () => {
  const upstream = await startUpstream((req, res) => {
    assert.equal(req.method, "POST")
    assert.equal(req.url, "/api/security/posture")
    res.writeHead(405, { allow: "GET", "content-type": "application/json" })
    res.end('{"error":"method_not_allowed"}')
  })
  const server = createHttpServer({ controlPlaneTarget: upstream.url })
  const port = await listen(server)
  try {
    const res = await new Promise((resolve, reject) => {
      const req = http.request({ hostname: "127.0.0.1", port, path: "/api/security/posture", method: "POST" }, resolve)
      req.on("error", reject)
      req.end()
    })
    assert.equal(res.statusCode, 405)
    assert.equal(res.headers.allow, "GET")
    assert.equal(await readBody(res), '{"error":"method_not_allowed"}')
  } finally {
    await close(server)
    await close(upstream.server)
  }
})

test("redirects HTTP console traffic to HTTPS when TLS is enabled", async () => {
  const server = createHttpServer({ redirectToHttps: true, httpsPort: 3443 })
  const port = await listen(server)

  try {
    const res = await request(port, "/login", { Host: "gateway.local:3000" })

    assert.equal(res.statusCode, 308)
    assert.equal(res.headers.location, "https://gateway.local:3443/login")
  } finally {
    await close(server)
  }
})

test("redirects to the externally published HTTPS port", async () => {
  const server = createHttpServer({ redirectToHttps: true, httpsPort: 443 })
  const port = await listen(server)

  try {
    const res = await request(port, "/login", { Host: "gateway.local:3000" })

    assert.equal(res.statusCode, 308)
    assert.equal(res.headers.location, "https://gateway.local/login")
  } finally {
    await close(server)
  }
})

test("keeps HTTP health checks available without redirect", async () => {
  const server = createHttpServer({ redirectToHttps: true, httpsPort: 3443 })
  const port = await listen(server)

  try {
    const res = await request(port, "/health", { Host: "gateway.local:3000" })
    let body = ""
    for await (const chunk of res) {
      body += chunk
    }

    assert.equal(res.statusCode, 200)
    assert.equal(body, "OK")
  } finally {
    await close(server)
  }
})

test("serves console assets with browser security headers", async () => {
  const distDir = await mkdtemp(path.join(os.tmpdir(), "web-console-dist-"))
  await writeFile(path.join(distDir, "index.html"), "<!doctype html><div id=\"root\"></div>")
  const server = createHttpServer({ distDir })
  const port = await listen(server)

  try {
    const res = await request(port, "/", { Host: "gateway.local:3000" })

    assert.equal(res.statusCode, 200)
    assert.equal(res.headers["x-content-type-options"], "nosniff")
    assert.equal(res.headers["x-frame-options"], "DENY")
    assert.equal(res.headers["referrer-policy"], "no-referrer")
    assert.match(res.headers["content-security-policy"], /default-src 'self'/)
    assert.match(res.headers["content-security-policy"], /frame-ancestors 'none'/)
    assert.equal(res.headers["permissions-policy"], "camera=(), microphone=(), geolocation=()")
    assert.equal(res.headers["cache-control"], "no-store, max-age=0, must-revalidate")
    assert.equal(res.headers.pragma, "no-cache")
    assert.equal(res.headers.expires, "0")
  } finally {
    await close(server)
    await rm(distDir, { recursive: true, force: true })
  }
})

test("returns 404 for stale hashed assets instead of the SPA shell", async () => {
  const distDir = await mkdtemp(path.join(os.tmpdir(), "web-console-dist-"))
  await writeFile(path.join(distDir, "index.html"), "<!doctype html><div id=\"root\"></div>")
  const server = createHttpServer({ distDir })
  const port = await listen(server)

  try {
    const res = await request(port, "/assets/index-stale.js", { Host: "gateway.local:3000" })

    assert.equal(res.statusCode, 404)
    assert.equal(await readBody(res), "not found")
  } finally {
    await close(server)
    await rm(distDir, { recursive: true, force: true })
  }
})

test("does not serve SPA fallback for unknown API paths", async () => {
  const distDir = await mkdtemp(path.join(os.tmpdir(), "web-console-dist-"))
  await writeFile(path.join(distDir, "index.html"), "<!doctype html><div id=\"root\"></div>")
  const server = createHttpServer({ distDir })
  const port = await listen(server)

  try {
    const res = await request(port, "/api/health", { Host: "gateway.local:3000" })
    let body = ""
    for await (const chunk of res) {
      body += chunk
    }

    assert.equal(res.statusCode, 404)
    assert.equal(body, "not found")
  } finally {
    await close(server)
    await rm(distDir, { recursive: true, force: true })
  }
})

test("proxies /chat through the internal chat edge without rewriting the path", async () => {
  const upstream = await startUpstream((req, res) => {
    assert.equal(req.url, "/chat/api/models?limit=2")
    assert.equal(req.headers.host, "gateway.local")
    assert.equal(req.headers["x-forwarded-host"], "gateway.local")
    assert.equal(req.headers["x-forwarded-proto"], "http")
    assert.notEqual(req.headers["x-forwarded-for"], "203.0.113.9")
    res.writeHead(200, { "content-type": "text/event-stream" })
    res.write("data: first\n\n")
    res.end("data: second\n\n")
  })
  const server = createHttpServer({ chatTarget: upstream.url })
  const port = await listen(server)

  try {
    const res = await request(port, "/chat/api/models?limit=2", {
      Host: "gateway.local",
      "X-Forwarded-Proto": "https",
      "X-Forwarded-Host": "evil.example",
      "X-Forwarded-For": "203.0.113.9",
    })
    assert.equal(res.statusCode, 200)
    assert.equal(await readBody(res), "data: first\n\ndata: second\n\n")
  } finally {
    await close(server)
    await close(upstream.server)
  }
})

test("collapses a duplicated Chat base path in upstream redirects", async () => {
  const upstream = await startUpstream((_req, res) => {
    res.writeHead(307, {
      location: "/chat/chat/login?callbackUrl=%2Fchat%2Frecords",
    })
    res.end()
  })
  const server = createHttpServer({ chatTarget: upstream.url })
  const port = await listen(server)

  try {
    const res = await request(port, "/chat", { Host: "gateway.local" })
    assert.equal(res.statusCode, 307)
    assert.equal(
      res.headers.location,
      "/chat/login?callbackUrl=%2Fchat%2Frecords",
    )
  } finally {
    await close(server)
    await close(upstream.server)
  }
})

test("proxies only the public /sso boundary to the identity edge", async () => {
  const upstream = await startUpstream((req, res) => {
    assert.equal(req.url, "/sso/realms/jjdguard/.well-known/openid-configuration")
    res.writeHead(200, { "content-type": "application/json" })
    res.end('{"issuer":"https://gateway.local/sso/realms/jjdguard"}')
  })
  const server = createHttpServer({ ssoTarget: upstream.url })
  const port = await listen(server)

  try {
    const res = await request(port, "/sso/realms/jjdguard/.well-known/openid-configuration", {
      Host: "gateway.local",
    })
    assert.equal(res.statusCode, 200)
    assert.match(await readBody(res), /gateway\.local\/sso/)
  } finally {
    await close(server)
    await close(upstream.server)
  }
})

test("proxies the public MCP endpoint to gateway-core without rewriting the route", async () => {
  const upstream = await startUpstream((req, res) => {
    assert.equal(req.method, "GET")
    assert.equal(req.url, "/mcp/server-1?cursor=next")
    assert.equal(req.headers.authorization, "Bearer gateway-key")
    assert.equal(req.headers.accept, "application/json, text/event-stream")
    res.writeHead(200, {
      "content-type": "text/event-stream",
      "mcp-session-id": "session-1",
    })
    res.end("data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n")
  })
  const server = createHttpServer({ gatewayTarget: upstream.url })
  const port = await listen(server)

  try {
    const res = await request(port, "/mcp/server-1?cursor=next", {
      Host: "gateway.local",
      Authorization: "Bearer gateway-key",
      Accept: "application/json, text/event-stream",
    })

    assert.equal(res.statusCode, 200)
    assert.equal(res.headers["mcp-session-id"], "session-1")
    assert.match(await readBody(res), /notifications\/tools\/list_changed/)
  } finally {
    await close(server)
    await close(upstream.server)
  }
})


// D7：控制台页面 /mcp-gateway/* 刷新/深链接必须回落 SPA；网关数据面 /mcp/{serverID} 仍转 gateway-core。
// 旧书签 /mcp/servers 等曾因此被当成 serverID 转给网关而 404，现在页面已迁走，旧路径由前端重定向。
test("console pages under /mcp-gateway fall back to the SPA and are never proxied to the gateway", async () => {
  let gatewayCalls = 0
  const upstream = await startUpstream((req, res) => {
    gatewayCalls++
    res.writeHead(200)
    res.end("gateway")
  })
  const distDir = await mkdtemp(path.join(os.tmpdir(), "web-console-dist-"))
  await writeFile(path.join(distDir, "index.html"), "console shell")
  const server = createHttpServer({ distDir, gatewayTarget: upstream.url })
  const port = await listen(server)
  try {
    for (const p of ["/mcp-gateway/servers", "/mcp-gateway/policies", "/mcp-gateway/approvals", "/mcp-gateway/audit?request_id=r1"]) {
      const res = await request(port, p)
      assert.equal(res.statusCode, 200, p)
      assert.equal(await readBody(res), "console shell", p)
    }
    assert.equal(gatewayCalls, 0, "控制台页面不得被转给网关")
    const data = await request(port, "/mcp/server-1")
    assert.equal(await readBody(data), "gateway")
    assert.equal(gatewayCalls, 1, "数据面 /mcp/{serverID} 必须继续转给网关")
  } finally {
    await close(server)
    await close(upstream.server)
    await rm(distDir, { recursive: true, force: true })
  }
})

// D7：旧书签/外链直接打开 /mcp/servers 等控制台旧路径时，请求先到边缘代理，不会进到前端路由。
// 浏览器导航（GET + Accept: text/html）必须 302 到新路径并保留 query；MCP 客户端（POST，或 GET + event-stream）不受影响。
test("old console bookmarks under /mcp are redirected for browser navigation only", async () => {
  const seen = []
  const upstream = await startUpstream((req, res) => {
    seen.push(`${req.method} ${req.url}`)
    res.writeHead(200)
    res.end("gateway")
  })
  const server = createHttpServer({ gatewayTarget: upstream.url })
  const port = await listen(server)
  try {
    const cases = [
      ["/mcp/servers", "/mcp-gateway/servers"],
      ["/mcp/policies", "/mcp-gateway/policies"],
      ["/mcp/approvals", "/mcp-gateway/approvals"],
      ["/mcp/audit?request_id=r1", "/mcp-gateway/audit?request_id=r1"],
      ["/mcp/overview", "/mcp-gateway/audit"],
    ]
    for (const [from, to] of cases) {
      const res = await request(port, from, { Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8" })
      assert.equal(res.statusCode, 302, from)
      assert.equal(res.headers.location, to, from)
      await readBody(res)
    }
    assert.deepEqual(seen, [], "浏览器导航的旧书签不得到达网关")

    // MCP 客户端：GET 长流（event-stream）与其他 serverID 仍转给网关，路由不被改写。
    const sse = await request(port, "/mcp/servers", { Accept: "text/event-stream" })
    assert.equal(await readBody(sse), "gateway")
    const other = await request(port, "/mcp/mcp_srv1", { Accept: "text/html" })
    assert.equal(await readBody(other), "gateway")
    assert.deepEqual(seen, ["GET /mcp/servers", "GET /mcp/mcp_srv1"])
  } finally {
    await close(server)
    await close(upstream.server)
  }
})

test("serves agent-kit files without falling back to the console, including an empty kit", async () => {
  const agentKitDir = await mkdtemp(path.join(os.tmpdir(), "web-console-kit-"))
  const distDir = await mkdtemp(path.join(os.tmpdir(), "web-console-dist-"))
  await writeFile(path.join(distDir, "index.html"), "console shell")
  const server = createHttpServer({ distDir, agentKitDir })
  const port = await listen(server)

  try {
    for (const name of ["/agent-kit/", "/agent-kit/missing.js"]) {
      const res = await request(port, name)
      assert.equal(res.statusCode, 404)
      assert.equal(await readBody(res), "not found")
    }
    await writeFile(path.join(agentKitDir, "install.sh"), "#!/bin/sh\n")
    const res = await request(port, "/agent-kit/install.sh")
    assert.equal(res.statusCode, 200)
    assert.equal(await readBody(res), "#!/bin/sh\n")
    assert.equal(res.headers["cache-control"], "no-store")
    assert.equal(res.headers["x-content-type-options"], "nosniff")
  } finally {
    await close(server)
    await rm(agentKitDir, { recursive: true, force: true })
    await rm(distDir, { recursive: true, force: true })
  }
})

test("rejects agent-kit path traversal and symlinks escaping its directory", async () => {
  const base = await mkdtemp(path.join(os.tmpdir(), "web-console-kit-base-"))
  const agentKitDir = path.join(base, "agent-kit")
  await mkdir(agentKitDir)
  await writeFile(path.join(base, "secret.txt"), "private")
  await writeFile(path.join(agentKitDir, "index.html"), "kit shell")
  await symlink(path.join(base, "secret.txt"), path.join(agentKitDir, "linked.txt"))
  const server = createHttpServer({ agentKitDir })
  const port = await listen(server)

  try {
    for (const name of ["/agent-kit/%2e%2e/secret.txt", "/agent-kit/%2e%2e%2fsecret.txt", "/agent-kit%2f..%2fsecret.txt", "/agent-kit/%5c..%5csecret.txt", "/agent-kit/linked.txt"]) {
      const res = await request(port, name)
      assert.equal(res.statusCode, 403, name)
      assert.equal(await readBody(res), "forbidden", name)
    }
  } finally {
    await close(server)
    await rm(base, { recursive: true, force: true })
  }
})

test("Gemini native requests reach the data plane through public HTTPS routing instead of the SPA", async () => {
  const calls = []
  const payload = JSON.stringify({ contents: [{ role: "user", parts: [{ text: "hello" }] }] })
  const upstream = await startUpstream(async (req, res) => {
    calls.push(req.url)
    assert.equal(req.method, "POST")
    assert.equal(req.headers["x-goog-api-key"], "fixture-google-gateway-key")
    assert.equal(await readBody(req), payload)
    res.writeHead(401, { "content-type": "application/json" })
    res.end(JSON.stringify({ error: { code: 401, status: "UNAUTHENTICATED" } }))
  })
  const server = createHttpServer({ gatewayTarget: upstream.url })
  const port = await listen(server)
  try {
    for (const route of ["/v1beta/models/model:generateContent", "/v1beta/models/model:streamGenerateContent?alt=sse", "/v1/models/model:generateContent"]) {
      const response = await fetch(`http://127.0.0.1:${port}${route}`, { method: "POST", headers: { "x-goog-api-key": "fixture-google-gateway-key", "content-type": "application/json" }, body: payload })
      assert.equal(response.status, 401)
      assert.equal((await response.json()).error.status, "UNAUTHENTICATED")
    }
    assert.equal(calls.length, 3)
  } finally {
    await close(server)
    await close(upstream.server)
  }
})


test('model API target corrects the managed legacy forward-proxy port only', async () => {
 const {resolveGatewayApiTarget}=await import('./server.js');
 assert.equal(resolveGatewayApiTarget('', 'http://gateway-core:8082'),'http://gateway-core:8080/');
 assert.equal(resolveGatewayApiTarget('', 'http://custom-gateway:8082'),'http://custom-gateway:8082');
 assert.equal(resolveGatewayApiTarget('http://dedicated:18080','http://gateway-core:8082'),'http://dedicated:18080');
 assert.equal(resolveGatewayApiTarget('', 'http://gateway-core:8080'),'http://gateway-core:8080');
});

// D7：nginx.conf 与 server.js 必须重定向同一批旧页面（nginx 无法在单测里直接起，这里做静态一致性；真实行为见 nginx-legacy-redirect.e2e.sh）。
test("nginx.conf and server.js redirect the same legacy MCP console pages", async () => {
  const { readFile } = await import("node:fs/promises")
  const serverSrc = await readFile(new URL("./server.js", import.meta.url), "utf8")
  const nginxSrc = await readFile(new URL("./nginx.conf", import.meta.url), "utf8")
  const fromServer = [...serverSrc.matchAll(/\['\/mcp\/([a-z]+)', '\/mcp-gateway\/[a-z]+'\]/g)].map((m) => m[1]).sort()
  const loc = nginxSrc.match(/location ~ \^\/mcp\/\(([a-z|]+)\)\$/)
  assert.ok(loc, "nginx.conf 缺少旧书签 location")
  assert.deepEqual(loc[1].split("|").sort(), fromServer)
  assert.match(nginxSrc, /GET\|HEAD/, "nginx 重定向必须限制 GET/HEAD")
})
