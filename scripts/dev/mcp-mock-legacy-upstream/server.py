#!/usr/bin/env python3
"""多画像 MCP 上游 mock，供开发 VM 端到端验证 JJDGuard 的 MCP 通用上游适配层。

用法:
  python3 server.py --profile amap --key MYKEY [--port 18999]
  python3 server.py --profile legacy-sse
  python3 server.py --list

画像（--profile）：
  legacy        原行为：仅 POST /mcp，Streamable HTTP（保留旧参数 --version / --sse）
  amap          高德形态：/mcp(Streamable) 与 /sse(旧SSE)，鉴权在 query 参数 key；未鉴权返回 HTTP 200 + 业务错误体
  zhipu         智谱形态：/mcp 用 Authorization: Bearer 头；/sse 用 query 参数 Authorization(值为密钥)；未鉴权 200 + {"code":1001}
  baidu         百度 AppBuilder 形态：/sse，query 参数 api_key，值带 "Bearer " 前缀
  dashscope     百炼形态：/mcp 与 /sse，Authorization: Bearer；未鉴权 401 + 私有 JSON {"code":"InvalidApiKey"}
  legacy-sse    纯旧 SSE，无鉴权：/sse + /messages，endpoint 为相对路径
  legacy-sse-abs    同上，endpoint 事件给绝对 URL
  legacy-sse-cross  同上，endpoint 指向另一个 origin（必须被网关拒绝，用于验证 SSRF 防护）
  heartbeat     旧 SSE + 心跳/注释行/CRLF/缺省事件名/多行 data
  mixed         Streamable：initialize 回带 charset 的 JSON，tools/call 回 SSE，session id 大小写混用，initialized 回 404
  version-future    协商版本 2099-01-01（网关应前向兼容接受）
  version-ancient   协商版本 1999-01-01（网关应拒绝并报双方版本）
  oauth         401 + WWW-Authenticate resource_metadata（应提示暂不支持 OAuth）
  paging-weird  tools/list 空页 + 重复 nextCursor
  plain401      401 + text/plain
  header-extra  必须带请求头 Stripe-Account: acct_demo 才放行

每个请求会把 方法 / 路径(query 已脱敏) / MCP-Protocol-Version / Mcp-Session-Id / 鉴权是否通过 打到 stdout，
tools/call 会额外打印工具名，便于确认「红线拦截时上游收不到请求」。
说明：mock 仅用于联调，不含任何真实厂商凭据；--key 的值只用于本机比对，日志里不打印。
"""
import argparse
import json
import re
import sys
import threading
import time
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PROFILES = {
    "legacy": "原行为：POST /mcp",
    "amap": "query key + /mcp + /sse",
    "zhipu": "/mcp Bearer, /sse query Authorization",
    "baidu": "/sse query api_key=Bearer <key>",
    "dashscope": "Bearer + 401 私有 JSON",
    "legacy-sse": "旧 SSE 相对 endpoint",
    "legacy-sse-abs": "旧 SSE 绝对 endpoint",
    "legacy-sse-cross": "旧 SSE 跨源 endpoint",
    "heartbeat": "旧 SSE 心跳/注释/CRLF",
    "mixed": "Streamable 混合形态",
    "version-future": "协商 2099-01-01",
    "version-ancient": "协商 1999-01-01",
    "oauth": "401 + resource_metadata",
    "paging-weird": "tools/list 分页异常",
    "plain401": "401 text/plain",
    "header-extra": "需要 Stripe-Account 头",
}

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=18999)
ap.add_argument("--profile", default="legacy")
ap.add_argument("--key", default="demo-key-123456", help="期望的鉴权密钥（仅本机比对，不打印）")
ap.add_argument("--version", default=None, help="legacy 画像：固定协商版本（默认 2024-11-05）")
ap.add_argument("--sse", action="store_true", help="legacy 画像：用 text/event-stream 回包")
ap.add_argument("--list", action="store_true")
ARGS = ap.parse_args()
if ARGS.list:
    for k, v in PROFILES.items():
        print(f"{k:18s} {v}")
    sys.exit(0)
if ARGS.profile not in PROFILES:
    sys.exit(f"未知画像 {ARGS.profile}，用 --list 查看")

P = ARGS.profile
KEY = ARGS.key
LOCK = threading.Lock()
SESSIONS = {}  # sid -> queue(list)
SEQ = [0]


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def default_version():
    return {
        "legacy": ARGS.version or "2024-11-05",
        "zhipu": "2025-06-18", "dashscope": "2025-06-18", "oauth": "2025-06-18", "plain401": "2025-06-18",
        "header-extra": "2025-06-18", "baidu": "2025-03-26", "heartbeat": "2025-03-26",
        "version-future": "2099-01-01", "version-ancient": "1999-01-01",
    }.get(P, "2025-11-25")


VERSION = default_version()


def tools(cursor=None):
    defs = [
        {"name": "echo", "description": "回显文本", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
        {"name": "get_weather", "description": "查询城市天气", "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}}},
        {"name": "delete_all", "description": "清空全部数据（演示用高危工具）", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    ]
    if P == "paging-weird":
        if not cursor:
            return {"tools": [], "nextCursor": "c1"}
        return {"tools": defs[:2], "nextCursor": "c1"}
    if not cursor:
        return {"tools": defs[:2], "nextCursor": "p2"}
    return {"tools": defs[2:]}


# ---- 鉴权规格：(位置, 名称, 模板, 未鉴权形态) ----
def auth_spec(kind):
    """kind: 'stream' | 'sse'。返回 None 表示不鉴权。"""
    if P in ("amap",):
        return ("query", "key", "{s}", "amap")
    if P == "zhipu":
        return ("header", "Authorization", "Bearer {s}", "zhipu") if kind == "stream" else ("query", "Authorization", "{s}", "zhipu")
    if P == "baidu":
        return ("query", "api_key", "Bearer {s}", "plain401")
    if P == "dashscope":
        return ("header", "Authorization", "Bearer {s}", "dashscope")
    if P == "oauth":
        return ("header", "Authorization", "Bearer {s}", "oauth")
    if P in ("plain401", "header-extra"):
        return ("header", "Authorization", "Bearer {s}", "plain401")
    return None


def auth_ok(h, spec):
    if spec is None:
        return True
    loc, name, tmpl, _ = spec
    want = tmpl.replace("{s}", KEY)
    if loc == "header":
        return h.headers.get(name) == want
    q = parse_qs(urlparse(h.path).query)
    return q.get(name, [None])[0] == want


def send_unauth(h, spec):
    kind = spec[3]
    if kind == "amap":
        body, status, ct = b'{"status":"0","info":"INVALID_USER_KEY","infocode":"10001"}', 200, "application/json"
    elif kind == "zhipu":
        body, status, ct = '{"code":1001,"msg":"Header中未收到Authorization参数，无法进行身份验证。","success":false}'.encode(), 200, "application/json"
    elif kind == "dashscope":
        body, status, ct = b'{"code":"InvalidApiKey","message":"No API-key provided.","request_id":"mock"}', 401, "application/json"
    elif kind == "oauth":
        h.send_response(401)
        h.send_header("WWW-Authenticate", 'Bearer realm="OAuth", resource_metadata="http://%s/.well-known/oauth-protected-resource/mcp/", scope="default"' % h.headers.get("Host"))
        h.send_header("Content-Length", "0")
        h.end_headers()
        return
    else:
        body, status, ct = b"bad request: missing required Authorization header", 401, "text/plain"
    h.send_response(status)
    h.send_header("Content-Type", ct)
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


def handle_rpc(req):
    method, rid = req.get("method"), req.get("id")
    if rid is None:
        return None
    if method == "initialize":
        result = {"protocolVersion": VERSION, "capabilities": {"tools": {}}, "serverInfo": {"name": f"mock-{P}", "version": "1"}}
    elif method == "tools/list":
        result = tools((req.get("params") or {}).get("cursor"))
    elif method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        log("  >>> tools/call 到达上游:", name)
        text = f"echo: {(params.get('arguments') or {}).get('text')}" if name == "echo" else f"ok:{name}"
        result = {"content": [{"type": "text", "text": text}]}
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def safe_path(p):
    u = urlparse(p)
    q = re.sub(r"=[^&]*", "=***", u.query)
    return u.path + ("?" + q if q else "")


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def routes(self):
        path = urlparse(self.path).path
        if P == "legacy":
            return "stream" if path == "/mcp" else None
        if P in ("legacy-sse", "legacy-sse-abs", "legacy-sse-cross", "heartbeat", "baidu"):
            return "sse" if path == "/sse" else ("msg" if path == "/messages" else None)
        if P in ("amap", "zhipu", "dashscope"):
            return {"/mcp": "stream", "/sse": "sse", "/messages": "msg"}.get(path)
        return "stream" if path == "/mcp" else None

    def do_GET(self):
        route = self.routes()
        log("GET ", safe_path(self.path), "route=", route)
        if route != "sse":
            self.send_response(405 if route == "stream" else 404)
            self.send_header("Allow", "POST")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        spec = auth_spec("sse")
        if not auth_ok(self, spec):
            log("  鉴权失败(SSE GET)")
            return send_unauth(self, spec)
        with LOCK:
            SEQ[0] += 1
            sid = f"sid{SEQ[0]}"
            SESSIONS[sid] = []
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        crlf = "\r\n" if P == "heartbeat" else "\n"

        def emit(name, data):
            out = ""
            if name:
                out += f"event: {name}{crlf}"
            for line in data.split("\n"):
                out += f"data: {line}{crlf}"
            out += crlf
            self.wfile.write(out.encode())
            self.wfile.flush()

        ep = f"/messages?sessionId={sid}"
        if P == "legacy-sse-abs":
            ep = f"http://{self.headers.get('Host')}{ep}"
        elif P == "legacy-sse-cross":
            ep = f"http://169.254.169.254:80{ep}"
        try:
            if P == "heartbeat":
                self.wfile.write(f": welcome{crlf}{crlf}".encode())
            emit("endpoint", ep)
            while True:
                time.sleep(0.05)
                with LOCK:
                    q = SESSIONS.get(sid)
                    items, q[:] = list(q), [] if q is not None else []
                for it in items:
                    if P == "heartbeat":
                        emit(None, json.dumps(it, ensure_ascii=False, indent=1))
                    else:
                        emit("message", json.dumps(it, ensure_ascii=False))
                if P == "heartbeat":
                    self.wfile.write(f": ping{crlf}{crlf}".encode())
                    self.wfile.flush()
        except Exception:
            pass
        finally:
            with LOCK:
                SESSIONS.pop(sid, None)
            log("  SSE 流关闭", sid)

    def do_DELETE(self):
        self.send_response(204 if self.routes() == "stream" else 405)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b""
        route = self.routes()
        try:
            req = json.loads(raw or b"{}")
        except Exception:
            req = {}
        method = req.get("method")
        log("POST", safe_path(self.path), f"{method!s:28s}", "MCP-Protocol-Version=%r" % self.headers.get("MCP-Protocol-Version"),
            "Mcp-Session-Id=%r" % self.headers.get("Mcp-Session-Id"), "UA=%r" % (self.headers.get("User-Agent") or "")[:24])
        if route not in ("stream", "msg"):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        spec = auth_spec("stream" if route == "stream" else "sse")
        if not auth_ok(self, spec):
            log("  鉴权失败")
            return send_unauth(self, spec)
        if P == "header-extra" and self.headers.get("Stripe-Account") != "acct_demo":
            body = b'{"error":{"message":"Stripe-Account header required"}}'
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        resp = handle_rpc(req)

        if route == "msg":  # 旧 SSE：202 + 响应走 SSE 流
            sid = parse_qs(urlparse(self.path).query).get("sessionId", [None])[0]
            with LOCK:
                q = SESSIONS.get(sid)
                if q is not None and resp is not None:
                    q.append(resp)
            code = 202 if q is not None else 404
            self.send_response(code)
            self.send_header("Content-Length", "8")
            self.end_headers()
            self.wfile.write(b"Accepted" if code == 202 else b"no sess ")
            return

        # Streamable
        if resp is None:  # 通知
            self.send_response(404 if P == "mixed" else 202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps(resp, ensure_ascii=False).encode()
        ctype, extra = "application/json", []
        if method == "initialize":
            sid = "sess-mixed-1" if P == "mixed" else "legacy-session-1" if P == "legacy" else "sess-1"
            extra.append(("mcp-SESSION-id" if P == "mixed" else "Mcp-Session-Id", sid))
        if P == "legacy" and method != "initialize" and VERSION >= "2025-06-18" and self.headers.get("MCP-Protocol-Version") != VERSION:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if P == "mixed":
            if method == "initialize":
                ctype = "application/json; charset=utf-8"
            elif method == "tools/call":
                ctype = "text/event-stream; charset=utf-8"
                body = f": open\n\nevent: message\ndata: {body.decode()}\n\n".encode()
            elif method == "tools/list":
                ctype = "Application/JSON; Charset=UTF-8"
                body = gzip.compress(body)
                extra.append(("Content-Encoding", "gzip"))
        elif P == "legacy" and ARGS.sse:
            ctype = "text/event-stream"
            body = f"event: message\ndata: {body.decode()}\n\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class S(ThreadingHTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    log(f"mock MCP 上游启动 profile={P} port={ARGS.port} 协商版本={VERSION}")
    S(("0.0.0.0", ARGS.port), H).serve_forever()
