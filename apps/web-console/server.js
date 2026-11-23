import { createReadStream, existsSync, readFileSync } from 'node:fs'
import { promises as fs } from 'node:fs'
import {createHmac} from 'node:crypto'
import http from 'node:http'
import https from 'node:https'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const modulePath = fileURLToPath(import.meta.url)
const __dirname = path.dirname(modulePath)
const defaultDistDir = path.join(__dirname, 'dist')
const defaultAgentKitDir = path.join(__dirname, 'agent-kit')
const defaultPort = Number(process.env.PORT || '3000')
const defaultHttpsPort = Number(process.env.HTTPS_PORT || '3443')
const defaultControlPlaneTarget = process.env.CONTROL_PLANE_URL || 'http://control-plane:8081'
const defaultGatewayTarget = resolveGatewayApiTarget(process.env.GATEWAY_API_URL, process.env.GATEWAY_CORE_URL)
const defaultChatTarget = process.env.CHAT_EDGE_URL || 'http://chat-edge:3100'
const defaultSsoTarget = process.env.SSO_EDGE_URL || 'http://chat-edge:8180'
const defaultPortalAdminTarget = process.env.PORTAL_ADMIN_EDGE_URL || 'http://chat-edge:8280'

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.map': 'application/json; charset=utf-8',
}

const staticSecurityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "style-src 'self' 'unsafe-inline'",
    "script-src 'self'",
    "connect-src 'self'",
  ].join('; '),
}

// 8082 is the managed forward-proxy listener, never the model API listener.
// Preserve custom gateway hosts/ports and provide an explicit API override.
export function resolveGatewayApiTarget(apiURL, legacyURL) {
  if (apiURL?.trim()) return apiURL.trim()
  const value = legacyURL?.trim() || 'http://gateway-core:8080'
  try {
    const parsed = new URL(value)
    if (parsed.protocol === 'http:' && parsed.hostname === 'gateway-core' && parsed.port === '8082' && parsed.pathname === '/' && !parsed.username && !parsed.password && !parsed.search && !parsed.hash) {
      parsed.port = '8080'
      return parsed.toString()
    }
  } catch { /* Let normal upstream error handling report invalid deployment configuration. */ }
  return value
}

export function proxyRequest(req, res, baseURL, options = {}) {
  const target = new URL(req.url, baseURL)
  const client = target.protocol === 'https:' ? https : http
  const originalHost = req.headers.host || target.host
  const remoteAddress = (req.socket.remoteAddress || '').replace(/^::ffff:/,'')
  const ipTime=String(Math.floor(Date.now()/1000))
  const ipSecret=process.env.JJD_LOGIN_IP_FORWARD_SECRET?.trim()
  const ipSignature=ipSecret?createHmac('sha256',ipSecret).update('v1\n'+remoteAddress+'\n'+ipTime).digest('hex'):''
  const forwardedProto = req.socket.encrypted ? 'https' : 'http'

  const upstream = client.request(
    target,
    {
      method: req.method,
      headers: {
        ...req.headers,
        host: options.preserveHost ? originalHost : target.host,
        'x-forwarded-host': originalHost,
        'x-forwarded-proto': forwardedProto,
        'x-forwarded-for': remoteAddress,
        'x-real-ip': remoteAddress,
        'x-jjd-client-ip-time':ipSecret?ipTime:'',
        'x-jjd-client-ip-signature':ipSignature,
      },
    },
    (upstreamRes) => {
      const responseHeaders = { ...upstreamRes.headers }
      if (typeof responseHeaders.location === 'string' && options.locationPathPrefix) {
        responseHeaders.location = collapseDuplicatePathPrefix(
          responseHeaders.location,
          options.locationPathPrefix
        )
      }
      res.writeHead(upstreamRes.statusCode || 502, responseHeaders)
      upstreamRes.pipe(res)
    }
  )

  upstream.on('error', (err) => {
    if (res.headersSent) {
      res.destroy(err)
      return
    }
    res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({ error: { code: 'bad_gateway', message: err.message } }))
  })

  req.pipe(upstream)
}

export function collapseDuplicatePathPrefix(location, pathPrefix) {
  const normalizedPrefix = pathPrefix.replace(/\/$/, '')
  const duplicatePrefix = `${normalizedPrefix}${normalizedPrefix}`
  const collapsePathname = (pathname) => {
    if (pathname === duplicatePrefix) return normalizedPrefix
    if (pathname.startsWith(`${duplicatePrefix}/`)) {
      return normalizedPrefix + pathname.slice(duplicatePrefix.length)
    }
    return pathname
  }

  if (location.startsWith('/')) {
    const parsed = new URL(location, 'http://proxy.invalid')
    parsed.pathname = collapsePathname(parsed.pathname)
    return `${parsed.pathname}${parsed.search}${parsed.hash}`
  }

  try {
    const parsed = new URL(location)
    parsed.pathname = collapsePathname(parsed.pathname)
    return parsed.toString()
  } catch {
    return location
  }
}

export async function serveStatic(req, res, options = {}) {
  const distDir = options.distDir || defaultDistDir
  let requestedPath = decodeURIComponent(new URL(req.url, `http://${req.headers.host || 'localhost'}`).pathname)
  if (requestedPath === '/') {
    requestedPath = '/index.html'
  }

  const isAssetRequest = requestedPath.startsWith('/assets/') || path.extname(requestedPath) !== ''
  let filePath = path.join(distDir, requestedPath)
  if (!filePath.startsWith(distDir)) {
    res.writeHead(403)
    res.end('forbidden')
    return
  }

  try {
    let stats
    try {
      stats = await fs.stat(filePath)
      if (stats.isDirectory()) {
        filePath = path.join(filePath, 'index.html')
      }
    } catch {
      if (isAssetRequest) {
        writeNotFound(res)
        return
      }
      filePath = path.join(distDir, 'index.html')
    }

    if (!existsSync(filePath)) {
      if (isAssetRequest) {
        writeNotFound(res)
        return
      }
      filePath = path.join(distDir, 'index.html')
    }

    const ext = path.extname(filePath).toLowerCase()
    const isIndex = filePath.endsWith('index.html')
    res.writeHead(200, {
      ...staticSecurityHeaders,
      'Content-Type': mimeTypes[ext] || 'application/octet-stream',
      'Cache-Control': isIndex ? 'no-store, max-age=0, must-revalidate' : 'public, max-age=31536000, immutable',
      ...(isIndex ? { Pragma: 'no-cache', Expires: '0' } : {}),
    })
    createReadStream(filePath).pipe(res)
  } catch {
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' })
    res.end('internal server error')
  }
}

export async function serveAgentKit(req, res, options = {}) {
  const agentKitDir = options.agentKitDir || defaultAgentKitDir
  const rawPath = req.url.split('?', 1)[0]
  let relativePath
  try {
    relativePath = decodeURIComponent(rawPath.slice('/agent-kit'.length))
  } catch {
    res.writeHead(400)
    res.end('bad request')
    return
  }

  if (relativePath.includes('\\') || relativePath.includes('\0')) {
    res.writeHead(403)
    res.end('forbidden')
    return
  }

  const root = path.resolve(agentKitDir)
  const filePath = path.resolve(root, `.${relativePath || '/'}`)
  const insideRoot = (candidate) => {
    const relative = path.relative(root, candidate)
    return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  }
  if (!insideRoot(filePath)) {
    res.writeHead(403)
    res.end('forbidden')
    return
  }

  try {
    let resolved = filePath
    let stats = await fs.stat(resolved)
    if (stats.isDirectory()) {
      resolved = path.join(resolved, 'index.html')
      stats = await fs.stat(resolved)
    }
    if (!stats.isFile() || !insideRoot(await fs.realpath(resolved))) {
      res.writeHead(403)
      res.end('forbidden')
      return
    }
    const ext = path.extname(resolved).toLowerCase()
    res.writeHead(200, {
      ...staticSecurityHeaders,
      'Content-Type': mimeTypes[ext] || 'application/octet-stream',
      'Cache-Control': 'no-store',
    })
    createReadStream(resolved).pipe(res)
  } catch (err) {
    if (err.code === 'ENOENT' || err.code === 'ENOTDIR') {
      writeNotFound(res)
      return
    }
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' })
    res.end('internal server error')
  }
}

function parseBoolean(value, defaultValue = false) {
  if (value === undefined || value === null || value === '') {
    return defaultValue
  }
  return !['0', 'false', 'no', 'off'].includes(String(value).toLowerCase())
}

function hostnameFromRequest(req) {
  const hostHeader = req.headers.host || 'localhost'
  try {
    return new URL(`http://${hostHeader}`).hostname
  } catch {
    return hostHeader.replace(/:\d+$/, '') || 'localhost'
  }
}

export function buildHttpsLocation(req, httpsPort = defaultHttpsPort) {
  const hostname = hostnameFromRequest(req)
  const port = Number(httpsPort)
  const portSuffix = port === 443 ? '' : `:${port}`
  return `https://${hostname}${portSuffix}${req.url || '/'}`
}

function writeHealth(res) {
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' })
  res.end('OK')
}

function writeHttpsRedirect(req, res, httpsPort) {
  res.writeHead(308, {
    Location: buildHttpsLocation(req, httpsPort),
    'Cache-Control': 'no-store',
  })
  res.end()
}

function writeNotFound(res) {
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' })
  res.end('not found')
}

const legacyMcpConsolePages = new Map([
  ['/mcp/servers', '/mcp-gateway/servers'],
  ['/mcp/policies', '/mcp-gateway/policies'],
  ['/mcp/approvals', '/mcp-gateway/approvals'],
  ['/mcp/audit', '/mcp-gateway/audit'],
  ['/mcp/overview', '/mcp-gateway/audit'],
])

function legacyMcpConsoleRedirect(req, requestPath) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return ''
  const target = legacyMcpConsolePages.get(requestPath)
  if (!target) return ''
  if (!String(req.headers.accept || '').toLowerCase().includes('text/html')) return ''
  const query = new URL(req.url, 'http://localhost').search
  return target === '/mcp-gateway/audit' && requestPath === '/mcp/overview' ? target : target + query
}

export function createRequestHandler(options = {}) {
  const distDir = options.distDir || defaultDistDir
  const controlPlaneTarget = options.controlPlaneTarget || defaultControlPlaneTarget
  const gatewayTarget = options.gatewayTarget || defaultGatewayTarget
  const chatTarget = options.chatTarget || defaultChatTarget
  const ssoTarget = options.ssoTarget || defaultSsoTarget
  const portalAdminTarget = options.portalAdminTarget || defaultPortalAdminTarget
  const redirectToHttps = Boolean(options.redirectToHttps)
  const httpsPort = Number(options.httpsPort || defaultHttpsPort)

  return (req, res) => {
    if (!req.url) {
      res.writeHead(400)
      res.end('bad request')
      return
    }
    const requestPath = new URL(req.url, 'http://localhost').pathname

    if (requestPath === '/health') {
      writeHealth(res)
      return
    }

    if (redirectToHttps) {
      writeHttpsRedirect(req, res, httpsPort)
      return
    }

    if (requestPath === '/chat' || requestPath.startsWith('/chat/')) {
      proxyRequest(req, res, chatTarget, { preserveHost: true, locationPathPrefix: '/chat' })
      return
    }

    if (requestPath === '/sso' || requestPath.startsWith('/sso/')) {
      proxyRequest(req, res, ssoTarget, { preserveHost: true, locationPathPrefix: '/sso' })
      return
    }

    if (requestPath === '/portal' || requestPath.startsWith('/portal/')) {
      proxyRequest(req, res, portalAdminTarget, { preserveHost: true, locationPathPrefix: '/portal' })
      return
    }

    if (requestPath === '/api/security/posture' || requestPath.startsWith('/admin/')) {
      proxyRequest(req, res, controlPlaneTarget)
      return
    }

    if (req.url.startsWith('/v1/') || req.url.startsWith('/v1beta/')) {
      proxyRequest(req, res, gatewayTarget)
      return
    }

    // 控制台页面已迁到 /mcp-gateway/*；旧书签 /mcp/servers 等是浏览器导航（GET + Accept: text/html）时，
    // 302 到新路径并保留 query。MCP 客户端不发 text/html，仍原样转给网关（数据面 /mcp/{serverID} 不变）。
    const legacyConsoleTarget = legacyMcpConsoleRedirect(req, requestPath)
    if (legacyConsoleTarget) {
      res.writeHead(302, { Location: legacyConsoleTarget, 'Cache-Control': 'no-store' })
      res.end()
      return
    }

    // Keep MCP on the same public HTTPS origin as the console. The public
    // /mcp/{serverID} route must reach gateway-core instead of the SPA fallback.
    if (requestPath === '/mcp' || requestPath.startsWith('/mcp/')) {
      proxyRequest(req, res, gatewayTarget)
      return
    }

    const rawPath = req.url.split('?', 1)[0]
    if (rawPath === '/agent-kit' || /^\/agent-kit(?:\/|%(?:2f|5c))/i.test(rawPath)) {
      serveAgentKit(req, res, { agentKitDir: options.agentKitDir })
      return
    }

    if (requestPath.startsWith('/api/')) {
      writeNotFound(res)
      return
    }

    serveStatic(req, res, { distDir })
  }
}

export function createHttpServer(options = {}) {
  return http.createServer(createRequestHandler(options))
}

export function createHttpsServer(options = {}) {
  const certFile = options.certFile || process.env.TLS_CERT_FILE
  const keyFile = options.keyFile || process.env.TLS_KEY_FILE
  if (!certFile || !keyFile) {
    throw new Error('TLS_CERT_FILE and TLS_KEY_FILE are required when TLS is enabled')
  }

  return https.createServer(
    {
      cert: readFileSync(certFile),
      key: readFileSync(keyFile),
    },
    createRequestHandler({ ...options, redirectToHttps: false })
  )
}

export function start() {
  const tlsEnabled = parseBoolean(process.env.TLS_ENABLED, false)
  const redirectHttpsPort = Number(process.env.HTTPS_REDIRECT_PORT || defaultHttpsPort)
  const httpServer = createHttpServer({ redirectToHttps: tlsEnabled, httpsPort: redirectHttpsPort })

  httpServer.listen(defaultPort, '0.0.0.0', () => {
    const mode = tlsEnabled ? 'redirecting to HTTPS' : 'serving HTTP'
    console.log(`web-console HTTP listening on ${defaultPort} (${mode})`)
  })

  if (tlsEnabled) {
    const httpsServer = createHttpsServer({ httpsPort: defaultHttpsPort })
    httpsServer.listen(defaultHttpsPort, '0.0.0.0', () => {
      console.log(`web-console HTTPS listening on ${defaultHttpsPort}`)
    })
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === modulePath) {
  start()
}
