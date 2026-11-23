import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'agent-kit-static',
      configureServer(server) {
        const rootUrl = new URL(`file://${server.config.root}/`)
        const agentKitDir = new URL('../../deploy/docker-compose/agent-kit/', rootUrl).pathname
        const staticHandlerUrl = new URL('./server.js', rootUrl).href
        server.middlewares.use((req, res, next) => {
          const requestUrl = (req as { url?: string }).url
          const requestPath = requestUrl?.split('?', 1)[0]
          if (requestPath !== '/agent-kit' && !/^\/agent-kit(?:\/|%(?:2f|5c))/i.test(requestPath || '')) {
            next()
            return
          }
          // The production handler enforces identical path and symlink checks in development.
          import(staticHandlerUrl).then(({ serveAgentKit }) => serveAgentKit(req, res, { agentKitDir })).catch(next)
        })
      },
    },
  ],
  server: {
    host: '0.0.0.0', // Listen on all interfaces for Docker
    port: 3000,
    proxy: {
      '/admin': {
        target: 'http://127.0.0.1:28081',
        changeOrigin: true,
      },
      '/v1': {
        target: 'http://gateway-core:8080',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
})