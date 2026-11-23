import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ThemedApp from './ThemedApp'
import AuditQueryIdentityBoundary from './components/AuditQueryIdentityBoundary'
import './index.css'
import './refine.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuditQueryIdentityBoundary>
        <ThemedApp />
      </AuditQueryIdentityBoundary>
    </QueryClientProvider>
  </React.StrictMode>,
)
