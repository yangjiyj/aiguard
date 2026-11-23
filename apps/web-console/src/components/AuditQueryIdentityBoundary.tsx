import { Fragment, type ReactNode, useLayoutEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'

import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'

const isSensitiveAuditQuery = (queryKey: readonly unknown[]) => {
  const root = String(queryKey[0] || '')
  return root === 'agent'
    || root === 'content-audit'
    || root === 'tool-audit'
    || root === 'audit-dispositions'
    || root === 'audit-operations'
    || root === 'mcpAudit'
    || root.startsWith('alerts-inbox')
    || root.startsWith('access-retention')
}

function AuditQueryIdentityBoundary({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const identityKey = useAuditQueryIdentity()
  const previousIdentity = useRef(identityKey)

  useLayoutEffect(() => {
    if (previousIdentity.current === identityKey) return
    previousIdentity.current = identityKey
    const predicate = (query: { queryKey: readonly unknown[] }) => (
      isSensitiveAuditQuery(query.queryKey) && query.queryKey[1] !== identityKey
    )
    void queryClient.cancelQueries({ predicate })
    queryClient.removeQueries({ predicate })
  }, [identityKey, queryClient])

  return <Fragment key={identityKey}>{children}</Fragment>
}

export default AuditQueryIdentityBoundary
