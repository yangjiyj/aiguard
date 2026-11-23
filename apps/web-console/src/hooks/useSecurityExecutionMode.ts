import { useQuery } from '@tanstack/react-query'
import {
  normalizeSecurityExecutionMode,
  SECURITY_EXECUTION_MODE_QUERY_KEY,
  securityExecutionModeApi,
} from '../services/securityExecutionMode'

export function useSecurityExecutionMode() {
  const query = useQuery({
    queryKey: SECURITY_EXECUTION_MODE_QUERY_KEY,
    queryFn: securityExecutionModeApi.getSettings,
    refetchInterval: (query) => {
      const mode = normalizeSecurityExecutionMode(query.state.data)
      return mode && (!mode.runtime_verified || mode.configured_mode !== mode.effective_mode) ? 2000 : false
    },
  })
  return { ...query, settings: query.data, mode: normalizeSecurityExecutionMode(query.data) }
}
