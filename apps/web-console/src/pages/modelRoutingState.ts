import type { ModelRoutingConfig } from '../services/api'

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, canonical(item)]))
  }
  return value
}

export function configFingerprint(config: ModelRoutingConfig): string {
  return JSON.stringify(canonical(config))
}

export function editorIdentity(kind: 'default' | 'override', modelName = '', version = 0): string {
  return `${kind}:${modelName}:${version}`
}
