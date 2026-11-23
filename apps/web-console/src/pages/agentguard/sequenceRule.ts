// W5 5.5: sensitive-read -> egress sequence rule helpers. 0 seconds = off.
export const SEQUENCE_DEFAULT_MINUTES = 10
export const SEQUENCE_MAX_MINUTES = 24 * 60

export function sequenceWindowSeconds(enabled: boolean, minutes: number | null): number {
  if (!enabled) return 0
  const value = Math.round(minutes ?? SEQUENCE_DEFAULT_MINUTES)
  return Math.min(Math.max(value, 1), SEQUENCE_MAX_MINUTES) * 60
}
