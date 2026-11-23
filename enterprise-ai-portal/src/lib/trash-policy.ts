// 回收站留存期（6.17）。纯逻辑，前后端共用。
export const DEFAULT_TRASH_RETENTION_DAYS = 30;

export function trashRetentionDays(env: Record<string, string | undefined> = process.env): number {
  const n = Number(env.PORTAL_TRASH_RETENTION_DAYS);
  return Number.isInteger(n) && n >= 1 && n <= 3650 ? n : DEFAULT_TRASH_RETENTION_DAYS;
}

export function trashCutoff(now = Date.now(), days = trashRetentionDays()): Date {
  return new Date(now - days * 86400_000);
}
