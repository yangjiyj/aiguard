export type HistoryItem = { id: string; title: string; updatedAt: number };
export type HistoryGroup = { label: string; items: HistoryItem[] };

// 侧栏历史按本地日期分组；「7 天内」不含今天和昨天。
export function groupByDate(list: HistoryItem[], now: number = Date.now()): HistoryGroup[] {
  const d = new Date(now);
  const startOfToday = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  const day = 86400000;
  const groups: HistoryGroup[] = [
    { label: "今天", items: [] },
    { label: "昨天", items: [] },
    { label: "7 天内", items: [] },
    { label: "更早", items: [] },
  ];
  for (const c of list) {
    const i = c.updatedAt >= startOfToday ? 0 : c.updatedAt >= startOfToday - day ? 1 : c.updatedAt >= startOfToday - 7 * day ? 2 : 3;
    groups[i].items.push(c);
  }
  return groups.filter((g) => g.items.length > 0);
}
