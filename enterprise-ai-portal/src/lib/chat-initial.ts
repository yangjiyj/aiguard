// 进门户默认是新对话；只有从工作台点历史对话（地址带 ?c=<id>）才直接打开那一条。
export function initialConversationId(search: string, ids: string[]): string | null {
  const id = new URLSearchParams(search).get("c");
  return id && ids.includes(id) ? id : null;
}

export function clearConversationParam(): void {
  const url = new URL(window.location.href);
  if (!url.searchParams.has("c")) return;
  url.searchParams.delete("c");
  window.history.replaceState(null, "", url.pathname + url.search + url.hash);
}
