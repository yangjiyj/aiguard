// Consume the fragment before any network request or navigation. Never
// persist it in storage, query strings, error text or telemetry.
export function takeChatLoginTicket(
  location: Pick<Location, 'hash' | 'pathname' | 'search'>,
  history: Pick<History, 'replaceState'>,
): string | null {
  const fragment = new URLSearchParams(location.hash.replace(/^#/, ''));
  if (!fragment.has('chat_ticket')) return null;
  const ticket = fragment.get('chat_ticket') ?? '';
  history.replaceState(null, '', location.pathname + location.search);
  if (!/^[A-Za-z0-9_-]{43}$/.test(ticket)) throw new Error('invalid_chat_ticket');
  return ticket;
}
