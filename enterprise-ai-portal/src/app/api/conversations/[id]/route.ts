import { NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { normalizeTitle } from '@/lib/chat-history';
import { requireConversationUser } from '@/lib/conversation-access';

async function ownConversation(id: string, userId: string, historyUserIds?:string[]) {
  const conv = await prisma.conversation.findUnique({ where: { id } });
  if (!conv || !(historyUserIds??[userId]).includes(conv.userId)) return null;
  return conv;
}

export async function GET(_req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const gate = await requireConversationUser();
  if (gate instanceof Response) return gate;
  const { id } = await ctx.params;
  const conv = await ownConversation(id, gate.id,gate.historyUserIds);
  if (!conv || conv.deletedAt) return Response.json({ error: 'not_found' }, { status: 404 });
  const messages = await prisma.message.findMany({
    where: { conversationId: id },
    orderBy: { createdAt: 'asc' },
  });
  return Response.json({ conversation: conv, messages });
}

export async function PATCH(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const gate = await requireConversationUser();
  if (gate instanceof Response) return gate;
  const { id } = await ctx.params;
  const conv = await ownConversation(id, gate.id,gate.historyUserIds);
  if (!conv) return Response.json({ error: 'not_found' }, { status: 404 });
  let body: { title?: unknown; restore?: unknown } = {};
  try {
    body = await req.json();
  } catch {}
  if (body.restore === true) {
    const restored = await prisma.conversation.update({ where: { id }, data: { deletedAt: null } });
    return Response.json({ conversation: restored });
  }
  if (conv.deletedAt) return Response.json({ error: 'not_found' }, { status: 404 });
  const title = normalizeTitle(body.title);
  if (title === null) return Response.json({ error: 'missing_title' }, { status: 400 });
  const updated = await prisma.conversation.update({
    where: { id },
    data: { title },
  });
  return Response.json({ conversation: updated });
}

export async function DELETE(_req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const gate = await requireConversationUser();
  if (gate instanceof Response) return gate;
  const { id } = await ctx.params;
  const conv = await ownConversation(id, gate.id,gate.historyUserIds);
  if (!conv) return Response.json({ error: 'not_found' }, { status: 404 });
  // 6.17：软删进回收站，留存期（PORTAL_TRASH_RETENTION_DAYS，默认 30 天）后由列表接口清理
  await prisma.conversation.update({ where: { id }, data: { deletedAt: new Date() } });
  return Response.json({ ok: true });
}
