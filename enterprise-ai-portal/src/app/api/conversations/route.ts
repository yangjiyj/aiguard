// 会话管理 API
// GET    /api/conversations            列表（不含回收站）
// GET    /api/conversations?trash=1    回收站列表（6.17）
// POST   /api/conversations            新建
// GET    /api/conversations/[id]       取单条+消息
// PATCH  /api/conversations/[id]       重命名 / {restore:true} 从回收站恢复
// DELETE /api/conversations/[id]       移入回收站（软删，留存期后清理）
// 所有操作强制带 user_id 隔离
import { NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { normalizeTitle } from '@/lib/chat-history';
import { requireConversationUser, trashCutoff } from '@/lib/conversation-access';

export async function GET(req: Request) {
  const gate = await requireConversationUser();
  if (gate instanceof Response) return gate;
  const user = gate;
  const trash = new URL(req.url).searchParams.get('trash') === '1';
  // 超过留存期的回收站会话在这里顺手物理清理（级联删消息），失败不影响列表
  try {
    await prisma.conversation.deleteMany({
      where: { userId: user.historyUserIds?{in:user.historyUserIds}:user.id, deletedAt: { lt: trashCutoff() } },
    });
  } catch {}
  const list = await prisma.conversation.findMany({
    where: { userId: user.historyUserIds?{in:user.historyUserIds}:user.id, deletedAt: trash ? { not: null } : null },
    orderBy: trash ? { deletedAt: 'desc' } : { updatedAt: 'desc' },
    select: { id: true, title: true, createdAt: true, updatedAt: true, deletedAt: true },
  });
  return Response.json({ conversations: list });
}

export async function POST(req: NextRequest) {
  const gate = await requireConversationUser();
  if (gate instanceof Response) return gate;
  const user = gate;
  let title = '新对话';
  try {
    const body = await req.json();
    title = normalizeTitle(body?.title) ?? title;
  } catch {}
  const conv = await prisma.conversation.create({
    data: { userId: user.id, title },
  });
  return Response.json({ conversation: conv });
}
