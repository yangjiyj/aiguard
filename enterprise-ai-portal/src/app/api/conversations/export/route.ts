// GET /api/conversations/export —— 一次性导出本人全部对话（6.17）
// 替代前端逐条串行拉取；每次导出写 ExportEvent 留痕（只记数量，不存内容）。
// 留痕写不进去就拒绝导出：导出行为必须可追溯。
import { prisma } from '@/lib/prisma';
import { requireConversationUser } from '@/lib/conversation-access';
import { exportAILabel } from '@/lib/ai-label';

export async function GET() {
  const gate = await requireConversationUser();
  if (gate instanceof Response) return gate;
  const list = await prisma.conversation.findMany({
    where: { userId: gate.historyUserIds?{in:gate.historyUserIds}:gate.id, deletedAt: null },
    orderBy: { updatedAt: 'desc' },
    select: {
      id: true,
      title: true,
      messages: {
        orderBy: { createdAt: 'asc' },
        select: { role: true, content: true, model: true },
      },
    },
  });
  const messageCount = list.reduce((n, c) => n + c.messages.length, 0);
  try {
    await prisma.exportEvent.create({
      data: { userId: gate.id, scope: 'all', conversationCount: list.length, messageCount },
    });
  } catch {
    return Response.json({ error: 'export_audit_unavailable' }, { status: 503 });
  }
  return Response.json(
    {
      ai_label: exportAILabel(),
      conversations: list.map((c) => ({
        title: c.title,
        messages: c.messages.map((m) => ({ role: m.role, content: m.content, model: m.model ?? undefined })),
      })),
    },
    { headers: { 'cache-control': 'private, no-store' } },
  );
}
