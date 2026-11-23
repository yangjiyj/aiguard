// GET /api/me —— 前端取当前登录用户身份 + 品牌配置
import { auth } from '@/auth';
import { requireActivePortalUser } from '@/lib/require-active-user';

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) {
    return Response.json({ authenticated: false }, { status: 401 });
  }
  const active = await requireActivePortalUser(session);
  if (active instanceof Response) return active;
  const authorization = active.user;
  return Response.json({
    authenticated: true,
    user: {
      id: session.user.id,
      external_subject: session.user.id,
      email: session.user.email,
      name: session.user.name,
      department: authorization.departmentName,
      role: session.user.role,
    },
    brand: {
      name: process.env.BRAND_NAME ?? '企业 AI 对话门户',
      shortName: process.env.BRAND_SHORT_NAME ?? 'AI 门户',
      accent: process.env.BRAND_ACCENT ?? '#2451eb',
    },
  }, { headers: { 'cache-control': 'private, no-store' } });
}
